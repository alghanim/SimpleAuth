// Package simpleauth provides a Go SDK for SimpleAuth. It includes token
// acquisition, JWT verification with JWKS caching, user helpers, and HTTP
// middleware.
package simpleauth

import (
	"context"
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"strings"
	"sync"
	"time"
)

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

// Options configures a new Client.
type Options struct {
	URL                string // SimpleAuth server URL (e.g. "https://auth.example.com/sauth")
	AdminKey           string // Admin API key (for admin operations and bootstrap)
	InsecureSkipVerify bool   // Allow self-signed TLS certificates

	// AppID / AppSecret are an app's OAuth client credentials. When set, the
	// app-management methods (AppBootstrap, GetAppAuthz, ...) authenticate to
	// /api/app/* with HTTP Basic app_id:app_secret. Set Audience to AppID so
	// Verify rejects tokens minted for other apps.
	AppID     string
	AppSecret string

	// ExpectedIssuer, when non-empty, must equal the token's `iss` claim.
	// Leave empty to skip the issuer check. NOTE: direct login/refresh tokens
	// are issued with iss="simpleauth"; OIDC code-flow tokens use the realm URL.
	ExpectedIssuer string
	// Audience, when non-empty, must be present in the token's `aud` claim.
	// Leave empty to skip the audience check.
	Audience string
}

// TokenResponse is the OAuth2 token endpoint response.
type TokenResponse struct {
	AccessToken         string `json:"access_token"`
	RefreshToken        string `json:"refresh_token,omitempty"`
	IDToken             string `json:"id_token,omitempty"`
	TokenType           string `json:"token_type"`
	ExpiresIn           int    `json:"expires_in"`
	Scope               string `json:"scope,omitempty"`
	ForcePasswordChange bool   `json:"force_password_change,omitempty"`
}

// User represents the claims extracted from a verified JWT.
type User struct {
	Sub               string   `json:"sub"`
	Name              string   `json:"name,omitempty"`
	Email             string   `json:"email,omitempty"`
	PreferredUsername string   `json:"preferred_username,omitempty"`
	Roles             []string `json:"roles,omitempty"`
	Permissions       []string `json:"permissions,omitempty"`
	Groups            []string `json:"groups,omitempty"`
	Department        string   `json:"department,omitempty"`
	Company           string   `json:"company,omitempty"`
	JobTitle          string   `json:"job_title,omitempty"`
}

// HasRole returns true if the user has the given role.
func (u *User) HasRole(role string) bool {
	for _, r := range u.Roles {
		if r == role {
			return true
		}
	}
	return false
}

// HasPermission returns true if the user has the given permission.
func (u *User) HasPermission(perm string) bool {
	for _, p := range u.Permissions {
		if p == perm {
			return true
		}
	}
	return false
}

// HasAnyRole returns true if the user has at least one of the given roles.
func (u *User) HasAnyRole(roles ...string) bool {
	for _, role := range roles {
		if u.HasRole(role) {
			return true
		}
	}
	return false
}

// UserInfo holds the response from the OIDC userinfo endpoint.
type UserInfo struct {
	Sub               string `json:"sub"`
	Name              string `json:"name,omitempty"`
	Email             string `json:"email,omitempty"`
	PreferredUsername string `json:"preferred_username,omitempty"`
	EmailVerified     bool   `json:"email_verified,omitempty"`
}

// ---------------------------------------------------------------------------
// Client
// ---------------------------------------------------------------------------

// Client is the main entry point for interacting with SimpleAuth.
type Client struct {
	baseURL   string
	adminKey  string
	appID     string
	appSecret string
	http      *http.Client

	expectedIssuer string
	audience       string

	mu      sync.RWMutex
	keys    map[string]*rsa.PublicKey
	keysAt  time.Time
	keysTTL time.Duration

	// lastFetch / minRefetch bound how often an (unauthenticated) cache miss
	// can trigger an outbound JWKS fetch, so a flood of tokens carrying
	// unknown/attacker-chosen kids cannot amplify into a flood of backend
	// JWKS requests.
	lastFetch  time.Time
	minRefetch time.Duration
}

// New creates a new SimpleAuth client with the given options.
func New(opts Options) *Client {
	transport := http.DefaultTransport.(*http.Transport).Clone()
	if opts.InsecureSkipVerify {
		transport.TLSClientConfig = &tls.Config{InsecureSkipVerify: true} //nolint:gosec
	}

	return &Client{
		baseURL:        strings.TrimRight(opts.URL, "/"),
		adminKey:       opts.AdminKey,
		appID:          opts.AppID,
		appSecret:      opts.AppSecret,
		http:           &http.Client{Transport: transport, Timeout: 30 * time.Second},
		expectedIssuer: opts.ExpectedIssuer,
		audience:       opts.Audience,
		keys:           make(map[string]*rsa.PublicKey),
		keysTTL:        1 * time.Hour,
		minRefetch:     30 * time.Second,
	}
}

// ---------------------------------------------------------------------------
// Token acquisition
// ---------------------------------------------------------------------------

func (c *Client) postJSON(ctx context.Context, path string, payload interface{}) ([]byte, error) {
	data, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("simpleauth: marshal request: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+path, strings.NewReader(string(data)))
	if err != nil {
		return nil, fmt.Errorf("simpleauth: create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("simpleauth: request: %w", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("simpleauth: %s returned %d: %s", path, resp.StatusCode, string(body))
	}
	return body, nil
}

func (c *Client) decodeToken(data []byte) (*TokenResponse, error) {
	var tok TokenResponse
	if err := json.Unmarshal(data, &tok); err != nil {
		return nil, fmt.Errorf("simpleauth: decode token response: %w", err)
	}
	return &tok, nil
}

// Login authenticates a user with username and password.
func (c *Client) Login(ctx context.Context, username, password string) (*TokenResponse, error) {
	body, err := c.postJSON(ctx, "/api/auth/login", map[string]string{
		"username": username,
		"password": password,
	})
	if err != nil {
		return nil, err
	}
	return c.decodeToken(body)
}

// Refresh exchanges a refresh token for a new token set.
func (c *Client) Refresh(ctx context.Context, refreshToken string) (*TokenResponse, error) {
	body, err := c.postJSON(ctx, "/api/auth/refresh", map[string]string{
		"refresh_token": refreshToken,
	})
	if err != nil {
		return nil, err
	}
	return c.decodeToken(body)
}

// ---------------------------------------------------------------------------
// UserInfo
// ---------------------------------------------------------------------------

// UserInfo calls the userinfo endpoint.
func (c *Client) UserInfo(ctx context.Context, accessToken string) (*UserInfo, error) {
	u := c.baseURL + "/api/auth/userinfo"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, fmt.Errorf("simpleauth: create request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)

	resp, err := c.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("simpleauth: userinfo request: %w", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("simpleauth: userinfo returned %d: %s", resp.StatusCode, string(body))
	}

	var info UserInfo
	if err := json.Unmarshal(body, &info); err != nil {
		return nil, fmt.Errorf("simpleauth: decode userinfo: %w", err)
	}
	return &info, nil
}

// ---------------------------------------------------------------------------
// Admin: roles & permissions
// ---------------------------------------------------------------------------

func (c *Client) adminRequest(ctx context.Context, method, path string, payload interface{}) ([]byte, error) {
	var bodyReader io.Reader
	if payload != nil {
		data, err := json.Marshal(payload)
		if err != nil {
			return nil, fmt.Errorf("simpleauth: marshal payload: %w", err)
		}
		bodyReader = strings.NewReader(string(data))
	}

	u := fmt.Sprintf("%s%s", c.baseURL, path)
	req, err := http.NewRequestWithContext(ctx, method, u, bodyReader)
	if err != nil {
		return nil, fmt.Errorf("simpleauth: create request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+c.adminKey)
	if payload != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	resp, err := c.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("simpleauth: admin request: %w", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("simpleauth: admin endpoint returned %d: %s", resp.StatusCode, string(body))
	}
	return body, nil
}

// GetUserRoles returns the roles assigned to a user.
func (c *Client) GetUserRoles(ctx context.Context, guid string) ([]string, error) {
	body, err := c.adminRequest(ctx, http.MethodGet, fmt.Sprintf("/api/admin/users/%s/roles", guid), nil)
	if err != nil {
		return nil, err
	}
	var roles []string
	if err := json.Unmarshal(body, &roles); err != nil {
		return nil, fmt.Errorf("simpleauth: decode roles: %w", err)
	}
	return roles, nil
}

// SetUserRoles replaces the roles for a user.
func (c *Client) SetUserRoles(ctx context.Context, guid string, roles []string) error {
	_, err := c.adminRequest(ctx, http.MethodPut, fmt.Sprintf("/api/admin/users/%s/roles", guid), roles)
	return err
}

// GetUserPermissions returns the permissions assigned to a user.
func (c *Client) GetUserPermissions(ctx context.Context, guid string) ([]string, error) {
	body, err := c.adminRequest(ctx, http.MethodGet, fmt.Sprintf("/api/admin/users/%s/permissions", guid), nil)
	if err != nil {
		return nil, err
	}
	var perms []string
	if err := json.Unmarshal(body, &perms); err != nil {
		return nil, fmt.Errorf("simpleauth: decode permissions: %w", err)
	}
	return perms, nil
}

// SetUserPermissions replaces the permissions for a user.
func (c *Client) SetUserPermissions(ctx context.Context, guid string, perms []string) error {
	_, err := c.adminRequest(ctx, http.MethodPut, fmt.Sprintf("/api/admin/users/%s/permissions", guid), perms)
	return err
}

// ---------------------------------------------------------------------------
// App self-management (v2 — per-app authorization)
// ---------------------------------------------------------------------------
//
// An "app" is an OAuth client (app_id + app_secret) that self-manages its own
// authorization under /api/app/*, authenticated with HTTP Basic app_id:app_secret.
// The app_id is derived from the credential by the server — an app can only ever
// read or write its own scope. Set Options.Audience to the app's audience/app_id
// so Verify rejects tokens minted for other apps.

// AppAuthz is an app's complete authorization: its roles, permissions, the
// role -> permission map, and the user/group -> role assignments. It is the
// shape of GET/PUT /api/app/authz.
type AppAuthz struct {
	AppID            string              `json:"app_id"`
	Roles            []string            `json:"roles,omitempty"`
	Permissions      []string            `json:"permissions,omitempty"`
	RolePermissions  map[string][]string `json:"role_permissions,omitempty"`
	UserAssignments  map[string][]string `json:"user_assignments,omitempty"`  // user ref (guid/sAMAccountName/username) -> roles
	GroupAssignments map[string][]string `json:"group_assignments,omitempty"` // group identifier -> roles
}

// Assignment grants a set of roles to either a directory user or an AD group.
// Set exactly one of User (a username/sAMAccountName/GUID) or Group (the group's
// identifier, sAMAccountName by default).
type Assignment struct {
	User  string   `json:"user,omitempty"`
	Group string   `json:"group,omitempty"`
	Roles []string `json:"roles"`
}

// BootstrapSpec is idempotent authz-as-code for the calling app: it declares the
// app's roles, permissions, role -> permission map, and assignments. It is the
// body of POST /api/app/bootstrap and is safe to call on every deploy.
type BootstrapSpec struct {
	Roles           []string            `json:"roles,omitempty"`
	Permissions     []string            `json:"permissions,omitempty"`
	RolePermissions map[string][]string `json:"role_permissions,omitempty"`
	Assignments     []Assignment        `json:"assignments,omitempty"`
}

// BootstrapResult is the response from POST /api/app/bootstrap.
type BootstrapResult struct {
	Status           string `json:"status"`
	AppID            string `json:"app_id"`
	RolesCount       int    `json:"roles_count"`
	AssignmentsCount int    `json:"assignments_count"`
}

// AppSettings is an app's own settings (no secret), the shape of
// GET /api/app/settings.
type AppSettings struct {
	AppID             string   `json:"app_id"`
	Name              string   `json:"name"`
	Audience          string   `json:"audience"`
	RedirectURIs      []string `json:"redirect_uris"`
	CORSOrigins       []string `json:"cors_origins"`
	RequireAssignment bool     `json:"require_assignment"`
	AllowLocalUsers   bool     `json:"allow_local_users"`
	Disabled          bool     `json:"disabled"`
	CreatedAt         string   `json:"created_at"`
}

// LocalUser is an app-local user (a user owned by one app, e.g. a customer
// portal account not in the directory). Returned by ListLocalUsers and (with
// just the GUID/username populated) CreateLocalUser.
type LocalUser struct {
	GUID        string `json:"guid"`
	Username    string `json:"username,omitempty"`
	DisplayName string `json:"display_name,omitempty"`
	Email       string `json:"email,omitempty"`
	OwnerAppID  string `json:"owner_app_id,omitempty"`
	Disabled    bool   `json:"disabled,omitempty"`
	CreatedAt   string `json:"created_at,omitempty"`
}

// appRequest performs an authenticated request against /api/app/*. It mirrors
// adminRequest but authenticates with HTTP Basic app_id:app_secret instead of a
// Bearer admin key. It returns a clear error if AppID/AppSecret are unset.
func (c *Client) appRequest(ctx context.Context, method, path string, payload interface{}) ([]byte, error) {
	if c.appID == "" || c.appSecret == "" {
		return nil, errors.New("simpleauth: AppID and AppSecret are required for app-management operations")
	}

	var bodyReader io.Reader
	if payload != nil {
		data, err := json.Marshal(payload)
		if err != nil {
			return nil, fmt.Errorf("simpleauth: marshal payload: %w", err)
		}
		bodyReader = strings.NewReader(string(data))
	}

	u := fmt.Sprintf("%s%s", c.baseURL, path)
	req, err := http.NewRequestWithContext(ctx, method, u, bodyReader)
	if err != nil {
		return nil, fmt.Errorf("simpleauth: create request: %w", err)
	}
	req.SetBasicAuth(c.appID, c.appSecret)
	if payload != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	resp, err := c.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("simpleauth: app request: %w", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("simpleauth: app endpoint returned %d: %s", resp.StatusCode, string(body))
	}
	return body, nil
}

// AppBootstrap declares the calling app's roles, permissions, role->permission
// map, and assignments (authz-as-code). It is idempotent and safe to call on
// every deploy. POST /api/app/bootstrap.
func (c *Client) AppBootstrap(ctx context.Context, spec BootstrapSpec) (*BootstrapResult, error) {
	body, err := c.appRequest(ctx, http.MethodPost, "/api/app/bootstrap", spec)
	if err != nil {
		return nil, err
	}
	var res BootstrapResult
	if err := json.Unmarshal(body, &res); err != nil {
		return nil, fmt.Errorf("simpleauth: decode bootstrap result: %w", err)
	}
	return &res, nil
}

// GetAppAuthz returns the calling app's current authorization (roles,
// permissions, role->permission map, and assignments). GET /api/app/authz.
func (c *Client) GetAppAuthz(ctx context.Context) (*AppAuthz, error) {
	body, err := c.appRequest(ctx, http.MethodGet, "/api/app/authz", nil)
	if err != nil {
		return nil, err
	}
	var authz AppAuthz
	if err := json.Unmarshal(body, &authz); err != nil {
		return nil, fmt.Errorf("simpleauth: decode authz: %w", err)
	}
	return &authz, nil
}

// SetAppAuthz replaces the calling app's authorization wholesale. The server
// uses the credential's app_id authoritatively, so AppAuthz.AppID may be left
// empty. PUT /api/app/authz.
func (c *Client) SetAppAuthz(ctx context.Context, authz AppAuthz) (*AppAuthz, error) {
	body, err := c.appRequest(ctx, http.MethodPut, "/api/app/authz", authz)
	if err != nil {
		return nil, err
	}
	var updated AppAuthz
	if err := json.Unmarshal(body, &updated); err != nil {
		return nil, fmt.Errorf("simpleauth: decode authz: %w", err)
	}
	return &updated, nil
}

// AppSettings returns the calling app's own settings (no secret).
// GET /api/app/settings.
func (c *Client) AppSettings(ctx context.Context) (*AppSettings, error) {
	body, err := c.appRequest(ctx, http.MethodGet, "/api/app/settings", nil)
	if err != nil {
		return nil, err
	}
	var s AppSettings
	if err := json.Unmarshal(body, &s); err != nil {
		return nil, fmt.Errorf("simpleauth: decode settings: %w", err)
	}
	return &s, nil
}

// CreateLocalUser provisions an app-local user owned by the calling app. It
// requires the app's allow_local_users flag. roles, if non-empty, are recorded
// as the app's assignment for that username. displayName and email are optional
// (pass ""). POST /api/app/users.
func (c *Client) CreateLocalUser(ctx context.Context, username, password, displayName, email string, roles []string) (*LocalUser, error) {
	payload := map[string]interface{}{
		"username": username,
		"password": password,
	}
	if displayName != "" {
		payload["display_name"] = displayName
	}
	if email != "" {
		payload["email"] = email
	}
	if len(roles) > 0 {
		payload["roles"] = roles
	}
	body, err := c.appRequest(ctx, http.MethodPost, "/api/app/users", payload)
	if err != nil {
		return nil, err
	}
	var u LocalUser
	if err := json.Unmarshal(body, &u); err != nil {
		return nil, fmt.Errorf("simpleauth: decode local user: %w", err)
	}
	return &u, nil
}

// ListLocalUsers lists the calling app's local users. GET /api/app/users.
func (c *Client) ListLocalUsers(ctx context.Context) ([]LocalUser, error) {
	body, err := c.appRequest(ctx, http.MethodGet, "/api/app/users", nil)
	if err != nil {
		return nil, err
	}
	var wrapper struct {
		Users []LocalUser `json:"users"`
	}
	if err := json.Unmarshal(body, &wrapper); err != nil {
		return nil, fmt.Errorf("simpleauth: decode local users: %w", err)
	}
	return wrapper.Users, nil
}

// DeleteLocalUser deletes an app-local user owned by the calling app.
// DELETE /api/app/users/{guid}.
func (c *Client) DeleteLocalUser(ctx context.Context, guid string) error {
	_, err := c.appRequest(ctx, http.MethodDelete, fmt.Sprintf("/api/app/users/%s", guid), nil)
	return err
}

// SetLocalUserPassword resets an app-local user's password.
// PUT /api/app/users/{guid}/password.
func (c *Client) SetLocalUserPassword(ctx context.Context, guid, password string) error {
	_, err := c.appRequest(ctx, http.MethodPut, fmt.Sprintf("/api/app/users/%s/password", guid), map[string]string{
		"password": password,
	})
	return err
}

// ---------------------------------------------------------------------------
// JWKS fetching & caching
// ---------------------------------------------------------------------------

type jwksResponse struct {
	Keys []jwkKey `json:"keys"`
}

type jwkKey struct {
	Kty string `json:"kty"`
	Kid string `json:"kid"`
	Use string `json:"use"`
	Alg string `json:"alg"`
	N   string `json:"n"`
	E   string `json:"e"`
}

func (c *Client) certsURL() string {
	return c.baseURL + "/.well-known/jwks.json"
}

func (c *Client) fetchJWKS() error {
	c.mu.Lock()
	c.lastFetch = time.Now()
	c.mu.Unlock()

	resp, err := c.http.Get(c.certsURL())
	if err != nil {
		return fmt.Errorf("simpleauth: fetch JWKS: %w", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("simpleauth: JWKS endpoint returned %d: %s", resp.StatusCode, string(body))
	}

	var jwks jwksResponse
	if err := json.Unmarshal(body, &jwks); err != nil {
		return fmt.Errorf("simpleauth: decode JWKS: %w", err)
	}

	keys := make(map[string]*rsa.PublicKey, len(jwks.Keys))
	for _, k := range jwks.Keys {
		if k.Kty != "RSA" {
			continue
		}
		pub, err := parseRSAPublicKey(k.N, k.E)
		if err != nil {
			return fmt.Errorf("simpleauth: parse RSA key kid=%s: %w", k.Kid, err)
		}
		keys[k.Kid] = pub
	}

	c.mu.Lock()
	c.keys = keys
	c.keysAt = time.Now()
	c.mu.Unlock()
	return nil
}

func parseRSAPublicKey(nB64, eB64 string) (*rsa.PublicKey, error) {
	nBytes, err := base64.RawURLEncoding.DecodeString(nB64)
	if err != nil {
		return nil, fmt.Errorf("decode n: %w", err)
	}
	eBytes, err := base64.RawURLEncoding.DecodeString(eB64)
	if err != nil {
		return nil, fmt.Errorf("decode e: %w", err)
	}

	n := new(big.Int).SetBytes(nBytes)
	e := 0
	for _, b := range eBytes {
		e = e<<8 + int(b)
	}

	return &rsa.PublicKey{N: n, E: e}, nil
}

// getKey returns the RSA public key for the given kid. It uses the cache when
// possible and re-fetches from the JWKS endpoint on cache miss or expiry.
//
// getKey runs on attacker-controlled input (the token's kid) BEFORE the
// signature is verified, so cache misses must not translate one-to-one into
// outbound JWKS fetches. A re-fetch is therefore only attempted at most once
// per minRefetch window; within that window an unknown kid fails fast against
// the existing cache instead of triggering another fetch. This bounds the
// fetch-amplification a flood of unknown-kid tokens can cause.
func (c *Client) getKey(kid string) (*rsa.PublicKey, error) {
	c.mu.RLock()
	key, ok := c.keys[kid]
	expired := time.Since(c.keysAt) > c.keysTTL
	throttled := time.Since(c.lastFetch) < c.minRefetch
	c.mu.RUnlock()

	if ok && !expired {
		return key, nil
	}

	// Cache miss or expired. Only re-fetch if we have not fetched too recently;
	// otherwise serve from (or fail against) the current cache so a stream of
	// unknown kids cannot amplify into a stream of JWKS fetches.
	if throttled {
		if ok {
			return key, nil
		}
		return nil, fmt.Errorf("simpleauth: unknown signing key kid=%s", kid)
	}

	if err := c.fetchJWKS(); err != nil {
		return nil, err
	}

	c.mu.RLock()
	key, ok = c.keys[kid]
	c.mu.RUnlock()

	if !ok {
		return nil, fmt.Errorf("simpleauth: unknown signing key kid=%s", kid)
	}
	return key, nil
}

// ---------------------------------------------------------------------------
// JWT verification (RS256, stdlib only)
// ---------------------------------------------------------------------------

// jwtHeader is the minimal JOSE header we need.
type jwtHeader struct {
	Alg string `json:"alg"`
	Kid string `json:"kid"`
}

// Verify parses and cryptographically verifies a JWT (RS256). It returns the
// decoded User claims on success.
func (c *Client) Verify(tokenString string) (*User, error) {
	parts := strings.SplitN(tokenString, ".", 3)
	if len(parts) != 3 {
		return nil, errors.New("simpleauth: malformed JWT: expected 3 parts")
	}

	// Decode header.
	headerJSON, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return nil, fmt.Errorf("simpleauth: decode JWT header: %w", err)
	}
	var hdr jwtHeader
	if err := json.Unmarshal(headerJSON, &hdr); err != nil {
		return nil, fmt.Errorf("simpleauth: parse JWT header: %w", err)
	}
	if hdr.Alg != "RS256" {
		return nil, fmt.Errorf("simpleauth: unsupported JWT algorithm %q", hdr.Alg)
	}

	// Decode signature.
	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return nil, fmt.Errorf("simpleauth: decode JWT signature: %w", err)
	}

	// Fetch public key.
	pubKey, err := c.getKey(hdr.Kid)
	if err != nil {
		return nil, err
	}

	// Verify RS256: RSASSA-PKCS1-v1_5 using SHA-256.
	signed := []byte(parts[0] + "." + parts[1])
	hash := sha256.Sum256(signed)
	if err := rsa.VerifyPKCS1v15(pubKey, crypto.SHA256, hash[:], sig); err != nil {
		return nil, fmt.Errorf("simpleauth: invalid JWT signature: %w", err)
	}

	// Decode payload.
	payloadJSON, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, fmt.Errorf("simpleauth: decode JWT payload: %w", err)
	}

	// Parse standard claims for validation.
	var claims struct {
		Exp      json.Number `json:"exp"`
		Iss      string      `json:"iss"`
		Aud      audience    `json:"aud"`
		FamilyID string      `json:"family_id"`
		Typ      string      `json:"typ"`
	}
	if err := json.Unmarshal(payloadJSON, &claims); err != nil {
		return nil, fmt.Errorf("simpleauth: decode JWT claims: %w", err)
	}

	// Reject non-access token classes. The server signs several token classes
	// with the same key, distinguished by claims: access tokens carry no
	// family_id and either no typ (direct-login) or typ="Bearer" (OIDC and
	// client_credentials service tokens); refresh tokens carry a family_id; OIDC
	// ID tokens carry typ="ID"; app-management tokens carry typ="app-mgmt".
	// Reject refresh/ID/app-mgmt so none of those can be replayed as a bearer
	// credential for resource access, while still accepting both access-token
	// shapes ("" and "Bearer").
	if claims.FamilyID != "" {
		return nil, errors.New("simpleauth: refresh token is not valid for resource access")
	}
	if claims.Typ == "ID" || claims.Typ == "app-mgmt" {
		return nil, fmt.Errorf("simpleauth: token type %q is not a user access token", claims.Typ)
	}

	// Expiration is mandatory — fail closed if the claim is absent or unparseable.
	expInt, err := claims.Exp.Int64()
	if err != nil || expInt == 0 {
		return nil, errors.New("simpleauth: token missing a valid exp claim")
	}
	if time.Now().Unix() > expInt {
		return nil, errors.New("simpleauth: token has expired")
	}

	// Optional issuer / audience checks.
	if c.expectedIssuer != "" && claims.Iss != c.expectedIssuer {
		return nil, fmt.Errorf("simpleauth: unexpected issuer %q", claims.Iss)
	}
	if c.audience != "" && !claims.Aud.contains(c.audience) {
		return nil, fmt.Errorf("simpleauth: token audience does not include %q", c.audience)
	}

	var user User
	if err := json.Unmarshal(payloadJSON, &user); err != nil {
		return nil, fmt.Errorf("simpleauth: decode JWT claims: %w", err)
	}
	return &user, nil
}

// audience handles the `aud` claim which may be encoded as a single string or
// an array of strings.
type audience []string

func (a *audience) UnmarshalJSON(b []byte) error {
	var single string
	if err := json.Unmarshal(b, &single); err == nil {
		*a = []string{single}
		return nil
	}
	var multi []string
	if err := json.Unmarshal(b, &multi); err != nil {
		return err
	}
	*a = multi
	return nil
}

func (a audience) contains(s string) bool {
	for _, v := range a {
		if v == s {
			return true
		}
	}
	return false
}

// ---------------------------------------------------------------------------
// HTTP middleware
// ---------------------------------------------------------------------------

type contextKey struct{}

// UserFromContext retrieves the authenticated User from the request context.
// Returns nil if no user is present (e.g. middleware was not applied).
func UserFromContext(ctx context.Context) *User {
	u, _ := ctx.Value(contextKey{}).(*User)
	return u
}

// Middleware returns an http.Handler middleware that validates the Bearer token
// in the Authorization header and stores the resulting User in the request
// context. Unauthenticated requests receive a 401 response.
func (c *Client) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token := extractBearer(r)
		if token == "" {
			http.Error(w, `{"error":"missing or invalid Authorization header"}`, http.StatusUnauthorized)
			return
		}

		user, err := c.Verify(token)
		if err != nil {
			http.Error(w, fmt.Sprintf(`{"error":"%s"}`, err.Error()), http.StatusUnauthorized)
			return
		}

		ctx := context.WithValue(r.Context(), contextKey{}, user)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// RequireRole wraps a handler and rejects requests from users that lack the
// specified role with a 403 Forbidden response.
func (c *Client) RequireRole(role string, next http.Handler) http.Handler {
	return c.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		user := UserFromContext(r.Context())
		if user == nil || !user.HasRole(role) {
			http.Error(w, `{"error":"forbidden: missing required role"}`, http.StatusForbidden)
			return
		}
		next.ServeHTTP(w, r)
	}))
}

// RequirePermission wraps a handler and rejects requests from users that lack
// the specified permission with a 403 Forbidden response.
func (c *Client) RequirePermission(perm string, next http.Handler) http.Handler {
	return c.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		user := UserFromContext(r.Context())
		if user == nil || !user.HasPermission(perm) {
			http.Error(w, `{"error":"forbidden: missing required permission"}`, http.StatusForbidden)
			return
		}
		next.ServeHTTP(w, r)
	}))
}

func extractBearer(r *http.Request) string {
	auth := r.Header.Get("Authorization")
	if len(auth) > 7 && strings.EqualFold(auth[:7], "bearer ") {
		return auth[7:]
	}
	return ""
}
