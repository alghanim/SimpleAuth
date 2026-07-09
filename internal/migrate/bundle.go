// Package migrate builds and applies migration BUNDLES that move a standalone
// SimpleAuth deployment into a single named app on a central deployment.
//
// What moves is the AUTHORIZATION POLICY, not signing keys or PII we can avoid:
//   - the source home app's config (audience, redirect_uris, cors, secret hash,
//     flags) is carried onto the target named app, so the consumer app's existing
//     client_id / secret / redirect_uri keep working;
//   - the role->permission catalog becomes the target app's per-app authz;
//   - each user's EFFECTIVE roles travel keyed by a PORTABLE identity —
//   - AD users    -> sAMAccountName: the central re-binds them from the SAME
//     AD on login; no record or password is copied.
//   - local users -> username, with their password hash, materialized as
//     app-local users on the target app.
//
// The split is by AUTHENTICATION method, because that is the thing that does not
// move: a local user carries their hash; an AD user needs the central on the same
// AD. Classify (dry-run) reports whether every user is satisfiable on the central
// BEFORE any write; Apply performs the import.
package migrate

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"simpleauth/internal/store"
)

// SchemaRev is the bundle wire-format revision; bump on incompatible changes.
const SchemaRev = 1

// UserKind is how a user authenticates, which determines how they migrate.
type UserKind string

const (
	KindAD    UserKind = "ad"    // AD-backed: re-bound from the central's AD; key = sAMAccountName
	KindLocal UserKind = "local" // local password: materialized as an app-local user
)

// Bundle is the portable migration payload.
type Bundle struct {
	SchemaRev     int       `json:"schema_rev"`
	SourceVersion string    `json:"source_version"`
	CreatedAt     time.Time `json:"created_at"`

	// SourceAD describes the source's directory binding (nil if not AD-connected),
	// so the central can confirm it is the SAME AD before resolving AD users.
	SourceAD *ADInfo `json:"source_ad,omitempty"`

	App     AppConfig   `json:"app"`
	Catalog Catalog     `json:"catalog"`
	Users   []UserEntry `json:"users"`
}

// ADInfo identifies the source's Active Directory binding.
type ADInfo struct {
	Domain string `json:"domain,omitempty"`
	BaseDN string `json:"base_dn,omitempty"`
}

// AppConfig is the source home app's config, carried onto the target app.
type AppConfig struct {
	Audience          string            `json:"audience,omitempty"`
	RedirectURIs      []string          `json:"redirect_uris,omitempty"`
	CORSOrigins       []string          `json:"cors_origins,omitempty"`
	SecretHash        string            `json:"secret_hash,omitempty"`
	RequireAssignment bool              `json:"require_assignment"`
	BaseURL           string            `json:"base_url,omitempty"`
	DisplayName       map[string]string `json:"display_name,omitempty"`
	Category          string            `json:"category,omitempty"`
	Icon              string            `json:"icon,omitempty"`
}

// Catalog is the source's role/permission definitions.
type Catalog struct {
	RolePermissions map[string][]string `json:"role_permissions,omitempty"`
	Permissions     []string            `json:"permissions,omitempty"`
	DefaultRoles    []string            `json:"default_roles,omitempty"`
}

// UserEntry is one user's portable identity + effective roles.
type UserEntry struct {
	Kind  UserKind `json:"kind"`
	Key   string   `json:"key"`             // sAMAccountName (AD) or username (local)
	Roles []string `json:"roles,omitempty"` // effective roles (explicit, or default_roles)

	// DirectPerms are the user's direct (non-role) permissions. Reported by the
	// dry-run; NOT applied in this revision (named apps derive perms from roles).
	DirectPerms []string `json:"direct_perms,omitempty"`

	// Local-only: enough to materialize an app-local user with the same login.
	DisplayName  string `json:"display_name,omitempty"`
	Email        string `json:"email,omitempty"`
	PasswordHash string `json:"password_hash,omitempty"`
}

// Package builds a Bundle from a standalone deployment's store, capturing its home
// app (homeAppID) config + the whole directory.
func Package(s store.Store, homeAppID, sourceVersion string) (*Bundle, error) {
	b := &Bundle{SchemaRev: SchemaRev, SourceVersion: sourceVersion, CreatedAt: time.Now().UTC()}

	if ldap, _ := s.GetLDAPConfig(); ldap != nil && (ldap.Domain != "" || ldap.BaseDN != "") {
		b.SourceAD = &ADInfo{Domain: ldap.Domain, BaseDN: ldap.BaseDN}
	}

	if app, err := s.GetApp(homeAppID); err == nil {
		aud := app.Audience
		if aud == "" {
			aud = app.AppID
		}
		b.App = AppConfig{
			Audience:          aud,
			RedirectURIs:      app.RedirectURIs,
			CORSOrigins:       app.CORSOrigins,
			SecretHash:        app.SecretHash,
			RequireAssignment: app.RequireAssignment,
			BaseURL:           app.BaseURL,
			DisplayName:       app.DisplayName,
			Category:          app.Category,
			Icon:              app.Icon,
		}
	}

	rp, _ := s.GetRolePermissions()
	perms, _ := s.GetDefinedPermissions()
	defs, _ := s.GetDefaultRoles()
	b.Catalog = Catalog{RolePermissions: rp, Permissions: perms, DefaultRoles: defs}

	users, err := s.ListUsers()
	if err != nil {
		return nil, fmt.Errorf("list users: %w", err)
	}
	for _, u := range users {
		if u.MergedInto != "" {
			continue // merged-away shadow
		}
		// App-local users owned by ANOTHER app aren't part of this home directory.
		if u.OwnerAppID != "" && u.OwnerAppID != homeAppID {
			continue
		}
		if entry, ok := classifyUser(s, u, b.Catalog.DefaultRoles); ok {
			b.Users = append(b.Users, entry)
		}
	}
	return b, nil
}

// classifyUser turns a source user into a portable UserEntry. ok=false skips a
// user with no usable identity.
func classifyUser(s store.Store, u *store.User, defaultRoles []string) (UserEntry, bool) {
	roles, _ := s.GetUserRoles(u.GUID)
	if len(roles) == 0 {
		roles = defaultRoles // effective baseline the user had on the home app
	}
	direct, _ := s.GetUserPermissions(u.GUID)

	if u.PasswordHash != "" {
		username := localUsername(s, u)
		if username == "" {
			return UserEntry{}, false
		}
		return UserEntry{
			Kind: KindLocal, Key: username, Roles: roles, DirectPerms: direct,
			DisplayName: u.DisplayName, Email: u.Email, PasswordHash: u.PasswordHash,
		}, true
	}
	if u.SAMAccountName != "" {
		return UserEntry{Kind: KindAD, Key: u.SAMAccountName, Roles: roles, DirectPerms: direct}, true
	}
	return UserEntry{}, false
}

// localUsername finds the login username for a local user.
func localUsername(s store.Store, u *store.User) string {
	mappings, _ := s.GetMappingsForUser(u.GUID)
	for _, m := range mappings {
		if m.Provider == "local" {
			return m.ExternalID
		}
	}
	for _, m := range mappings {
		if strings.HasPrefix(m.Provider, "applocal:") {
			return m.ExternalID
		}
	}
	if u.SAMAccountName != "" {
		return u.SAMAccountName
	}
	return u.Email
}

// Report is the dry-run result the central computes before any write.
type Report struct {
	SourceVersion string `json:"source_version"`
	TargetApp     string `json:"target_app"`

	ADUsersSameDomain int           `json:"ad_users_same_domain"` // resolvable from the central's AD
	ADUsersKnown      int           `json:"ad_users_known"`       // already present in the central directory
	LocalUsers        int           `json:"local_users"`          // materialized as app-local users
	Blocked           []BlockedUser `json:"blocked,omitempty"`
	Notes             []string      `json:"notes,omitempty"`

	RedirectURIsToReview []string `json:"redirect_uris_to_review,omitempty"`
}

// BlockedUser is a user the central cannot satisfy as-is.
type BlockedUser struct {
	Key    string `json:"key"`
	Reason string `json:"reason"`
}

// OK reports whether the migration can proceed (no blocked users).
func (r *Report) OK() bool { return len(r.Blocked) == 0 }

// Classify computes the dry-run report. It validates every user is satisfiable on
// the central WITHOUT mutating anything.
func Classify(b *Bundle, central store.Store, targetAppID string) (*Report, error) {
	r := &Report{SourceVersion: b.SourceVersion, TargetApp: targetAppID, RedirectURIsToReview: b.App.RedirectURIs}

	// Fresh-target guard: Apply wholesale-replaces the target's authz, so refuse a
	// target that already has ANY per-app authorization — user OR group
	// assignments, roles, role→perm map, or a permission catalog. Migrate into a
	// freshly-created app to avoid clobbering an in-use one.
	if cur, _ := central.GetAppAuthz(targetAppID); cur != nil && (len(cur.UserAssignments) > 0 || len(cur.GroupAssignments) > 0 || len(cur.RolePermissions) > 0 || len(cur.Roles) > 0 || len(cur.Permissions) > 0) {
		r.Blocked = append(r.Blocked, BlockedUser{Key: targetAppID, Reason: "target app already has authorization configured — migrate into a freshly-created app"})
		return r, nil
	}

	centralLDAP, _ := central.GetLDAPConfig()
	centralHasAD := centralLDAP != nil && (centralLDAP.Domain != "" || centralLDAP.BaseDN != "")
	sameAD := centralHasAD && b.SourceAD != nil && sameADDomain(b.SourceAD, centralLDAP)

	known := map[string]bool{}
	if cu, err := central.ListUsers(); err == nil {
		for _, u := range cu {
			if u.SAMAccountName != "" {
				known[u.SAMAccountName] = true
			}
		}
	}

	directPermUsers := 0
	for _, u := range b.Users {
		if len(u.DirectPerms) > 0 {
			directPermUsers++
		}
		switch u.Kind {
		case KindLocal:
			r.LocalUsers++
		case KindAD:
			switch {
			case !centralHasAD:
				r.Blocked = append(r.Blocked, BlockedUser{Key: u.Key, Reason: "central is not connected to AD; cannot authenticate this user"})
			case !sameAD:
				r.Blocked = append(r.Blocked, BlockedUser{Key: u.Key, Reason: "central is on a different AD; key by UPN/email or connect the same AD"})
			default:
				r.ADUsersSameDomain++
				if known[u.Key] {
					r.ADUsersKnown++
				}
			}
		}
	}

	if directPermUsers > 0 {
		r.Notes = append(r.Notes, fmt.Sprintf("%d user(s) have direct (non-role) permissions that are NOT carried in this version — re-grant via roles on the target app", directPermUsers))
	}
	if b.SourceAD != nil && !centralHasAD {
		r.Notes = append(r.Notes, "source is AD-connected but the central is not — connect the central to the same AD to migrate AD users")
	}
	return r, nil
}

func sameADDomain(src *ADInfo, c *store.LDAPConfig) bool {
	if src.Domain != "" && c.Domain != "" {
		return strings.EqualFold(strings.TrimSpace(src.Domain), strings.TrimSpace(c.Domain))
	}
	if src.BaseDN != "" && c.BaseDN != "" {
		return strings.EqualFold(strings.TrimSpace(src.BaseDN), strings.TrimSpace(c.BaseDN))
	}
	return false
}

// ApplyResult summarizes a committed import.
type ApplyResult struct {
	AppUpdated        bool `json:"app_updated"`
	RolesDefined      int  `json:"roles_defined"`
	AssignmentsSet    int  `json:"assignments_set"`
	LocalUsersCreated int  `json:"local_users_created"`
	Skipped           int  `json:"skipped"`
}

// Apply imports the bundle into targetAppID on the central store. Additive, and
// idempotent for local users (an existing app-local username is left in place).
// carrySecret copies the source app's secret hash so the consumer's existing
// secret keeps working; pass false to keep the target app's own secret.
func Apply(b *Bundle, central store.Store, targetAppID string, carrySecret bool) (*ApplyResult, error) {
	res := &ApplyResult{}

	app, err := central.GetApp(targetAppID)
	if err != nil {
		return nil, fmt.Errorf("target app: %w", err)
	}

	if b.App.Audience != "" {
		app.Audience = b.App.Audience
	}
	if len(b.App.RedirectURIs) > 0 {
		app.RedirectURIs = b.App.RedirectURIs
	}
	if len(b.App.CORSOrigins) > 0 {
		app.CORSOrigins = b.App.CORSOrigins
	}
	// Carry the SA-1 presentation metadata onto the target (additive; never blanks
	// an existing value the operator set on the target).
	if b.App.BaseURL != "" {
		app.BaseURL = b.App.BaseURL
	}
	if len(b.App.DisplayName) > 0 {
		app.DisplayName = b.App.DisplayName
	}
	if b.App.Category != "" {
		app.Category = b.App.Category
	}
	if b.App.Icon != "" {
		app.Icon = b.App.Icon
	}
	// Never WEAKEN the target's access gate via a migration: OR-in only. A target
	// the operator deliberately created with require_assignment=true must not be
	// downgraded to open by a source home app that ran with it off.
	app.RequireAssignment = app.RequireAssignment || b.App.RequireAssignment
	if carrySecret && b.App.SecretHash != "" {
		app.SecretHash = b.App.SecretHash
	}
	for _, u := range b.Users {
		if u.Kind == KindLocal {
			app.AllowLocalUsers = true
			break
		}
	}
	if err := central.UpdateApp(app); err != nil {
		return nil, fmt.Errorf("update app: %w", err)
	}
	res.AppUpdated = true

	authz, _ := central.GetAppAuthz(targetAppID)
	if authz == nil {
		authz = &store.AppAuthz{AppID: targetAppID}
	}
	authz.AppID = targetAppID
	if b.Catalog.RolePermissions != nil {
		authz.RolePermissions = b.Catalog.RolePermissions
		authz.Roles = sortedKeys(b.Catalog.RolePermissions)
	}
	if len(b.Catalog.Permissions) > 0 {
		authz.Permissions = b.Catalog.Permissions
	}
	if authz.UserAssignments == nil {
		authz.UserAssignments = map[string][]string{}
	}
	res.RolesDefined = len(authz.Roles)

	mapKey := "applocal:" + targetAppID
	for _, u := range b.Users {
		if len(u.Roles) == 0 {
			res.Skipped++ // nothing to grant
			continue
		}
		if u.Kind == KindLocal {
			if existing, _ := central.ResolveMapping(mapKey, u.Key); existing == "" {
				nu := &store.User{OwnerAppID: targetAppID, DisplayName: u.DisplayName, Email: u.Email, PasswordHash: u.PasswordHash, CreatedAt: time.Now().UTC()}
				if err := central.CreateUser(nu); err != nil {
					return nil, fmt.Errorf("create local user %q: %w", u.Key, err)
				}
				if err := central.SetIdentityMapping(mapKey, u.Key, nu.GUID); err != nil {
					return nil, fmt.Errorf("map local user %q: %w", u.Key, err)
				}
				res.LocalUsersCreated++
			}
		}
		authz.UserAssignments[u.Key] = u.Roles
		res.AssignmentsSet++
	}

	if err := central.SaveAppAuthz(authz); err != nil {
		return nil, fmt.Errorf("save authz: %w", err)
	}
	return res, nil
}

func sortedKeys(m map[string][]string) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
