// ---------------------------------------------------------------------------
// SimpleAuth Example: Service-to-Service Authentication (Go)
// ---------------------------------------------------------------------------
// Demonstrates machine-to-machine (M2M) authentication in Go using a dedicated
// service-account login — the recommended SimpleAuth M2M pattern, since a
// service is just a user. Patterns shown:
//
//  1. Obtain a token by logging in as the service account
//  2. Token caching with automatic renewal
//  3. HTTP client with auto-injected Bearer token
//  4. Calling another internal service
//
// Usage:
//
//	SIMPLEAUTH_SERVICE_USER=billing-svc SIMPLEAUTH_SERVICE_PASSWORD=... go run main.go
//
// Environment variables:
//
//	SIMPLEAUTH_URL, SIMPLEAUTH_SERVICE_USER, SIMPLEAUTH_SERVICE_PASSWORD,
//	ORDER_SERVICE_URL, SIMPLEAUTH_INSECURE (set "true" to trust self-signed certs)
//
// ---------------------------------------------------------------------------
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"sync"
	"time"

	simpleauth "github.com/bodaay/simpleauth-go"
)

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

// =========================================================================
// 1. TokenManager — caches tokens and refreshes before expiry
// =========================================================================

// TokenManager acquires and caches an access token via service-account login.
// It is safe for concurrent use.
type TokenManager struct {
	client        *simpleauth.Client
	username      string
	password      string
	refreshMargin time.Duration

	mu        sync.Mutex
	token     *simpleauth.TokenResponse
	expiresAt time.Time
}

// NewTokenManager creates a TokenManager that authenticates as the given
// service account. refreshMargin controls how early before expiry a new token
// is fetched (default 30 seconds).
func NewTokenManager(client *simpleauth.Client, username, password string, refreshMargin time.Duration) *TokenManager {
	if refreshMargin <= 0 {
		refreshMargin = 30 * time.Second
	}
	return &TokenManager{
		client:        client,
		username:      username,
		password:      password,
		refreshMargin: refreshMargin,
	}
}

// GetToken returns a valid access token, fetching a new one if necessary.
func (tm *TokenManager) GetToken(ctx context.Context) (string, error) {
	tm.mu.Lock()
	defer tm.mu.Unlock()

	// Return cached token if still valid
	if tm.token != nil && time.Now().Before(tm.expiresAt.Add(-tm.refreshMargin)) {
		return tm.token.AccessToken, nil
	}

	// Fetch a fresh token by logging in as the service account.
	tok, err := tm.client.Login(ctx, tm.username, tm.password)
	if err != nil {
		return "", fmt.Errorf("token manager: %w", err)
	}

	tm.token = tok
	tm.expiresAt = time.Now().Add(time.Duration(tok.ExpiresIn) * time.Second)

	log.Printf("[TokenManager] New token acquired (expires in %d seconds)", tok.ExpiresIn)
	return tok.AccessToken, nil
}

// Invalidate clears the cached token, forcing a fresh fetch on the next call.
func (tm *TokenManager) Invalidate() {
	tm.mu.Lock()
	defer tm.mu.Unlock()
	tm.token = nil
	tm.expiresAt = time.Time{}
}

// =========================================================================
// 2. AuthTransport — http.RoundTripper that injects Bearer tokens
// =========================================================================

// AuthTransport is an http.RoundTripper that automatically injects a Bearer
// token into every outgoing request. On a 401 response, it invalidates the
// token and retries once.
type AuthTransport struct {
	TokenManager *TokenManager
	Base         http.RoundTripper
}

func (t *AuthTransport) base() http.RoundTripper {
	if t.Base != nil {
		return t.Base
	}
	return http.DefaultTransport
}

func (t *AuthTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	// Get a valid token
	token, err := t.TokenManager.GetToken(req.Context())
	if err != nil {
		return nil, fmt.Errorf("auth transport: %w", err)
	}

	// Clone the request so we don't modify the original
	reqClone := req.Clone(req.Context())
	reqClone.Header.Set("Authorization", "Bearer "+token)

	resp, err := t.base().RoundTrip(reqClone)
	if err != nil {
		return nil, err
	}

	// Retry once on 401 — the token may have been revoked
	if resp.StatusCode == http.StatusUnauthorized {
		resp.Body.Close()
		log.Println("[AuthTransport] Got 401, refreshing token and retrying...")

		t.TokenManager.Invalidate()
		token, err = t.TokenManager.GetToken(req.Context())
		if err != nil {
			return nil, fmt.Errorf("auth transport retry: %w", err)
		}

		retryReq := req.Clone(req.Context())
		retryReq.Header.Set("Authorization", "Bearer "+token)
		return t.base().RoundTrip(retryReq)
	}

	return resp, nil
}

// =========================================================================
// 3. OrderService client — demonstrates calling an internal service
// =========================================================================

type Order struct {
	ID         string  `json:"id"`
	CustomerID string  `json:"customer_id"`
	Total      float64 `json:"total"`
	Status     string  `json:"status"`
}

type OrderServiceClient struct {
	baseURL string
	http    *http.Client
}

func NewOrderServiceClient(baseURL string, httpClient *http.Client) *OrderServiceClient {
	return &OrderServiceClient{
		baseURL: baseURL,
		http:    httpClient,
	}
}

func (c *OrderServiceClient) ListOrders(ctx context.Context) ([]Order, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.baseURL+"/api/orders", nil)
	if err != nil {
		return nil, err
	}

	resp, err := c.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("list orders: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("list orders: status %d: %s", resp.StatusCode, string(body))
	}

	var orders []Order
	if err := json.NewDecoder(resp.Body).Decode(&orders); err != nil {
		return nil, fmt.Errorf("list orders: decode: %w", err)
	}
	return orders, nil
}

func (c *OrderServiceClient) GetOrder(ctx context.Context, id string) (*Order, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, fmt.Sprintf("%s/api/orders/%s", c.baseURL, id), nil)
	if err != nil {
		return nil, err
	}

	resp, err := c.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("get order: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("get order: status %d: %s", resp.StatusCode, string(body))
	}

	var order Order
	if err := json.NewDecoder(resp.Body).Decode(&order); err != nil {
		return nil, fmt.Errorf("get order: decode: %w", err)
	}
	return &order, nil
}

func (c *OrderServiceClient) CancelOrder(ctx context.Context, id string) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, fmt.Sprintf("%s/api/orders/%s/cancel", c.baseURL, id), nil)
	if err != nil {
		return err
	}

	resp, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("cancel order: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusNoContent {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("cancel order: status %d: %s", resp.StatusCode, string(body))
	}
	return nil
}

// =========================================================================
// 4. Main — putting it all together
// =========================================================================

func main() {
	// Initialize the SimpleAuth client.
	authClient := simpleauth.New(simpleauth.Options{
		URL:                envOr("SIMPLEAUTH_URL", "https://auth.example.com/sauth"),
		InsecureSkipVerify: os.Getenv("SIMPLEAUTH_INSECURE") == "true", // dev only: trust self-signed certs
	})

	// Service-account credentials (this service's own identity). Never hardcode
	// secrets — require them from the environment.
	serviceUser := os.Getenv("SIMPLEAUTH_SERVICE_USER")
	servicePassword := os.Getenv("SIMPLEAUTH_SERVICE_PASSWORD")
	if serviceUser == "" || servicePassword == "" {
		log.Fatal("set SIMPLEAUTH_SERVICE_USER and SIMPLEAUTH_SERVICE_PASSWORD")
	}

	// Create a token manager with 60-second refresh margin
	tokenMgr := NewTokenManager(authClient, serviceUser, servicePassword, 60*time.Second)

	// Build an HTTP client that auto-injects Bearer tokens
	authenticatedHTTP := &http.Client{
		Timeout: 15 * time.Second,
		Transport: &AuthTransport{
			TokenManager: tokenMgr,
			Base:         http.DefaultTransport,
		},
	}

	// Create the order service client
	orderServiceURL := envOr("ORDER_SERVICE_URL", "https://orders.internal:8080")
	orderSvc := NewOrderServiceClient(orderServiceURL, authenticatedHTTP)

	ctx := context.Background()

	// -----------------------------------------------------------------
	// Use the order service — token management is fully automatic
	// -----------------------------------------------------------------

	fmt.Println("[1] Listing orders...")
	orders, err := orderSvc.ListOrders(ctx)
	if err != nil {
		log.Printf("  Failed to list orders: %v", err)
	} else {
		fmt.Printf("  Found %d orders\n", len(orders))
		for _, o := range orders {
			fmt.Printf("  - %s: $%.2f (%s)\n", o.ID, o.Total, o.Status)
		}
	}

	fmt.Println("\n[2] Fetching order-42...")
	order, err := orderSvc.GetOrder(ctx, "order-42")
	if err != nil {
		log.Printf("  Failed to get order: %v", err)
	} else {
		fmt.Printf("  Order %s: $%.2f (%s)\n", order.ID, order.Total, order.Status)
	}

	fmt.Println("\n[3] Cancelling order-42...")
	if err := orderSvc.CancelOrder(ctx, "order-42"); err != nil {
		log.Printf("  Failed to cancel order: %v", err)
	} else {
		fmt.Println("  Order cancelled successfully.")
	}

	// -----------------------------------------------------------------
	// Demonstrate that repeated calls reuse the cached token
	// -----------------------------------------------------------------
	fmt.Println("\n[4] Making multiple calls (token should be cached)...")
	start := time.Now()
	for i := 0; i < 3; i++ {
		_, _ = orderSvc.ListOrders(ctx)
	}
	fmt.Printf("  3 sequential calls completed in %v\n", time.Since(start))

	fmt.Println("\nDone.")
}
