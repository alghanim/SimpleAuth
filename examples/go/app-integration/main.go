// ---------------------------------------------------------------------------
// SimpleAuth Example: Per-App Integration (Go, v2)
// ---------------------------------------------------------------------------
// Demonstrates the v2 "per-app management" surface — the whole integration story
// for an app: get app_id/app_secret from the admin, then on every deploy:
//
//  1. Construct the client with URL + AppID + AppSecret + Audience (= app_id)
//  2. AppBootstrap: declare this app's roles + a group assignment (authz-as-code)
//  3. Read back the app's authz and settings
//  4. Verify(token): rejected when the audience is wrong, accepted (with this
//     app's roles) when it matches — this is the RP-side enforcement that makes
//     a token minted for another app useless here.
//
// An "app" is an OAuth client authenticating to /api/app/* with HTTP Basic
// app_id:app_secret. The app_id is derived from the credential server-side, so
// an app can only ever touch its own scope.
//
// Usage:
//
//	SIMPLEAUTH_URL=https://auth.example.com/sauth \
//	SIMPLEAUTH_APP_ID=billing \
//	SIMPLEAUTH_APP_SECRET=sa_app_... \
//	go run main.go [optional-access-token]
//
// Environment variables:
//
//	SIMPLEAUTH_URL         — SimpleAuth server URL incl. base path (default: https://auth.corp.local/sauth)
//	SIMPLEAUTH_APP_ID      — this app's app_id   (required)
//	SIMPLEAUTH_APP_SECRET  — this app's app_secret (required; never hardcode)
//	SIMPLEAUTH_AUDIENCE    — expected token audience (default: SIMPLEAUTH_APP_ID)
//	SIMPLEAUTH_INSECURE    — set "true" to trust self-signed certs (dev only)
//
// An access token may be passed as the first CLI arg to exercise Verify against
// a real token; otherwise step 4 only demonstrates audience rejection.
// ---------------------------------------------------------------------------
package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"strings"
	"time"

	simpleauth "github.com/bodaay/simpleauth-go"
)

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func main() {
	// -----------------------------------------------------------------
	// Step 1: Construct the app client.
	//
	// Audience is set to the app_id so Verify() rejects tokens minted for
	// any other app. Secrets come from the environment — never hardcode them.
	// -----------------------------------------------------------------
	appID := os.Getenv("SIMPLEAUTH_APP_ID")
	appSecret := os.Getenv("SIMPLEAUTH_APP_SECRET")
	if appID == "" || appSecret == "" {
		log.Fatal("set SIMPLEAUTH_APP_ID and SIMPLEAUTH_APP_SECRET")
	}
	audience := envOr("SIMPLEAUTH_AUDIENCE", appID)

	client := simpleauth.New(simpleauth.Options{
		URL:                envOr("SIMPLEAUTH_URL", "https://auth.corp.local/sauth"),
		AppID:              appID,
		AppSecret:          appSecret,
		Audience:           audience,                                   // reject tokens for other apps
		InsecureSkipVerify: os.Getenv("SIMPLEAUTH_INSECURE") == "true", // dev only: trust self-signed certs
	})

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// -----------------------------------------------------------------
	// Step 2: Bootstrap this app's authorization on startup (authz-as-code).
	//
	// Idempotent and safe on every deploy: declare the roles this app uses,
	// what each role can do, and who is allowed in (here: an AD group gets
	// "admin", and a named directory user gets "viewer").
	// -----------------------------------------------------------------
	fmt.Println("[1] Bootstrapping app authorization (authz-as-code)...")

	res, err := client.AppBootstrap(ctx, simpleauth.BootstrapSpec{
		Roles:       []string{"admin", "viewer"},
		Permissions: []string{"invoice:read", "invoice:write"},
		RolePermissions: map[string][]string{
			"admin":  {"invoice:read", "invoice:write"},
			"viewer": {"invoice:read"},
		},
		Assignments: []simpleauth.Assignment{
			{Group: "Finance", Roles: []string{"admin"}}, // AD group -> admin
			{User: "jsmith", Roles: []string{"viewer"}},  // directory user -> viewer
		},
	})
	if err != nil {
		log.Fatalf("Bootstrap failed: %v", err)
	}
	fmt.Printf("  Bootstrapped app %q: %d roles, %d assignments (status: %s)\n",
		res.AppID, res.RolesCount, res.AssignmentsCount, res.Status)

	// -----------------------------------------------------------------
	// Step 3: Read back what the server now holds for this app.
	// -----------------------------------------------------------------
	fmt.Println("\n[2] Reading back this app's authz...")

	authz, err := client.GetAppAuthz(ctx)
	if err != nil {
		log.Fatalf("GetAppAuthz failed: %v", err)
	}
	fmt.Printf("  Roles: %s\n", orDefault(strings.Join(authz.Roles, ", "), "(none)"))
	fmt.Printf("  Permissions: %s\n", orDefault(strings.Join(authz.Permissions, ", "), "(none)"))
	fmt.Printf("  User assignments: %d\n", len(authz.UserAssignments))
	fmt.Printf("  Group assignments: %d\n", len(authz.GroupAssignments))

	fmt.Println("\n[3] Reading this app's settings...")

	settings, err := client.AppSettings(ctx)
	if err != nil {
		log.Fatalf("AppSettings failed: %v", err)
	}
	fmt.Printf("  Name: %s\n", orDefault(settings.Name, "(unset)"))
	fmt.Printf("  Audience: %s\n", orDefault(settings.Audience, "(unset)"))
	fmt.Printf("  Require assignment: %v\n", settings.RequireAssignment)
	fmt.Printf("  Allow local users: %v\n", settings.AllowLocalUsers)

	// If this app provisions its own users (allow_local_users), CreateLocalUser /
	// ListLocalUsers / SetLocalUserPassword / DeleteLocalUser are available, e.g.:
	//
	//   u, err := client.CreateLocalUser(ctx, "customer1", "S3cret!", "Customer One", "", []string{"viewer"})
	//   users, err := client.ListLocalUsers(ctx)
	//   err = client.SetLocalUserPassword(ctx, u.GUID, "newS3cret!")
	//   err = client.DeleteLocalUser(ctx, u.GUID)

	// -----------------------------------------------------------------
	// Step 4: Verify tokens — audience-scoped enforcement.
	//
	// The client was built with Audience = this app's id, so a token whose
	// `aud` is some other app is rejected by Verify(). This is the RP-side
	// check that makes a foreign-app token useless here.
	// -----------------------------------------------------------------
	fmt.Println("\n[4] Token verification (audience-scoped)...")

	// A structurally-invalid / foreign token is rejected. (We don't have a
	// signing key for another app, so this also covers the "wrong audience"
	// intent: anything not minted for this app fails to verify.)
	if _, err := client.Verify("not.a.valid-token-for-this-app"); err != nil {
		fmt.Printf("  Rejected token not minted for %q: %v\n", audience, err)
	} else {
		fmt.Println("  WARNING: a foreign token verified — check the Audience option")
	}

	// If a real access token is supplied, verify it and read the per-app roles.
	if len(os.Args) > 1 {
		token := os.Args[1]
		user, err := client.Verify(token)
		if err != nil {
			// Expected when the token's aud != this app, or it has expired.
			fmt.Printf("  Supplied token rejected: %v\n", err)
		} else {
			fmt.Printf("  Accepted token for %s (aud matches %q)\n",
				orDefault(user.PreferredUsername, user.Sub), audience)
			fmt.Printf("  Per-app roles: %s\n", orDefault(strings.Join(user.Roles, ", "), "(none)"))
			fmt.Printf("  Per-app permissions: %s\n", orDefault(strings.Join(user.Permissions, ", "), "(none)"))
			fmt.Printf("  Is admin in this app? %v\n", user.HasRole("admin"))
		}
	} else {
		fmt.Println("  (pass an access token as the first arg to verify a real, accepted token)")
	}

	fmt.Println("\nDone.")
}

func orDefault(s, fallback string) string {
	if s == "" {
		return fallback
	}
	return s
}
