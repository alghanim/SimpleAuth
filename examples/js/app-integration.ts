// ---------------------------------------------------------------------------
// SimpleAuth Example: Per-App Management (v2)
// ---------------------------------------------------------------------------
// Shows the v2 "app" integration model. An app is an OAuth client identified by
// app_id + app_secret. It self-manages its own authorization via /api/app/*
// (HTTP Basic app_id:app_secret) — no master admin key required.
//
// A developer's whole integration is:
//   1. Get app_id / app_secret from the SimpleAuth admin.
//   2. Call appBootstrap(...) on startup to declare roles + assignments
//      (idempotent — safe on every deploy).
//   3. Point the SDK at SimpleAuth with `audience` set to the app, so verify()
//      rejects tokens minted for other apps.
//   4. verify(token) and read the per-app roles/permissions.
//
// Configuration comes entirely from the environment — no hardcoded secrets:
//   SIMPLEAUTH_URL    default https://auth.example.com/sauth
//   SIMPLEAUTH_APP_ID        required
//   SIMPLEAUTH_APP_SECRET    required
//   SIMPLEAUTH_AUDIENCE      defaults to the app_id
//
// Usage:
//   SIMPLEAUTH_APP_ID=billing SIMPLEAUTH_APP_SECRET=sa_app_... \
//     npx tsx app-integration.ts
// ---------------------------------------------------------------------------

import { createSimpleAuth, SimpleAuthError } from "@simpleauth/js";

// --- Configuration --------------------------------------------------------

const url = process.env.SIMPLEAUTH_URL ?? "https://auth.example.com/sauth";
const appId = process.env.SIMPLEAUTH_APP_ID;
const appSecret = process.env.SIMPLEAUTH_APP_SECRET;

if (!appId || !appSecret) {
  console.error(
    "Set SIMPLEAUTH_APP_ID and SIMPLEAUTH_APP_SECRET (obtained from the SimpleAuth admin).",
  );
  process.exit(1);
}

// The audience anchors this app: verify() will reject any token whose `aud`
// claim does not include it, so tokens minted for other apps are rejected.
const audience = process.env.SIMPLEAUTH_AUDIENCE ?? appId;

const auth = createSimpleAuth({
  url,
  appId,
  appSecret,
  audience,
});

// --- Startup: declare this app's authorization (idempotent) ---------------

/**
 * Call once on startup / every deploy. appBootstrap is idempotent, so it is
 * safe to run unconditionally — it converges the app's roles, permissions, and
 * assignments to the declared state.
 */
async function bootstrapAuthz(): Promise<void> {
  console.log(`[1] Bootstrapping authz for app "${appId}"...`);

  await auth.appBootstrap({
    roles: ["admin", "viewer"],
    permissions: ["invoice:read", "invoice:write"],
    role_permissions: {
      admin: ["invoice:read", "invoice:write"],
      viewer: ["invoice:read"],
    },
    assignments: [
      // Grant everyone in the directory "Finance" group the admin role.
      { group: "Finance", roles: ["admin"] },
      // Grant a specific directory user the viewer role.
      { user: "jsmith", roles: ["viewer"] },
    ],
  });

  console.log("    Bootstrap complete (idempotent).");

  // Read back what the server now has for this app.
  const authz = await auth.getAppAuthz();
  console.log(`    Roles:            ${authz.roles.join(", ")}`);
  console.log(`    Group assignments:`, authz.group_assignments);

  // The read-only settings view (no secret) confirms the app's policy.
  const settings = await auth.appSettings();
  console.log(
    `    require_assignment=${settings.require_assignment} allow_local_users=${settings.allow_local_users}`,
  );
}

// --- Request path: verify a token and read per-app roles ------------------

/**
 * Verify an incoming access token and report the per-app roles/permissions.
 * Because the client was constructed with `audience`, verify() rejects tokens
 * that were not minted for this app.
 */
async function handleRequest(token: string): Promise<void> {
  console.log("[2] Verifying an incoming access token...");

  try {
    const user = await auth.verify(token);

    console.log(`    Subject:     ${user.sub}`);
    console.log(`    Roles:       ${user.roles.join(", ") || "(none)"}`);
    console.log(`    Permissions: ${user.permissions.join(", ") || "(none)"}`);

    if (user.hasRole("admin")) {
      console.log("    -> user may write invoices");
    } else if (user.hasPermission("invoice:read")) {
      console.log("    -> user may read invoices");
    } else {
      console.log("    -> user has no invoice access");
    }
  } catch (err) {
    if (err instanceof SimpleAuthError) {
      // e.g. a token minted for a different app fails the audience check here.
      console.error(`    Token rejected (${err.status}): ${err.message}`);
      return;
    }
    throw err;
  }
}

// --- Main -----------------------------------------------------------------

async function main() {
  try {
    await bootstrapAuthz();

    // In a real service this token arrives on an inbound request (e.g. the
    // Authorization: Bearer header). Provide one via SIMPLEAUTH_TEST_TOKEN to
    // exercise the verification path.
    const token = process.env.SIMPLEAUTH_TEST_TOKEN;
    if (token) {
      await handleRequest(token);
    } else {
      console.log(
        "[2] Skipping verify(): set SIMPLEAUTH_TEST_TOKEN to a token minted for this app.",
      );
    }
  } catch (err) {
    if (err instanceof SimpleAuthError) {
      console.error(`SimpleAuth error (${err.status}): ${err.message}`);
      process.exit(1);
    }
    throw err;
  }
}

main();
