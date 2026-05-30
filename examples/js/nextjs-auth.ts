// ---------------------------------------------------------------------------
// SimpleAuth Example: Next.js Integration
// ---------------------------------------------------------------------------
// Demonstrates three integration patterns for Next.js (App Router):
//
//   1. Server-side token verification in API Route Handlers
//   2. Middleware for protecting pages (middleware.ts)
//   3. Client-side login component pattern (React)
//
// This file contains all three patterns in a single file for reference.
// In a real Next.js project you would split these into separate files
// as indicated by the "File:" comments.
//
// Prerequisites:
//   npm install next react react-dom @simpleauth/js
// ---------------------------------------------------------------------------

import { createSimpleAuth, SimpleAuthError, SimpleAuthUser } from "@simpleauth/js";

// ==========================================================================
// Shared: auth client instance (used by server-side code)
// ==========================================================================
// File: lib/auth.ts

// Base SimpleAuth URL (includes the `/sauth` base path). Used both to build
// the SDK client and to construct OIDC authorization/token endpoints. Do not
// reach into the SDK's private `url` field — keep this as the single source.
const SIMPLEAUTH_URL = process.env.SIMPLEAUTH_URL ?? "https://auth.example.com/sauth";

const auth = createSimpleAuth({
  url: SIMPLEAUTH_URL,
});

// --- OIDC helpers ---------------------------------------------------------

/** Base64url-encode an ArrayBuffer (no padding, URL-safe alphabet). */
function base64url(buffer: ArrayBuffer): string {
  const bytes = new Uint8Array(buffer);
  let binary = "";
  for (let i = 0; i < bytes.length; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

/** Parse a Cookie header into a name->value map. */
function parseCookies(header: string | null): Record<string, string> {
  const out: Record<string, string> = {};
  if (!header) return out;
  for (const part of header.split(";")) {
    const idx = part.indexOf("=");
    if (idx === -1) continue;
    const name = part.slice(0, idx).trim();
    const value = part.slice(idx + 1).trim();
    if (name) out[name] = decodeURIComponent(value);
  }
  return out;
}

/**
 * Generate a PKCE code_verifier and its S256 code_challenge.
 * The verifier is a high-entropy random string; the challenge is
 * base64url(SHA-256(verifier)) per RFC 7636.
 */
async function pkceChallenge(): Promise<{ verifier: string; challenge: string }> {
  const random = new Uint8Array(32);
  crypto.getRandomValues(random);
  const verifier = base64url(random.buffer);

  const digest = await crypto.subtle.digest(
    "SHA-256",
    new TextEncoder().encode(verifier),
  );
  const challenge = base64url(digest);

  return { verifier, challenge };
}

/**
 * Extract and verify the Bearer token from a Request object.
 * Works with both Next.js API Route Handlers and Middleware.
 */
async function getAuthenticatedUser(request: Request): Promise<SimpleAuthUser | null> {
  const authHeader = request.headers.get("authorization");
  if (!authHeader?.startsWith("Bearer ")) {
    return null;
  }

  try {
    return await auth.verify(authHeader.slice(7));
  } catch {
    return null;
  }
}

/**
 * Same as getAuthenticatedUser, but throws a Response if unauthenticated.
 * Convenient for API routes that always require auth.
 */
async function requireUser(request: Request): Promise<SimpleAuthUser> {
  const user = await getAuthenticatedUser(request);
  if (!user) {
    throw new Response(JSON.stringify({ error: "Unauthorized" }), {
      status: 401,
      headers: { "Content-Type": "application/json" },
    });
  }
  return user;
}

// ==========================================================================
// Pattern 1: Server-side API Route Handlers
// ==========================================================================
// File: app/api/profile/route.ts

export async function GET_profile(request: Request): Promise<Response> {
  try {
    const user = await requireUser(request);

    return Response.json({
      id: user.sub,
      name: user.name,
      email: user.email,
      roles: user.roles,
    });
  } catch (err) {
    // If requireUser threw a Response, return it directly
    if (err instanceof Response) return err;

    console.error("Profile API error:", err);
    return Response.json({ error: "Internal server error" }, { status: 500 });
  }
}

// File: app/api/admin/stats/route.ts

export async function GET_admin_stats(request: Request): Promise<Response> {
  try {
    const user = await requireUser(request);

    // Check for admin role
    if (!user.hasRole("admin")) {
      return Response.json({ error: "Forbidden: admin role required" }, { status: 403 });
    }

    // Return admin-only data
    return Response.json({
      total_users: 1250,
      active_sessions: 87,
      last_24h_logins: 342,
    });
  } catch (err) {
    if (err instanceof Response) return err;
    return Response.json({ error: "Internal server error" }, { status: 500 });
  }
}

// File: app/api/auth/callback/route.ts
// Handles the OIDC authorization code callback

export async function GET_auth_callback(request: Request): Promise<Response> {
  const url = new URL(request.url);
  const code = url.searchParams.get("code");
  const state = url.searchParams.get("state");
  const error = url.searchParams.get("error");

  if (error) {
    const description = url.searchParams.get("error_description") ?? "Authentication failed";
    return Response.redirect(new URL(`/login?error=${encodeURIComponent(description)}`, url.origin));
  }

  if (!code) {
    return Response.json({ error: "Missing authorization code" }, { status: 400 });
  }

  // Read the state and PKCE verifier we stored when initiating the flow.
  const cookies = parseCookies(request.headers.get("cookie"));
  const expectedState = cookies["oauth_state"];
  const codeVerifier = cookies["pkce_verifier"];

  // Verify the state parameter to defend against CSRF. The value returned by
  // the authorization server must match the one we set in the cookie.
  if (!state || !expectedState || state !== expectedState) {
    return Response.redirect(new URL("/login?error=invalid_state", url.origin));
  }

  if (!codeVerifier) {
    return Response.redirect(new URL("/login?error=missing_pkce_verifier", url.origin));
  }

  try {
    // Exchange the authorization code for tokens at the OIDC token endpoint.
    const redirectUri = `${url.origin}/api/auth/callback`;
    const tokenUrl = `${SIMPLEAUTH_URL}/realms/simpleauth/protocol/openid-connect/token`;

    const body = new URLSearchParams({
      grant_type: "authorization_code",
      code,
      redirect_uri: redirectUri,
      client_id: "simpleauth",
      code_verifier: codeVerifier,
    });

    const resp = await fetch(tokenUrl, {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: body.toString(),
    });

    if (!resp.ok) {
      const errBody = await resp.json().catch(() => ({}));
      throw new SimpleAuthError(
        errBody.error_description ?? errBody.error ?? "Code exchange failed",
        resp.status,
        errBody.error,
        errBody.error_description,
      );
    }

    const tokens = (await resp.json()) as {
      access_token: string;
      refresh_token?: string;
      expires_in: number;
    };

    // In a real app: store the tokens in an HTTP-only cookie or session.
    // Here we set a cookie with the access token for demonstration.
    const headers = new Headers();
    headers.set("Location", "/dashboard");
    headers.append(
      "Set-Cookie",
      `access_token=${tokens.access_token}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=${tokens.expires_in}`,
    );

    // If a refresh token was issued, store it in a separate cookie
    if (tokens.refresh_token) {
      headers.append(
        "Set-Cookie",
        `refresh_token=${tokens.refresh_token}; Path=/api/auth; HttpOnly; Secure; SameSite=Lax; Max-Age=2592000`,
      );
    }

    // Clear the one-time state and PKCE verifier cookies.
    headers.append("Set-Cookie", "oauth_state=; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=0");
    headers.append("Set-Cookie", "pkce_verifier=; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=0");

    return new Response(null, { status: 302, headers });
  } catch (err) {
    console.error("Code exchange failed:", err instanceof Error ? err.message : err);
    return Response.redirect(new URL("/login?error=code_exchange_failed", url.origin));
  }
}

// File: app/api/auth/login/route.ts
// Initiates the OIDC authorization code flow

export async function GET_auth_login(request: Request): Promise<Response> {
  const url = new URL(request.url);
  const redirectUri = `${url.origin}/api/auth/callback`;

  // Generate a random state parameter for CSRF protection, plus a PKCE
  // verifier/challenge pair (RFC 7636) so the code exchange is bound to this
  // browser even without a client secret.
  const state = crypto.randomUUID();
  const { verifier, challenge } = await pkceChallenge();

  // Build the OIDC authorization URL.
  const authUrl = new URL(`${SIMPLEAUTH_URL}/realms/simpleauth/protocol/openid-connect/auth`);
  authUrl.searchParams.set("client_id", "simpleauth");
  authUrl.searchParams.set("redirect_uri", redirectUri);
  authUrl.searchParams.set("response_type", "code");
  authUrl.searchParams.set("scope", "openid profile email");
  authUrl.searchParams.set("state", state);
  authUrl.searchParams.set("code_challenge", challenge);
  authUrl.searchParams.set("code_challenge_method", "S256");

  // Store the state and PKCE verifier in HttpOnly cookies to verify/use on the
  // callback. Both are short-lived and cleared once the flow completes.
  const headers = new Headers();
  headers.set("Location", authUrl.toString());
  headers.append(
    "Set-Cookie",
    `oauth_state=${state}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=600`,
  );
  headers.append(
    "Set-Cookie",
    `pkce_verifier=${verifier}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=600`,
  );

  return new Response(null, { status: 302, headers });
}

// ==========================================================================
// Pattern 2: Next.js Middleware for Protected Pages
// ==========================================================================
// File: middleware.ts
//
// This middleware runs on every request matching the configured paths.
// It checks for a valid token (from cookie or header) and redirects
// unauthenticated users to the login page.

interface NextRequest {
  url: string;
  cookies: { get(name: string): { value: string } | undefined };
  headers: Headers;
  nextUrl: { pathname: string };
}

interface NextResponse {
  next(): NextResponse;
  redirect(url: URL): NextResponse;
}

/**
 * Next.js middleware function.
 * In your actual middleware.ts, export this as the default middleware.
 */
async function middleware(request: NextRequest, NextResponse: NextResponse) {
  const { pathname } = request.nextUrl;

  // Public pages that do not require authentication
  const publicPaths = ["/", "/login", "/signup", "/about", "/api/public"];
  if (publicPaths.some((p) => pathname === p || pathname.startsWith(p + "/"))) {
    return NextResponse.next();
  }

  // Static assets and Next.js internals
  if (
    pathname.startsWith("/_next") ||
    pathname.startsWith("/favicon") ||
    pathname.includes(".")
  ) {
    return NextResponse.next();
  }

  // Try to get the token from the cookie (set during OIDC callback)
  const tokenCookie = request.cookies.get("access_token");
  const token = tokenCookie?.value;

  if (!token) {
    // Redirect to login with a return URL
    const loginUrl = new URL("/login", request.url);
    loginUrl.searchParams.set("returnTo", pathname);
    return NextResponse.redirect(loginUrl);
  }

  try {
    // Verify the token
    const user = await auth.verify(token);

    // For admin pages, additionally check the role
    if (pathname.startsWith("/admin") && !user.hasRole("admin")) {
      return NextResponse.redirect(new URL("/unauthorized", request.url));
    }

    // Token is valid — allow the request to proceed.
    // The page/layout can re-verify the token or read user claims from
    // the cookie if needed.
    return NextResponse.next();
  } catch {
    // Token invalid or expired — redirect to login
    const loginUrl = new URL("/login", request.url);
    loginUrl.searchParams.set("returnTo", pathname);
    return NextResponse.redirect(loginUrl);
  }
}

// The matcher config tells Next.js which routes this middleware applies to.
export const middlewareConfig = {
  matcher: [
    // Match all paths except static files and API auth routes
    "/((?!_next/static|_next/image|favicon.ico|api/auth).*)",
  ],
};

// ==========================================================================
// Pattern 3: Client-Side Login Component
// ==========================================================================
// File: components/LoginForm.tsx
//
// This is a React component pattern. It performs a direct login (ROPC grant)
// or redirects to the OIDC authorization endpoint. The OIDC redirect flow
// is recommended for production.

/**
 * Example React login component (pseudo-code — this is TypeScript, not JSX,
 * so treat this as a reference implementation).
 *
 * In a real .tsx file you would use JSX syntax.
 */
interface LoginFormState {
  username: string;
  password: string;
  error: string | null;
  loading: boolean;
}

/**
 * Direct login via the API (ROPC grant).
 * The API proxies the request to SimpleAuth to avoid exposing the
 * app secret to the browser.
 */
async function handleDirectLogin(username: string, password: string): Promise<void> {
  const response = await fetch("/api/auth/login", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ username, password }),
  });

  if (!response.ok) {
    const body = await response.json();
    throw new Error(body.error ?? "Login failed");
  }

  const body = await response.json();

  // If the user must change their password, redirect to the password change page
  if (body.force_password_change) {
    window.location.href = "/change-password";
    return;
  }

  // The API sets HTTP-only cookies. Redirect to the dashboard.
  window.location.href = "/dashboard";
}

/**
 * OIDC redirect login (recommended for production).
 * Redirects the browser to the SimpleAuth authorization endpoint.
 */
function handleOIDCLogin(): void {
  // This hits our API route which builds the authorization URL and redirects
  window.location.href = "/api/auth/login";
}

// File: app/api/auth/login/route.ts (POST handler for direct login)

export async function POST_auth_login(request: Request): Promise<Response> {
  try {
    const { username, password } = (await request.json()) as {
      username: string;
      password: string;
    };

    if (!username || !password) {
      return Response.json({ error: "Username and password required" }, { status: 400 });
    }

    const tokens = await auth.login(username, password);

    // Set HTTP-only cookies — never expose tokens to client-side JavaScript
    const headers = new Headers();
    headers.set("Content-Type", "application/json");
    headers.set(
      "Set-Cookie",
      `access_token=${tokens.access_token}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=${tokens.expires_in}`,
    );
    if (tokens.refresh_token) {
      headers.append(
        "Set-Cookie",
        `refresh_token=${tokens.refresh_token}; Path=/api/auth; HttpOnly; Secure; SameSite=Lax; Max-Age=2592000`,
      );
    }

    // If the server requires the user to change their password, inform the client
    if (tokens.force_password_change) {
      return new Response(
        JSON.stringify({ ok: true, force_password_change: true }),
        { status: 200, headers },
      );
    }

    return new Response(JSON.stringify({ ok: true }), { status: 200, headers });
  } catch (err) {
    if (err instanceof SimpleAuthError) {
      return Response.json({ error: err.message }, { status: err.status });
    }
    return Response.json({ error: "Internal server error" }, { status: 500 });
  }
}

// File: app/api/auth/logout/route.ts

export async function POST_auth_logout(request: Request): Promise<Response> {
  // Read the token from the cookie to pass as id_token_hint
  const cookieHeader = request.headers.get("cookie") ?? "";
  const accessToken = cookieHeader
    .split(";")
    .map((c) => c.trim())
    .find((c) => c.startsWith("access_token="))
    ?.split("=")[1];

  try {
    if (accessToken) {
      await auth.logout(accessToken);
    }
  } catch {
    // Best-effort logout on the server side
  }

  // Clear cookies
  const headers = new Headers();
  headers.set("Content-Type", "application/json");
  headers.set("Set-Cookie", "access_token=; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=0");
  headers.append("Set-Cookie", "refresh_token=; Path=/api/auth; HttpOnly; Secure; SameSite=Lax; Max-Age=0");

  return new Response(JSON.stringify({ ok: true }), { status: 200, headers });
}

// File: hooks/useAuth.ts
// A custom React hook pattern for accessing auth state client-side

interface AuthContext {
  user: { name: string; email: string; roles: string[] } | null;
  loading: boolean;
  login: (username: string, password: string) => Promise<void>;
  loginWithOIDC: () => void;
  logout: () => Promise<void>;
}

/**
 * Custom hook to manage auth state. In a real app, wrap this in a
 * React Context provider at the root layout.
 *
 * Usage:
 *   const { user, login, logout } = useAuth();
 */
async function fetchCurrentUser(): Promise<AuthContext["user"]> {
  const res = await fetch("/api/profile");
  if (!res.ok) return null;
  return res.json();
}

async function performLogout(): Promise<void> {
  await fetch("/api/auth/logout", { method: "POST" });
  // Redirect to /logout instead of /login to clear SSO cookies and prevent
  // auto-SSO from immediately re-authenticating the user.
  window.location.href = "/logout?redirect_uri=" + encodeURIComponent(window.location.origin + "/login");
}

// ---------------------------------------------------------------------------
// This file is a reference — copy the relevant sections into your Next.js
// project structure as indicated by the "File:" comments above.
// ---------------------------------------------------------------------------
