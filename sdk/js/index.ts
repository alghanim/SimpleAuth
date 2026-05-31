// SimpleAuth JavaScript/TypeScript SDK
// Zero-dependency, works in Node.js (18+) and browsers

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export interface SimpleAuthOptions {
  /** SimpleAuth server URL (e.g. https://auth.corp.local:9090) */
  url: string;
  /** Admin API key for admin operations */
  adminKey?: string;
  /**
   * App (OAuth client) identifier. Required for the v2 per-app management API
   * (`/api/app/*`). Combined with `appSecret`, sent as HTTP Basic auth.
   */
  appId?: string;
  /**
   * App secret paired with `appId`. Required for the v2 per-app management API.
   * Treat as a credential — never embed in browser code.
   */
  appSecret?: string;
  /**
   * If set, verify() requires the token's `iss` claim to equal this value.
   * Leave undefined to skip the issuer check. Note: direct login/refresh
   * tokens are issued with iss="simpleauth"; OIDC code-flow tokens use the
   * realm URL.
   */
  expectedIssuer?: string;
  /**
   * If set, verify() requires this value to be present in the `aud` claim.
   * In v2 each app sets this to its own audience so verify() rejects tokens
   * minted for other apps.
   */
  audience?: string;
}

export interface TokenResponse {
  access_token: string;
  refresh_token?: string;
  id_token?: string;
  token_type: string;
  expires_in: number;
  scope?: string;
  force_password_change?: boolean;
}

export interface UserInfo {
  sub: string;
  name?: string;
  email?: string;
  preferred_username?: string;
  department?: string;
  company?: string;
  job_title?: string;
  roles?: string[];
  groups?: string[];
  realm_access?: { roles: string[] };
  resource_access?: Record<string, { roles: string[] }>;
}

export interface User {
  guid: string;
  display_name?: string;
  email?: string;
  department?: string;
  company?: string;
  job_title?: string;
  disabled?: boolean;
  created_at?: string;
  updated_at?: string;
}

// ---------------------------------------------------------------------------
// v2 per-app management types (/api/app/*)
// ---------------------------------------------------------------------------

/**
 * A single bootstrap assignment binding either a directory `user` or a `group`
 * to a list of roles. Exactly one of `user` / `group` is set.
 */
export type BootstrapAssignment =
  | { user: string; group?: never; roles: string[] }
  | { group: string; user?: never; roles: string[] };

/**
 * Idempotent authz-as-code spec for `POST /api/app/bootstrap`. Safe to send on
 * every deploy — declares the app's roles, permissions, role→permission map,
 * and user/group→role assignments. All fields are optional.
 */
export interface BootstrapSpec {
  roles?: string[];
  permissions?: string[];
  /** Map of role name → permissions granted by that role. */
  role_permissions?: Record<string, string[]>;
  /** User/group → role assignments. */
  assignments?: BootstrapAssignment[];
}

/**
 * The app's current authorization, as returned by `GET /api/app/authz` and
 * accepted by `PUT /api/app/authz`.
 */
export interface AppAuthz {
  app_id: string;
  roles: string[];
  permissions: string[];
  /** Map of role name → permissions granted by that role. */
  role_permissions: Record<string, string[]>;
  /** User reference (GUID, sAMAccountName, or username) → roles. */
  user_assignments: Record<string, string[]>;
  /** Group identifier → roles. */
  group_assignments: Record<string, string[]>;
}

/**
 * Read-only view of an app's settings from `GET /api/app/settings`.
 * Field set mirrors the app registry; extra fields are preserved.
 */
export interface AppSettings {
  app_id: string;
  name?: string;
  audience?: string;
  redirect_uris?: string[];
  cors_origins?: string[];
  require_assignment?: boolean;
  allow_local_users?: boolean;
  disabled?: boolean;
  [key: string]: unknown;
}

/** An app-local user as returned by `GET /api/app/users`. */
export interface LocalUser {
  guid: string;
  username: string;
  display_name?: string;
  email?: string;
  roles?: string[];
  created_at?: string;
  updated_at?: string;
}

/** Options for creating an app-local user via `POST /api/app/users`. */
export interface CreateLocalUserOptions {
  username: string;
  password: string;
  display_name?: string;
  email?: string;
  roles?: string[];
}

export interface SimpleAuthUser {
  /** User GUID */
  sub: string;
  name?: string;
  email?: string;
  preferred_username?: string;
  roles: string[];
  permissions: string[];
  groups: string[];
  department?: string;
  company?: string;
  job_title?: string;

  /** Check if user has a specific role */
  hasRole(role: string): boolean;
  /** Check if user has a specific permission */
  hasPermission(permission: string): boolean;
  /** Check if user has any of the given roles */
  hasAnyRole(...roles: string[]): boolean;
}

interface JWK {
  kty: string;
  use: string;
  kid: string;
  alg: string;
  n: string;
  e: string;
}

interface JWKSResponse {
  keys: JWK[];
}

interface JWTHeader {
  alg: string;
  typ?: string;
  kid?: string;
}

interface JWTPayload {
  sub?: string;
  iss?: string;
  aud?: string | string[];
  exp?: number;
  iat?: number;
  jti?: string;
  name?: string;
  email?: string;
  preferred_username?: string;
  department?: string;
  company?: string;
  job_title?: string;
  roles?: string[];
  permissions?: string[];
  groups?: string[];
  realm_access?: { roles: string[] };
  resource_access?: Record<string, { roles: string[] }>;
  scope?: string;
  typ?: string;
  azp?: string;
  nonce?: string;
  at_hash?: string;
  family_id?: string;
}

// Express-compatible types
interface ExpressRequest {
  headers: Record<string, string | string[] | undefined>;
  user?: SimpleAuthUser;
}

interface ExpressResponse {
  status(code: number): ExpressResponse;
  json(body: unknown): void;
}

type ExpressNextFunction = (err?: unknown) => void;

type ExpressMiddleware = (
  req: ExpressRequest,
  res: ExpressResponse,
  next: ExpressNextFunction,
) => void;

export class SimpleAuthError extends Error {
  public readonly status: number;
  public readonly code?: string;
  public readonly description?: string;

  constructor(message: string, status: number, code?: string, description?: string) {
    super(message);
    this.name = 'SimpleAuthError';
    this.status = status;
    this.code = code;
    this.description = description;
  }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/** Base64url decode to Uint8Array */
function base64urlDecode(str: string): Uint8Array {
  // Pad to multiple of 4
  let padded = str.replace(/-/g, '+').replace(/_/g, '/');
  while (padded.length % 4 !== 0) padded += '=';

  // Decode — works in both Node.js and browser
  if (typeof globalThis.atob === 'function') {
    const binary = globalThis.atob(padded);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) {
      bytes[i] = binary.charCodeAt(i);
    }
    return bytes;
  }
  // Node.js Buffer fallback (older Node without atob)
  return new Uint8Array(Buffer.from(padded, 'base64'));
}

/** Encode Uint8Array to base64url string */
function base64urlEncode(bytes: Uint8Array): string {
  let binary = '';
  for (let i = 0; i < bytes.length; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  if (typeof globalThis.btoa === 'function') {
    return globalThis.btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
  }
  return Buffer.from(bytes).toString('base64url');
}

/** Decode a JWT without verification — returns header and payload */
function decodeJWT(token: string): { header: JWTHeader; payload: JWTPayload; signatureInput: string; signature: Uint8Array } {
  const parts = token.split('.');
  if (parts.length !== 3) {
    throw new SimpleAuthError('Invalid JWT: expected 3 parts', 400);
  }

  const header: JWTHeader = JSON.parse(new TextDecoder().decode(base64urlDecode(parts[0])));
  const payload: JWTPayload = JSON.parse(new TextDecoder().decode(base64urlDecode(parts[1])));
  const signatureInput = parts[0] + '.' + parts[1];
  const signature = base64urlDecode(parts[2]);

  return { header, payload, signatureInput, signature };
}

/** Create a SimpleAuthUser from JWT payload */
function payloadToUser(payload: JWTPayload): SimpleAuthUser {
  const roles = payload.roles ?? payload.realm_access?.roles ?? [];
  const permissions = payload.permissions ?? [];
  const groups = payload.groups ?? [];

  return {
    sub: payload.sub ?? '',
    name: payload.name,
    email: payload.email,
    preferred_username: payload.preferred_username,
    roles,
    permissions,
    groups,
    department: payload.department,
    company: payload.company,
    job_title: payload.job_title,
    hasRole(role: string): boolean {
      return roles.includes(role);
    },
    hasPermission(permission: string): boolean {
      return permissions.includes(permission);
    },
    hasAnyRole(...checkRoles: string[]): boolean {
      return checkRoles.some((r) => roles.includes(r));
    },
  };
}

// ---------------------------------------------------------------------------
// RSA Verification — platform-agnostic
// ---------------------------------------------------------------------------

/** Convert JWK (n, e) to a CryptoKey (browser) or verify directly (Node.js) */
async function verifyRS256(
  signatureInput: string,
  signature: Uint8Array,
  jwk: JWK,
): Promise<boolean> {
  const encoder = new TextEncoder();
  const data = encoder.encode(signatureInput);

  // Try SubtleCrypto first (browser + Node 15+)
  if (typeof globalThis.crypto?.subtle?.importKey === 'function') {
    const cryptoKey = await globalThis.crypto.subtle.importKey(
      'jwk',
      {
        kty: jwk.kty,
        n: jwk.n,
        e: jwk.e,
        alg: 'RS256',
        ext: true,
      },
      { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' },
      false,
      ['verify'],
    );
    return globalThis.crypto.subtle.verify('RSASSA-PKCS1-v1_5', cryptoKey, signature as BufferSource, data as BufferSource);
  }

  // Fallback: Node.js crypto module
  try {
    const nodeCrypto = await import('crypto');
    // Build a PEM from the JWK components
    const nBytes = base64urlDecode(jwk.n);
    const eBytes = base64urlDecode(jwk.e);

    // Construct RSA public key in DER (PKCS#1) then wrap in PKIX
    const nLen = nBytes.length;
    const eLen = eBytes.length;

    // Use Node's createPublicKey with JWK input (Node 15.12+)
    const pubKey = nodeCrypto.createPublicKey({
      key: {
        kty: 'RSA',
        n: jwk.n,
        e: jwk.e,
      },
      format: 'jwk',
    });

    const verifier = nodeCrypto.createVerify('RSA-SHA256');
    verifier.update(signatureInput);
    return verifier.verify(pubKey, Buffer.from(signature));
  } catch {
    throw new SimpleAuthError(
      'RS256 verification failed: no suitable crypto API available',
      500,
    );
  }
}

// ---------------------------------------------------------------------------
// JWKS Cache
// ---------------------------------------------------------------------------

class JWKSCache {
  private keys: Map<string, JWK> = new Map();
  private fetchedAt = 0;
  private fetching: Promise<void> | null = null;
  private readonly ttlMs = 60 * 60 * 1000; // 1 hour
  // Minimum interval between network refreshes triggered by an unknown kid.
  // The kid is attacker-controlled and read before signature verification, so
  // without this cooldown a stream of tokens with random kids would force one
  // upstream JWKS fetch per token (DoS amplification against the auth server).
  private readonly unknownKidCooldownMs = 30 * 1000; // 30 seconds
  private readonly jwksUrl: string;

  constructor(jwksUrl: string) {
    this.jwksUrl = jwksUrl;
  }

  async getKey(kid: string): Promise<JWK> {
    // Try cache first
    const cached = this.keys.get(kid);
    const now = Date.now();

    if (cached && now - this.fetchedAt < this.ttlMs) {
      return cached;
    }

    // Unknown kid: only hit the network if we haven't refreshed recently.
    // Within the cooldown window, serve the not-found result from cache so a
    // burst of bogus kids can't amplify into one upstream fetch per request.
    if (!cached && now - this.fetchedAt < this.unknownKidCooldownMs) {
      throw new SimpleAuthError(`JWKS: no key found for kid "${kid}"`, 401);
    }

    // Refresh if stale or kid not found
    await this.refresh();

    const key = this.keys.get(kid);
    if (!key) {
      throw new SimpleAuthError(`JWKS: no key found for kid "${kid}"`, 401);
    }
    return key;
  }

  private async refresh(): Promise<void> {
    // Deduplicate concurrent fetches
    if (this.fetching) {
      await this.fetching;
      return;
    }

    this.fetching = (async () => {
      try {
        const resp = await fetch(this.jwksUrl);
        if (!resp.ok) {
          throw new SimpleAuthError(
            `JWKS fetch failed: ${resp.status} ${resp.statusText}`,
            resp.status,
          );
        }
        const jwks: JWKSResponse = await resp.json();
        this.keys.clear();
        for (const key of jwks.keys) {
          if (key.kid) {
            this.keys.set(key.kid, key);
          }
        }
        this.fetchedAt = Date.now();
      } finally {
        this.fetching = null;
      }
    })();

    await this.fetching;
  }
}

// ---------------------------------------------------------------------------
// SimpleAuth Client
// ---------------------------------------------------------------------------

export class SimpleAuth {
  private readonly url: string;
  private readonly adminKey?: string;
  private readonly appId?: string;
  private readonly appSecret?: string;
  private readonly expectedIssuer?: string;
  private readonly audience?: string;
  private readonly jwksCache: JWKSCache;

  constructor(options: SimpleAuthOptions) {
    // Strip trailing slash
    this.url = options.url.replace(/\/+$/, '');
    this.adminKey = options.adminKey;
    this.appId = options.appId;
    this.appSecret = options.appSecret;
    this.expectedIssuer = options.expectedIssuer;
    this.audience = options.audience;

    const jwksUrl = `${this.url}/.well-known/jwks.json`;
    this.jwksCache = new JWKSCache(jwksUrl);
  }

  /** Build admin Bearer header */
  private adminAuthHeader(): string {
    if (!this.adminKey) {
      throw new SimpleAuthError('adminKey is required for admin operations', 401);
    }
    return 'Bearer ' + this.adminKey;
  }

  /** Build HTTP Basic header from app_id:app_secret for the /api/app/* surface */
  private appAuthHeader(): string {
    if (!this.appId || !this.appSecret) {
      throw new SimpleAuthError('appId and appSecret are required for app management operations', 401);
    }
    const raw = `${this.appId}:${this.appSecret}`;
    // Match the file's base64 strategy: btoa in browsers/modern Node, Buffer fallback.
    const encoded =
      typeof globalThis.btoa === 'function'
        ? globalThis.btoa(raw)
        : Buffer.from(raw, 'utf-8').toString('base64');
    return 'Basic ' + encoded;
  }

  // -------------------------------------------------------------------------
  // Authentication
  // -------------------------------------------------------------------------

  /**
   * Authenticate with username and password via the direct login API.
   */
  async login(username: string, password: string): Promise<TokenResponse> {
    const resp = await fetch(`${this.url}/api/auth/login`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({ username, password }),
    });

    if (!resp.ok) {
      const err = await resp.json().catch(() => ({}));
      throw new SimpleAuthError(
        err.error_description ?? err.error ?? 'Login failed',
        resp.status,
        err.error,
        err.error_description,
      );
    }

    return resp.json();
  }

  /**
   * Refresh an access token using a refresh token.
   */
  async refresh(refreshToken: string): Promise<TokenResponse> {
    const resp = await fetch(`${this.url}/api/auth/refresh`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({ refresh_token: refreshToken }),
    });

    if (!resp.ok) {
      const err = await resp.json().catch(() => ({}));
      throw new SimpleAuthError(
        err.error_description ?? err.error ?? 'Token refresh failed',
        resp.status,
        err.error,
        err.error_description,
      );
    }

    return resp.json();
  }

  /**
   * Logout is not available as a direct API endpoint.
   * This method is a no-op retained for backward compatibility.
   * @deprecated No direct logout endpoint exists. Discard tokens client-side instead.
   */
  async logout(_idToken?: string): Promise<void> {
    // No-op: SimpleAuth direct API does not have a logout endpoint.
    // To "log out", simply discard the access and refresh tokens client-side.
  }

  // -------------------------------------------------------------------------
  // Token Verification (server-side)
  // -------------------------------------------------------------------------

  /**
   * Verify a JWT access token using the server's JWKS.
   * Checks RS256 signature, expiration, and issuer.
   * Returns a SimpleAuthUser with helper methods.
   */
  async verify(token: string): Promise<SimpleAuthUser> {
    const { header, payload, signatureInput, signature } = decodeJWT(token);

    if (header.alg !== 'RS256') {
      throw new SimpleAuthError(`Unsupported algorithm: ${header.alg}`, 401);
    }

    // Get the signing key
    const kid = header.kid;
    if (!kid) {
      throw new SimpleAuthError('JWT missing kid header', 401);
    }

    const jwk = await this.jwksCache.getKey(kid);

    // Verify signature
    const valid = await verifyRS256(signatureInput, signature, jwk);
    if (!valid) {
      throw new SimpleAuthError('Invalid token signature', 401);
    }

    // Reject refresh tokens presented as access tokens: they are signed by the
    // same key but carry a family_id and no authorization claims.
    if (payload.family_id) {
      throw new SimpleAuthError('Refresh token is not valid for resource access', 401);
    }

    // Reject non-access token types. User access tokens carry no `typ`; OIDC ID
    // tokens use typ="ID" and app-management tokens use typ="app-mgmt". All are
    // signed by the same key, so without this check an id_token (which is
    // exposed to the browser by design) could be replayed as a Bearer access
    // token. verify() must only ever accept user access tokens.
    if (payload.typ === 'ID' || payload.typ === 'app-mgmt') {
      throw new SimpleAuthError('Token is not a user access token', 401);
    }

    // Expiration is mandatory — fail closed if the claim is absent.
    const now = Math.floor(Date.now() / 1000);
    if (typeof payload.exp !== 'number') {
      throw new SimpleAuthError('Token missing a valid exp claim', 401);
    }
    if (payload.exp < now) {
      throw new SimpleAuthError('Token has expired', 401);
    }

    // Issuer check is opt-in. Direct login tokens use iss="simpleauth", so the
    // old hardcoded URL check rejected every login token — only enforce when
    // an expectedIssuer is configured.
    if (this.expectedIssuer && payload.iss !== this.expectedIssuer) {
      throw new SimpleAuthError(
        `Invalid issuer: expected "${this.expectedIssuer}", got "${payload.iss ?? ''}"`,
        401,
      );
    }

    // Optional audience check.
    if (this.audience) {
      const aud = Array.isArray(payload.aud) ? payload.aud : payload.aud ? [payload.aud] : [];
      if (!aud.includes(this.audience)) {
        throw new SimpleAuthError(`Token audience does not include "${this.audience}"`, 401);
      }
    }

    return payloadToUser(payload);
  }

  // -------------------------------------------------------------------------
  // User Info
  // -------------------------------------------------------------------------

  /**
   * Fetch user claims from the UserInfo endpoint.
   */
  async userInfo(accessToken: string): Promise<UserInfo> {
    const resp = await fetch(`${this.url}/api/auth/userinfo`, {
      headers: { Authorization: `Bearer ${accessToken}` },
    });

    if (!resp.ok) {
      const err = await resp.json().catch(() => ({}));
      throw new SimpleAuthError(
        err.error_description ?? 'UserInfo request failed',
        resp.status,
        err.error,
        err.error_description,
      );
    }

    return resp.json();
  }

  // -------------------------------------------------------------------------
  // Admin Operations (require adminKey as Bearer API key)
  // -------------------------------------------------------------------------

  /**
   * Get a user by GUID.
   * Requires adminKey.
   */
  async getUser(guid: string): Promise<User> {
    const resp = await fetch(`${this.url}/api/admin/users/${encodeURIComponent(guid)}`, {
      headers: { Authorization: this.adminAuthHeader() },
    });

    if (!resp.ok) {
      const err = await resp.json().catch(() => ({}));
      throw new SimpleAuthError(err.error ?? 'Failed to get user', resp.status);
    }

    return resp.json();
  }

  /**
   * Get the roles assigned to a user.
   * Requires adminKey.
   */
  async getUserRoles(guid: string): Promise<string[]> {
    const resp = await fetch(
      `${this.url}/api/admin/users/${encodeURIComponent(guid)}/roles`,
      { headers: { Authorization: this.adminAuthHeader() } },
    );

    if (!resp.ok) {
      const err = await resp.json().catch(() => ({}));
      throw new SimpleAuthError(err.error ?? 'Failed to get roles', resp.status);
    }

    return resp.json();
  }

  /**
   * Set the roles for a user.
   * Requires adminKey.
   */
  async setUserRoles(guid: string, roles: string[]): Promise<void> {
    const resp = await fetch(
      `${this.url}/api/admin/users/${encodeURIComponent(guid)}/roles`,
      {
        method: 'PUT',
        headers: {
          Authorization: this.adminAuthHeader(),
          'Content-Type': 'application/json',
        },
        body: JSON.stringify(roles),
      },
    );

    if (!resp.ok) {
      const err = await resp.json().catch(() => ({}));
      throw new SimpleAuthError(err.error ?? 'Failed to set roles', resp.status);
    }
  }

  /**
   * Get the permissions assigned to a user.
   * Requires adminKey.
   */
  async getUserPermissions(guid: string): Promise<string[]> {
    const resp = await fetch(
      `${this.url}/api/admin/users/${encodeURIComponent(guid)}/permissions`,
      { headers: { Authorization: this.adminAuthHeader() } },
    );

    if (!resp.ok) {
      const err = await resp.json().catch(() => ({}));
      throw new SimpleAuthError(err.error ?? 'Failed to get permissions', resp.status);
    }

    return resp.json();
  }

  /**
   * Set the permissions for a user.
   * Requires adminKey.
   */
  async setUserPermissions(guid: string, permissions: string[]): Promise<void> {
    const resp = await fetch(
      `${this.url}/api/admin/users/${encodeURIComponent(guid)}/permissions`,
      {
        method: 'PUT',
        headers: {
          Authorization: this.adminAuthHeader(),
          'Content-Type': 'application/json',
        },
        body: JSON.stringify(permissions),
      },
    );

    if (!resp.ok) {
      const err = await resp.json().catch(() => ({}));
      throw new SimpleAuthError(err.error ?? 'Failed to set permissions', resp.status);
    }
  }

  // -------------------------------------------------------------------------
  // App self-management (v2) — require appId + appSecret (HTTP Basic)
  //
  // The /api/app/* surface is scoped entirely to the calling app: the app_id
  // comes from the credential, never the path, so an app can only ever read or
  // write its own roles, permissions, assignments, and local users.
  // -------------------------------------------------------------------------

  /**
   * Idempotently declare this app's roles, permissions, role→permission map,
   * and user/group→role assignments via `POST /api/app/bootstrap`.
   *
   * Safe to call on every deploy. Requires appId + appSecret.
   */
  async appBootstrap(spec: BootstrapSpec): Promise<void> {
    const resp = await fetch(`${this.url}/api/app/bootstrap`, {
      method: 'POST',
      headers: {
        Authorization: this.appAuthHeader(),
        'Content-Type': 'application/json',
      },
      body: JSON.stringify(spec),
    });

    if (!resp.ok) {
      const err = await resp.json().catch(() => ({}));
      throw new SimpleAuthError(
        err.error_description ?? err.error ?? 'App bootstrap failed',
        resp.status,
        err.error,
        err.error_description,
      );
    }
  }

  /**
   * Read this app's current authorization (roles, permissions, role→permission
   * map, and user/group assignments) via `GET /api/app/authz`.
   *
   * Requires appId + appSecret.
   */
  async getAppAuthz(): Promise<AppAuthz> {
    const resp = await fetch(`${this.url}/api/app/authz`, {
      headers: { Authorization: this.appAuthHeader() },
    });

    if (!resp.ok) {
      const err = await resp.json().catch(() => ({}));
      throw new SimpleAuthError(err.error ?? 'Failed to get app authz', resp.status);
    }

    return resp.json();
  }

  /**
   * Replace this app's authorization via `PUT /api/app/authz`.
   *
   * Requires appId + appSecret.
   */
  async setAppAuthz(authz: AppAuthz): Promise<void> {
    const resp = await fetch(`${this.url}/api/app/authz`, {
      method: 'PUT',
      headers: {
        Authorization: this.appAuthHeader(),
        'Content-Type': 'application/json',
      },
      body: JSON.stringify(authz),
    });

    if (!resp.ok) {
      const err = await resp.json().catch(() => ({}));
      throw new SimpleAuthError(err.error ?? 'Failed to set app authz', resp.status);
    }
  }

  /**
   * Read this app's settings (read-only policy view) via `GET /api/app/settings`.
   *
   * Requires appId + appSecret.
   */
  async appSettings(): Promise<AppSettings> {
    const resp = await fetch(`${this.url}/api/app/settings`, {
      headers: { Authorization: this.appAuthHeader() },
    });

    if (!resp.ok) {
      const err = await resp.json().catch(() => ({}));
      throw new SimpleAuthError(err.error ?? 'Failed to get app settings', resp.status);
    }

    return resp.json();
  }

  /**
   * Create an app-local user via `POST /api/app/users`. Only available when the
   * app has `allow_local_users` enabled.
   *
   * Requires appId + appSecret.
   */
  async createLocalUser(opts: CreateLocalUserOptions): Promise<LocalUser> {
    const resp = await fetch(`${this.url}/api/app/users`, {
      method: 'POST',
      headers: {
        Authorization: this.appAuthHeader(),
        'Content-Type': 'application/json',
      },
      body: JSON.stringify(opts),
    });

    if (!resp.ok) {
      const err = await resp.json().catch(() => ({}));
      throw new SimpleAuthError(
        err.error_description ?? err.error ?? 'Failed to create local user',
        resp.status,
        err.error,
        err.error_description,
      );
    }

    return resp.json();
  }

  /**
   * List this app's local users via `GET /api/app/users`.
   *
   * Requires appId + appSecret.
   */
  async listLocalUsers(): Promise<LocalUser[]> {
    const resp = await fetch(`${this.url}/api/app/users`, {
      headers: { Authorization: this.appAuthHeader() },
    });

    if (!resp.ok) {
      const err = await resp.json().catch(() => ({}));
      throw new SimpleAuthError(err.error ?? 'Failed to list local users', resp.status);
    }

    return resp.json();
  }

  /**
   * Delete an app-local user (must be owned by this app) via
   * `DELETE /api/app/users/{guid}`.
   *
   * Requires appId + appSecret.
   */
  async deleteLocalUser(guid: string): Promise<void> {
    const resp = await fetch(
      `${this.url}/api/app/users/${encodeURIComponent(guid)}`,
      {
        method: 'DELETE',
        headers: { Authorization: this.appAuthHeader() },
      },
    );

    if (!resp.ok) {
      const err = await resp.json().catch(() => ({}));
      throw new SimpleAuthError(err.error ?? 'Failed to delete local user', resp.status);
    }
  }

  /**
   * Reset an app-local user's password via
   * `PUT /api/app/users/{guid}/password`.
   *
   * Requires appId + appSecret.
   */
  async setLocalUserPassword(guid: string, password: string): Promise<void> {
    const resp = await fetch(
      `${this.url}/api/app/users/${encodeURIComponent(guid)}/password`,
      {
        method: 'PUT',
        headers: {
          Authorization: this.appAuthHeader(),
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({ password }),
      },
    );

    if (!resp.ok) {
      const err = await resp.json().catch(() => ({}));
      throw new SimpleAuthError(err.error ?? 'Failed to set local user password', resp.status);
    }
  }

  // -------------------------------------------------------------------------
  // Express Middleware
  // -------------------------------------------------------------------------

  /**
   * Create Express middleware that verifies the Bearer token and sets req.user.
   *
   * @param options.required - If true (default), returns 401 when no token is present.
   *                           If false, continues without setting req.user.
   */
  expressMiddleware(options?: { required?: boolean }): ExpressMiddleware {
    const required = options?.required ?? true;

    return async (req: ExpressRequest, res: ExpressResponse, next: ExpressNextFunction) => {
      const authHeader = req.headers['authorization'] ?? req.headers['Authorization'];
      const headerValue = Array.isArray(authHeader) ? authHeader[0] : authHeader;

      if (!headerValue || !headerValue.startsWith('Bearer ')) {
        if (required) {
          res.status(401).json({ error: 'Missing or invalid Authorization header' });
          return;
        }
        return next();
      }

      const token = headerValue.slice(7);

      try {
        const user = await this.verify(token);
        (req as any).user = user;
        next();
      } catch (err) {
        if (required) {
          const message = err instanceof SimpleAuthError ? err.message : 'Token verification failed';
          res.status(401).json({ error: message });
          return;
        }
        next();
      }
    };
  }
}

// ---------------------------------------------------------------------------
// Convenience factory
// ---------------------------------------------------------------------------

/**
 * Create a new SimpleAuth client.
 *
 * @example
 * ```ts
 * import { createSimpleAuth } from '@simpleauth/js';
 *
 * const auth = createSimpleAuth({
 *   url: 'https://auth.corp.local:9090',
 *   adminKey: 'my-admin-key',      // optional, for admin operations
 * });
 *
 * const tokens = await auth.login('admin', 'password');
 * const user = await auth.verify(tokens.access_token);
 * console.log(user.hasRole('admin'));
 * ```
 */
export function createSimpleAuth(options: SimpleAuthOptions): SimpleAuth {
  return new SimpleAuth(options);
}

// Default export
export default SimpleAuth;
