/**
 * JWT Service
 * Handles creation and validation of JSON Web Tokens using Web Crypto API
 *
 * Uses HMAC-SHA256 for signing (HS256 algorithm)
 * Compatible with Cloudflare Workers (no Node.js crypto required)
 */

import type { JWTPayload, DiscordUser, Env, UserRow, AuthProvider, PrimaryCharacter } from '../types.js';

/**
 * Convert Uint8Array to binary string safely (without spread operator)
 *
 * OAUTH-BUG-001 FIX: Using Array.from().map().join() instead of
 * String.fromCharCode(...bytes) to avoid call stack size limits
 * with large byte arrays.
 */
function bytesToBinaryString(bytes: Uint8Array): string {
  // Using Array.from to avoid spread operator call stack limits
  return Array.from(bytes)
    .map((b) => String.fromCharCode(b))
    .join('');
}

/**
 * Base64URL encode a string or ArrayBuffer
 * OAUTH-REF-002: Exported for reuse in refresh.ts to avoid duplication
 */
export function base64UrlEncode(data: string | ArrayBuffer): string {
  let base64: string;

  if (typeof data === 'string') {
    // Use TextEncoder for strings
    const bytes = new TextEncoder().encode(data);
    base64 = btoa(bytesToBinaryString(bytes));
  } else {
    // Handle ArrayBuffer
    const bytes = new Uint8Array(data);
    base64 = btoa(bytesToBinaryString(bytes));
  }

  // Convert to base64url
  return base64.replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

/**
 * Base64URL decode to string
 * OAUTH-REF-003: Exported for reuse in state-signing.ts to avoid duplication
 */
export function base64UrlDecode(str: string): string {
  // Convert from base64url to base64
  let base64 = str.replace(/-/g, '+').replace(/_/g, '/');

  // Add padding if needed
  const padding = base64.length % 4;
  if (padding) {
    base64 += '='.repeat(4 - padding);
  }

  // Decode
  const decoded = atob(base64);
  const bytes = new Uint8Array(decoded.length);
  for (let i = 0; i < decoded.length; i++) {
    bytes[i] = decoded.charCodeAt(i);
  }

  return new TextDecoder().decode(bytes);
}

/**
 * Import secret key for HMAC signing
 */
async function getSigningKey(secret: string): Promise<CryptoKey> {
  const encoder = new TextEncoder();
  const keyData = encoder.encode(secret);

  return crypto.subtle.importKey(
    'raw',
    keyData,
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign', 'verify']
  );
}

/**
 * Sign data with HMAC-SHA256
 * OAUTH-REF-002: Exported for reuse in refresh.ts to avoid duplication
 */
export async function signJwtData(data: string, secret: string): Promise<string> {
  const key = await getSigningKey(secret);
  const encoder = new TextEncoder();
  const signature = await crypto.subtle.sign('HMAC', key, encoder.encode(data));
  return base64UrlEncode(signature);
}

/**
 * Verify HMAC-SHA256 signature
 */
async function verify(
  data: string,
  signature: string,
  secret: string
): Promise<boolean> {
  const key = await getSigningKey(secret);
  const encoder = new TextEncoder();

  // Decode signature from base64url
  let base64 = signature.replace(/-/g, '+').replace(/_/g, '/');
  const padding = base64.length % 4;
  if (padding) {
    base64 += '='.repeat(4 - padding);
  }
  const sigBytes = Uint8Array.from(atob(base64), (c) => c.charCodeAt(0));

  return crypto.subtle.verify('HMAC', key, sigBytes, encoder.encode(data));
}

/**
 * Create a JWT for a Discord user (legacy function, kept for backwards compatibility)
 * Includes jti (JWT ID) claim for token revocation support
 * @deprecated Use createJWTForUser instead for multi-provider support
 */
export async function createJWT(
  user: DiscordUser,
  env: Env
): Promise<{ token: string; expires_at: number; jti: string }> {
  const now = Math.floor(Date.now() / 1000);
  const expirySeconds = parseInt(env.JWT_EXPIRY, 10) || 3600;
  const expiresAt = now + expirySeconds;

  // Generate unique token ID for revocation tracking
  const jti = crypto.randomUUID();

  const payload: JWTPayload = {
    sub: user.id,
    iat: now,
    exp: expiresAt,
    iss: env.WORKER_URL,
    jti,
    username: user.username,
    global_name: user.global_name,
    avatar: user.avatar,
    auth_provider: 'discord',
    discord_id: user.id,
  };

  // JWT Header
  const header = {
    alg: 'HS256',
    typ: 'JWT',
  };

  // Encode header and payload
  const encodedHeader = base64UrlEncode(JSON.stringify(header));
  const encodedPayload = base64UrlEncode(JSON.stringify(payload));

  // Create signature
  const signatureInput = `${encodedHeader}.${encodedPayload}`;
  const signature = await signJwtData(signatureInput, env.JWT_SECRET);

  // Combine into JWT
  const token = `${signatureInput}.${signature}`;

  return { token, expires_at: expiresAt, jti };
}

/**
 * Extra options for JWT creation from a database user
 */
export interface CreateJWTForUserOptions {
  auth_provider?: AuthProvider;
  primary_character?: PrimaryCharacter;
  global_name?: string | null;
  avatar?: string | null;
}

/**
 * Create a JWT for a database user (supports both Discord and XIVAuth)
 * This is the preferred method for multi-provider authentication
 */
export async function createJWTForUser(
  user: UserRow,
  env: Env,
  options?: CreateJWTForUserOptions
): Promise<{ token: string; expires_at: number; jti: string }> {
  const now = Math.floor(Date.now() / 1000);
  const expirySeconds = parseInt(env.JWT_EXPIRY, 10) || 3600;
  const expiresAt = now + expirySeconds;

  // Generate unique token ID for revocation tracking
  const jti = crypto.randomUUID();

  const payload: JWTPayload = {
    // Standard claims
    sub: user.id, // Our internal user ID
    iat: now,
    exp: expiresAt,
    iss: env.WORKER_URL,
    jti,

    // User info
    username: user.username,
    global_name: options?.global_name ?? null,
    avatar: options?.avatar ?? null,

    // Multi-provider support
    auth_provider: options?.auth_provider ?? (user.auth_provider as AuthProvider),
    discord_id: user.discord_id ?? undefined,
    xivauth_id: user.xivauth_id ?? undefined,

    // XIVAuth-specific
    primary_character: options?.primary_character,
  };

  // JWT Header
  const header = {
    alg: 'HS256',
    typ: 'JWT',
  };

  // Encode header and payload
  const encodedHeader = base64UrlEncode(JSON.stringify(header));
  const encodedPayload = base64UrlEncode(JSON.stringify(payload));

  // Create signature
  const signatureInput = `${encodedHeader}.${encodedPayload}`;
  const signature = await signJwtData(signatureInput, env.JWT_SECRET);

  // Combine into JWT
  const token = `${signatureInput}.${signature}`;

  return { token, expires_at: expiresAt, jti };
}

/**
 * Verify and decode a JWT
 * Returns the payload if valid, throws if invalid
 */
export async function verifyJWT(
  token: string,
  secret: string
): Promise<JWTPayload> {
  const parts = token.split('.');

  if (parts.length !== 3) {
    throw new Error('Invalid JWT format');
  }

  const [encodedHeader, encodedPayload, signature] = parts;

  // Verify signature
  const signatureInput = `${encodedHeader}.${encodedPayload}`;
  const isValid = await verify(signatureInput, signature, secret);

  if (!isValid) {
    throw new Error('Invalid JWT signature');
  }

  // Decode payload
  const payload: JWTPayload = JSON.parse(base64UrlDecode(encodedPayload));

  // Check expiration
  const now = Math.floor(Date.now() / 1000);
  if (payload.exp < now) {
    throw new Error('JWT has expired');
  }

  return payload;
}

/**
 * Decode JWT without verification (for debugging/display)
 * WARNING: Do not trust the contents without calling verifyJWT
 */
export function decodeJWT(token: string): JWTPayload | null {
  try {
    const parts = token.split('.');
    if (parts.length !== 3) return null;

    const payload = JSON.parse(base64UrlDecode(parts[1]));
    return payload as JWTPayload;
  } catch {
    return null;
  }
}

/**
 * Verify JWT signature ONLY (ignores expiration)
 * Used for token refresh where we allow recently expired tokens
 *
 * SECURITY: This verifies the token was signed with our secret,
 * preventing attackers from forging tokens with arbitrary user IDs.
 *
 * @returns payload if signature is valid, null if invalid
 */
export async function verifyJWTSignatureOnly(
  token: string,
  secret: string
): Promise<JWTPayload | null> {
  try {
    const parts = token.split('.');

    if (parts.length !== 3) {
      return null;
    }

    const [encodedHeader, encodedPayload, signature] = parts;

    // Verify signature
    const signatureInput = `${encodedHeader}.${encodedPayload}`;
    const isValid = await verify(signatureInput, signature, secret);

    if (!isValid) {
      return null; // Signature invalid - do not trust payload
    }

    // Signature verified - decode and return payload
    const payload: JWTPayload = JSON.parse(base64UrlDecode(encodedPayload));
    return payload;
  } catch {
    return null;
  }
}

/**
 * Check if a JWT is expired without full verification
 */
export function isJWTExpired(token: string): boolean {
  const payload = decodeJWT(token);
  if (!payload) return true;

  const now = Math.floor(Date.now() / 1000);
  return payload.exp < now;
}

/**
 * Get Discord avatar URL from user info
 */
export function getAvatarUrl(
  userId: string,
  avatarHash: string | null
): string | null {
  if (!avatarHash) return null;

  const format = avatarHash.startsWith('a_') ? 'gif' : 'png';
  return `https://cdn.discordapp.com/avatars/${userId}/${avatarHash}.${format}`;
}

/**
 * Check if a token has been revoked
 * Uses KV to store revoked token JTIs
 */
export async function isTokenRevoked(
  jti: string,
  kv: KVNamespace | undefined
): Promise<boolean> {
  if (!kv || !jti) return false;

  try {
    const revoked = await kv.get(`revoked:${jti}`);
    return revoked !== null;
  } catch {
    // If KV lookup fails, allow token (fail-open for availability)
    return false;
  }
}

/**
 * Revoke a token by adding its JTI to the blacklist
 * TTL matches token expiry to auto-cleanup expired entries
 */
export async function revokeToken(
  jti: string,
  expiresAt: number,
  kv: KVNamespace | undefined
): Promise<boolean> {
  if (!kv || !jti) return false;

  try {
    // Calculate TTL - how long until token would expire naturally
    const now = Math.floor(Date.now() / 1000);
    const ttl = Math.max(expiresAt - now, 60); // Minimum 60 seconds

    await kv.put(`revoked:${jti}`, '1', { expirationTtl: ttl });
    return true;
  } catch {
    return false;
  }
}

/**
 * Verify JWT with revocation check
 * Combines signature/expiry verification with blacklist check
 */
export async function verifyJWTWithRevocationCheck(
  token: string,
  secret: string,
  kv: KVNamespace | undefined
): Promise<JWTPayload> {
  // First, verify signature and expiration
  const payload = await verifyJWT(token, secret);

  // Then check revocation if KV is available and token has JTI
  if (payload.jti && kv) {
    const revoked = await isTokenRevoked(payload.jti, kv);
    if (revoked) {
      throw new Error('Token has been revoked');
    }
  }

  return payload;
}
