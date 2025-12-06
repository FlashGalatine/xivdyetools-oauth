/**
 * JWT Service
 * Handles creation and validation of JSON Web Tokens using Web Crypto API
 *
 * Uses HMAC-SHA256 for signing (HS256 algorithm)
 * Compatible with Cloudflare Workers (no Node.js crypto required)
 */

import type { JWTPayload, DiscordUser, Env } from '../types.js';

/**
 * Base64URL encode a string or ArrayBuffer
 */
function base64UrlEncode(data: string | ArrayBuffer): string {
  let base64: string;

  if (typeof data === 'string') {
    // Use TextEncoder for strings
    const bytes = new TextEncoder().encode(data);
    base64 = btoa(String.fromCharCode(...bytes));
  } else {
    // Handle ArrayBuffer
    const bytes = new Uint8Array(data);
    base64 = btoa(String.fromCharCode(...bytes));
  }

  // Convert to base64url
  return base64.replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

/**
 * Base64URL decode to string
 */
function base64UrlDecode(str: string): string {
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
 */
async function sign(data: string, secret: string): Promise<string> {
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
 * Create a JWT for a Discord user
 */
export async function createJWT(
  user: DiscordUser,
  env: Env
): Promise<{ token: string; expires_at: number }> {
  const now = Math.floor(Date.now() / 1000);
  const expirySeconds = parseInt(env.JWT_EXPIRY, 10) || 3600;
  const expiresAt = now + expirySeconds;

  const payload: JWTPayload = {
    sub: user.id,
    iat: now,
    exp: expiresAt,
    iss: env.WORKER_URL,
    username: user.username,
    global_name: user.global_name,
    avatar: user.avatar,
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
  const signature = await sign(signatureInput, env.JWT_SECRET);

  // Combine into JWT
  const token = `${signatureInput}.${signature}`;

  return { token, expires_at: expiresAt };
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
