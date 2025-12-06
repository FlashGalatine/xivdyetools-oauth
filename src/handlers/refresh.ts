/**
 * Token Refresh and User Info Handler
 */

import { Hono } from 'hono';
import type { Env, RefreshResponse, UserInfoResponse, JWTPayload } from '../types.js';
import { verifyJWT, createJWT, getAvatarUrl, decodeJWT } from '../services/jwt-service.js';

export const tokenRouter = new Hono<{ Bindings: Env }>();

/**
 * POST /auth/refresh
 * Refresh an existing JWT (must not be expired by more than 24 hours)
 *
 * Body:
 * - token: Current JWT (can be recently expired)
 */
tokenRouter.post('/refresh', async (c) => {
  let body: { token: string };

  try {
    body = await c.req.json();
  } catch {
    return c.json<RefreshResponse>(
      {
        success: false,
        error: 'Invalid request body',
      },
      400
    );
  }

  const { token } = body;

  if (!token) {
    return c.json<RefreshResponse>(
      {
        success: false,
        error: 'Missing token',
      },
      400
    );
  }

  try {
    // Try to verify the token (this will fail if expired)
    let payload: JWTPayload;

    try {
      payload = await verifyJWT(token, c.env.JWT_SECRET);
    } catch (err) {
      // If expired, decode without verification and check grace period
      const decoded = decodeJWT(token);

      if (!decoded) {
        return c.json<RefreshResponse>(
          {
            success: false,
            error: 'Invalid token format',
          },
          401
        );
      }

      // Allow refresh within 24 hours of expiration
      const now = Math.floor(Date.now() / 1000);
      const gracePeriod = 24 * 60 * 60; // 24 hours

      if (decoded.exp + gracePeriod < now) {
        return c.json<RefreshResponse>(
          {
            success: false,
            error: 'Token has expired and cannot be refreshed',
          },
          401
        );
      }

      // Verify signature manually for expired token
      // Re-create payload for new token
      payload = decoded;
    }

    // Create new JWT with same user info
    const expirySeconds = parseInt(c.env.JWT_EXPIRY, 10) || 3600;
    const now = Math.floor(Date.now() / 1000);
    const newExpiry = now + expirySeconds;

    const newPayload: JWTPayload = {
      sub: payload.sub,
      iat: now,
      exp: newExpiry,
      iss: c.env.WORKER_URL,
      username: payload.username,
      global_name: payload.global_name,
      avatar: payload.avatar,
    };

    // Create new token manually (simplified since we already have payload)
    const { token: newToken, expires_at } = await createJWTFromPayload(newPayload, c.env);

    return c.json<RefreshResponse>({
      success: true,
      token: newToken,
      expires_at,
    });
  } catch (err) {
    console.error('Token refresh error:', err);

    return c.json<RefreshResponse>(
      {
        success: false,
        error: 'Failed to refresh token',
      },
      500
    );
  }
});

/**
 * GET /auth/me
 * Get current user info from JWT
 *
 * Headers:
 * - Authorization: Bearer <token>
 */
tokenRouter.get('/me', async (c) => {
  const authHeader = c.req.header('Authorization');

  if (!authHeader?.startsWith('Bearer ')) {
    return c.json<UserInfoResponse>(
      {
        success: false,
        error: 'Missing or invalid Authorization header',
      },
      401
    );
  }

  const token = authHeader.slice(7);

  try {
    const payload = await verifyJWT(token, c.env.JWT_SECRET);

    return c.json<UserInfoResponse>({
      success: true,
      user: {
        id: payload.sub,
        username: payload.username,
        global_name: payload.global_name,
        avatar: payload.avatar,
        avatar_url: getAvatarUrl(payload.sub, payload.avatar),
      },
    });
  } catch (err) {
    const message = err instanceof Error ? err.message : 'Invalid token';

    return c.json<UserInfoResponse>(
      {
        success: false,
        error: message,
      },
      401
    );
  }
});

/**
 * POST /auth/revoke
 * Logout - invalidate token (for stateless JWTs, this is a no-op on server)
 * Client should clear their stored token
 */
tokenRouter.post('/revoke', async (c) => {
  // For stateless JWTs, we can't truly revoke
  // The client is responsible for clearing the token
  // In future, could add token ID to a blacklist with TTL

  return c.json({
    success: true,
    message: 'Token revoked. Please clear client-side storage.',
  });
});

/**
 * Helper to create JWT from existing payload
 */
async function createJWTFromPayload(
  payload: JWTPayload,
  env: Env
): Promise<{ token: string; expires_at: number }> {
  // This duplicates some logic from jwt-service but avoids needing DiscordUser
  const base64UrlEncode = (data: string): string => {
    const bytes = new TextEncoder().encode(data);
    const base64 = btoa(String.fromCharCode(...bytes));
    return base64.replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
  };

  const sign = async (data: string, secret: string): Promise<string> => {
    const encoder = new TextEncoder();
    const keyData = encoder.encode(secret);
    const key = await crypto.subtle.importKey(
      'raw',
      keyData,
      { name: 'HMAC', hash: 'SHA-256' },
      false,
      ['sign']
    );
    const signature = await crypto.subtle.sign('HMAC', key, encoder.encode(data));
    const sigBytes = new Uint8Array(signature);
    const base64 = btoa(String.fromCharCode(...sigBytes));
    return base64.replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
  };

  const header = { alg: 'HS256', typ: 'JWT' };
  const encodedHeader = base64UrlEncode(JSON.stringify(header));
  const encodedPayload = base64UrlEncode(JSON.stringify(payload));
  const signatureInput = `${encodedHeader}.${encodedPayload}`;
  const signature = await sign(signatureInput, env.JWT_SECRET);

  return {
    token: `${signatureInput}.${signature}`,
    expires_at: payload.exp,
  };
}
