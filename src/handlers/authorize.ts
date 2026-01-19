/**
 * Authorization Handler
 * Redirects users to Discord OAuth with PKCE parameters
 *
 * OAUTH-REF-002: Refactored to use shared validation utilities from oauth-validation.ts
 * This reduces code duplication between Discord and XIVAuth handlers.
 */

import { Hono } from 'hono';
import type { Env } from '../types.js';
import { STATE_EXPIRY_SECONDS, ALLOWED_REDIRECT_ORIGINS } from '../constants/oauth.js';
import { signState } from '../utils/state-signing.js';
import { validateCodeChallenge, validateRedirectUri } from '../utils/oauth-validation.js';

export const authorizeRouter = new Hono<{ Bindings: Env }>();

/**
 * GET /auth/discord
 * Initiates the OAuth flow by redirecting to Discord
 *
 * Query parameters:
 * - code_challenge: PKCE code challenge (required for security)
 * - code_challenge_method: Must be 'S256' (SHA-256)
 * - state: Random state for CSRF protection (optional, generated if not provided)
 * - redirect_uri: Where to redirect after auth (must be whitelisted)
 * - return_path: Path in frontend to return to after auth (optional)
 *
 * SECURITY NOTE: The code_verifier should NEVER be sent to this endpoint.
 * It must remain on the client and be sent directly to POST /auth/callback.
 * This is the core security guarantee of PKCE - the verifier never travels through redirects.
 */
authorizeRouter.get('/discord', async (c) => {
  const { code_challenge, code_challenge_method, state, redirect_uri, return_path } =
    c.req.query();

  // Validate PKCE parameters
  if (!code_challenge) {
    return c.json(
      {
        error: 'Missing code_challenge',
        message: 'PKCE code_challenge is required for security',
      },
      400
    );
  }

  // OAUTH-REF-002: Use shared validation utility instead of inline regex
  if (!validateCodeChallenge(code_challenge)) {
    return c.json(
      {
        error: 'Invalid code_challenge format',
        message: 'code_challenge must be a valid base64url-encoded value',
      },
      400
    );
  }

  if (code_challenge_method && code_challenge_method !== 'S256') {
    return c.json(
      {
        error: 'Invalid code_challenge_method',
        message: 'Only S256 is supported',
      },
      400
    );
  }

  // OAUTH-REF-002: Build allowlist from shared constants + env-specific frontend URL
  const allowedOrigins = [
    ...ALLOWED_REDIRECT_ORIGINS,
    c.env.FRONTEND_URL,
    `${c.env.FRONTEND_URL}/auth/callback`,
  ];

  const finalRedirectUri = redirect_uri || `${c.env.FRONTEND_URL}/auth/callback`;

  // OAUTH-REF-002: Use shared validation utility for redirect URI
  try {
    validateRedirectUri(finalRedirectUri, allowedOrigins);
  } catch {
    return c.json(
      {
        error: 'Invalid redirect_uri',
        message: 'Redirect URI is not whitelisted',
      },
      400
    );
  }

  // Generate state with only safe data (NO code_verifier!)
  // The code_verifier is kept on the client and sent via POST callback
  const now = Math.floor(Date.now() / 1000);
  const stateData = {
    csrf: state || crypto.randomUUID(),
    code_challenge, // Store for logging/debugging only
    redirect_uri: finalRedirectUri,
    return_path: return_path || '/',
    provider: 'discord', // Mark this as Discord flow
    iat: now, // Issued at timestamp
    exp: now + STATE_EXPIRY_SECONDS, // 10 minute expiration (OAuth flow should complete quickly)
  };

  // SECURITY: Sign state to prevent tampering
  const encodedState = await signState(stateData, c.env.JWT_SECRET);

  // Build Discord OAuth URL
  const discordUrl = new URL('https://discord.com/oauth2/authorize');
  discordUrl.searchParams.set('client_id', c.env.DISCORD_CLIENT_ID);
  discordUrl.searchParams.set('redirect_uri', `${c.env.WORKER_URL}/auth/callback`);
  discordUrl.searchParams.set('response_type', 'code');
  discordUrl.searchParams.set('scope', 'identify');
  discordUrl.searchParams.set('state', encodedState);

  // Add PKCE challenge (Discord supports this)
  discordUrl.searchParams.set('code_challenge', code_challenge);
  discordUrl.searchParams.set('code_challenge_method', 'S256');

  return c.redirect(discordUrl.toString());
});
