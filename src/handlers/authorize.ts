/**
 * Authorization Handler
 * Redirects users to Discord OAuth with PKCE parameters
 */

import { Hono } from 'hono';
import type { Env } from '../types.js';

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
 */
authorizeRouter.get('/discord', (c) => {
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

  if (code_challenge_method && code_challenge_method !== 'S256') {
    return c.json(
      {
        error: 'Invalid code_challenge_method',
        message: 'Only S256 is supported',
      },
      400
    );
  }

  // Validate redirect_uri if provided
  // Support both the primary frontend URL and the custom domain
  const allowedRedirects = [
    c.env.FRONTEND_URL,
    `${c.env.FRONTEND_URL}/auth/callback`,
    'https://xivdyetools.projectgalatine.com',
    'https://xivdyetools.projectgalatine.com/auth/callback',
    'http://localhost:5173',
    'http://localhost:5173/auth/callback',
  ];

  const finalRedirectUri = redirect_uri || `${c.env.FRONTEND_URL}/auth/callback`;

  // Check if redirect is to an allowed origin
  const redirectOrigin = new URL(finalRedirectUri).origin;
  const isAllowed = allowedRedirects.some(
    (allowed) => new URL(allowed).origin === redirectOrigin
  );

  if (!isAllowed) {
    return c.json(
      {
        error: 'Invalid redirect_uri',
        message: 'Redirect URI is not whitelisted',
      },
      400
    );
  }

  // Generate state if not provided (includes return info)
  const stateData = {
    csrf: state || crypto.randomUUID(),
    code_challenge, // Store for verification in callback
    redirect_uri: finalRedirectUri,
    return_path: return_path || '/',
  };

  // Encode state as base64
  const encodedState = btoa(JSON.stringify(stateData));

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
