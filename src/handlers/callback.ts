/**
 * OAuth Callback Handler
 * Exchanges authorization code for tokens and issues JWT
 */

import { Hono } from 'hono';
import type { Env, DiscordTokenResponse, DiscordUser, AuthResponse } from '../types.js';
import { createJWTForUser, getAvatarUrl } from '../services/jwt-service.js';
import { findOrCreateUser } from '../services/user-service.js';
import { verifyState } from '../utils/state-signing.js';

export const callbackRouter = new Hono<{ Bindings: Env }>();

/**
 * GET /auth/callback
 * Discord redirects here after user authorizes
 *
 * SECURITY: This endpoint does NOT exchange the code directly.
 * Instead, it redirects the auth code to the frontend, which then
 * calls POST /auth/callback with the code + code_verifier from sessionStorage.
 * This ensures the code_verifier never travels through URL redirects.
 *
 * Query parameters (from Discord):
 * - code: Authorization code
 * - state: State we sent (contains redirect info, but NO code_verifier)
 *
 * Or for errors:
 * - error: Error code
 * - error_description: Human-readable error
 */
callbackRouter.get('/callback', async (c) => {
  const { code, state, error, error_description } = c.req.query();

  // Handle Discord errors
  if (error) {
    const errorMessage = error_description || error;
    const redirectUrl = new URL(`${c.env.FRONTEND_URL}/auth/callback`);
    redirectUrl.searchParams.set('error', errorMessage);
    return c.redirect(redirectUrl.toString());
  }

  // Validate required parameters
  if (!code || !state) {
    const redirectUrl = new URL(`${c.env.FRONTEND_URL}/auth/callback`);
    redirectUrl.searchParams.set('error', 'Missing code or state parameter');
    return c.redirect(redirectUrl.toString());
  }

  // Decode and verify state signature
  let stateData: {
    csrf: string;
    code_challenge?: string;
    redirect_uri: string;
    return_path: string;
    provider?: string;
    iat: number;
    exp: number;
  };

  // SECURITY: Verify state signature to prevent tampering
  // Allow unsigned states during transition period
  try {
    const allowUnsigned =
      c.env.ENVIRONMENT === 'development' || c.env.STATE_TRANSITION_PERIOD === 'true';

    stateData = await verifyState(state, c.env.JWT_SECRET, allowUnsigned);
  } catch (err) {
    const redirectUrl = new URL(`${c.env.FRONTEND_URL}/auth/callback`);
    const errorMsg = err instanceof Error ? err.message : 'Invalid state';
    redirectUrl.searchParams.set('error', errorMsg);
    return c.redirect(redirectUrl.toString());
  }

  // SECURITY: Validate state expiration to prevent replay attacks
  const now = Math.floor(Date.now() / 1000);
  if (stateData.exp && stateData.exp < now) {
    const redirectUrl = new URL(`${c.env.FRONTEND_URL}/auth/callback`);
    redirectUrl.searchParams.set('error', 'OAuth state expired. Please try logging in again.');
    return c.redirect(redirectUrl.toString());
  }

  // OAUTH-CRITICAL-002: Validate redirect URI to prevent open redirect attacks
  // Only allow redirects to trusted origins
  const allowedOrigins = [
    new URL(c.env.FRONTEND_URL).origin,
  ];

  // Allow localhost in development for testing
  if (c.env.ENVIRONMENT === 'development') {
    allowedOrigins.push('http://localhost:5173');
    allowedOrigins.push('http://localhost:3000');
    allowedOrigins.push('http://127.0.0.1:5173');
    allowedOrigins.push('http://127.0.0.1:3000');
  }

  let redirectUrl: URL;
  try {
    redirectUrl = new URL(stateData.redirect_uri);
  } catch {
    const errorRedirect = new URL(`${c.env.FRONTEND_URL}/auth/callback`);
    errorRedirect.searchParams.set('error', 'Invalid redirect URI');
    return c.redirect(errorRedirect.toString());
  }

  if (!allowedOrigins.includes(redirectUrl.origin)) {
    console.error('Blocked redirect to untrusted origin:', redirectUrl.origin);
    const errorRedirect = new URL(`${c.env.FRONTEND_URL}/auth/callback`);
    errorRedirect.searchParams.set('error', 'Untrusted redirect origin');
    return c.redirect(errorRedirect.toString());
  }

  // Redirect back to frontend with the auth code
  // The frontend will then call POST /auth/callback with code + code_verifier
  redirectUrl.searchParams.set('code', code);
  redirectUrl.searchParams.set('csrf', stateData.csrf);
  if (stateData.return_path && stateData.return_path !== '/') {
    redirectUrl.searchParams.set('return_path', stateData.return_path);
  }

  return c.redirect(redirectUrl.toString());
});

/**
 * POST /auth/callback
 * Alternative method for SPA to exchange code
 * Used when the SPA handles the callback itself
 *
 * Body:
 * - code: Authorization code from Discord
 * - code_verifier: PKCE verifier to prove ownership
 * - redirect_uri: The redirect URI used in the initial request
 */
callbackRouter.post('/callback', async (c) => {
  let body: { code: string; code_verifier: string; redirect_uri?: string };

  try {
    body = await c.req.json();
  } catch {
    return c.json<AuthResponse>(
      {
        success: false,
        error: 'Invalid request body',
      },
      400
    );
  }

  const { code, code_verifier, redirect_uri } = body;

  if (!code || !code_verifier) {
    return c.json<AuthResponse>(
      {
        success: false,
        error: 'Missing code or code_verifier',
      },
      400
    );
  }

  // SECURITY: Validate code_verifier format (RFC 7636)
  // Must be 43-128 characters using only unreserved characters: [A-Za-z0-9-._~]
  // This is defense in depth - Discord also validates this
  const verifierRegex = /^[A-Za-z0-9\-._~]{43,128}$/;
  if (!verifierRegex.test(code_verifier)) {
    return c.json<AuthResponse>(
      {
        success: false,
        error: 'Invalid code_verifier format',
      },
      400
    );
  }

  try {
    // The redirect URI used when exchanging the code MUST match the one sent to Discord
    // during the initial authorize step. That value is always the worker callback URL.
    const tokenExchangeRedirectUri = `${c.env.WORKER_URL}/auth/callback`;

    // Warn in development if the client tried to send a different redirect URI so we can
    // spot potential misconfigurations, but always prefer the canonical value for security.
    if (
      redirect_uri &&
      redirect_uri !== tokenExchangeRedirectUri &&
      c.env.ENVIRONMENT === 'development'
    ) {
      console.warn('Ignoring mismatched redirect_uri during token exchange', {
        provided: redirect_uri,
        expected: tokenExchangeRedirectUri,
      });
    }

    // OAUTH-HIGH-001: Exchange code for tokens with PKCE verifier
    // Added 10 second timeout to prevent worker hang if Discord API is slow
    const tokenResponse = await fetch('https://discord.com/api/oauth2/token', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
      },
      body: new URLSearchParams({
        client_id: c.env.DISCORD_CLIENT_ID,
        client_secret: c.env.DISCORD_CLIENT_SECRET,
        grant_type: 'authorization_code',
        code,
        redirect_uri: tokenExchangeRedirectUri,
        code_verifier,
      }),
      signal: AbortSignal.timeout(10000), // 10 second timeout
    });

    if (!tokenResponse.ok) {
      const errorData = await tokenResponse.json().catch(() => ({}));
      // Only log detailed error data in development to prevent info leakage
      if (c.env.ENVIRONMENT === 'development') {
        console.error('Token exchange failed:', errorData);
      } else {
        console.error('Token exchange failed');
      }

      return c.json<AuthResponse>(
        {
          success: false,
          error: 'Failed to exchange authorization code',
        },
        401
      );
    }

    const tokens: DiscordTokenResponse = await tokenResponse.json();

    // SECURITY: Validate that we received the required 'identify' scope
    // This ensures the token has the permissions we need
    if (!tokens.scope || !tokens.scope.includes('identify')) {
      console.error('Token missing required identify scope', { scope: tokens.scope });
      return c.json<AuthResponse>(
        {
          success: false,
          error: 'Token missing required permissions',
        },
        401
      );
    }

    // OAUTH-HIGH-001: Fetch user info with 5 second timeout
    const userResponse = await fetch('https://discord.com/api/users/@me', {
      headers: {
        Authorization: `Bearer ${tokens.access_token}`,
      },
      signal: AbortSignal.timeout(5000), // 5 second timeout
    });

    if (!userResponse.ok) {
      return c.json<AuthResponse>(
        {
          success: false,
          error: 'Failed to fetch user information',
        },
        401
      );
    }

    const discordUser: DiscordUser = await userResponse.json();

    // SECURITY: Validate required user fields exist
    // Protects against malformed responses or unexpected API changes
    if (!discordUser.id || !discordUser.username) {
      console.error('Discord user response missing required fields', {
        hasId: !!discordUser.id,
        hasUsername: !!discordUser.username,
      });
      return c.json<AuthResponse>(
        {
          success: false,
          error: 'Invalid user data received',
        },
        401
      );
    }

    // Find or create user in database
    const user = await findOrCreateUser(c.env.DB, {
      discord_id: discordUser.id,
      xivauth_id: null, // Discord login doesn't provide XIVAuth ID
      username: discordUser.global_name || discordUser.username,
      avatar_url: getAvatarUrl(discordUser.id, discordUser.avatar),
      auth_provider: 'discord',
    });

    // Create our JWT with the database user
    const { token, expires_at } = await createJWTForUser(user, c.env, {
      auth_provider: 'discord',
      global_name: discordUser.global_name,
      avatar: discordUser.avatar,
    });

    return c.json<AuthResponse>({
      success: true,
      token,
      user: {
        id: user.id, // Now returns our internal user ID
        username: discordUser.username,
        global_name: discordUser.global_name,
        avatar: discordUser.avatar,
        avatar_url: getAvatarUrl(discordUser.id, discordUser.avatar),
        auth_provider: 'discord',
      },
      expires_at,
    });
  } catch (err) {
    // Sanitize logs in production - only log error name and message
    if (c.env.ENVIRONMENT === 'development') {
      console.error('OAuth callback error:', err);
    } else {
      const error = err as Error;
      console.error('OAuth callback error:', { name: error.name, message: error.message });
    }

    return c.json<AuthResponse>(
      {
        success: false,
        error: 'Authentication failed',
      },
      500
    );
  }
});
