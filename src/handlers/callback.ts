/**
 * OAuth Callback Handler
 * Exchanges authorization code for tokens and issues JWT
 */

import { Hono } from 'hono';
import type { Env, DiscordTokenResponse, DiscordUser, AuthResponse } from '../types.js';
import { createJWT, getAvatarUrl } from '../services/jwt-service.js';

export const callbackRouter = new Hono<{ Bindings: Env }>();

/**
 * GET /auth/callback
 * Discord redirects here after user authorizes
 * Exchanges code for tokens, fetches user info, issues JWT
 *
 * Query parameters (from Discord):
 * - code: Authorization code
 * - state: State we sent (contains redirect info)
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

  // Decode state
  let stateData: {
    csrf: string;
    code_challenge: string;
    code_verifier: string;
    redirect_uri: string;
    return_path: string;
  };

  try {
    stateData = JSON.parse(atob(state));
  } catch {
    const redirectUrl = new URL(`${c.env.FRONTEND_URL}/auth/callback`);
    redirectUrl.searchParams.set('error', 'Invalid state parameter');
    return c.redirect(redirectUrl.toString());
  }

  try {
    // Exchange code for tokens (include code_verifier for PKCE)
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
        redirect_uri: `${c.env.WORKER_URL}/auth/callback`,
        code_verifier: stateData.code_verifier,
      }),
    });

    if (!tokenResponse.ok) {
      const errorText = await tokenResponse.text();
      console.error('Token exchange failed:', errorText);

      const redirectUrl = new URL(stateData.redirect_uri);
      redirectUrl.searchParams.set('error', 'Failed to exchange authorization code');
      return c.redirect(redirectUrl.toString());
    }

    const tokens: DiscordTokenResponse = await tokenResponse.json();

    // Fetch user info
    const userResponse = await fetch('https://discord.com/api/users/@me', {
      headers: {
        Authorization: `Bearer ${tokens.access_token}`,
      },
    });

    if (!userResponse.ok) {
      const errorText = await userResponse.text();
      console.error('User fetch failed:', errorText);

      const redirectUrl = new URL(stateData.redirect_uri);
      redirectUrl.searchParams.set('error', 'Failed to fetch user information');
      return c.redirect(redirectUrl.toString());
    }

    const discordUser: DiscordUser = await userResponse.json();

    // Create our JWT
    const { token, expires_at } = await createJWT(discordUser, c.env);

    // Redirect back to frontend with token
    const redirectUrl = new URL(stateData.redirect_uri);
    redirectUrl.searchParams.set('token', token);
    redirectUrl.searchParams.set('expires_at', expires_at.toString());
    if (stateData.return_path && stateData.return_path !== '/') {
      redirectUrl.searchParams.set('return_path', stateData.return_path);
    }

    return c.redirect(redirectUrl.toString());
  } catch (err) {
    console.error('OAuth callback error:', err);

    const redirectUrl = new URL(stateData.redirect_uri);
    redirectUrl.searchParams.set('error', 'Authentication failed');
    return c.redirect(redirectUrl.toString());
  }
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

  try {
    // Exchange code for tokens with PKCE verifier
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
        redirect_uri: redirect_uri || `${c.env.FRONTEND_URL}/auth/callback`,
        code_verifier,
      }),
    });

    if (!tokenResponse.ok) {
      const errorData = await tokenResponse.json().catch(() => ({}));
      console.error('Token exchange failed:', errorData);

      return c.json<AuthResponse>(
        {
          success: false,
          error: 'Failed to exchange authorization code',
        },
        401
      );
    }

    const tokens: DiscordTokenResponse = await tokenResponse.json();

    // Fetch user info
    const userResponse = await fetch('https://discord.com/api/users/@me', {
      headers: {
        Authorization: `Bearer ${tokens.access_token}`,
      },
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

    // Create our JWT
    const { token, expires_at } = await createJWT(discordUser, c.env);

    return c.json<AuthResponse>({
      success: true,
      token,
      user: {
        id: discordUser.id,
        username: discordUser.username,
        global_name: discordUser.global_name,
        avatar: discordUser.avatar,
        avatar_url: getAvatarUrl(discordUser.id, discordUser.avatar),
      },
      expires_at,
    });
  } catch (err) {
    console.error('OAuth callback error:', err);

    return c.json<AuthResponse>(
      {
        success: false,
        error: 'Authentication failed',
      },
      500
    );
  }
});
