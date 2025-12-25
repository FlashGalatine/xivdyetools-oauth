/**
 * XIVAuth OAuth Handler
 * Handles XIVAuth OAuth flow with PKCE for FFXIV community authentication
 */

import { Hono } from 'hono';
import type {
  Env,
  XIVAuthTokenResponse,
  XIVAuthUser,
  XIVAuthCharacterRegistration,
  AuthResponse,
} from '../types.js';
import { createJWTForUser } from '../services/jwt-service.js';
import { findOrCreateUser, storeCharacters } from '../services/user-service.js';

export const xivauthRouter = new Hono<{ Bindings: Env }>();

// XIVAuth OAuth endpoints
const XIVAUTH_AUTH_URL = 'https://xivauth.net/oauth/authorize';
const XIVAUTH_TOKEN_URL = 'https://xivauth.net/oauth/token';
const XIVAUTH_USER_URL = 'https://xivauth.net/api/v1/user';
const XIVAUTH_CHARACTERS_URL = 'https://xivauth.net/api/v1/characters';

// Scopes to request from XIVAuth
// - user: Basic user info (User ID, username)
// - user:social: Discord ID for moderation compatibility
// - character: FFXIV character info
// - refresh: Refresh token support
const XIVAUTH_SCOPES = 'user user:social character refresh';

/**
 * GET /auth/xivauth
 * Initiates the XIVAuth OAuth flow by redirecting to XIVAuth
 *
 * Query parameters:
 * - code_challenge: PKCE code challenge (required for security)
 * - code_challenge_method: Must be 'S256' (SHA-256)
 * - state: Random state for CSRF protection (optional, generated if not provided)
 * - redirect_uri: Where to redirect after auth (must be whitelisted)
 * - return_path: Path in frontend to return to after auth (optional)
 */
xivauthRouter.get('/xivauth', (c) => {
  const { code_challenge, code_challenge_method, state, redirect_uri, return_path } = c.req.query();

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
  const isAllowed = allowedRedirects.some((allowed) => new URL(allowed).origin === redirectOrigin);

  if (!isAllowed) {
    return c.json(
      {
        error: 'Invalid redirect_uri',
        message: 'Redirect URI is not whitelisted',
      },
      400
    );
  }

  // Generate state with provider marker
  const stateData = {
    csrf: state || crypto.randomUUID(),
    code_challenge,
    redirect_uri: finalRedirectUri,
    return_path: return_path || '/',
    provider: 'xivauth', // Mark this as XIVAuth flow
  };

  const encodedState = btoa(JSON.stringify(stateData));

  // Build XIVAuth authorization URL
  const xivauthUrl = new URL(XIVAUTH_AUTH_URL);
  xivauthUrl.searchParams.set('client_id', c.env.XIVAUTH_CLIENT_ID);
  xivauthUrl.searchParams.set('redirect_uri', `${c.env.WORKER_URL}/auth/xivauth/callback`);
  xivauthUrl.searchParams.set('response_type', 'code');
  xivauthUrl.searchParams.set('scope', XIVAUTH_SCOPES);
  xivauthUrl.searchParams.set('state', encodedState);

  // Add PKCE challenge
  xivauthUrl.searchParams.set('code_challenge', code_challenge);
  xivauthUrl.searchParams.set('code_challenge_method', 'S256');

  return c.redirect(xivauthUrl.toString());
});

/**
 * GET /auth/xivauth/callback
 * XIVAuth redirects here after user authorizes
 * Passes the code to the frontend for PKCE exchange
 */
xivauthRouter.get('/xivauth/callback', async (c) => {
  const { code, state, error, error_description } = c.req.query();

  // Handle XIVAuth errors
  if (error) {
    const errorMessage = error_description || error;
    const redirectUrl = new URL(`${c.env.FRONTEND_URL}/auth/callback`);
    redirectUrl.searchParams.set('error', errorMessage);
    redirectUrl.searchParams.set('provider', 'xivauth');
    return c.redirect(redirectUrl.toString());
  }

  // Validate required parameters
  if (!code || !state) {
    const redirectUrl = new URL(`${c.env.FRONTEND_URL}/auth/callback`);
    redirectUrl.searchParams.set('error', 'Missing code or state parameter');
    redirectUrl.searchParams.set('provider', 'xivauth');
    return c.redirect(redirectUrl.toString());
  }

  // Decode state
  let stateData: {
    csrf: string;
    code_challenge: string;
    redirect_uri: string;
    return_path: string;
    provider: string;
  };

  try {
    stateData = JSON.parse(atob(state));
  } catch {
    const redirectUrl = new URL(`${c.env.FRONTEND_URL}/auth/callback`);
    redirectUrl.searchParams.set('error', 'Invalid state parameter');
    redirectUrl.searchParams.set('provider', 'xivauth');
    return c.redirect(redirectUrl.toString());
  }

  // Redirect back to frontend with the auth code and provider marker
  const redirectUrl = new URL(stateData.redirect_uri);
  redirectUrl.searchParams.set('code', code);
  redirectUrl.searchParams.set('csrf', stateData.csrf);
  redirectUrl.searchParams.set('provider', 'xivauth');
  if (stateData.return_path && stateData.return_path !== '/') {
    redirectUrl.searchParams.set('return_path', stateData.return_path);
  }

  return c.redirect(redirectUrl.toString());
});

/**
 * POST /auth/xivauth/callback
 * Exchange authorization code for tokens (called by frontend with PKCE verifier)
 *
 * Body:
 * - code: Authorization code from XIVAuth
 * - code_verifier: PKCE verifier to prove ownership
 */
xivauthRouter.post('/xivauth/callback', async (c) => {
  let body: { code: string; code_verifier: string };

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

  const { code, code_verifier } = body;

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
    // Build token exchange parameters
    // client_secret is optional - XIVAuth supports public client mode with PKCE only
    const tokenParams: Record<string, string> = {
      client_id: c.env.XIVAUTH_CLIENT_ID,
      grant_type: 'authorization_code',
      code,
      redirect_uri: `${c.env.WORKER_URL}/auth/xivauth/callback`,
      code_verifier,
    };

    // Include client_secret only if configured (confidential client mode)
    if (c.env.XIVAUTH_CLIENT_SECRET) {
      tokenParams.client_secret = c.env.XIVAUTH_CLIENT_SECRET;
    }

    // Exchange code for tokens with PKCE verifier
    const tokenResponse = await fetch(XIVAUTH_TOKEN_URL, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
      },
      body: new URLSearchParams(tokenParams),
    });

    if (!tokenResponse.ok) {
      const errorData = await tokenResponse.text().catch(() => '');
      console.error('XIVAuth token exchange failed:', {
        status: tokenResponse.status,
        statusText: tokenResponse.statusText,
        error: errorData,
      });

      return c.json<AuthResponse>(
        {
          success: false,
          error: 'Failed to exchange authorization code',
        },
        401
      );
    }

    const tokens: XIVAuthTokenResponse = await tokenResponse.json();

    // Log token response for debugging (redact sensitive data in production)
    console.log('XIVAuth token exchange successful:', {
      token_type: tokens.token_type,
      expires_in: tokens.expires_in,
      scope: tokens.scope,
      has_access_token: !!tokens.access_token,
      has_refresh_token: !!tokens.refresh_token,
    });

    // Fetch user info from XIVAuth
    // IMPORTANT: Must include Accept header - XIVAuth Rails API requires it (responds with 406 otherwise)
    const userResponse = await fetch(XIVAUTH_USER_URL, {
      headers: {
        Authorization: `Bearer ${tokens.access_token}`,
        Accept: 'application/json',
      },
    });

    if (!userResponse.ok) {
      const userErrorData = await userResponse.text().catch(() => '');
      console.error('XIVAuth user info fetch failed:', {
        status: userResponse.status,
        statusText: userResponse.statusText,
        error: userErrorData,
        url: XIVAUTH_USER_URL,
      });

      return c.json<AuthResponse>(
        {
          success: false,
          error: 'Failed to fetch user information',
        },
        401
      );
    }

    const xivauthUser: XIVAuthUser = await userResponse.json();

    // Log user info structure for debugging
    console.log('XIVAuth user info received:', {
      id: xivauthUser.id,
      has_social_identities: !!xivauthUser.social_identities?.length,
      social_identities_count: xivauthUser.social_identities?.length || 0,
      mfa_enabled: xivauthUser.mfa_enabled,
      verified_characters: xivauthUser.verified_characters,
      raw_keys: Object.keys(xivauthUser),
    });

    // Fetch characters separately (user endpoint doesn't include them)
    let characters: XIVAuthCharacterRegistration[] = [];
    try {
      const charactersResponse = await fetch(XIVAUTH_CHARACTERS_URL, {
        headers: {
          Authorization: `Bearer ${tokens.access_token}`,
          Accept: 'application/json',
        },
      });

      if (charactersResponse.ok) {
        characters = await charactersResponse.json();
        console.log('XIVAuth characters fetched:', {
          count: characters.length,
          verified_count: characters.filter((c) => c.verified).length,
        });
      } else {
        console.warn('Failed to fetch XIVAuth characters:', {
          status: charactersResponse.status,
          statusText: charactersResponse.statusText,
        });
      }
    } catch (charErr) {
      console.warn('Error fetching XIVAuth characters:', charErr);
      // Continue without characters - not a fatal error
    }

    // Extract linked Discord ID from social_identities array (from user:social scope)
    const discordIdentity = xivauthUser.social_identities?.find(
      (identity) => identity.provider === 'discord'
    );
    const linkedDiscordId = discordIdentity?.external_id || null;

    // Get primary character (prefer verified, fall back to first)
    const primaryCharacter =
      characters.find((ch) => ch.verified) || characters[0] || null;

    // Determine username: use primary character name, or XIVAuth ID as fallback
    const username = primaryCharacter?.name || `XIVAuth User ${xivauthUser.id.slice(0, 8)}`;

    console.log('Creating/updating user:', {
      xivauth_id: xivauthUser.id,
      discord_id: linkedDiscordId,
      username,
      primary_character: primaryCharacter?.name,
    });

    // Find or create user in database, handling potential merge
    const user = await findOrCreateUser(c.env.DB, {
      xivauth_id: xivauthUser.id,
      discord_id: linkedDiscordId,
      username,
      avatar_url: null, // XIVAuth user endpoint doesn't provide avatar_url
      auth_provider: 'xivauth',
    });

    // Store characters if present (for future features)
    if (characters.length > 0) {
      // Convert XIVAuthCharacterRegistration to the format expected by storeCharacters
      const characterData = characters.map((ch) => ({
        id: ch.lodestone_id,
        name: ch.name,
        home_world: ch.home_world, // XIVAuth uses home_world
        verified: ch.verified,
      }));
      await storeCharacters(c.env.DB, user.id, characterData);
    }

    // Create JWT with user info
    const { token, expires_at } = await createJWTForUser(user, c.env, {
      auth_provider: 'xivauth',
      primary_character: primaryCharacter
        ? {
            name: primaryCharacter.name,
            server: primaryCharacter.home_world, // XIVAuth uses home_world
            verified: primaryCharacter.verified,
          }
        : undefined,
    });

    return c.json<AuthResponse>({
      success: true,
      token,
      user: {
        id: user.id,
        username: user.username,
        global_name: primaryCharacter?.name || null, // Use character name as global_name
        avatar: null,
        avatar_url: null, // XIVAuth doesn't provide avatar URL
        auth_provider: 'xivauth',
        primary_character: primaryCharacter
          ? {
              name: primaryCharacter.name,
              server: primaryCharacter.home_world,
              verified: primaryCharacter.verified,
            }
          : undefined,
      },
      expires_at,
    });
  } catch (err) {
    if (c.env.ENVIRONMENT === 'development') {
      console.error('XIVAuth callback error:', err);
    } else {
      const error = err as Error;
      console.error('XIVAuth callback error:', { name: error.name, message: error.message });
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
