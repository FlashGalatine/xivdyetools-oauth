/**
 * Type definitions for OAuth Worker
 */

/**
 * Cloudflare Worker environment bindings
 */
export interface Env {
  // Environment variables
  ENVIRONMENT: string;
  DISCORD_CLIENT_ID: string;
  FRONTEND_URL: string;
  WORKER_URL: string;
  JWT_EXPIRY: string;

  // Secrets
  DISCORD_CLIENT_SECRET: string;
  JWT_SECRET: string;

  // KV Namespaces (optional for backward compatibility)
  TOKEN_BLACKLIST?: KVNamespace;
}

/**
 * Discord OAuth token response
 */
export interface DiscordTokenResponse {
  access_token: string;
  token_type: string;
  expires_in: number;
  refresh_token: string;
  scope: string;
}

/**
 * Discord user object from /users/@me
 */
export interface DiscordUser {
  id: string;
  username: string;
  discriminator: string;
  global_name: string | null;
  avatar: string | null;
  bot?: boolean;
  system?: boolean;
  mfa_enabled?: boolean;
  banner?: string | null;
  accent_color?: number | null;
  locale?: string;
  verified?: boolean;
  email?: string | null;
  flags?: number;
  premium_type?: number;
  public_flags?: number;
}

/**
 * JWT payload structure
 */
export interface JWTPayload {
  // Standard claims
  sub: string; // Discord user ID
  iat: number; // Issued at timestamp
  exp: number; // Expiration timestamp
  iss: string; // Issuer (worker URL)
  jti?: string; // JWT ID for revocation (optional for backward compat)

  // Custom claims
  username: string;
  global_name: string | null;
  avatar: string | null;
}

/**
 * OAuth state stored during flow
 */
export interface OAuthState {
  code_verifier: string;
  redirect_uri: string;
  return_path?: string;
}

/**
 * API response types
 */
export interface AuthResponse {
  success: boolean;
  token?: string;
  user?: {
    id: string;
    username: string;
    global_name: string | null;
    avatar: string | null;
    avatar_url: string | null;
  };
  expires_at?: number;
  error?: string;
}

export interface RefreshResponse {
  success: boolean;
  token?: string;
  expires_at?: number;
  error?: string;
}

export interface UserInfoResponse {
  success: boolean;
  user?: {
    id: string;
    username: string;
    global_name: string | null;
    avatar: string | null;
    avatar_url: string | null;
  };
  error?: string;
}
