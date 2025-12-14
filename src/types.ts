/**
 * Type definitions for OAuth Worker
 */

/**
 * Authentication provider type
 */
export type AuthProvider = 'discord' | 'xivauth';

/**
 * Cloudflare Worker environment bindings
 */
export interface Env {
  // Environment variables
  ENVIRONMENT: string;
  DISCORD_CLIENT_ID: string;
  XIVAUTH_CLIENT_ID: string;
  FRONTEND_URL: string;
  WORKER_URL: string;
  JWT_EXPIRY: string;

  // Secrets
  DISCORD_CLIENT_SECRET: string;
  XIVAUTH_CLIENT_SECRET?: string; // Optional - only needed for confidential client mode
  JWT_SECRET: string;

  // KV Namespaces (optional for backward compatibility)
  TOKEN_BLACKLIST?: KVNamespace;

  // D1 Database for user management
  DB: D1Database;
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
 * XIVAuth OAuth token response
 */
export interface XIVAuthTokenResponse {
  access_token: string;
  token_type: string;
  expires_in: number;
  refresh_token: string;
  scope: string;
}

/**
 * XIVAuth character object from /api/v1/characters
 */
export interface XIVAuthCharacter {
  id: number; // Lodestone ID
  name: string;
  home_world: string; // XIVAuth uses home_world, not server
  verified: boolean;
}

/**
 * XIVAuth character registration from /api/v1/characters (full response)
 */
export interface XIVAuthCharacterRegistration {
  lodestone_id: number;
  name: string;
  home_world: string;
  data_center: string;
  verified: boolean;
}

/**
 * XIVAuth social identity from /api/v1/user
 */
export interface XIVAuthSocialIdentity {
  provider: string; // e.g., 'discord'
  external_id: string; // e.g., Discord snowflake
  name: string | null;
  nickname: string | null;
  created_at: string;
  updated_at: string;
}

/**
 * XIVAuth user object from /api/v1/user
 * NOTE: This is the ACTUAL response structure from XIVAuth
 */
export interface XIVAuthUser {
  id: string; // XIVAuth UUID
  // NOTE: XIVAuth does NOT return username or avatar_url in user endpoint
  social_identities?: XIVAuthSocialIdentity[]; // Array of linked accounts (Discord, etc.)
  mfa_enabled: boolean;
  verified_characters: boolean; // Boolean indicating if user has any verified characters
  created_at: string;
  updated_at: string;
}

/**
 * Database user row
 */
export interface UserRow {
  id: string; // Our internal UUID
  discord_id: string | null;
  xivauth_id: string | null;
  auth_provider: string;
  username: string;
  avatar_url: string | null;
  created_at: string;
  updated_at: string;
}

/**
 * Primary character info (included in JWT for XIVAuth users)
 */
export interface PrimaryCharacter {
  name: string;
  server: string;
  verified: boolean;
}

/**
 * JWT payload structure
 */
export interface JWTPayload {
  // Standard claims
  sub: string; // Internal user ID (changed from Discord ID)
  iat: number; // Issued at timestamp
  exp: number; // Expiration timestamp
  iss: string; // Issuer (worker URL)
  jti?: string; // JWT ID for revocation (optional for backward compat)

  // Custom claims
  username: string;
  global_name: string | null;
  avatar: string | null;

  // Multi-provider support
  auth_provider: AuthProvider;
  discord_id?: string; // Discord snowflake (if available)
  xivauth_id?: string; // XIVAuth UUID (if available)

  // XIVAuth-specific (optional)
  primary_character?: PrimaryCharacter;
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
    auth_provider?: AuthProvider;
    primary_character?: PrimaryCharacter;
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
