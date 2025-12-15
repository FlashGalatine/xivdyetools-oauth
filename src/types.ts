/**
 * Type definitions for OAuth Worker
 *
 * Re-exports shared types from @xivdyetools/types and defines
 * project-specific types for the OAuth worker.
 */

// ============================================
// RE-EXPORT SHARED TYPES
// ============================================

/**
 * @deprecated Import directly from '@xivdyetools/types' instead.
 * These re-exports will be removed in the next major version.
 */
export type { AuthProvider } from '@xivdyetools/types';

/**
 * @deprecated Import directly from '@xivdyetools/types' instead.
 * These re-exports will be removed in the next major version.
 */
export type { PrimaryCharacter, JWTPayload, OAuthState } from '@xivdyetools/types';

/**
 * @deprecated Import directly from '@xivdyetools/types' instead.
 * These re-exports will be removed in the next major version.
 */
export type { DiscordTokenResponse, DiscordUser } from '@xivdyetools/types';

/**
 * @deprecated Import directly from '@xivdyetools/types' instead.
 * These re-exports will be removed in the next major version.
 */
export type {
  XIVAuthTokenResponse,
  XIVAuthCharacter,
  XIVAuthCharacterRegistration,
  XIVAuthSocialIdentity,
  XIVAuthUser,
} from '@xivdyetools/types';

/**
 * @deprecated Import directly from '@xivdyetools/types' instead.
 * These re-exports will be removed in the next major version.
 */
export type { AuthResponse, RefreshResponse, UserInfoResponse } from '@xivdyetools/types';

// ============================================
// CLOUDFLARE BINDINGS (Project-specific)
// ============================================

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

// ============================================
// DATABASE ROW TYPES (Project-specific)
// ============================================

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
