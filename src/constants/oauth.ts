/**
 * OAuth Security Constants
 * Shared constants for OAuth flow validation and security
 */

/**
 * Allowed redirect URI origins
 * These origins are permitted as OAuth callback destinations
 */
export const ALLOWED_REDIRECT_ORIGINS = [
  'https://xivdyetools.projectgalatine.com',
  'http://localhost:5173',
  'http://localhost:3000',
  'http://127.0.0.1:5173',
  'http://127.0.0.1:3000',
];

/**
 * State parameter expiration time (seconds)
 * OAuth state tokens expire after this duration
 */
export const STATE_EXPIRY_SECONDS = 600; // 10 minutes

/**
 * Request timeout for external API calls (milliseconds)
 */
export const REQUEST_TIMEOUT_MS = 10000; // 10 seconds

/**
 * User info fetch timeout (milliseconds)
 * Shorter timeout for user info endpoints
 */
export const USER_INFO_TIMEOUT_MS = 5000; // 5 seconds

/**
 * Required OAuth scopes for XIVAuth provider
 * Must be present in token response
 */
export const XIVAUTH_REQUIRED_SCOPES = ['user', 'character'];

/**
 * Required OAuth scopes for Discord provider
 * Must be present in token response
 */
export const DISCORD_REQUIRED_SCOPES = ['identify'];
