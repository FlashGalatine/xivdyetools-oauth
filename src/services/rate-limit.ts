/**
 * Rate Limiting Service for OAuth Endpoints
 *
 * Implements IP-based sliding window rate limiting to protect auth endpoints
 * from abuse (brute force attacks, credential stuffing, etc.)
 *
 * REFACTOR-002: Now uses @xivdyetools/rate-limiter shared package
 *
 * Limits:
 * - /auth/discord: 10 req/min per IP (initiate login)
 * - /auth/callback: 20 req/min per IP (token exchange)
 * - /auth/refresh: 30 req/min per IP (token refresh)
 */

import {
  MemoryRateLimiter,
  getClientIp as sharedGetClientIp,
  OAUTH_LIMITS,
  type RateLimitConfig as SharedConfig,
} from '@xivdyetools/rate-limiter';

/**
 * Rate limit check result
 */
export interface RateLimitResult {
  allowed: boolean;
  remaining: number;
  resetAt: Date;
  limit: number;
}

/**
 * Singleton rate limiter instance
 */
const limiter = new MemoryRateLimiter({
  maxEntries: 10_000, // Match previous MAX_ENTRIES
  cleanupIntervalRequests: 100, // Match previous CLEANUP_INTERVAL
});

/**
 * Get client IP from request headers
 */
export function getClientIp(request: Request): string {
  return sharedGetClientIp(request);
}

/**
 * Get rate limit config for a given path
 */
function getConfigForPath(path: string): SharedConfig {
  // Use preset configs from shared package
  if (path.startsWith('/auth/discord') || path.startsWith('/auth/xivauth')) {
    return OAUTH_LIMITS['/auth/discord'];
  }
  if (path.startsWith('/auth/callback') || path.startsWith('/auth/xivauth/callback')) {
    return OAUTH_LIMITS['/auth/callback'];
  }
  if (path.startsWith('/auth/refresh')) {
    return OAUTH_LIMITS['/auth/refresh'];
  }
  return OAUTH_LIMITS.default;
}

/**
 * Check if a request is within rate limits
 *
 * @param ip - Client IP address
 * @param path - Request path (e.g., "/auth/discord")
 * @returns Rate limit result
 */
export async function checkRateLimit(ip: string, path: string): Promise<RateLimitResult> {
  const config = getConfigForPath(path);
  // Use compound key for path-specific rate limiting
  const key = `${ip}:${path}`;

  const result = await limiter.check(key, config);

  return {
    allowed: result.allowed,
    remaining: result.remaining,
    resetAt: result.resetAt,
    limit: result.limit,
  };
}

/**
 * Reset the rate limiter (for testing purposes)
 */
export async function resetRateLimiter(): Promise<void> {
  await limiter.resetAll();
}
