/**
 * Durable Objects Rate Limiter Service
 * Wrapper around RateLimiter DO for easy migration from in-memory
 *
 * This service provides the same interface as the in-memory rate limiter
 * but uses Durable Objects for persistence across worker restarts and
 * consistency across edge locations.
 */

import type { RateLimitConfig } from '../durable-objects/rate-limiter.js';

/**
 * Rate limit check result
 * Matches the interface from services/rate-limit.ts for easy migration
 */
export interface RateLimitResult {
  allowed: boolean;
  remaining: number;
  resetAt: Date;
  limit: number;
}

/**
 * Rate limit configuration per endpoint
 * Same configs as in-memory implementation
 */
const RATE_LIMITS: Record<string, RateLimitConfig> = {
  // Login initiation - stricter limit (10 per minute)
  '/auth/discord': { maxRequests: 10, windowMs: 60_000 },
  '/auth/xivauth': { maxRequests: 10, windowMs: 60_000 },
  // Token exchange - moderate limit (20 per minute)
  '/auth/callback': { maxRequests: 20, windowMs: 60_000 },
  '/auth/xivauth/callback': { maxRequests: 20, windowMs: 60_000 },
  // Token refresh - more lenient (30 per minute)
  '/auth/refresh': { maxRequests: 30, windowMs: 60_000 },
  // Default for other auth endpoints
  default: { maxRequests: 30, windowMs: 60_000 },
};

/**
 * Get rate limit configuration for a path
 */
function getConfigForPath(path: string): RateLimitConfig {
  // Match the most specific path
  for (const [key, config] of Object.entries(RATE_LIMITS)) {
    if (key !== 'default' && path.startsWith(key)) {
      return config;
    }
  }
  return RATE_LIMITS.default;
}

/**
 * Check rate limit using Durable Objects
 *
 * @param ip - Client IP address
 * @param path - Request path (e.g., "/auth/discord")
 * @param rateLimiterNamespace - Durable Object namespace binding
 * @returns Rate limit result
 */
export async function checkRateLimitDO(
  ip: string,
  path: string,
  rateLimiterNamespace: DurableObjectNamespace
): Promise<RateLimitResult> {
  // Get config for this path
  const config = getConfigForPath(path);

  try {
    // Get DO instance for this IP
    // Using idFromName ensures the same IP always gets the same DO instance
    const id = rateLimiterNamespace.idFromName(ip);
    const stub = rateLimiterNamespace.get(id);

    // Call DO to check rate limit
    const response = await stub.fetch('https://rate-limiter/check', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ endpoint: path, config }),
    });

    if (!response.ok) {
      // DO error - fail open for availability
      console.error('Rate limiter DO error:', {
        status: response.status,
        statusText: response.statusText,
      });
      return {
        allowed: true, // Fail-open: allow request if DO fails
        remaining: config.maxRequests,
        resetAt: new Date(Date.now() + config.windowMs),
        limit: config.maxRequests,
      };
    }

    const result = await response.json<RateLimitResult>();

    // Convert resetAt string back to Date object
    return {
      ...result,
      resetAt: new Date(result.resetAt),
    };
  } catch (err) {
    // DO communication error - fail open for availability
    console.error('Rate limiter DO communication error:', err);
    return {
      allowed: true, // Fail-open: allow request on error
      remaining: config.maxRequests,
      resetAt: new Date(Date.now() + config.windowMs),
      limit: config.maxRequests,
    };
  }
}
