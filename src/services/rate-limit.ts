/**
 * Rate Limiting Service for OAuth Endpoints
 *
 * Implements IP-based sliding window rate limiting to protect auth endpoints
 * from abuse (brute force attacks, credential stuffing, etc.)
 *
 * Limits:
 * - /auth/discord: 10 req/min per IP (initiate login)
 * - /auth/callback: 20 req/min per IP (token exchange)
 * - /auth/refresh: 30 req/min per IP (token refresh)
 */

/**
 * Rate limit configuration per endpoint
 */
interface RateLimitConfig {
  maxRequests: number;
  windowMs: number;
}

const RATE_LIMITS: Record<string, RateLimitConfig> = {
  // Login initiation - stricter limit (10 per minute)
  '/auth/discord': { maxRequests: 10, windowMs: 60_000 },
  // Token exchange - moderate limit (20 per minute)
  '/auth/callback': { maxRequests: 20, windowMs: 60_000 },
  // Token refresh - more lenient (30 per minute)
  '/auth/refresh': { maxRequests: 30, windowMs: 60_000 },
  // Default for other auth endpoints
  default: { maxRequests: 30, windowMs: 60_000 },
};

/**
 * In-memory store for rate limiting
 * Maps "ip:endpoint" -> array of request timestamps
 */
const requestLog = new Map<string, number[]>();

/**
 * Maximum number of unique keys to track before forced cleanup
 */
const MAX_ENTRIES = 10000;

/**
 * Request counter for deterministic cleanup
 */
let requestCount = 0;

/**
 * Interval for deterministic cleanup (every N requests)
 */
const CLEANUP_INTERVAL = 100;

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
 * Get client IP from request headers
 */
export function getClientIp(request: Request): string {
  return (
    request.headers.get('CF-Connecting-IP') ||
    request.headers.get('X-Forwarded-For')?.split(',')[0]?.trim() ||
    'unknown'
  );
}

/**
 * Get rate limit config for a given path
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
 * Check if a request is within rate limits
 *
 * @param ip - Client IP address
 * @param path - Request path (e.g., "/auth/discord")
 * @returns Rate limit result
 */
export function checkRateLimit(ip: string, path: string): RateLimitResult {
  const config = getConfigForPath(path);
  const key = `${ip}:${path}`;
  const now = Date.now();
  const windowStart = now - config.windowMs;

  // Get existing timestamps for this key
  const timestamps = requestLog.get(key) || [];

  // Filter to only include requests within the current window
  const recentTimestamps = timestamps.filter((ts) => ts > windowStart);

  // Check if within limit
  const allowed = recentTimestamps.length < config.maxRequests;
  const remaining = Math.max(0, config.maxRequests - recentTimestamps.length);

  // Calculate reset time
  const oldestInWindow = recentTimestamps[0];
  const resetAt = oldestInWindow ? new Date(oldestInWindow + config.windowMs) : new Date(now + config.windowMs);

  // Record this request if allowed
  if (allowed) {
    recentTimestamps.push(now);
    requestLog.set(key, recentTimestamps);
  }

  // Deterministic cleanup: every CLEANUP_INTERVAL requests
  requestCount++;
  if (requestCount % CLEANUP_INTERVAL === 0) {
    cleanupOldEntries();
  }

  // Emergency cleanup if map grows too large
  if (requestLog.size > MAX_ENTRIES) {
    cleanupOldEntries();
    // If still too large after cleanup, remove oldest entries
    if (requestLog.size > MAX_ENTRIES) {
      pruneOldestEntries();
    }
  }

  return { allowed, remaining, resetAt, limit: config.maxRequests };
}

/**
 * Clean up old entries to prevent memory leaks
 */
function cleanupOldEntries(): void {
  const maxAge = 120_000; // 2 minutes
  const cutoff = Date.now() - maxAge;

  requestLog.forEach((timestamps, key) => {
    const filtered = timestamps.filter((ts) => ts > cutoff);
    if (filtered.length === 0) {
      requestLog.delete(key);
    } else {
      requestLog.set(key, filtered);
    }
  });
}

/**
 * Prune oldest entries when map exceeds MAX_ENTRIES
 * Removes entries with the oldest last-activity timestamp
 */
function pruneOldestEntries(): void {
  // Calculate how many to remove (remove 20% of entries)
  const targetSize = Math.floor(MAX_ENTRIES * 0.8);
  const toRemove = requestLog.size - targetSize;

  if (toRemove <= 0) return;

  // Find entries with oldest last-activity
  const entries: Array<{ key: string; lastActivity: number }> = [];
  requestLog.forEach((timestamps, key) => {
    const lastActivity = timestamps.length > 0 ? Math.max(...timestamps) : 0;
    entries.push({ key, lastActivity });
  });

  // Sort by last activity (oldest first)
  entries.sort((a, b) => a.lastActivity - b.lastActivity);

  // Remove oldest entries
  for (let i = 0; i < toRemove; i++) {
    requestLog.delete(entries[i].key);
  }
}

/**
 * Reset the rate limiter (for testing purposes)
 */
export function resetRateLimiter(): void {
  requestLog.clear();
  requestCount = 0;
}
