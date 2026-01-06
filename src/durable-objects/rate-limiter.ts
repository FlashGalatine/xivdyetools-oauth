/**
 * RateLimiter Durable Object
 * Distributed, persistent rate limiting for OAuth endpoints
 *
 * Each DO instance handles rate limiting for a single IP address
 * Uses sliding window algorithm (same as in-memory implementation)
 *
 * Design:
 * - One DO instance per IP address (using idFromName)
 * - Stores timestamps of requests per endpoint
 * - Automatic cleanup via alarm handler (every 2 minutes)
 * - Persists to Durable Storage for cross-isolate consistency
 */

import type { Env } from '../types.js';

/**
 * Rate limit configuration for an endpoint
 */
export interface RateLimitConfig {
  maxRequests: number;
  windowMs: number;
}

/**
 * Persisted state structure
 */
export interface RateLimitState {
  [endpoint: string]: number[]; // endpoint -> array of request timestamps
}

/**
 * Rate limit check request body
 */
interface RateLimitCheckRequest {
  endpoint: string;
  config: RateLimitConfig;
}

/**
 * Rate limit check response
 */
interface RateLimitCheckResponse {
  allowed: boolean;
  remaining: number;
  resetAt: Date;
  limit: number;
}

/**
 * RateLimiter Durable Object
 * Handles rate limiting for a single IP address
 */
export class RateLimiter {
  private state: DurableObjectState;
  private env: Env;
  private requestLog: Map<string, number[]>;
  private initialized: boolean = false;

  constructor(state: DurableObjectState, env: Env) {
    this.state = state;
    this.env = env;
    this.requestLog = new Map();

    // Block concurrent requests until initialization is complete
    this.state.blockConcurrencyWhile(async () => {
      await this.initialize();
    });
  }

  /**
   * Initialize DO by loading persisted state
   */
  private async initialize(): Promise<void> {
    if (this.initialized) return;

    const stored = await this.state.storage.get<RateLimitState>('requestLog');
    if (stored) {
      this.requestLog = new Map(Object.entries(stored));

      // Clean up old entries on init
      this.cleanupOldEntries();
    }

    // Schedule first alarm for cleanup
    const currentAlarm = await this.state.storage.getAlarm();
    if (currentAlarm === null) {
      // Set alarm for 2 minutes from now
      await this.state.storage.setAlarm(Date.now() + 120_000);
    }

    this.initialized = true;
  }

  /**
   * Handle incoming HTTP requests to this DO
   */
  async fetch(request: Request): Promise<Response> {
    const url = new URL(request.url);

    // POST /check - Check rate limit for an endpoint
    if (request.method === 'POST' && url.pathname === '/check') {
      try {
        const body = await request.json<RateLimitCheckRequest>();
        const { endpoint, config } = body;

        if (!endpoint || !config) {
          return Response.json(
            { error: 'Missing endpoint or config' },
            { status: 400 }
          );
        }

        const result = await this.checkRateLimit(endpoint, config);
        return Response.json(result);
      } catch (err) {
        return Response.json(
          { error: 'Invalid request', message: err instanceof Error ? err.message : 'Unknown error' },
          { status: 400 }
        );
      }
    }

    // POST /reset - Reset rate limits (for testing)
    if (request.method === 'POST' && url.pathname === '/reset') {
      await this.state.storage.deleteAll();
      this.requestLog.clear();
      return Response.json({ success: true });
    }

    // GET /stats - Get current rate limit stats (for debugging)
    if (request.method === 'GET' && url.pathname === '/stats') {
      const stats: Record<string, { count: number; oldestTimestamp: number | null }> = {};
      this.requestLog.forEach((timestamps, endpoint) => {
        stats[endpoint] = {
          count: timestamps.length,
          oldestTimestamp: timestamps.length > 0 ? timestamps[0] : null,
        };
      });
      return Response.json(stats);
    }

    return new Response('Not Found', { status: 404 });
  }

  /**
   * Check rate limit for an endpoint
   *
   * @param endpoint - Endpoint path (e.g., "/auth/discord")
   * @param config - Rate limit configuration
   * @returns Rate limit result
   */
  private async checkRateLimit(
    endpoint: string,
    config: RateLimitConfig
  ): Promise<RateLimitCheckResponse> {
    const now = Date.now();
    const windowStart = now - config.windowMs;

    // Get existing timestamps for this endpoint
    const timestamps = this.requestLog.get(endpoint) || [];

    // Filter to only include requests within the current window
    const recentTimestamps = timestamps.filter((ts) => ts > windowStart);

    // Check if within limit
    const allowed = recentTimestamps.length < config.maxRequests;
    const remaining = Math.max(0, config.maxRequests - recentTimestamps.length);

    // Calculate reset time (when the oldest request in window expires)
    const oldestInWindow = recentTimestamps[0];
    const resetAt = oldestInWindow
      ? new Date(oldestInWindow + config.windowMs)
      : new Date(now + config.windowMs);

    // Record this request if allowed
    if (allowed) {
      recentTimestamps.push(now);
      this.requestLog.set(endpoint, recentTimestamps);

      // Persist to storage asynchronously (don't await to improve performance)
      this.persistState();
    }

    return {
      allowed,
      remaining,
      resetAt,
      limit: config.maxRequests,
    };
  }

  /**
   * Persist current state to durable storage
   * Called asynchronously to avoid blocking the response
   */
  private async persistState(): Promise<void> {
    try {
      const state: RateLimitState = Object.fromEntries(this.requestLog.entries());
      await this.state.storage.put('requestLog', state);
    } catch (err) {
      // Log error but don't throw - we don't want persistence failures to break rate limiting
      console.error('Failed to persist rate limiter state:', err);
    }
  }

  /**
   * Clean up old entries to prevent memory bloat
   * Removes timestamps older than 2 minutes (max window size)
   */
  private cleanupOldEntries(): void {
    const maxAge = 120_000; // 2 minutes - enough for all our rate limit windows
    const cutoff = Date.now() - maxAge;

    this.requestLog.forEach((timestamps, endpoint) => {
      const filtered = timestamps.filter((ts) => ts > cutoff);
      if (filtered.length === 0) {
        // No recent requests - remove endpoint entirely
        this.requestLog.delete(endpoint);
      } else {
        // Update with filtered timestamps
        this.requestLog.set(endpoint, filtered);
      }
    });

    // Persist cleanup results
    this.persistState();
  }

  /**
   * Alarm handler for periodic cleanup
   * Called by the Durable Objects runtime at scheduled times
   */
  async alarm(): Promise<void> {
    // Clean up old entries
    this.cleanupOldEntries();

    // Schedule next cleanup in 2 minutes
    await this.state.storage.setAlarm(Date.now() + 120_000);
  }
}
