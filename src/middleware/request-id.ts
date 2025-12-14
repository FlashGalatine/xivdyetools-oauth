/**
 * Request ID Middleware
 *
 * Generates or preserves a unique request ID for each request.
 * This enables distributed tracing across service boundaries.
 *
 * - Preserves incoming X-Request-ID header if present
 * - Generates a new UUID v4 if not
 * - Stores in Hono context for use in logging
 * - Adds to response headers for client visibility
 */

import type { Context, Next } from 'hono';
import type { Env } from '../types.js';

/**
 * Variables type for Hono context
 */
export type RequestIdVariables = {
  requestId: string;
};

/**
 * Request ID middleware function.
 * Add this early in the middleware chain (after logger, before business logic).
 */
export async function requestIdMiddleware(
  c: Context<{ Bindings: Env; Variables: RequestIdVariables }>,
  next: Next
): Promise<void | Response> {
  // Get existing request ID from header or generate new one
  const requestId = c.req.header('X-Request-ID') || crypto.randomUUID();

  // Store in context for use in handlers and error logging
  c.set('requestId', requestId);

  await next();

  // Add to response headers so clients can see it
  c.header('X-Request-ID', requestId);
}

/**
 * Helper to get request ID from context with fallback.
 * Useful in error handlers where the middleware may not have run.
 */
// eslint-disable-next-line @typescript-eslint/no-explicit-any
export function getRequestId(c: Context<any>): string {
  try {
    return c.get('requestId') || 'unknown';
  } catch {
    return 'unknown';
  }
}
