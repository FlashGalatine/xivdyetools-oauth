/**
 * Request Logger Middleware
 *
 * Creates a per-request structured logger using @xivdyetools/logger.
 * The logger is request-scoped with correlation ID for distributed tracing.
 *
 * This middleware should be used after requestIdMiddleware to ensure
 * the request ID is available.
 */

import type { Context, Next } from 'hono';
import type { ExtendedLogger } from '@xivdyetools/logger';
import { createRequestLogger } from '@xivdyetools/logger/worker';
import type { Env } from '../types.js';

/**
 * Variables type for Hono context with logger
 */
export type LoggerVariables = {
  requestId: string;
  logger: ExtendedLogger;
};

/**
 * Request logger middleware function.
 * Add this after requestIdMiddleware in the middleware chain.
 *
 * @example
 * ```typescript
 * // In your Hono app setup
 * app.use('*', requestIdMiddleware);
 * app.use('*', loggerMiddleware);
 *
 * // In a handler
 * app.get('/auth/example', (c) => {
 *   const logger = c.get('logger');
 *   logger.info('Processing request', { path: c.req.path });
 *   // ...
 * });
 * ```
 */
export async function loggerMiddleware(
  c: Context<{ Bindings: Env; Variables: LoggerVariables }>,
  next: Next
): Promise<void | Response> {
  const requestId = c.get('requestId');
  const logger = createRequestLogger(
    {
      ENVIRONMENT: c.env.ENVIRONMENT,
      SERVICE_NAME: 'xivdyetools-oauth',
    },
    requestId
  );

  // Store logger in context
  c.set('logger', logger);

  // Log request start
  const startTime = performance.now();
  const { method, path } = getRequestInfo(c);

  logger.info('Request started', {
    method,
    path,
    userAgent: c.req.header('user-agent'),
  });

  await next();

  // Log request completion
  const duration = performance.now() - startTime;
  const status = c.res.status;

  logger.info('Request completed', {
    method,
    path,
    status,
    durationMs: Math.round(duration * 100) / 100,
  });
}

/**
 * Helper to get logger from context with fallback.
 * Useful in error handlers where the middleware may not have run.
 */
// eslint-disable-next-line @typescript-eslint/no-explicit-any
export function getLogger(c: Context<any>): ExtendedLogger | undefined {
  try {
    return c.get('logger');
  } catch {
    return undefined;
  }
}

/**
 * Extract request info for logging
 */
function getRequestInfo(c: Context): { method: string; path: string } {
  return {
    method: c.req.method,
    path: new URL(c.req.url).pathname,
  };
}
