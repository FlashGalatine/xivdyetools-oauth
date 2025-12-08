/**
 * XIV Dye Tools OAuth Worker
 * Handles Discord OAuth flow and JWT issuance for web app authentication
 */

import { Hono } from 'hono';
import { cors } from 'hono/cors';
import { logger } from 'hono/logger';
import type { Env } from './types.js';
import { authorizeRouter } from './handlers/authorize.js';
import { callbackRouter } from './handlers/callback.js';
import { tokenRouter } from './handlers/refresh.js';
import { checkRateLimit, getClientIp } from './services/rate-limit.js';

const app = new Hono<{ Bindings: Env }>();

// ============================================
// MIDDLEWARE
// ============================================

// Request logging
app.use('*', logger());

// CORS configuration
// SECURITY: Allow specific origins plus any localhost port for development
app.use(
  '*',
  cors({
    origin: (origin, c) => {
      if (!origin) {
        // No origin header (e.g., curl, Postman) - don't allow for security
        return '';
      }

      // Allow the configured frontend URL
      if (origin === c.env.FRONTEND_URL) {
        return origin;
      }

      // Allow any localhost port for development flexibility
      const localhostPattern = /^http:\/\/(localhost|127\.0\.0\.1)(:\d+)?$/;
      if (localhostPattern.test(origin)) {
        return origin;
      }

      // Not allowed
      return '';
    },
    allowMethods: ['GET', 'POST', 'OPTIONS'],
    allowHeaders: ['Content-Type', 'Authorization'],
    exposeHeaders: ['X-RateLimit-Limit', 'X-RateLimit-Remaining', 'X-RateLimit-Reset', 'Retry-After'],
    maxAge: 86400, // 24 hours
    credentials: true,
  })
);

// Rate limiting middleware for auth endpoints
// Protects against brute force and credential stuffing attacks
app.use('/auth/*', async (c, next) => {
  const clientIp = getClientIp(c.req.raw);
  const path = new URL(c.req.url).pathname;
  const result = checkRateLimit(clientIp, path);

  // Set rate limit headers on all responses
  c.header('X-RateLimit-Limit', result.limit.toString());
  c.header('X-RateLimit-Remaining', result.remaining.toString());
  c.header('X-RateLimit-Reset', Math.floor(result.resetAt.getTime() / 1000).toString());

  if (!result.allowed) {
    const retryAfter = Math.ceil((result.resetAt.getTime() - Date.now()) / 1000);
    c.header('Retry-After', retryAfter.toString());

    return c.json(
      {
        error: 'Too Many Requests',
        message: 'Rate limit exceeded. Please try again later.',
        retryAfter,
      },
      429
    );
  }

  await next();
});

// ============================================
// ROUTES
// ============================================

// Health check
app.get('/', (c) => {
  return c.json({
    service: 'xivdyetools-oauth',
    status: 'healthy',
    environment: c.env.ENVIRONMENT,
  });
});

// Health check endpoint
app.get('/health', (c) => {
  return c.json({
    status: 'healthy',
    timestamp: new Date().toISOString(),
  });
});

// Mount routers
app.route('/auth', authorizeRouter);
app.route('/auth', callbackRouter);
app.route('/auth', tokenRouter);

// ============================================
// ERROR HANDLING
// ============================================

// 404 handler
app.notFound((c) => {
  return c.json(
    {
      error: 'Not Found',
      message: `Route ${c.req.method} ${c.req.path} not found`,
    },
    404
  );
});

// Global error handler
app.onError((err, c) => {
  // Sanitize logs in production - only log error name and message, not full stack
  const isDev = c.env.ENVIRONMENT === 'development';
  const logMessage = isDev ? err : { name: err.name, message: err.message };
  console.error('Unhandled error:', logMessage);

  return c.json(
    {
      error: 'Internal Server Error',
      message: c.env.ENVIRONMENT === 'development' ? err.message : 'An error occurred',
    },
    500
  );
});

export default app;
