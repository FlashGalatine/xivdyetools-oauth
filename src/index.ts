/**
 * XIV Dye Tools OAuth Worker
 * Handles Discord OAuth flow and JWT issuance for web app authentication
 */

import { Hono } from 'hono';
import { cors } from 'hono/cors';
import type { ExtendedLogger } from '@xivdyetools/logger';
import type { Env } from './types.js';
import { authorizeRouter } from './handlers/authorize.js';
import { callbackRouter } from './handlers/callback.js';
import { tokenRouter } from './handlers/refresh.js';
import { xivauthRouter } from './handlers/xivauth.js';
import { checkRateLimit, getClientIp } from './services/rate-limit.js';
import { checkRateLimitDO } from './services/rate-limit-do.js';
import { validateEnv, logValidationErrors } from './utils/env-validation.js';
import { requestIdMiddleware, getRequestId, type RequestIdVariables } from './middleware/request-id.js';
import { loggerMiddleware, getLogger } from './middleware/logger.js';

// Define context variables type
type Variables = RequestIdVariables & {
  logger: ExtendedLogger;
};

const app = new Hono<{ Bindings: Env; Variables: Variables }>();

// Track if we've validated env in this isolate
let envValidated = false;

// ============================================
// MIDDLEWARE
// ============================================

// Request ID middleware (must be early for tracing)
app.use('*', requestIdMiddleware);

// Structured request logger (after request ID for correlation)
app.use('*', loggerMiddleware);

// Environment validation middleware
// Validates required env vars once per isolate and caches result
app.use('*', async (c, next) => {
  if (!envValidated) {
    const result = validateEnv(c.env);
    envValidated = true;
    if (!result.valid) {
      logValidationErrors(result.errors);
      // In production, fail fast on misconfiguration
      if (c.env.ENVIRONMENT === 'production') {
        return c.json({ error: 'Service misconfigured' }, 500);
      }
      // In development, log warnings but continue
      const logger = getLogger(c);
      if (logger) {
        logger.warn('Continuing with invalid env configuration (development mode)');
      }
    }
  }
  await next();
});

// CORS configuration
// SECURITY: Allow specific origins plus whitelisted localhost ports for development
// OAUTH-SEC-001: Restrict localhost to specific ports to prevent malicious localhost apps
const ALLOWED_LOCALHOST_PORTS = ['3000', '5173', '8787'];

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

      // SECURITY: Only allow localhost in development environment
      // Prevents malicious localhost apps from accessing OAuth in production
      if (c.env.ENVIRONMENT === 'development') {
        try {
          const url = new URL(origin);
          if (url.hostname === 'localhost' || url.hostname === '127.0.0.1') {
            // Must have a port and it must be in our whitelist
            if (url.port && ALLOWED_LOCALHOST_PORTS.includes(url.port)) {
              return origin;
            }
          }
        } catch {
          // Invalid URL - not allowed
        }
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

// Security headers middleware
// Applies to all responses (after handler execution)
app.use('*', async (c, next) => {
  await next();
  // Prevent MIME-type sniffing attacks
  c.header('X-Content-Type-Options', 'nosniff');
  // Prevent clickjacking by denying iframe embedding
  c.header('X-Frame-Options', 'DENY');
  // Enforce HTTPS for 1 year (only in production)
  if (c.env.ENVIRONMENT === 'production') {
    c.header('Strict-Transport-Security', 'max-age=31536000; includeSubDomains');
  }
});

// Rate limiting middleware for auth endpoints
// Protects against brute force and credential stuffing attacks
// Supports both in-memory (legacy) and Durable Objects (persistent) rate limiting
app.use('/auth/*', async (c, next) => {
  const clientIp = getClientIp(c.req.raw);
  const path = new URL(c.req.url).pathname;

  // Feature flag: use DO or in-memory rate limiting
  const useDO = c.env.USE_DO_RATE_LIMITING === 'true' && c.env.RATE_LIMITER;

  let result;
  if (useDO) {
    // Use Durable Objects rate limiting (persistent, distributed)
    result = await checkRateLimitDO(clientIp, path, c.env.RATE_LIMITER!);
  } else {
    // Use in-memory rate limiting (legacy, per-isolate)
    result = await checkRateLimit(clientIp, path);
  }

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

// ============================================
// AUTH ROUTES
// All routes are mounted at /auth prefix
//
// Route Structure:
// ┌──────────────────────────────────────────┐
// │ Discord OAuth                            │
// │  /auth/discord      - Initiate login     │
// │  /auth/callback     - Discord callback   │
// ├──────────────────────────────────────────┤
// │ XIVAuth OAuth                            │
// │  /auth/xivauth      - Initiate login     │
// │  /auth/xivauth/cb   - XIVAuth callback   │
// ├──────────────────────────────────────────┤
// │ Token Management                         │
// │  /auth/refresh      - Refresh JWT token  │
// │  /auth/revoke       - Revoke session     │
// └──────────────────────────────────────────┘
// ============================================

app.route('/auth', authorizeRouter);  // Discord: /auth/discord
app.route('/auth', callbackRouter);   // Discord: /auth/callback
app.route('/auth', xivauthRouter);    // XIVAuth: /auth/xivauth, /auth/xivauth/cb
app.route('/auth', tokenRouter);      // Tokens: /auth/refresh, /auth/revoke

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
  const requestId = getRequestId(c);
  const logger = getLogger(c);
  const isDev = c.env.ENVIRONMENT === 'development';

  // Use structured logger if available
  if (logger) {
    logger.error('Unhandled error', err, { operation: 'globalErrorHandler' });
  } else {
    // Fallback to console if logger not available
    const logMessage = isDev ? err : { name: err.name, message: err.message };
    console.error(`[${requestId}] Unhandled error:`, logMessage);
  }

  return c.json(
    {
      error: 'Internal Server Error',
      message: isDev ? err.message : 'An error occurred',
      requestId,
    },
    500
  );
});

export default app;
