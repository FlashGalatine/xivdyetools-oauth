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

const app = new Hono<{ Bindings: Env }>();

// ============================================
// MIDDLEWARE
// ============================================

// Request logging
app.use('*', logger());

// CORS configuration
// SECURITY: Only allow specific origins - no wildcards for localhost
app.use(
  '*',
  cors({
    origin: (origin, c) => {
      // Allow requests from frontend URLs
      // Only specific development ports are allowed (no wildcards)
      const allowedOrigins = [
        c.env.FRONTEND_URL,
        'http://localhost:5173', // Vite dev server
        'http://localhost:4173', // Vite preview
        'http://127.0.0.1:5173',
        'http://127.0.0.1:4173',
      ];

      if (allowedOrigins.includes(origin || '')) {
        return origin || '';
      }

      // No origin header (e.g., curl, Postman) - don't allow for security
      return '';
    },
    allowMethods: ['GET', 'POST', 'OPTIONS'],
    allowHeaders: ['Content-Type', 'Authorization'],
    exposeHeaders: [],
    maxAge: 86400, // 24 hours
    credentials: true,
  })
);

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
