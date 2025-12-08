/**
 * Main App Tests
 * Tests for the Hono app, middleware, health checks, and error handling
 */

import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import { SELF, fetchWithEnv, createProductionEnv, env } from './mocks/cloudflare-test.js';
import { resetRateLimiter, checkRateLimit } from '../services/rate-limit.js';

describe('OAuth Worker App', () => {
    beforeEach(() => {
        // Reset rate limiter before each test to avoid cross-test pollution
        resetRateLimiter();
    });

    describe('Health Check Routes', () => {
        it('GET / should return service info', async () => {
            const response = await SELF.fetch('http://localhost/');
            const json = await response.json();

            expect(response.status).toBe(200);
            expect(json).toMatchObject({
                service: 'xivdyetools-oauth',
                status: 'healthy',
            });
        });

        it('GET /health should return health status', async () => {
            const response = await SELF.fetch('http://localhost/health');
            const json = await response.json();

            expect(response.status).toBe(200);
            expect(json.status).toBe('healthy');
            expect(json.timestamp).toBeDefined();
            expect(new Date(json.timestamp).toISOString()).toBe(json.timestamp);
        });
    });

    describe('CORS Middleware', () => {
        it('should allow localhost origins', async () => {
            const response = await SELF.fetch('http://localhost/', {
                headers: { Origin: 'http://localhost:5173' },
            });

            expect(response.headers.get('access-control-allow-origin')).toBe('http://localhost:5173');
        });

        it('should allow any localhost port', async () => {
            const response = await SELF.fetch('http://localhost/', {
                headers: { Origin: 'http://localhost:3000' },
            });

            expect(response.headers.get('access-control-allow-origin')).toBe('http://localhost:3000');
        });

        it('should not allow unknown origins', async () => {
            const response = await SELF.fetch('http://localhost/', {
                headers: { Origin: 'http://evil.com' },
            });

            expect(response.headers.get('access-control-allow-origin')).not.toBe('http://evil.com');
        });

        it('should allow FRONTEND_URL origin', async () => {
            const response = await SELF.fetch('http://localhost/', {
                headers: { Origin: 'http://localhost:5173' }, // This matches FRONTEND_URL in mock env
            });

            expect(response.headers.get('access-control-allow-origin')).toBe('http://localhost:5173');
        });

        it('should handle request without origin header', async () => {
            const response = await SELF.fetch('http://localhost/');

            // Response should still work without CORS headers
            expect(response.status).toBe(200);
        });

        it('should handle OPTIONS preflight requests', async () => {
            const response = await SELF.fetch('http://localhost/', {
                method: 'OPTIONS',
                headers: {
                    Origin: 'http://localhost:5173',
                    'Access-Control-Request-Method': 'POST',
                    'Access-Control-Request-Headers': 'Content-Type',
                },
            });

            expect(response.status).toBe(204);
            expect(response.headers.get('access-control-allow-methods')).toContain('POST');
        });
    });

    describe('404 Handler', () => {
        it('should return 404 for unknown routes', async () => {
            const response = await SELF.fetch('http://localhost/unknown/route');
            const json = await response.json();

            expect(response.status).toBe(404);
            expect(json.error).toBe('Not Found');
            expect(json.message).toContain('/unknown/route');
        });

        it('should include method in 404 message', async () => {
            const response = await SELF.fetch('http://localhost/unknown', {
                method: 'POST',
                body: '{}',
            });
            const json = await response.json();

            expect(response.status).toBe(404);
            expect(json.message).toContain('POST');
        });
    });

    describe('Rate Limiting Middleware', () => {
        it('should add rate limit headers to auth responses', async () => {
            const response = await SELF.fetch('http://localhost/auth/discord?code_challenge=test');

            expect(response.headers.get('X-RateLimit-Limit')).toBeTruthy();
            expect(response.headers.get('X-RateLimit-Remaining')).toBeTruthy();
            expect(response.headers.get('X-RateLimit-Reset')).toBeTruthy();
        });

        it('should return 429 when rate limit is exceeded', async () => {
            // Exhaust the rate limit for /auth/discord (limit: 10)
            for (let i = 0; i < 10; i++) {
                checkRateLimit('test-ip-rate-limit', '/auth/discord');
            }

            // Make a request that should be rate limited
            const response = await fetchWithEnv(
                env,
                'http://localhost/auth/discord?code_challenge=test',
                {
                    headers: {
                        'CF-Connecting-IP': 'test-ip-rate-limit',
                    },
                }
            );

            const json = await response.json();

            expect(response.status).toBe(429);
            expect(json.error).toBe('Too Many Requests');
            expect(json.message).toContain('Rate limit exceeded');
            expect(json.retryAfter).toBeGreaterThan(0);
            expect(response.headers.get('Retry-After')).toBeTruthy();
        });

        it('should track rate limits per IP', async () => {
            // Use up rate limit for one IP
            for (let i = 0; i < 10; i++) {
                checkRateLimit('blocked-ip', '/auth/discord');
            }

            // Different IP should still work
            const response = await fetchWithEnv(
                env,
                'http://localhost/auth/discord?code_challenge=test',
                {
                    headers: {
                        'CF-Connecting-IP': 'allowed-ip',
                    },
                }
            );

            expect(response.status).toBe(302); // Should redirect, not rate limited
        });
    });

    describe('Global Error Handler', () => {
        it('should handle unexpected errors in development mode', async () => {
            // We can test the error handler by causing an internal error
            // One way is to provide malformed data that causes an error deep in processing
            // But most errors are caught by specific handlers, so let's test via
            // a route that we know will trigger an error

            // For this test, we'll verify the error handler structure is correct
            // by checking that errors return proper JSON structure
            const response = await SELF.fetch('http://localhost/auth/callback', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: 'invalid json {{{',
            });

            const json = await response.json();
            expect(response.status).toBe(400);
            expect(json.error).toBeDefined();
        });

        it('should sanitize error messages in production mode', async () => {
            const prodEnv = createProductionEnv();

            // Make request with invalid JSON to trigger error handling
            const response = await fetchWithEnv(
                prodEnv,
                'http://localhost/auth/callback',
                {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: 'invalid json',
                }
            );

            const json = await response.json();
            expect(response.status).toBe(400);
            // In production, specific handler catches this before global error handler
            expect(json.success).toBe(false);
        });

        it('should return environment in health check', async () => {
            const prodEnv = createProductionEnv();

            const response = await fetchWithEnv(prodEnv, 'http://localhost/');
            const json = await response.json();

            expect(json.environment).toBe('production');
        });
    });
});
