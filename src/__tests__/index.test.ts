/**
 * Main App Tests
 * Tests for the Hono app, middleware, health checks, and error handling
 */

import { describe, it, expect } from 'vitest';
import { SELF } from './mocks/cloudflare-test.js';

describe('OAuth Worker App', () => {
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
});
