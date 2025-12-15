/**
 * Middleware Tests
 * Tests for logger and request-id middleware
 */

import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { Hono } from 'hono';
import { getRequestId, requestIdMiddleware, type RequestIdVariables } from '../middleware/request-id.js';
import { getLogger, loggerMiddleware, type LoggerVariables } from '../middleware/logger.js';
import type { Env } from '../types.js';

describe('Request ID Middleware', () => {
    describe('requestIdMiddleware', () => {
        it('should generate a new request ID when not provided', async () => {
            const app = new Hono<{ Bindings: Env; Variables: RequestIdVariables }>();
            app.use('*', requestIdMiddleware);
            app.get('/', (c) => {
                const requestId = c.get('requestId');
                return c.json({ requestId });
            });

            const response = await app.fetch(new Request('http://localhost/'), {
                ENVIRONMENT: 'development',
            } as Env);

            const json = await response.json() as { requestId: string };
            expect(json.requestId).toBeTruthy();
            expect(json.requestId).toMatch(/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i);
        });

        it('should preserve existing X-Request-ID header', async () => {
            const app = new Hono<{ Bindings: Env; Variables: RequestIdVariables }>();
            app.use('*', requestIdMiddleware);
            app.get('/', (c) => {
                const requestId = c.get('requestId');
                return c.json({ requestId });
            });

            const response = await app.fetch(
                new Request('http://localhost/', {
                    headers: { 'X-Request-ID': 'custom-request-id-123' },
                }),
                { ENVIRONMENT: 'development' } as Env
            );

            const json = await response.json() as { requestId: string };
            expect(json.requestId).toBe('custom-request-id-123');
        });

        it('should add request ID to response headers', async () => {
            const app = new Hono<{ Bindings: Env; Variables: RequestIdVariables }>();
            app.use('*', requestIdMiddleware);
            app.get('/', (c) => c.json({ ok: true }));

            const response = await app.fetch(new Request('http://localhost/'), {
                ENVIRONMENT: 'development',
            } as Env);

            expect(response.headers.get('X-Request-ID')).toBeTruthy();
        });
    });

    describe('getRequestId', () => {
        it('should return request ID from context', async () => {
            const app = new Hono<{ Bindings: Env; Variables: RequestIdVariables }>();
            app.use('*', requestIdMiddleware);
            app.get('/', (c) => {
                const requestId = getRequestId(c);
                return c.json({ requestId });
            });

            const response = await app.fetch(new Request('http://localhost/'), {
                ENVIRONMENT: 'development',
            } as Env);

            const json = await response.json() as { requestId: string };
            expect(json.requestId).toBeTruthy();
        });

        it('should return "unknown" when context has no request ID', () => {
            // Create a mock context without request ID set
            const mockContext = {
                get: () => { throw new Error('No request ID'); },
            };
            // eslint-disable-next-line @typescript-eslint/no-explicit-any
            const result = getRequestId(mockContext as any);
            expect(result).toBe('unknown');
        });

        it('should return "unknown" when c.get() returns undefined', () => {
            const mockContext = {
                get: () => undefined,
            };
            // eslint-disable-next-line @typescript-eslint/no-explicit-any
            const result = getRequestId(mockContext as any);
            expect(result).toBe('unknown');
        });
    });
});

describe('Logger Middleware', () => {
    let consoleSpy: ReturnType<typeof vi.spyOn>;

    beforeEach(() => {
        consoleSpy = vi.spyOn(console, 'log').mockImplementation(() => {});
    });

    afterEach(() => {
        consoleSpy.mockRestore();
    });

    describe('loggerMiddleware', () => {
        it('should create logger and add to context', async () => {
            const app = new Hono<{ Bindings: Env; Variables: LoggerVariables }>();
            app.use('*', requestIdMiddleware);
            app.use('*', loggerMiddleware);
            app.get('/', (c) => {
                const logger = c.get('logger');
                return c.json({ hasLogger: !!logger });
            });

            const response = await app.fetch(
                new Request('http://localhost/'),
                { ENVIRONMENT: 'development', SERVICE_NAME: 'test' } as unknown as Env
            );

            const json = await response.json() as { hasLogger: boolean };
            expect(json.hasLogger).toBe(true);
        });

        it('should log request start and completion', async () => {
            const app = new Hono<{ Bindings: Env; Variables: LoggerVariables }>();
            app.use('*', requestIdMiddleware);
            app.use('*', loggerMiddleware);
            app.get('/test-path', (c) => c.json({ ok: true }));

            await app.fetch(
                new Request('http://localhost/test-path'),
                { ENVIRONMENT: 'development' } as Env
            );

            // Logger outputs structured logs via console
            expect(consoleSpy).toHaveBeenCalled();
        });
    });

    describe('getLogger', () => {
        it('should return logger from context', async () => {
            const app = new Hono<{ Bindings: Env; Variables: LoggerVariables }>();
            app.use('*', requestIdMiddleware);
            app.use('*', loggerMiddleware);
            app.get('/', (c) => {
                const logger = getLogger(c);
                return c.json({ hasLogger: !!logger });
            });

            const response = await app.fetch(
                new Request('http://localhost/'),
                { ENVIRONMENT: 'development' } as Env
            );

            const json = await response.json() as { hasLogger: boolean };
            expect(json.hasLogger).toBe(true);
        });

        it('should return undefined when context has no logger', () => {
            const mockContext = {
                get: () => { throw new Error('No logger'); },
            };
            // eslint-disable-next-line @typescript-eslint/no-explicit-any
            const result = getLogger(mockContext as any);
            expect(result).toBeUndefined();
        });
    });
});
