/**
 * Mock for cloudflare:test module
 * Provides SELF and env for testing the worker
 */

import app from '../../index.js';
import type { Env } from '../../types.js';

// Mock environment bindings
export const env: Env = {
    ENVIRONMENT: 'development',
    DISCORD_CLIENT_ID: 'test-client-id',
    DISCORD_CLIENT_SECRET: 'test-client-secret',
    FRONTEND_URL: 'http://localhost:5173',
    WORKER_URL: 'http://localhost:8788',
    JWT_SECRET: 'test-jwt-secret-key-for-testing-32chars',
    JWT_EXPIRY: '3600',
};

// SELF helper to make requests to the worker
export const SELF = {
    async fetch(input: RequestInfo | URL, init?: RequestInit): Promise<Response> {
        const request = new Request(input, init);
        return app.fetch(request, env);
    },
};
