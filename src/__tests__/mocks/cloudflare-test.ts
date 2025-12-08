/**
 * Mock for cloudflare:test module
 * Provides SELF and env for testing the worker
 */

import app from '../../index.js';
import type { Env } from '../../types.js';

// Mock KV namespace for token revocation tests
export const createMockKV = (): KVNamespace & { _store: Map<string, string> } => {
    const store = new Map<string, string>();
    return {
        _store: store,
        get: async (key: string) => store.get(key) ?? null,
        put: async (key: string, value: string, _options?: { expirationTtl?: number }) => {
            store.set(key, value);
        },
        delete: async (key: string) => {
            store.delete(key);
        },
        list: async () => ({ keys: [], list_complete: true, cacheStatus: null }),
        getWithMetadata: async (key: string) => ({ value: store.get(key) ?? null, metadata: null, cacheStatus: null }),
    } as unknown as KVNamespace & { _store: Map<string, string> };
};

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

// Create production environment for testing production-specific code paths
export const createProductionEnv = (): Env => ({
    ...env,
    ENVIRONMENT: 'production',
});

// Create environment with KV namespace for revocation tests
export const createEnvWithKV = (): Env & { TOKEN_BLACKLIST: KVNamespace } => ({
    ...env,
    TOKEN_BLACKLIST: createMockKV(),
});

// SELF helper to make requests to the worker
export const SELF = {
    async fetch(input: RequestInfo | URL, init?: RequestInit): Promise<Response> {
        const request = new Request(input, init);
        return app.fetch(request, env);
    },
};

// Helper to make requests with a custom environment
export const fetchWithEnv = async (
    customEnv: Env,
    input: RequestInfo | URL,
    init?: RequestInit
): Promise<Response> => {
    const request = new Request(input, init);
    return app.fetch(request, customEnv);
};
