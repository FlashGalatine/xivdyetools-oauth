/**
 * Mock for cloudflare:test module
 * Provides SELF and env for testing the worker
 */

import app from '../../index.js';
import type { Env, UserRow } from '../../types.js';

// In-memory user store for D1 mock
const userStore = new Map<string, UserRow>();

// Mock D1Database for user management tests
export const createMockDB = (): D1Database & { _users: Map<string, UserRow> } => {
    const users = userStore;

    // Helper to create a chainable statement
    const createStatement = (sql: string) => {
        let boundParams: unknown[] = [];

        const statement = {
            bind: (...params: unknown[]) => {
                boundParams = params;
                return statement;
            },
            first: async <T>(): Promise<T | null> => {
                // Handle SELECT queries
                if (sql.includes('SELECT') && sql.includes('discord_id = ?')) {
                    const discordId = boundParams[0] as string;
                    for (const user of users.values()) {
                        if (user.discord_id === discordId) {
                            return user as T;
                        }
                    }
                    return null;
                }
                if (sql.includes('SELECT') && sql.includes('xivauth_id = ?')) {
                    const xivauthId = boundParams[0] as string;
                    for (const user of users.values()) {
                        if (user.xivauth_id === xivauthId) {
                            return user as T;
                        }
                    }
                    return null;
                }
                if (sql.includes('SELECT') && sql.includes('WHERE id = ?')) {
                    const userId = boundParams[boundParams.length - 1] as string;
                    return (users.get(userId) as T) || null;
                }
                return null;
            },
            run: async () => {
                // Handle INSERT for new users
                if (sql.includes('INSERT INTO users')) {
                    const [id, discord_id, xivauth_id, auth_provider, username, avatar_url] =
                        boundParams as [string, string | null, string | null, string, string, string | null];
                    const now = new Date().toISOString();
                    users.set(id, {
                        id,
                        discord_id,
                        xivauth_id,
                        auth_provider,
                        username,
                        avatar_url,
                        created_at: now,
                        updated_at: now,
                    });
                    return { success: true, meta: {} };
                }
                // Handle UPDATE
                if (sql.includes('UPDATE users')) {
                    const userId = boundParams[boundParams.length - 1] as string;
                    const existing = users.get(userId);
                    if (existing) {
                        existing.updated_at = new Date().toISOString();
                    }
                    return { success: true, meta: {} };
                }
                // Handle DELETE for characters (no-op for now)
                if (sql.includes('DELETE FROM xivauth_characters')) {
                    return { success: true, meta: {} };
                }
                // Handle INSERT for characters (no-op for now)
                if (sql.includes('INSERT INTO xivauth_characters')) {
                    return { success: true, meta: {} };
                }
                return { success: true, meta: {} };
            },
            all: async <T>(): Promise<D1Result<T>> => {
                // Handle character queries (return empty for now)
                return { results: [] as T[], success: true, meta: {} as D1Meta };
            },
        };
        return statement;
    };

    return {
        _users: users,
        prepare: (sql: string) => createStatement(sql),
        exec: async () => ({ count: 0, duration: 0 }),
        batch: async () => [],
        dump: async () => new ArrayBuffer(0),
    } as unknown as D1Database & { _users: Map<string, UserRow> };
};

// Shared mock DB instance
const mockDB = createMockDB();

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
    XIVAUTH_CLIENT_ID: 'test-xivauth-client-id',
    FRONTEND_URL: 'http://localhost:5173',
    WORKER_URL: 'http://localhost:8788',
    JWT_SECRET: 'test-jwt-secret-key-for-testing-32chars',
    JWT_EXPIRY: '3600',
    DB: mockDB,
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
