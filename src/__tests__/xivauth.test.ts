/**
 * XIVAuth Handler Tests
 * Tests for XIVAuth OAuth flow (initiation, callback GET, callback POST)
 */

import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { SELF, fetchWithEnv, createProductionEnv, env, createMockDB, VALID_CODE_VERIFIER } from './mocks/cloudflare-test.js';
import { resetRateLimiter } from '../services/rate-limit.js';
import { signState, type StateData } from '../utils/state-signing.js';
import type { Env } from '../types.js';

// Store original fetch
const originalFetch = globalThis.fetch;

/**
 * Helper to decode signed state format (base64url(json).signature)
 */
function decodeSignedState(signedState: string): Record<string, unknown> {
    const [encodedPart] = signedState.split('.');
    // Convert base64url to base64
    let base64 = encodedPart.replace(/-/g, '+').replace(/_/g, '/');
    // Add padding if needed
    while (base64.length % 4 !== 0) {
        base64 += '=';
    }
    return JSON.parse(atob(base64));
}

/**
 * Helper to create a signed state for testing GET callback
 */
async function createTestSignedState(data: Partial<StateData>): Promise<string> {
    const stateData: StateData = {
        csrf: data.csrf ?? 'test-csrf',
        code_challenge: data.code_challenge,
        redirect_uri: data.redirect_uri ?? 'http://localhost:5173/auth/callback',
        return_path: data.return_path ?? '/',
        provider: data.provider ?? 'xivauth',
        iat: data.iat ?? Math.floor(Date.now() / 1000),
        exp: data.exp ?? Math.floor(Date.now() / 1000) + 600, // 10 minutes
    };
    return signState(stateData, env.JWT_SECRET);
}

describe('XIVAuth Handler', () => {
    beforeEach(() => {
        vi.useFakeTimers();
        vi.setSystemTime(new Date('2024-01-01T12:00:00Z'));
        resetRateLimiter();
    });

    afterEach(() => {
        vi.useRealTimers();
        // Restore fetch
        globalThis.fetch = originalFetch;
    });

    /**
     * GET /auth/xivauth tests
     *
     * Initiates the XIVAuth OAuth flow with PKCE
     */
    describe('GET /auth/xivauth', () => {
        it('should require code_challenge parameter', async () => {
            const response = await SELF.fetch('http://localhost/auth/xivauth', {
                redirect: 'manual',
            });

            const json = await response.json();

            expect(response.status).toBe(400);
            expect(json.error).toBe('Missing code_challenge');
            expect(json.message).toContain('PKCE');
        });

        it('should reject invalid code_challenge_method', async () => {
            const params = new URLSearchParams({
                code_challenge: 'challenge123',
                code_challenge_method: 'plain',
            });

            const response = await SELF.fetch(`http://localhost/auth/xivauth?${params}`, {
                redirect: 'manual',
            });

            const json = await response.json();

            expect(response.status).toBe(400);
            expect(json.error).toBe('Invalid code_challenge_method');
            expect(json.message).toContain('S256');
        });

        it('should accept S256 code_challenge_method', async () => {
            const params = new URLSearchParams({
                code_challenge: 'challenge123',
                code_challenge_method: 'S256',
            });

            const response = await SELF.fetch(`http://localhost/auth/xivauth?${params}`, {
                redirect: 'manual',
            });

            expect(response.status).toBe(302);
            const location = response.headers.get('location');
            expect(location).toContain('xivauth.net/oauth/authorize');
        });

        it('should reject disallowed redirect_uri', async () => {
            const params = new URLSearchParams({
                code_challenge: 'challenge123',
                redirect_uri: 'http://evil.com/callback',
            });

            const response = await SELF.fetch(`http://localhost/auth/xivauth?${params}`, {
                redirect: 'manual',
            });

            const json = await response.json();

            expect(response.status).toBe(400);
            expect(json.error).toBe('Invalid redirect_uri');
            expect(json.message).toContain('whitelisted');
        });

        it('should allow localhost redirect_uri', async () => {
            const params = new URLSearchParams({
                code_challenge: 'challenge123',
                redirect_uri: 'http://localhost:5173/auth/callback',
            });

            const response = await SELF.fetch(`http://localhost/auth/xivauth?${params}`, {
                redirect: 'manual',
            });

            expect(response.status).toBe(302);
        });

        it('should redirect to XIVAuth OAuth URL', async () => {
            const params = new URLSearchParams({
                code_challenge: 'challenge123',
            });

            const response = await SELF.fetch(`http://localhost/auth/xivauth?${params}`, {
                redirect: 'manual',
            });

            expect(response.status).toBe(302);

            const location = new URL(response.headers.get('location')!);
            expect(location.origin).toBe('https://xivauth.net');
            expect(location.pathname).toBe('/oauth/authorize');
            expect(location.searchParams.get('client_id')).toBe('test-xivauth-client-id');
            expect(location.searchParams.get('response_type')).toBe('code');
            expect(location.searchParams.get('code_challenge')).toBe('challenge123');
            expect(location.searchParams.get('code_challenge_method')).toBe('S256');
        });

        it('should include correct scopes in XIVAuth URL', async () => {
            const params = new URLSearchParams({
                code_challenge: 'challenge123',
            });

            const response = await SELF.fetch(`http://localhost/auth/xivauth?${params}`, {
                redirect: 'manual',
            });

            const location = new URL(response.headers.get('location')!);
            const scope = location.searchParams.get('scope');
            expect(scope).toContain('user');
            expect(scope).toContain('user:social');
            expect(scope).toContain('character');
            expect(scope).toContain('refresh');
        });

        it('should encode state with provider marker', async () => {
            const params = new URLSearchParams({
                code_challenge: 'challenge123',
                return_path: '/settings',
            });

            const response = await SELF.fetch(`http://localhost/auth/xivauth?${params}`, {
                redirect: 'manual',
            });

            const location = new URL(response.headers.get('location')!);
            const state = location.searchParams.get('state');
            expect(state).toBeTruthy();

            // Decode the signed state (format: base64url(json).signature)
            const stateData = decodeSignedState(state!);
            expect(stateData.provider).toBe('xivauth');
            expect(stateData.code_challenge).toBe('challenge123');
            expect(stateData.return_path).toBe('/settings');
            expect(stateData.csrf).toBeTruthy();
        });

        it('should use default return_path when not provided', async () => {
            const params = new URLSearchParams({
                code_challenge: 'challenge123',
            });

            const response = await SELF.fetch(`http://localhost/auth/xivauth?${params}`, {
                redirect: 'manual',
            });

            const location = new URL(response.headers.get('location')!);
            const state = location.searchParams.get('state');
            const stateData = decodeSignedState(state!);
            expect(stateData.return_path).toBe('/');
        });

        it('should use provided state for CSRF', async () => {
            const params = new URLSearchParams({
                code_challenge: 'challenge123',
                state: 'my-csrf-token',
            });

            const response = await SELF.fetch(`http://localhost/auth/xivauth?${params}`, {
                redirect: 'manual',
            });

            const location = new URL(response.headers.get('location')!);
            const state = location.searchParams.get('state');
            const stateData = decodeSignedState(state!);
            expect(stateData.csrf).toBe('my-csrf-token');
        });
    });

    /**
     * GET /auth/xivauth/callback tests
     *
     * XIVAuth redirects here after user authorizes.
     * Passes the code to the frontend for PKCE exchange.
     */
    describe('GET /auth/xivauth/callback', () => {
        it('should redirect with error when XIVAuth returns error', async () => {
            const params = new URLSearchParams({
                error: 'access_denied',
                error_description: 'User denied access',
            });

            const response = await SELF.fetch(`http://localhost/auth/xivauth/callback?${params}`, {
                redirect: 'manual',
            });

            expect(response.status).toBe(302);

            const location = new URL(response.headers.get('location')!);
            expect(location.searchParams.get('error')).toBe('User denied access');
            expect(location.searchParams.get('provider')).toBe('xivauth');
        });

        it('should use error code when no description provided', async () => {
            const params = new URLSearchParams({
                error: 'server_error',
            });

            const response = await SELF.fetch(`http://localhost/auth/xivauth/callback?${params}`, {
                redirect: 'manual',
            });

            expect(response.status).toBe(302);

            const location = new URL(response.headers.get('location')!);
            expect(location.searchParams.get('error')).toBe('server_error');
            expect(location.searchParams.get('provider')).toBe('xivauth');
        });

        it('should require code parameter', async () => {
            const state = await createTestSignedState({
                csrf: 'test',
                code_challenge: 'challenge',
                redirect_uri: 'http://localhost:5173/auth/callback',
                return_path: '/',
                provider: 'xivauth',
            });

            const params = new URLSearchParams({ state });

            const response = await SELF.fetch(`http://localhost/auth/xivauth/callback?${params}`, {
                redirect: 'manual',
            });

            expect(response.status).toBe(302);

            const location = new URL(response.headers.get('location')!);
            expect(location.searchParams.get('error')).toContain('Missing');
            expect(location.searchParams.get('provider')).toBe('xivauth');
        });

        it('should require state parameter', async () => {
            const params = new URLSearchParams({ code: 'auth_code_123' });

            const response = await SELF.fetch(`http://localhost/auth/xivauth/callback?${params}`, {
                redirect: 'manual',
            });

            expect(response.status).toBe(302);

            const location = new URL(response.headers.get('location')!);
            expect(location.searchParams.get('error')).toContain('Missing');
            expect(location.searchParams.get('provider')).toBe('xivauth');
        });

        it('should handle invalid state encoding', async () => {
            const params = new URLSearchParams({
                code: 'auth_code_123',
                state: 'not-valid-base64!!!',
            });

            const response = await SELF.fetch(`http://localhost/auth/xivauth/callback?${params}`, {
                redirect: 'manual',
            });

            expect(response.status).toBe(302);

            const location = new URL(response.headers.get('location')!);
            expect(location.searchParams.get('error')).toContain('Invalid state');
            expect(location.searchParams.get('provider')).toBe('xivauth');
        });

        it('should redirect with code for secure PKCE flow', async () => {
            const state = await createTestSignedState({
                csrf: 'test-csrf-token',
                code_challenge: 'challenge',
                redirect_uri: 'http://localhost:5173/auth/callback',
                return_path: '/',
                provider: 'xivauth',
            });

            const params = new URLSearchParams({
                code: 'valid_auth_code',
                state,
            });

            const response = await SELF.fetch(`http://localhost/auth/xivauth/callback?${params}`, {
                redirect: 'manual',
            });

            expect(response.status).toBe(302);

            const location = new URL(response.headers.get('location')!);
            // Should have code (for frontend to exchange via POST)
            expect(location.searchParams.get('code')).toBe('valid_auth_code');
            // Should have csrf token for validation
            expect(location.searchParams.get('csrf')).toBe('test-csrf-token');
            // Should have provider marker
            expect(location.searchParams.get('provider')).toBe('xivauth');
        });

        it('should include return_path in redirect when provided', async () => {
            const state = await createTestSignedState({
                csrf: 'test',
                code_challenge: 'challenge',
                redirect_uri: 'http://localhost:5173/auth/callback',
                return_path: '/settings',
                provider: 'xivauth',
            });

            const params = new URLSearchParams({
                code: 'code',
                state,
            });

            const response = await SELF.fetch(`http://localhost/auth/xivauth/callback?${params}`, {
                redirect: 'manual',
            });

            const location = new URL(response.headers.get('location')!);
            expect(location.searchParams.get('return_path')).toBe('/settings');
        });

        it('should not include return_path when it is root', async () => {
            const state = await createTestSignedState({
                csrf: 'test',
                code_challenge: 'challenge',
                redirect_uri: 'http://localhost:5173/auth/callback',
                return_path: '/',
                provider: 'xivauth',
            });

            const params = new URLSearchParams({
                code: 'code',
                state,
            });

            const response = await SELF.fetch(`http://localhost/auth/xivauth/callback?${params}`, {
                redirect: 'manual',
            });

            const location = new URL(response.headers.get('location')!);
            expect(location.searchParams.has('return_path')).toBe(false);
        });
    });

    /**
     * POST /auth/xivauth/callback tests
     *
     * Exchange authorization code for tokens (called by frontend with PKCE verifier)
     */
    describe('POST /auth/xivauth/callback', () => {
        it('should reject invalid JSON body', async () => {
            const response = await SELF.fetch('http://localhost/auth/xivauth/callback', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: 'not-json',
            });

            const json = await response.json();

            expect(response.status).toBe(400);
            expect(json.success).toBe(false);
            expect(json.error).toBe('Invalid request body');
        });

        it('should require code in body', async () => {
            const response = await SELF.fetch('http://localhost/auth/xivauth/callback', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ code_verifier: VALID_CODE_VERIFIER }),
            });

            const json = await response.json();

            expect(response.status).toBe(400);
            expect(json.success).toBe(false);
            expect(json.error).toContain('code');
        });

        it('should require code_verifier in body', async () => {
            const response = await SELF.fetch('http://localhost/auth/xivauth/callback', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ code: 'auth_code' }),
            });

            const json = await response.json();

            expect(response.status).toBe(400);
            expect(json.success).toBe(false);
            expect(json.error).toContain('code_verifier');
        });

        it('should handle XIVAuth token exchange failure', async () => {
            globalThis.fetch = vi.fn().mockImplementation((url: string) => {
                if (url.includes('xivauth.net/oauth/token')) {
                    return Promise.resolve(new Response(JSON.stringify({ error: 'invalid_grant' }), { status: 400 }));
                }
                return originalFetch(url);
            });

            const response = await SELF.fetch('http://localhost/auth/xivauth/callback', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    code: 'invalid_code',
                    code_verifier: VALID_CODE_VERIFIER,
                }),
            });

            const json = await response.json();

            expect(response.status).toBe(401);
            expect(json.success).toBe(false);
            expect(json.error).toContain('authorization code');
        });

        it('should handle XIVAuth user fetch failure', async () => {
            globalThis.fetch = vi.fn().mockImplementation((url: string) => {
                if (url.includes('xivauth.net/oauth/token')) {
                    return Promise.resolve(new Response(JSON.stringify({
                        access_token: 'token',
                        token_type: 'Bearer',
                        expires_in: 604800,
                        refresh_token: 'refresh',
                        scope: 'user user:social character refresh',
                    }), { status: 200 }));
                }
                if (url.includes('xivauth.net/api/v1/user')) {
                    return Promise.resolve(new Response('Unauthorized', { status: 401 }));
                }
                return originalFetch(url);
            });

            const response = await SELF.fetch('http://localhost/auth/xivauth/callback', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    code: 'valid_code',
                    code_verifier: VALID_CODE_VERIFIER,
                }),
            });

            const json = await response.json();

            expect(response.status).toBe(401);
            expect(json.success).toBe(false);
            expect(json.error).toContain('user information');
        });

        it('should return token and user info on success', async () => {
            globalThis.fetch = vi.fn().mockImplementation((url: string) => {
                if (url.includes('xivauth.net/oauth/token')) {
                    return Promise.resolve(new Response(JSON.stringify({
                        access_token: 'xivauth_token',
                        token_type: 'Bearer',
                        expires_in: 604800,
                        refresh_token: 'refresh',
                        scope: 'user user:social character refresh',
                    }), { status: 200 }));
                }
                if (url.includes('xivauth.net/api/v1/user')) {
                    return Promise.resolve(new Response(JSON.stringify({
                        id: 'xivauth-user-uuid',
                        mfa_enabled: false,
                        verified_characters: 1,
                        social_identities: [
                            { provider: 'discord', external_id: '123456789' },
                        ],
                    }), { status: 200 }));
                }
                if (url.includes('xivauth.net/api/v1/characters')) {
                    return Promise.resolve(new Response(JSON.stringify([
                        {
                            lodestone_id: 12345678,
                            name: "Test Character",
                            home_world: "Excalibur",
                            verified: true,
                        },
                    ]), { status: 200 }));
                }
                return originalFetch(url);
            });

            const response = await SELF.fetch('http://localhost/auth/xivauth/callback', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    code: 'valid_code',
                    code_verifier: VALID_CODE_VERIFIER,
                }),
            });

            const json = await response.json();

            expect(response.status).toBe(200);
            expect(json.success).toBe(true);
            expect(json.token).toBeTruthy();
            expect(json.expires_at).toBeTruthy();
            // user.id is our internal database UUID
            expect(json.user.id).toMatch(/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i);
            expect(json.user.auth_provider).toBe('xivauth');
            expect(json.user.primary_character).toMatchObject({
                name: 'Test Character',
                server: 'Excalibur',
                verified: true,
            });
        });

        it('should handle characters fetch failure gracefully', async () => {
            globalThis.fetch = vi.fn().mockImplementation((url: string) => {
                if (url.includes('xivauth.net/oauth/token')) {
                    return Promise.resolve(new Response(JSON.stringify({
                        access_token: 'xivauth_token',
                        token_type: 'Bearer',
                        expires_in: 604800,
                        refresh_token: 'refresh',
                        scope: 'user user:social character refresh',
                    }), { status: 200 }));
                }
                if (url.includes('xivauth.net/api/v1/user')) {
                    return Promise.resolve(new Response(JSON.stringify({
                        id: 'xivauth-user-uuid-2',
                        mfa_enabled: false,
                        verified_characters: 0,
                        social_identities: [],
                    }), { status: 200 }));
                }
                if (url.includes('xivauth.net/api/v1/characters')) {
                    // Characters endpoint fails
                    return Promise.resolve(new Response('Server Error', { status: 500 }));
                }
                return originalFetch(url);
            });

            const response = await SELF.fetch('http://localhost/auth/xivauth/callback', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    code: 'valid_code',
                    code_verifier: VALID_CODE_VERIFIER,
                }),
            });

            const json = await response.json();

            // Should still succeed even if characters fetch fails
            expect(response.status).toBe(200);
            expect(json.success).toBe(true);
            expect(json.user.auth_provider).toBe('xivauth');
            // No primary character since fetch failed
            expect(json.user.primary_character).toBeUndefined();
        });

        it('should handle characters fetch error gracefully', async () => {
            globalThis.fetch = vi.fn().mockImplementation((url: string) => {
                if (url.includes('xivauth.net/oauth/token')) {
                    return Promise.resolve(new Response(JSON.stringify({
                        access_token: 'xivauth_token',
                        token_type: 'Bearer',
                        expires_in: 604800,
                        refresh_token: 'refresh',
                        scope: 'user user:social character refresh',
                    }), { status: 200 }));
                }
                if (url.includes('xivauth.net/api/v1/user')) {
                    return Promise.resolve(new Response(JSON.stringify({
                        id: 'xivauth-user-uuid-3',
                        mfa_enabled: false,
                        verified_characters: 0,
                        social_identities: [],
                    }), { status: 200 }));
                }
                if (url.includes('xivauth.net/api/v1/characters')) {
                    // Characters endpoint throws
                    throw new Error('Network error');
                }
                return originalFetch(url);
            });

            const response = await SELF.fetch('http://localhost/auth/xivauth/callback', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    code: 'valid_code',
                    code_verifier: VALID_CODE_VERIFIER,
                }),
            });

            const json = await response.json();

            // Should still succeed
            expect(response.status).toBe(200);
            expect(json.success).toBe(true);
        });

        it('should use fallback username when no characters', async () => {
            globalThis.fetch = vi.fn().mockImplementation((url: string) => {
                if (url.includes('xivauth.net/oauth/token')) {
                    return Promise.resolve(new Response(JSON.stringify({
                        access_token: 'xivauth_token',
                        token_type: 'Bearer',
                        expires_in: 604800,
                        refresh_token: 'refresh',
                        scope: 'user user:social character refresh',
                    }), { status: 200 }));
                }
                if (url.includes('xivauth.net/api/v1/user')) {
                    return Promise.resolve(new Response(JSON.stringify({
                        id: 'xivauth-no-char-user',
                        mfa_enabled: false,
                        verified_characters: 0,
                        social_identities: [],
                    }), { status: 200 }));
                }
                if (url.includes('xivauth.net/api/v1/characters')) {
                    // No characters
                    return Promise.resolve(new Response(JSON.stringify([]), { status: 200 }));
                }
                return originalFetch(url);
            });

            const response = await SELF.fetch('http://localhost/auth/xivauth/callback', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    code: 'valid_code',
                    code_verifier: VALID_CODE_VERIFIER,
                }),
            });

            const json = await response.json();

            expect(response.status).toBe(200);
            expect(json.success).toBe(true);
            // Should use fallback username
            expect(json.user.username).toContain('XIVAuth User');
            expect(json.user.global_name).toBeNull();
        });

        it('should prefer verified character over unverified', async () => {
            globalThis.fetch = vi.fn().mockImplementation((url: string) => {
                if (url.includes('xivauth.net/oauth/token')) {
                    return Promise.resolve(new Response(JSON.stringify({
                        access_token: 'xivauth_token',
                        token_type: 'Bearer',
                        expires_in: 604800,
                        refresh_token: 'refresh',
                        scope: 'user user:social character refresh',
                    }), { status: 200 }));
                }
                if (url.includes('xivauth.net/api/v1/user')) {
                    return Promise.resolve(new Response(JSON.stringify({
                        id: 'xivauth-multi-char-user',
                        mfa_enabled: false,
                        verified_characters: 1,
                        social_identities: [],
                    }), { status: 200 }));
                }
                if (url.includes('xivauth.net/api/v1/characters')) {
                    return Promise.resolve(new Response(JSON.stringify([
                        {
                            lodestone_id: 11111111,
                            name: "Unverified Character",
                            home_world: "Balmung",
                            verified: false,
                        },
                        {
                            lodestone_id: 22222222,
                            name: "Verified Character",
                            home_world: "Excalibur",
                            verified: true,
                        },
                    ]), { status: 200 }));
                }
                return originalFetch(url);
            });

            const response = await SELF.fetch('http://localhost/auth/xivauth/callback', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    code: 'valid_code',
                    code_verifier: VALID_CODE_VERIFIER,
                }),
            });

            const json = await response.json();

            expect(response.status).toBe(200);
            expect(json.success).toBe(true);
            // Should prefer verified character
            expect(json.user.primary_character.name).toBe('Verified Character');
            expect(json.user.primary_character.verified).toBe(true);
        });

        it('should handle generic errors gracefully', async () => {
            globalThis.fetch = vi.fn().mockImplementation(() => {
                throw new Error('Network error');
            });

            const response = await SELF.fetch('http://localhost/auth/xivauth/callback', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    code: 'code',
                    code_verifier: VALID_CODE_VERIFIER,
                }),
            });

            const json = await response.json();

            expect(response.status).toBe(500);
            expect(json.success).toBe(false);
            expect(json.error).toBe('Authentication failed');
        });

        it('should include client_secret when configured', async () => {
            // Create env with XIVAUTH_CLIENT_SECRET
            const envWithSecret: Env = {
                ...env,
                XIVAUTH_CLIENT_SECRET: 'test-xivauth-secret',
            };

            globalThis.fetch = vi.fn().mockImplementation((url: string, options?: RequestInit) => {
                if (url.includes('xivauth.net/oauth/token')) {
                    // Verify client_secret is included
                    const body = options?.body?.toString() || '';
                    expect(body).toContain('client_secret=test-xivauth-secret');

                    return Promise.resolve(new Response(JSON.stringify({
                        access_token: 'xivauth_token',
                        token_type: 'Bearer',
                        expires_in: 604800,
                        refresh_token: 'refresh',
                        scope: 'user user:social character refresh',
                    }), { status: 200 }));
                }
                if (url.includes('xivauth.net/api/v1/user')) {
                    return Promise.resolve(new Response(JSON.stringify({
                        id: 'xivauth-secret-user',
                        mfa_enabled: false,
                        verified_characters: 0,
                        social_identities: [],
                    }), { status: 200 }));
                }
                if (url.includes('xivauth.net/api/v1/characters')) {
                    return Promise.resolve(new Response(JSON.stringify([]), { status: 200 }));
                }
                return originalFetch(url);
            });

            const response = await fetchWithEnv(envWithSecret, 'http://localhost/auth/xivauth/callback', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    code: 'valid_code',
                    code_verifier: VALID_CODE_VERIFIER,
                }),
            });

            expect(response.status).toBe(200);
        });
    });

    describe('POST /auth/xivauth/callback (Production Environment)', () => {
        it('should return sanitized error response in production', async () => {
            const prodEnv = createProductionEnv();

            globalThis.fetch = vi.fn().mockImplementation(() => {
                throw new Error('Production network error');
            });

            const response = await fetchWithEnv(prodEnv, 'http://localhost/auth/xivauth/callback', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    code: 'code',
                    code_verifier: VALID_CODE_VERIFIER,
                }),
            });

            const json = await response.json();

            // Verify production returns generic error (no sensitive details leaked)
            expect(response.status).toBe(500);
            expect(json.success).toBe(false);
            expect(json.error).toBe('Authentication failed');
            // Ensure error message doesn't contain internal details
            expect(json.error).not.toContain('Production network error');
        });

        it('should return same error structure in development environment', async () => {
            globalThis.fetch = vi.fn().mockImplementation(() => {
                throw new Error('Development network error');
            });

            const response = await SELF.fetch('http://localhost/auth/xivauth/callback', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    code: 'code',
                    code_verifier: VALID_CODE_VERIFIER,
                }),
            });

            const json = await response.json();

            // In development, response should also be generic for consistency
            expect(response.status).toBe(500);
            expect(json.success).toBe(false);
            expect(json.error).toBe('Authentication failed');
        });
    });
});
