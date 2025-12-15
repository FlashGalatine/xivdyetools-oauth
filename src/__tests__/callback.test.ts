/**
 * Callback Handler Tests
 * Tests for OAuth callback handling (both GET and POST methods)
 */

import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { SELF, fetchWithEnv, createProductionEnv, VALID_CODE_VERIFIER } from './mocks/cloudflare-test.js';
import { resetRateLimiter } from '../services/rate-limit.js';

// Store original fetch
const originalFetch = globalThis.fetch;

describe('Callback Handler', () => {
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
     * GET /auth/callback tests
     *
     * SECURITY: The GET callback now returns the auth code to the frontend
     * instead of exchanging it directly. The frontend then calls POST /auth/callback
     * with the code + code_verifier from sessionStorage.
     *
     * This ensures the code_verifier NEVER travels through URL redirects.
     */
    describe('GET /auth/callback', () => {
        it('should redirect with error when Discord returns error', async () => {
            const params = new URLSearchParams({
                error: 'access_denied',
                error_description: 'User denied access',
            });

            const response = await SELF.fetch(`http://localhost/auth/callback?${params}`, {
                redirect: 'manual',
            });

            expect(response.status).toBe(302);

            const location = new URL(response.headers.get('location')!);
            expect(location.searchParams.get('error')).toBe('User denied access');
        });

        it('should use error code when no description provided', async () => {
            const params = new URLSearchParams({
                error: 'access_denied',
            });

            const response = await SELF.fetch(`http://localhost/auth/callback?${params}`, {
                redirect: 'manual',
            });

            expect(response.status).toBe(302);

            const location = new URL(response.headers.get('location')!);
            expect(location.searchParams.get('error')).toBe('access_denied');
        });

        it('should require code parameter', async () => {
            const state = btoa(JSON.stringify({
                csrf: 'test',
                code_challenge: 'challenge',
                redirect_uri: 'http://localhost:5173/auth/callback',
                return_path: '/',
            }));

            const params = new URLSearchParams({ state });

            const response = await SELF.fetch(`http://localhost/auth/callback?${params}`, {
                redirect: 'manual',
            });

            expect(response.status).toBe(302);

            const location = new URL(response.headers.get('location')!);
            expect(location.searchParams.get('error')).toContain('Missing');
        });

        it('should require state parameter', async () => {
            const params = new URLSearchParams({ code: 'auth_code_123' });

            const response = await SELF.fetch(`http://localhost/auth/callback?${params}`, {
                redirect: 'manual',
            });

            expect(response.status).toBe(302);

            const location = new URL(response.headers.get('location')!);
            expect(location.searchParams.get('error')).toContain('Missing');
        });

        it('should handle invalid state encoding', async () => {
            const params = new URLSearchParams({
                code: 'auth_code_123',
                state: 'not-valid-base64!!!',
            });

            const response = await SELF.fetch(`http://localhost/auth/callback?${params}`, {
                redirect: 'manual',
            });

            expect(response.status).toBe(302);

            const location = new URL(response.headers.get('location')!);
            expect(location.searchParams.get('error')).toContain('Invalid state');
        });

        it('should redirect with code (not token) for secure PKCE flow', async () => {
            // GET callback now returns the code to frontend, not the token
            // Frontend then exchanges code via POST /auth/callback with code_verifier

            const state = btoa(JSON.stringify({
                csrf: 'test-csrf-token',
                code_challenge: 'challenge',
                redirect_uri: 'http://localhost:5173/auth/callback',
                return_path: '/',
            }));

            const params = new URLSearchParams({
                code: 'valid_auth_code',
                state,
            });

            const response = await SELF.fetch(`http://localhost/auth/callback?${params}`, {
                redirect: 'manual',
            });

            expect(response.status).toBe(302);

            const location = new URL(response.headers.get('location')!);
            // Should have code (for frontend to exchange via POST)
            expect(location.searchParams.get('code')).toBe('valid_auth_code');
            // Should have csrf token for validation
            expect(location.searchParams.get('csrf')).toBe('test-csrf-token');
            // Should NOT have token (that comes from POST exchange)
            expect(location.searchParams.get('token')).toBeNull();
        });

        it('should include return_path in redirect when provided', async () => {
            const state = btoa(JSON.stringify({
                csrf: 'test',
                code_challenge: 'challenge',
                redirect_uri: 'http://localhost:5173/auth/callback',
                return_path: '/settings',
            }));

            const params = new URLSearchParams({
                code: 'code',
                state,
            });

            const response = await SELF.fetch(`http://localhost/auth/callback?${params}`, {
                redirect: 'manual',
            });

            const location = new URL(response.headers.get('location')!);
            expect(location.searchParams.get('return_path')).toBe('/settings');
        });

        it('should not include return_path when it is root', async () => {
            const state = btoa(JSON.stringify({
                csrf: 'test',
                code_challenge: 'challenge',
                redirect_uri: 'http://localhost:5173/auth/callback',
                return_path: '/',
            }));

            const params = new URLSearchParams({
                code: 'code',
                state,
            });

            const response = await SELF.fetch(`http://localhost/auth/callback?${params}`, {
                redirect: 'manual',
            });

            const location = new URL(response.headers.get('location')!);
            expect(location.searchParams.has('return_path')).toBe(false);
        });
    });

    describe('POST /auth/callback', () => {
        it('should reject invalid JSON body', async () => {
            const response = await SELF.fetch('http://localhost/auth/callback', {
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
            const response = await SELF.fetch('http://localhost/auth/callback', {
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
            const response = await SELF.fetch('http://localhost/auth/callback', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ code: 'auth_code' }),
            });

            const json = await response.json();

            expect(response.status).toBe(400);
            expect(json.success).toBe(false);
            expect(json.error).toContain('code_verifier');
        });

        it('should handle Discord token exchange failure', async () => {
            globalThis.fetch = vi.fn().mockImplementation((url: string) => {
                if (url.includes('oauth2/token')) {
                    return Promise.resolve(new Response(JSON.stringify({ error: 'invalid_grant' }), { status: 400 }));
                }
                return originalFetch(url);
            });

            const response = await SELF.fetch('http://localhost/auth/callback', {
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

        it('should handle Discord user fetch failure', async () => {
            globalThis.fetch = vi.fn().mockImplementation((url: string) => {
                if (url.includes('oauth2/token')) {
                    return Promise.resolve(new Response(JSON.stringify({
                        access_token: 'token',
                        token_type: 'Bearer',
                        expires_in: 604800,
                        refresh_token: 'refresh',
                        scope: 'identify',
                    }), { status: 200 }));
                }
                if (url.includes('users/@me')) {
                    return Promise.resolve(new Response('Unauthorized', { status: 401 }));
                }
                return originalFetch(url);
            });

            const response = await SELF.fetch('http://localhost/auth/callback', {
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
                if (url.includes('oauth2/token')) {
                    return Promise.resolve(new Response(JSON.stringify({
                        access_token: 'discord_token',
                        token_type: 'Bearer',
                        expires_in: 604800,
                        refresh_token: 'refresh',
                        scope: 'identify',
                    }), { status: 200 }));
                }
                if (url.includes('users/@me')) {
                    return Promise.resolve(new Response(JSON.stringify({
                        id: '123456789',
                        username: 'testuser',
                        discriminator: '0001',
                        global_name: 'Test User',
                        avatar: 'abc123',
                    }), { status: 200 }));
                }
                return originalFetch(url);
            });

            const response = await SELF.fetch('http://localhost/auth/callback', {
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
            // user.id is now our internal database UUID, not the Discord ID
            expect(json.user.id).toMatch(/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i);
            expect(json.user).toMatchObject({
                username: 'testuser',
                global_name: 'Test User',
                avatar: 'abc123',
            });
            expect(json.user.avatar_url).toContain('cdn.discordapp.com');
        });

        it('should ignore custom redirect_uri and use worker callback', async () => {
            globalThis.fetch = vi.fn().mockImplementation((url: string, options?: RequestInit) => {
                if (url.includes('oauth2/token')) {
                    // Verify redirect_uri is forced to the worker callback (matches authorize step)
                    const body = options?.body?.toString() || '';
                    expect(body).toContain('redirect_uri=http%3A%2F%2Flocalhost%3A8788%2Fauth%2Fcallback');

                    return Promise.resolve(new Response(JSON.stringify({
                        access_token: 'token',
                        token_type: 'Bearer',
                        expires_in: 604800,
                        refresh_token: 'refresh',
                        scope: 'identify',
                    }), { status: 200 }));
                }
                if (url.includes('users/@me')) {
                    return Promise.resolve(new Response(JSON.stringify({
                        id: '123',
                        username: 'test',
                        discriminator: '0001',
                        global_name: null,
                        avatar: null,
                    }), { status: 200 }));
                }
                return originalFetch(url);
            });

            const response = await SELF.fetch('http://localhost/auth/callback', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    code: 'code',
                    code_verifier: VALID_CODE_VERIFIER,
                    redirect_uri: 'http://localhost:5173/custom/callback',
                }),
            });

            expect(response.status).toBe(200);
        });

        it('should handle null avatar', async () => {
            globalThis.fetch = vi.fn().mockImplementation((url: string) => {
                if (url.includes('oauth2/token')) {
                    return Promise.resolve(new Response(JSON.stringify({
                        access_token: 'token',
                        token_type: 'Bearer',
                        expires_in: 604800,
                        refresh_token: 'refresh',
                        scope: 'identify',
                    }), { status: 200 }));
                }
                if (url.includes('users/@me')) {
                    return Promise.resolve(new Response(JSON.stringify({
                        id: '123',
                        username: 'test',
                        discriminator: '0001',
                        global_name: null,
                        avatar: null,
                    }), { status: 200 }));
                }
                return originalFetch(url);
            });

            const response = await SELF.fetch('http://localhost/auth/callback', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    code: 'code',
                    code_verifier: VALID_CODE_VERIFIER,
                }),
            });

            const json = await response.json();

            expect(response.status).toBe(200);
            expect(json.user.avatar).toBeNull();
            expect(json.user.avatar_url).toBeNull();
        });

        it('should handle generic errors gracefully', async () => {
            globalThis.fetch = vi.fn().mockImplementation(() => {
                throw new Error('Network error');
            });

            const response = await SELF.fetch('http://localhost/auth/callback', {
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
    });

    describe('POST /auth/callback (Production Environment)', () => {
        it('should sanitize error logging for token exchange failure in production', async () => {
            const prodEnv = createProductionEnv();
            const consoleSpy = vi.spyOn(console, 'error').mockImplementation(() => {});

            globalThis.fetch = vi.fn().mockImplementation((url: string) => {
                if (url.includes('oauth2/token')) {
                    return Promise.resolve(
                        new Response(JSON.stringify({ error: 'invalid_grant' }), { status: 400 })
                    );
                }
                return originalFetch(url);
            });

            const response = await fetchWithEnv(prodEnv, 'http://localhost/auth/callback', {
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
            // In production, console.error should only log 'Token exchange failed' without detailed error data
            expect(consoleSpy).toHaveBeenCalledWith('Token exchange failed');

            consoleSpy.mockRestore();
        });

        it('should sanitize error logging for generic errors in production', async () => {
            const prodEnv = createProductionEnv();
            const consoleSpy = vi.spyOn(console, 'error').mockImplementation(() => {});

            globalThis.fetch = vi.fn().mockImplementation(() => {
                throw new Error('Production network error');
            });

            const response = await fetchWithEnv(prodEnv, 'http://localhost/auth/callback', {
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
            // In production, should log sanitized error (name and message only)
            expect(consoleSpy).toHaveBeenCalledWith('OAuth callback error:', {
                name: 'Error',
                message: 'Production network error',
            });

            consoleSpy.mockRestore();
        });

        it('should log full error details in development environment', async () => {
            const consoleSpy = vi.spyOn(console, 'error').mockImplementation(() => {});

            globalThis.fetch = vi.fn().mockImplementation((url: string) => {
                if (url.includes('oauth2/token')) {
                    return Promise.resolve(
                        new Response(JSON.stringify({ error: 'invalid_grant' }), { status: 400 })
                    );
                }
                return originalFetch(url);
            });

            await SELF.fetch('http://localhost/auth/callback', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    code: 'invalid_code',
                    code_verifier: VALID_CODE_VERIFIER,
                }),
            });

            // In development, should log full error details
            expect(consoleSpy).toHaveBeenCalledWith('Token exchange failed:', { error: 'invalid_grant' });

            consoleSpy.mockRestore();
        });
    });
});
