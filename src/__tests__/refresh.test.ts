/**
 * Refresh Handler Tests
 * Tests for token refresh, user info, and revoke endpoints
 */

import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { SELF, env } from './mocks/cloudflare-test.js';
import { createJWT } from '../services/jwt-service.js';
import type { DiscordUser, Env } from '../types.js';

// Get environment from test context
const getEnv = (): Env => env;

const createMockUser = (): DiscordUser => ({
    id: '123456789',
    username: 'testuser',
    discriminator: '0001',
    global_name: 'Test User',
    avatar: 'abc123',
});

describe('Refresh Handler', () => {
    let mockEnv: Env;
    let mockUser: DiscordUser;

    beforeEach(() => {
        mockEnv = getEnv();
        mockUser = createMockUser();
        vi.useFakeTimers();
        vi.setSystemTime(new Date('2024-01-01T12:00:00Z'));
    });

    afterEach(() => {
        vi.useRealTimers();
    });

    describe('POST /auth/refresh', () => {
        it('should reject invalid JSON body', async () => {
            const response = await SELF.fetch('http://localhost/auth/refresh', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: 'not-json',
            });

            const json = await response.json();

            expect(response.status).toBe(400);
            expect(json.success).toBe(false);
            expect(json.error).toBe('Invalid request body');
        });

        it('should reject missing token', async () => {
            const response = await SELF.fetch('http://localhost/auth/refresh', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({}),
            });

            const json = await response.json();

            expect(response.status).toBe(400);
            expect(json.success).toBe(false);
            expect(json.error).toBe('Missing token');
        });

        it('should refresh a valid non-expired token', async () => {
            const { token } = await createJWT(mockUser, mockEnv);

            // Advance time by 1 second so the new token will have a different iat
            vi.advanceTimersByTime(1000);

            const response = await SELF.fetch('http://localhost/auth/refresh', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ token }),
            });

            const json = await response.json();

            expect(response.status).toBe(200);
            expect(json.success).toBe(true);
            expect(json.token).toBeTruthy();
            expect(json.token).not.toBe(token); // Should be a new token with different iat
            expect(json.expires_at).toBeGreaterThan(Date.now() / 1000);
        });

        it('should refresh an expired token within grace period', async () => {
            const { token } = await createJWT(mockUser, mockEnv);

            // Advance time past expiry but within 24-hour grace period
            vi.advanceTimersByTime(3601 * 1000); // Just past 1 hour expiry

            const response = await SELF.fetch('http://localhost/auth/refresh', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ token }),
            });

            const json = await response.json();

            expect(response.status).toBe(200);
            expect(json.success).toBe(true);
            expect(json.token).toBeTruthy();
        });

        it('should reject token expired beyond grace period', async () => {
            const { token } = await createJWT(mockUser, mockEnv);

            // Advance time past 24-hour grace period
            vi.advanceTimersByTime((3600 + 24 * 60 * 60 + 1) * 1000);

            const response = await SELF.fetch('http://localhost/auth/refresh', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ token }),
            });

            const json = await response.json();

            expect(response.status).toBe(401);
            expect(json.success).toBe(false);
            expect(json.error).toContain('expired');
        });

        it('should reject malformed token', async () => {
            const response = await SELF.fetch('http://localhost/auth/refresh', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ token: 'invalid-token-format' }),
            });

            const json = await response.json();

            expect(response.status).toBe(401);
            expect(json.success).toBe(false);
            expect(json.error).toContain('Invalid token format');
        });

        it('should preserve user info in refreshed token', async () => {
            const { token: originalToken } = await createJWT(mockUser, mockEnv);

            const response = await SELF.fetch('http://localhost/auth/refresh', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ token: originalToken }),
            });

            const json = await response.json();
            expect(json.success).toBe(true);

            // Verify by using /me endpoint
            const meResponse = await SELF.fetch('http://localhost/auth/me', {
                headers: { Authorization: `Bearer ${json.token}` },
            });

            const meJson = await meResponse.json();

            expect(meJson.user.id).toBe(mockUser.id);
            expect(meJson.user.username).toBe(mockUser.username);
        });
    });

    describe('GET /auth/me', () => {
        it('should reject missing Authorization header', async () => {
            const response = await SELF.fetch('http://localhost/auth/me');
            const json = await response.json();

            expect(response.status).toBe(401);
            expect(json.success).toBe(false);
            expect(json.error).toContain('Authorization');
        });

        it('should reject non-Bearer authorization', async () => {
            const response = await SELF.fetch('http://localhost/auth/me', {
                headers: { Authorization: 'Basic dXNlcjpwYXNz' },
            });

            const json = await response.json();

            expect(response.status).toBe(401);
            expect(json.error).toContain('Authorization');
        });

        it('should return user info for valid token', async () => {
            const { token } = await createJWT(mockUser, mockEnv);

            const response = await SELF.fetch('http://localhost/auth/me', {
                headers: { Authorization: `Bearer ${token}` },
            });

            const json = await response.json();

            expect(response.status).toBe(200);
            expect(json.success).toBe(true);
            expect(json.user.id).toBe(mockUser.id);
            expect(json.user.username).toBe(mockUser.username);
            expect(json.user.global_name).toBe(mockUser.global_name);
            expect(json.user.avatar).toBe(mockUser.avatar);
        });

        it('should include avatar_url in response', async () => {
            const { token } = await createJWT(mockUser, mockEnv);

            const response = await SELF.fetch('http://localhost/auth/me', {
                headers: { Authorization: `Bearer ${token}` },
            });

            const json = await response.json();

            expect(json.user.avatar_url).toContain('cdn.discordapp.com');
            expect(json.user.avatar_url).toContain(mockUser.id);
            expect(json.user.avatar_url).toContain(mockUser.avatar);
        });

        it('should return null avatar_url when avatar is null', async () => {
            mockUser.avatar = null;
            const { token } = await createJWT(mockUser, mockEnv);

            const response = await SELF.fetch('http://localhost/auth/me', {
                headers: { Authorization: `Bearer ${token}` },
            });

            const json = await response.json();

            expect(json.user.avatar).toBeNull();
            expect(json.user.avatar_url).toBeNull();
        });

        it('should reject expired token', async () => {
            const { token } = await createJWT(mockUser, mockEnv);

            // Advance time past expiry
            vi.advanceTimersByTime(3601 * 1000);

            const response = await SELF.fetch('http://localhost/auth/me', {
                headers: { Authorization: `Bearer ${token}` },
            });

            const json = await response.json();

            expect(response.status).toBe(401);
            expect(json.success).toBe(false);
            expect(json.error).toContain('expired');
        });

        it('should reject token with invalid signature', async () => {
            const { token } = await createJWT(mockUser, mockEnv);
            // Tamper with the token
            const tamperedToken = token.slice(0, -5) + 'xxxxx';

            const response = await SELF.fetch('http://localhost/auth/me', {
                headers: { Authorization: `Bearer ${tamperedToken}` },
            });

            const json = await response.json();

            expect(response.status).toBe(401);
            expect(json.success).toBe(false);
        });

        it('should reject malformed token', async () => {
            const response = await SELF.fetch('http://localhost/auth/me', {
                headers: { Authorization: 'Bearer not-a-jwt' },
            });

            const json = await response.json();

            expect(response.status).toBe(401);
            expect(json.success).toBe(false);
        });
    });

    describe('POST /auth/revoke', () => {
        it('should return success for revoke request', async () => {
            const response = await SELF.fetch('http://localhost/auth/revoke', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({}),
            });

            const json = await response.json();

            expect(response.status).toBe(200);
            expect(json.success).toBe(true);
            expect(json.message).toContain('revoked');
        });

        it('should return success without body', async () => {
            const response = await SELF.fetch('http://localhost/auth/revoke', {
                method: 'POST',
            });

            const json = await response.json();

            expect(response.status).toBe(200);
            expect(json.success).toBe(true);
        });
    });
});
