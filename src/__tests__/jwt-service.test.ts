/**
 * JWT Service Tests
 * Tests for JWT creation, verification, and utility functions
 */

import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import {
    createJWT,
    verifyJWT,
    decodeJWT,
    isJWTExpired,
    getAvatarUrl,
} from '../services/jwt-service.js';
import type { DiscordUser, Env } from '../types.js';

// Mock environment
const createMockEnv = (): Env => ({
    ENVIRONMENT: 'development',
    DISCORD_CLIENT_ID: 'test-client-id',
    DISCORD_CLIENT_SECRET: 'test-client-secret',
    FRONTEND_URL: 'http://localhost:5173',
    WORKER_URL: 'http://localhost:8788',
    JWT_SECRET: 'test-jwt-secret-key-for-testing-32chars',
    JWT_EXPIRY: '3600',
});

// Mock Discord user
const createMockUser = (): DiscordUser => ({
    id: '123456789',
    username: 'testuser',
    discriminator: '0001',
    global_name: 'Test User',
    avatar: 'abc123hash',
});

describe('JWT Service', () => {
    let mockEnv: Env;
    let mockUser: DiscordUser;

    beforeEach(() => {
        mockEnv = createMockEnv();
        mockUser = createMockUser();
        vi.useFakeTimers();
        vi.setSystemTime(new Date('2024-01-01T00:00:00Z'));
    });

    afterEach(() => {
        vi.useRealTimers();
    });

    describe('createJWT', () => {
        it('should create a valid JWT token', async () => {
            const result = await createJWT(mockUser, mockEnv);

            expect(result).toHaveProperty('token');
            expect(result).toHaveProperty('expires_at');
            expect(typeof result.token).toBe('string');
            expect(result.token.split('.')).toHaveLength(3);
        });

        it('should set correct expiration time based on JWT_EXPIRY', async () => {
            const result = await createJWT(mockUser, mockEnv);
            const expectedExp = Math.floor(new Date('2024-01-01T00:00:00Z').getTime() / 1000) + 3600;

            expect(result.expires_at).toBe(expectedExp);
        });

        it('should use default expiry when JWT_EXPIRY is invalid', async () => {
            mockEnv.JWT_EXPIRY = 'invalid';
            const result = await createJWT(mockUser, mockEnv);
            const expectedExp = Math.floor(new Date('2024-01-01T00:00:00Z').getTime() / 1000) + 3600;

            expect(result.expires_at).toBe(expectedExp);
        });

        it('should include user information in payload', async () => {
            const result = await createJWT(mockUser, mockEnv);
            const decoded = decodeJWT(result.token);

            expect(decoded).not.toBeNull();
            expect(decoded!.sub).toBe(mockUser.id);
            expect(decoded!.username).toBe(mockUser.username);
            expect(decoded!.global_name).toBe(mockUser.global_name);
            expect(decoded!.avatar).toBe(mockUser.avatar);
        });

        it('should set issuer to WORKER_URL', async () => {
            const result = await createJWT(mockUser, mockEnv);
            const decoded = decodeJWT(result.token);

            expect(decoded!.iss).toBe(mockEnv.WORKER_URL);
        });

        it('should handle null global_name', async () => {
            mockUser.global_name = null;
            const result = await createJWT(mockUser, mockEnv);
            const decoded = decodeJWT(result.token);

            expect(decoded!.global_name).toBeNull();
        });

        it('should handle null avatar', async () => {
            mockUser.avatar = null;
            const result = await createJWT(mockUser, mockEnv);
            const decoded = decodeJWT(result.token);

            expect(decoded!.avatar).toBeNull();
        });
    });

    describe('verifyJWT', () => {
        it('should verify a valid JWT', async () => {
            const { token } = await createJWT(mockUser, mockEnv);
            const payload = await verifyJWT(token, mockEnv.JWT_SECRET);

            expect(payload.sub).toBe(mockUser.id);
            expect(payload.username).toBe(mockUser.username);
        });

        it('should throw for invalid signature', async () => {
            const { token } = await createJWT(mockUser, mockEnv);
            const wrongSecret = 'wrong-secret-key-for-testing-32chars';

            await expect(verifyJWT(token, wrongSecret)).rejects.toThrow('Invalid JWT signature');
        });

        it('should throw for malformed token (wrong number of parts)', async () => {
            await expect(verifyJWT('invalid', mockEnv.JWT_SECRET)).rejects.toThrow('Invalid JWT format');
            await expect(verifyJWT('part1.part2', mockEnv.JWT_SECRET)).rejects.toThrow('Invalid JWT format');
            await expect(verifyJWT('a.b.c.d', mockEnv.JWT_SECRET)).rejects.toThrow('Invalid JWT format');
        });

        it('should throw for expired token', async () => {
            const { token } = await createJWT(mockUser, mockEnv);

            // Advance time beyond expiry
            vi.advanceTimersByTime(3601 * 1000);

            await expect(verifyJWT(token, mockEnv.JWT_SECRET)).rejects.toThrow('JWT has expired');
        });

        it('should verify token just before expiration', async () => {
            const { token } = await createJWT(mockUser, mockEnv);

            // Advance time to just before expiry
            vi.advanceTimersByTime(3599 * 1000);

            const payload = await verifyJWT(token, mockEnv.JWT_SECRET);
            expect(payload.sub).toBe(mockUser.id);
        });
    });

    describe('decodeJWT', () => {
        it('should decode a valid JWT payload', async () => {
            const { token } = await createJWT(mockUser, mockEnv);
            const decoded = decodeJWT(token);

            expect(decoded).not.toBeNull();
            expect(decoded!.sub).toBe(mockUser.id);
            expect(decoded!.username).toBe(mockUser.username);
        });

        it('should return null for invalid token format', () => {
            expect(decodeJWT('invalid')).toBeNull();
            expect(decodeJWT('only.two')).toBeNull();
            expect(decodeJWT('a.b.c.d')).toBeNull();
        });

        it('should return null for invalid base64 payload', () => {
            expect(decodeJWT('header.!!!invalid-base64!!!.signature')).toBeNull();
        });

        it('should decode expired token without error', async () => {
            const { token } = await createJWT(mockUser, mockEnv);

            // Advance time beyond expiry
            vi.advanceTimersByTime(3601 * 1000);

            const decoded = decodeJWT(token);
            expect(decoded).not.toBeNull();
            expect(decoded!.sub).toBe(mockUser.id);
        });
    });

    describe('isJWTExpired', () => {
        it('should return false for valid non-expired token', async () => {
            const { token } = await createJWT(mockUser, mockEnv);

            expect(isJWTExpired(token)).toBe(false);
        });

        it('should return true for expired token', async () => {
            const { token } = await createJWT(mockUser, mockEnv);

            vi.advanceTimersByTime(3601 * 1000);

            expect(isJWTExpired(token)).toBe(true);
        });

        it('should return true for invalid token', () => {
            expect(isJWTExpired('invalid')).toBe(true);
            expect(isJWTExpired('')).toBe(true);
        });
    });

    describe('getAvatarUrl', () => {
        it('should return null for null avatar hash', () => {
            expect(getAvatarUrl('123456789', null)).toBeNull();
        });

        it('should return PNG URL for static avatar', () => {
            const url = getAvatarUrl('123456789', 'abc123');

            expect(url).toBe('https://cdn.discordapp.com/avatars/123456789/abc123.png');
        });

        it('should return GIF URL for animated avatar', () => {
            const url = getAvatarUrl('123456789', 'a_abc123');

            expect(url).toBe('https://cdn.discordapp.com/avatars/123456789/a_abc123.gif');
        });

        it('should handle various avatar hash formats', () => {
            // Regular hash
            expect(getAvatarUrl('user123', 'hash456')).toContain('.png');

            // Animated hash
            expect(getAvatarUrl('user123', 'a_hash456')).toContain('.gif');
        });
    });
});
