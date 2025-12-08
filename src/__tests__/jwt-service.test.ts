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
    isTokenRevoked,
    revokeToken,
    verifyJWTWithRevocationCheck,
    verifyJWTSignatureOnly,
} from '../services/jwt-service.js';
import { createMockKV } from './mocks/cloudflare-test.js';
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

    describe('verifyJWTSignatureOnly', () => {
        it('should return payload for valid signature (even if expired)', async () => {
            const { token } = await createJWT(mockUser, mockEnv);

            // Advance time past expiry
            vi.advanceTimersByTime(3601 * 1000);

            // Should still return payload since we only check signature
            const payload = await verifyJWTSignatureOnly(token, mockEnv.JWT_SECRET);

            expect(payload).not.toBeNull();
            expect(payload!.sub).toBe(mockUser.id);
        });

        it('should return null for invalid signature', async () => {
            const { token } = await createJWT(mockUser, mockEnv);
            const wrongSecret = 'wrong-secret-key-for-testing-32chars';

            const payload = await verifyJWTSignatureOnly(token, wrongSecret);

            expect(payload).toBeNull();
        });

        it('should return null for malformed token', async () => {
            expect(await verifyJWTSignatureOnly('invalid', mockEnv.JWT_SECRET)).toBeNull();
            expect(await verifyJWTSignatureOnly('only.two', mockEnv.JWT_SECRET)).toBeNull();
            expect(await verifyJWTSignatureOnly('a.b.c.d', mockEnv.JWT_SECRET)).toBeNull();
        });

        it('should return null for token with invalid base64', async () => {
            const result = await verifyJWTSignatureOnly(
                'eyJhbGciOiJIUzI1NiJ9.!!!invalid!!!.sig',
                mockEnv.JWT_SECRET
            );
            expect(result).toBeNull();
        });
    });

    describe('isTokenRevoked', () => {
        it('should return false when KV is undefined', async () => {
            const result = await isTokenRevoked('test-jti', undefined);
            expect(result).toBe(false);
        });

        it('should return false when jti is empty', async () => {
            const kv = createMockKV();
            const result = await isTokenRevoked('', kv);
            expect(result).toBe(false);
        });

        it('should return false when token is not in blacklist', async () => {
            const kv = createMockKV();
            const result = await isTokenRevoked('not-revoked-jti', kv);
            expect(result).toBe(false);
        });

        it('should return true when token is in blacklist', async () => {
            const kv = createMockKV();
            // Add token to blacklist
            await kv.put('revoked:revoked-jti', '1');

            const result = await isTokenRevoked('revoked-jti', kv);
            expect(result).toBe(true);
        });

        it('should return false (fail-open) when KV lookup fails', async () => {
            const errorKV = {
                get: async () => { throw new Error('KV error'); },
                put: async () => {},
                delete: async () => {},
                list: async () => ({ keys: [], list_complete: true, cacheStatus: null }),
                getWithMetadata: async () => ({ value: null, metadata: null, cacheStatus: null }),
            } as unknown as KVNamespace;

            const result = await isTokenRevoked('test-jti', errorKV);
            expect(result).toBe(false); // Fail-open for availability
        });
    });

    describe('revokeToken', () => {
        it('should return false when KV is undefined', async () => {
            const now = Math.floor(Date.now() / 1000);
            const result = await revokeToken('test-jti', now + 3600, undefined);
            expect(result).toBe(false);
        });

        it('should return false when jti is empty', async () => {
            const kv = createMockKV();
            const now = Math.floor(Date.now() / 1000);
            const result = await revokeToken('', now + 3600, kv);
            expect(result).toBe(false);
        });

        it('should add token to blacklist successfully', async () => {
            const kv = createMockKV();
            const now = Math.floor(Date.now() / 1000);
            const expiresAt = now + 3600;

            const result = await revokeToken('new-jti', expiresAt, kv);

            expect(result).toBe(true);
            expect(kv._store.get('revoked:new-jti')).toBe('1');
        });

        it('should use minimum TTL of 60 seconds for nearly expired tokens', async () => {
            const kv = createMockKV();
            const now = Math.floor(Date.now() / 1000);
            const expiresAt = now + 10; // Only 10 seconds until expiry

            const result = await revokeToken('expiring-jti', expiresAt, kv);

            expect(result).toBe(true);
            // Token should still be stored (TTL enforced as minimum 60 seconds)
            expect(kv._store.get('revoked:expiring-jti')).toBe('1');
        });

        it('should return false when KV put fails', async () => {
            const errorKV = {
                get: async () => null,
                put: async () => { throw new Error('KV put error'); },
                delete: async () => {},
                list: async () => ({ keys: [], list_complete: true, cacheStatus: null }),
                getWithMetadata: async () => ({ value: null, metadata: null, cacheStatus: null }),
            } as unknown as KVNamespace;

            const now = Math.floor(Date.now() / 1000);
            const result = await revokeToken('test-jti', now + 3600, errorKV);
            expect(result).toBe(false);
        });
    });

    describe('verifyJWTWithRevocationCheck', () => {
        it('should verify valid non-revoked token', async () => {
            const kv = createMockKV();
            const { token } = await createJWT(mockUser, mockEnv);

            const payload = await verifyJWTWithRevocationCheck(token, mockEnv.JWT_SECRET, kv);

            expect(payload.sub).toBe(mockUser.id);
        });

        it('should throw for revoked token', async () => {
            const kv = createMockKV();
            const { token, jti, expires_at } = await createJWT(mockUser, mockEnv);

            // Revoke the token
            await revokeToken(jti, expires_at, kv);

            await expect(
                verifyJWTWithRevocationCheck(token, mockEnv.JWT_SECRET, kv)
            ).rejects.toThrow('Token has been revoked');
        });

        it('should work without KV (skip revocation check)', async () => {
            const { token } = await createJWT(mockUser, mockEnv);

            const payload = await verifyJWTWithRevocationCheck(token, mockEnv.JWT_SECRET, undefined);

            expect(payload.sub).toBe(mockUser.id);
        });

        it('should throw for expired token (regardless of revocation)', async () => {
            const kv = createMockKV();
            const { token } = await createJWT(mockUser, mockEnv);

            // Advance time past expiry
            vi.advanceTimersByTime(3601 * 1000);

            await expect(
                verifyJWTWithRevocationCheck(token, mockEnv.JWT_SECRET, kv)
            ).rejects.toThrow('JWT has expired');
        });

        it('should throw for invalid signature', async () => {
            const kv = createMockKV();
            const { token } = await createJWT(mockUser, mockEnv);
            const wrongSecret = 'wrong-secret-key-for-testing-32chars';

            await expect(
                verifyJWTWithRevocationCheck(token, wrongSecret, kv)
            ).rejects.toThrow('Invalid JWT signature');
        });

        it('should handle token without JTI gracefully', async () => {
            const kv = createMockKV();

            // Create a token manually without JTI
            const base64UrlEncode = (data: string): string => {
                const bytes = new TextEncoder().encode(data);
                const base64 = btoa(String.fromCharCode(...bytes));
                return base64.replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
            };

            const now = Math.floor(Date.now() / 1000);
            const payload = {
                sub: '123456789',
                iat: now,
                exp: now + 3600,
                iss: 'http://localhost:8788',
                username: 'testuser',
                global_name: 'Test User',
                avatar: 'abc123hash',
                // Note: no jti field
            };

            const header = { alg: 'HS256', typ: 'JWT' };
            const encodedHeader = base64UrlEncode(JSON.stringify(header));
            const encodedPayload = base64UrlEncode(JSON.stringify(payload));
            const signatureInput = `${encodedHeader}.${encodedPayload}`;

            // Sign with the test secret
            const encoder = new TextEncoder();
            const keyData = encoder.encode(mockEnv.JWT_SECRET);
            const key = await crypto.subtle.importKey(
                'raw',
                keyData,
                { name: 'HMAC', hash: 'SHA-256' },
                false,
                ['sign']
            );
            const signature = await crypto.subtle.sign('HMAC', key, encoder.encode(signatureInput));
            const sigBytes = new Uint8Array(signature);
            const base64Sig = btoa(String.fromCharCode(...sigBytes));
            const encodedSignature = base64Sig.replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');

            const tokenWithoutJTI = `${signatureInput}.${encodedSignature}`;

            // Should verify successfully (no JTI means no revocation check needed)
            const verifiedPayload = await verifyJWTWithRevocationCheck(
                tokenWithoutJTI,
                mockEnv.JWT_SECRET,
                kv
            );

            expect(verifiedPayload.sub).toBe('123456789');
        });
    });
});
