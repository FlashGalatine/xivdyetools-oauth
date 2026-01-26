/**
 * Rate Limiter Tests
 * Tests for the in-memory rate limiting service
 *
 * REFACTOR-002: Updated for async interface and shared package behavior
 */

import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { checkRateLimit, getClientIp, resetRateLimiter } from '../services/rate-limit.js';

describe('Rate Limiter Service', () => {
    beforeEach(async () => {
        vi.useFakeTimers();
        vi.setSystemTime(new Date('2024-01-01T12:00:00Z'));
        await resetRateLimiter();
    });

    afterEach(() => {
        vi.useRealTimers();
    });

    describe('checkRateLimit', () => {
        it('should allow requests within rate limit', async () => {
            const result = await checkRateLimit('192.168.1.1', '/auth/discord');

            expect(result.allowed).toBe(true);
            // Shared package decrements after check, so first call shows 9 remaining
            expect(result.remaining).toBe(9);
            expect(result.limit).toBe(10);
        });

        it('should block requests exceeding rate limit', async () => {
            // Use up the limit (10 requests for /auth/discord)
            for (let i = 0; i < 10; i++) {
                await checkRateLimit('192.168.1.2', '/auth/discord');
            }

            const result = await checkRateLimit('192.168.1.2', '/auth/discord');

            expect(result.allowed).toBe(false);
            expect(result.remaining).toBe(0);
        });

        it('should use different limits for different endpoints', async () => {
            // /auth/discord has limit of 10
            const discordResult = await checkRateLimit('192.168.1.3', '/auth/discord');
            expect(discordResult.limit).toBe(10);

            // /auth/callback has limit of 20
            const callbackResult = await checkRateLimit('192.168.1.3', '/auth/callback');
            expect(callbackResult.limit).toBe(20);

            // /auth/refresh has limit of 30
            const refreshResult = await checkRateLimit('192.168.1.3', '/auth/refresh');
            expect(refreshResult.limit).toBe(30);
        });

        it('should use default limit for unknown auth endpoints', async () => {
            const result = await checkRateLimit('192.168.1.4', '/auth/unknown');
            expect(result.limit).toBe(30); // default
        });

        it('should reset after window expires', async () => {
            // Use up the limit
            for (let i = 0; i < 10; i++) {
                await checkRateLimit('192.168.1.5', '/auth/discord');
            }

            // Should be blocked
            expect((await checkRateLimit('192.168.1.5', '/auth/discord')).allowed).toBe(false);

            // Advance time past the window (60 seconds)
            vi.advanceTimersByTime(61 * 1000);

            // Should be allowed again
            const result = await checkRateLimit('192.168.1.5', '/auth/discord');
            expect(result.allowed).toBe(true);
            // Shared package shows remaining after decrement
            expect(result.remaining).toBe(9);
        });

        it('should track limits per IP independently', async () => {
            // Use up limit for one IP
            for (let i = 0; i < 10; i++) {
                await checkRateLimit('192.168.1.6', '/auth/discord');
            }

            // Different IP should still have full limit
            const result = await checkRateLimit('192.168.1.7', '/auth/discord');
            expect(result.allowed).toBe(true);
            // Shared package shows remaining after decrement
            expect(result.remaining).toBe(9);
        });

        it('should calculate reset time based on oldest request in window', async () => {
            // Make a request
            await checkRateLimit('192.168.1.8', '/auth/discord');

            // Advance time by 30 seconds
            vi.advanceTimersByTime(30 * 1000);

            // Make another request
            const result = await checkRateLimit('192.168.1.8', '/auth/discord');

            // Reset time should be approximately 60 seconds from now
            // The shared package calculates resetAt based on the window
            const now = Date.now();
            const resetTime = result.resetAt.getTime();

            // Should be within 60 seconds (+/- some tolerance) from now
            expect(resetTime).toBeGreaterThan(now);
            expect(resetTime).toBeLessThanOrEqual(now + 61000);
        });

        it('should handle sliding window correctly', async () => {
            // Make 10 requests
            for (let i = 0; i < 10; i++) {
                await checkRateLimit('192.168.1.9', '/auth/discord');
            }

            // Should be blocked
            expect((await checkRateLimit('192.168.1.9', '/auth/discord')).allowed).toBe(false);

            // Advance time by 30 seconds (half the window)
            vi.advanceTimersByTime(30 * 1000);

            // Still blocked (all 10 requests are within window)
            expect((await checkRateLimit('192.168.1.9', '/auth/discord')).allowed).toBe(false);

            // Advance time by another 31 seconds (past the first request's window)
            vi.advanceTimersByTime(31 * 1000);

            // Should now have space for requests as old ones expire
            const result = await checkRateLimit('192.168.1.9', '/auth/discord');
            expect(result.allowed).toBe(true);
        });
    });

    describe('getClientIp', () => {
        it('should use CF-Connecting-IP header first', () => {
            const request = new Request('http://localhost/', {
                headers: {
                    'CF-Connecting-IP': '1.2.3.4',
                    'X-Forwarded-For': '5.6.7.8',
                },
            });

            const ip = getClientIp(request);
            expect(ip).toBe('1.2.3.4');
        });

        it('should fall back to X-Forwarded-For', () => {
            const request = new Request('http://localhost/', {
                headers: {
                    'X-Forwarded-For': '1.2.3.4, 5.6.7.8',
                },
            });

            const ip = getClientIp(request);
            expect(ip).toBe('1.2.3.4');
        });

        it('should return "unknown" when no IP headers present', () => {
            const request = new Request('http://localhost/');

            const ip = getClientIp(request);
            expect(ip).toBe('unknown');
        });

        it('should trim whitespace from X-Forwarded-For', () => {
            const request = new Request('http://localhost/', {
                headers: {
                    'X-Forwarded-For': '  1.2.3.4  , 5.6.7.8',
                },
            });

            const ip = getClientIp(request);
            expect(ip).toBe('1.2.3.4');
        });
    });

    describe('resetRateLimiter', () => {
        it('should clear all rate limit data', async () => {
            // Create some entries
            for (let i = 0; i < 5; i++) {
                await checkRateLimit('reset-test-ip', '/auth/discord');
            }

            // Verify we have entries (after 5 requests, remaining = 10 - 5 = 5)
            expect((await checkRateLimit('reset-test-ip', '/auth/discord')).remaining).toBe(4);

            // Reset
            await resetRateLimiter();

            // Should have fresh limit (remaining = 9 after decrement)
            const result = await checkRateLimit('reset-test-ip', '/auth/discord');
            expect(result.remaining).toBe(9);
        });
    });

    describe('path-based rate limiting', () => {
        it('should use compound key for path-specific limiting', async () => {
            // Make requests to /auth/discord
            for (let i = 0; i < 10; i++) {
                await checkRateLimit('192.168.1.10', '/auth/discord');
            }

            // Should be blocked for /auth/discord
            expect((await checkRateLimit('192.168.1.10', '/auth/discord')).allowed).toBe(false);

            // But should have full limit for /auth/callback (different path key)
            const result = await checkRateLimit('192.168.1.10', '/auth/callback');
            expect(result.allowed).toBe(true);
        });
    });
});
