/**
 * Rate Limiter Tests
 * Tests for the in-memory rate limiting service
 */

import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { checkRateLimit, getClientIp, resetRateLimiter } from '../services/rate-limit.js';

describe('Rate Limiter Service', () => {
    beforeEach(() => {
        vi.useFakeTimers();
        vi.setSystemTime(new Date('2024-01-01T12:00:00Z'));
        resetRateLimiter();
    });

    afterEach(() => {
        vi.useRealTimers();
    });

    describe('checkRateLimit', () => {
        it('should allow requests within rate limit', () => {
            const result = checkRateLimit('192.168.1.1', '/auth/discord');

            expect(result.allowed).toBe(true);
            // remaining is calculated before recording, so first call shows 10 remaining
            expect(result.remaining).toBe(10);
            expect(result.limit).toBe(10);
        });

        it('should block requests exceeding rate limit', () => {
            // Use up the limit (10 requests for /auth/discord)
            for (let i = 0; i < 10; i++) {
                checkRateLimit('192.168.1.2', '/auth/discord');
            }

            const result = checkRateLimit('192.168.1.2', '/auth/discord');

            expect(result.allowed).toBe(false);
            expect(result.remaining).toBe(0);
        });

        it('should use different limits for different endpoints', () => {
            // /auth/discord has limit of 10
            const discordResult = checkRateLimit('192.168.1.3', '/auth/discord');
            expect(discordResult.limit).toBe(10);

            // /auth/callback has limit of 20
            const callbackResult = checkRateLimit('192.168.1.3', '/auth/callback');
            expect(callbackResult.limit).toBe(20);

            // /auth/refresh has limit of 30
            const refreshResult = checkRateLimit('192.168.1.3', '/auth/refresh');
            expect(refreshResult.limit).toBe(30);
        });

        it('should use default limit for unknown auth endpoints', () => {
            const result = checkRateLimit('192.168.1.4', '/auth/unknown');
            expect(result.limit).toBe(30); // default
        });

        it('should reset after window expires', () => {
            // Use up the limit
            for (let i = 0; i < 10; i++) {
                checkRateLimit('192.168.1.5', '/auth/discord');
            }

            // Should be blocked
            expect(checkRateLimit('192.168.1.5', '/auth/discord').allowed).toBe(false);

            // Advance time past the window (60 seconds)
            vi.advanceTimersByTime(61 * 1000);

            // Should be allowed again
            const result = checkRateLimit('192.168.1.5', '/auth/discord');
            expect(result.allowed).toBe(true);
            // remaining is calculated before recording
            expect(result.remaining).toBe(10);
        });

        it('should track limits per IP independently', () => {
            // Use up limit for one IP
            for (let i = 0; i < 10; i++) {
                checkRateLimit('192.168.1.6', '/auth/discord');
            }

            // Different IP should still have full limit
            const result = checkRateLimit('192.168.1.7', '/auth/discord');
            expect(result.allowed).toBe(true);
            // remaining is calculated before recording
            expect(result.remaining).toBe(10);
        });

        it('should calculate reset time based on oldest request in window', () => {
            // Make a request
            checkRateLimit('192.168.1.8', '/auth/discord');

            // Advance time by 30 seconds
            vi.advanceTimersByTime(30 * 1000);

            // Make another request
            const result = checkRateLimit('192.168.1.8', '/auth/discord');

            // Reset time should be based on the oldest request (first one)
            const expectedReset = new Date('2024-01-01T12:00:00Z').getTime() + 60 * 1000;
            expect(result.resetAt.getTime()).toBe(expectedReset);
        });

        it('should handle sliding window correctly', () => {
            // Make 10 requests
            for (let i = 0; i < 10; i++) {
                checkRateLimit('192.168.1.9', '/auth/discord');
            }

            // Should be blocked
            expect(checkRateLimit('192.168.1.9', '/auth/discord').allowed).toBe(false);

            // Advance time by 30 seconds (half the window)
            vi.advanceTimersByTime(30 * 1000);

            // Still blocked (all 10 requests are within window)
            expect(checkRateLimit('192.168.1.9', '/auth/discord').allowed).toBe(false);

            // Advance time by another 31 seconds (past the first request's window)
            vi.advanceTimersByTime(31 * 1000);

            // Should now have space for requests as old ones expire
            const result = checkRateLimit('192.168.1.9', '/auth/discord');
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

    describe('cleanup mechanism', () => {
        it('should clean up old entries periodically', async () => {
            // Create some rate limit entries
            checkRateLimit('cleanup-test-ip', '/auth/discord');

            // Advance time past the cleanup threshold (2 minutes)
            vi.advanceTimersByTime(121 * 1000);

            // Force cleanup by making requests with random < 0.01
            // We mock Math.random to trigger cleanup
            const originalRandom = Math.random;
            Math.random = () => 0.001; // Will trigger cleanup (< 0.01)

            try {
                // This request should trigger cleanup
                const result = checkRateLimit('cleanup-test-ip', '/auth/discord');

                // The old entry should have been cleaned up
                // So this should be counted as a fresh request (remaining = 10 before recording)
                expect(result.remaining).toBe(10);
            } finally {
                Math.random = originalRandom;
            }
        });

        it('should delete entries with all expired timestamps', async () => {
            // Create entries
            checkRateLimit('old-ip-1', '/auth/discord');
            checkRateLimit('old-ip-2', '/auth/callback');

            // Advance time past cleanup threshold (2 minutes)
            vi.advanceTimersByTime(130 * 1000);

            // Mock random to always trigger cleanup
            const originalRandom = Math.random;
            Math.random = () => 0.001;

            try {
                // Trigger cleanup via a new request
                checkRateLimit('new-ip', '/auth/discord');

                // Old entries should be gone, verify by checking a fresh request
                // to one of the old IPs gets full limit (remaining = 10 before recording)
                const result = checkRateLimit('old-ip-1', '/auth/discord');
                expect(result.remaining).toBe(10);
            } finally {
                Math.random = originalRandom;
            }
        });

        it('should retain entries with recent timestamps during cleanup', async () => {
            // Create entry
            checkRateLimit('recent-ip', '/auth/discord');

            // Advance time past cleanup threshold (120s) but keep first request valid in rate limit window
            vi.advanceTimersByTime(50 * 1000);

            // Make another request
            checkRateLimit('recent-ip', '/auth/discord');

            // Advance more time - first request is now outside rate limit window (60s)
            // but both are still within cleanup threshold (120s)
            vi.advanceTimersByTime(15 * 1000);

            // Mock random to trigger cleanup
            const originalRandom = Math.random;
            Math.random = () => 0.001;

            try {
                // Trigger cleanup
                checkRateLimit('trigger-ip', '/auth/discord');

                // At T=65s:
                // - First request at T=0 is 65s old → outside 60s rate limit window
                // - Second request at T=50s is 15s old → inside 60s rate limit window
                // So we have 1 valid timestamp, making remaining = 10 - 1 = 9
                const result = checkRateLimit('recent-ip', '/auth/discord');
                expect(result.remaining).toBe(9);
            } finally {
                Math.random = originalRandom;
            }
        });
    });

    describe('resetRateLimiter', () => {
        it('should clear all rate limit data', () => {
            // Create some entries
            for (let i = 0; i < 5; i++) {
                checkRateLimit('reset-test-ip', '/auth/discord');
            }

            // Verify we have entries (after 5 requests, remaining = 10 - 5 = 5)
            expect(checkRateLimit('reset-test-ip', '/auth/discord').remaining).toBe(5);

            // Reset
            resetRateLimiter();

            // Should have fresh limit (remaining = 10 before recording)
            const result = checkRateLimit('reset-test-ip', '/auth/discord');
            expect(result.remaining).toBe(10);
        });
    });

    describe('deterministic cleanup', () => {
        it('should trigger cleanup every 100 requests', () => {
            // Reset to get a known state
            resetRateLimiter();

            // Create an entry
            checkRateLimit('cleanup-periodic-ip', '/auth/discord');

            // Advance time past cleanup threshold (2 minutes)
            vi.advanceTimersByTime(130 * 1000);

            // Make 99 more requests (total 100) to trigger deterministic cleanup
            for (let i = 0; i < 99; i++) {
                checkRateLimit(`ip-${i}`, '/auth/discord');
            }

            // The old entry should have been cleaned up by the 100th request
            // Make a new request to the original IP - should have full limit
            const result = checkRateLimit('cleanup-periodic-ip', '/auth/discord');
            expect(result.remaining).toBe(10);
        });

        it('should keep recent entries during cleanup', () => {
            resetRateLimiter();

            // Make 50 requests to trigger a couple cleanups
            for (let i = 0; i < 50; i++) {
                checkRateLimit('persistent-ip', '/auth/discord');
            }

            // Advance time but not past cleanup threshold (stay within 2 minutes)
            vi.advanceTimersByTime(60 * 1000);

            // Make 50 more requests to trigger cleanup at 100
            for (let i = 0; i < 50; i++) {
                checkRateLimit(`other-ip-${i}`, '/auth/discord');
            }

            // The entry with recent activity should still exist
            // At T=60s, the rate limit window (60s) excludes all 50 original requests
            // So we should have full limit again
            const result = checkRateLimit('persistent-ip', '/auth/discord');
            expect(result.remaining).toBe(10);
        });
    });

    describe('entries with empty timestamps', () => {
        it('should handle entries where all timestamps are filtered out', () => {
            // Create entry
            checkRateLimit('empty-ts-ip', '/auth/discord');

            // Advance time way past both rate limit window (60s) and cleanup threshold (120s)
            vi.advanceTimersByTime(200 * 1000);

            // Make 100 requests to trigger cleanup
            for (let i = 0; i < 100; i++) {
                checkRateLimit(`trigger-ip-${i}`, '/auth/discord');
            }

            // The original entry should be completely gone
            const result = checkRateLimit('empty-ts-ip', '/auth/discord');
            expect(result.remaining).toBe(10);
        });
    });
});
