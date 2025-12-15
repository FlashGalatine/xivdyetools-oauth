/**
 * Environment Validation Tests
 * Tests for env-validation.ts utility functions
 */

import { describe, it, expect, vi, afterEach } from 'vitest';
import { validateEnv, logValidationErrors } from '../utils/env-validation.js';
import type { Env } from '../types.js';

// Create a valid mock environment for testing
const createValidEnv = (): Env => ({
    ENVIRONMENT: 'development',
    DISCORD_CLIENT_ID: 'test-client-id',
    DISCORD_CLIENT_SECRET: 'test-client-secret',
    XIVAUTH_CLIENT_ID: 'test-xivauth-client-id',
    JWT_SECRET: 'test-jwt-secret-key-for-testing-32chars',
    JWT_EXPIRY: '3600',
    FRONTEND_URL: 'http://localhost:5173',
    WORKER_URL: 'http://localhost:8788',
    DB: {} as D1Database,
});

describe('Environment Validation', () => {
    describe('validateEnv', () => {
        it('should pass with valid development environment', () => {
            const env = createValidEnv();
            const result = validateEnv(env);

            expect(result.valid).toBe(true);
            expect(result.errors).toHaveLength(0);
        });

        it('should pass with valid production environment using HTTPS', () => {
            const env = createValidEnv();
            env.ENVIRONMENT = 'production';
            env.FRONTEND_URL = 'https://xivdyetools.example.com';
            env.WORKER_URL = 'https://oauth.example.com';

            const result = validateEnv(env);

            expect(result.valid).toBe(true);
            expect(result.errors).toHaveLength(0);
        });

        it('should fail when required string variables are missing', () => {
            const env = {
                ENVIRONMENT: 'development',
                // Missing other required fields
            } as unknown as Env;

            const result = validateEnv(env);

            expect(result.valid).toBe(false);
            expect(result.errors.length).toBeGreaterThan(0);
            expect(result.errors.some(e => e.includes('DISCORD_CLIENT_ID'))).toBe(true);
        });

        it('should fail when JWT_EXPIRY is not a valid number', () => {
            const env = createValidEnv();
            env.JWT_EXPIRY = 'not-a-number';

            const result = validateEnv(env);

            expect(result.valid).toBe(false);
            expect(result.errors.some(e => e.includes('JWT_EXPIRY'))).toBe(true);
            expect(result.errors.some(e => e.includes('positive number'))).toBe(true);
        });

        it('should fail when JWT_EXPIRY is zero', () => {
            const env = createValidEnv();
            env.JWT_EXPIRY = '0';

            const result = validateEnv(env);

            expect(result.valid).toBe(false);
            expect(result.errors.some(e => e.includes('JWT_EXPIRY'))).toBe(true);
        });

        it('should fail when JWT_EXPIRY is negative', () => {
            const env = createValidEnv();
            env.JWT_EXPIRY = '-100';

            const result = validateEnv(env);

            expect(result.valid).toBe(false);
            expect(result.errors.some(e => e.includes('JWT_EXPIRY'))).toBe(true);
        });

        it('should fail when URL is invalid', () => {
            const env = createValidEnv();
            env.FRONTEND_URL = 'not-a-valid-url';

            const result = validateEnv(env);

            expect(result.valid).toBe(false);
            expect(result.errors.some(e => e.includes('Invalid URL'))).toBe(true);
        });

        it('should fail when production URLs use HTTP instead of HTTPS', () => {
            const env = createValidEnv();
            env.ENVIRONMENT = 'production';
            env.FRONTEND_URL = 'http://insecure.example.com';

            const result = validateEnv(env);

            expect(result.valid).toBe(false);
            expect(result.errors.some(e => e.includes('must use HTTPS in production'))).toBe(true);
        });

        it('should fail when WORKER_URL uses HTTP in production', () => {
            const env = createValidEnv();
            env.ENVIRONMENT = 'production';
            env.FRONTEND_URL = 'https://secure.example.com';
            env.WORKER_URL = 'http://insecure-worker.example.com';

            const result = validateEnv(env);

            expect(result.valid).toBe(false);
            expect(result.errors.some(e => e.includes('WORKER_URL') && e.includes('HTTPS'))).toBe(true);
        });

        it('should fail when DB is not provided', () => {
            const env = createValidEnv();
            // @ts-expect-error - intentionally testing undefined DB
            env.DB = undefined;

            const result = validateEnv(env);

            expect(result.valid).toBe(false);
            expect(result.errors.some(e => e.includes('D1 database binding'))).toBe(true);
        });

        it('should fail when required string is empty', () => {
            const env = createValidEnv();
            env.DISCORD_CLIENT_ID = '';

            const result = validateEnv(env);

            expect(result.valid).toBe(false);
            expect(result.errors.some(e => e.includes('DISCORD_CLIENT_ID'))).toBe(true);
        });

        it('should fail when required string is only whitespace', () => {
            const env = createValidEnv();
            env.JWT_SECRET = '   ';

            const result = validateEnv(env);

            expect(result.valid).toBe(false);
            expect(result.errors.some(e => e.includes('JWT_SECRET'))).toBe(true);
        });
    });

    describe('logValidationErrors', () => {
        afterEach(() => {
            vi.restoreAllMocks();
        });

        it('should log all errors to console.error', () => {
            const consoleSpy = vi.spyOn(console, 'error').mockImplementation(() => {});

            const errors = ['Error 1', 'Error 2', 'Error 3'];
            logValidationErrors(errors);

            // First call is the header
            expect(consoleSpy).toHaveBeenCalledWith('Environment validation failed:');
            // Then one call per error
            expect(consoleSpy).toHaveBeenCalledWith('  - Error 1');
            expect(consoleSpy).toHaveBeenCalledWith('  - Error 2');
            expect(consoleSpy).toHaveBeenCalledWith('  - Error 3');
            expect(consoleSpy).toHaveBeenCalledTimes(4);
        });

        it('should handle empty error array', () => {
            const consoleSpy = vi.spyOn(console, 'error').mockImplementation(() => {});

            logValidationErrors([]);

            expect(consoleSpy).toHaveBeenCalledWith('Environment validation failed:');
            expect(consoleSpy).toHaveBeenCalledTimes(1);
        });
    });
});
