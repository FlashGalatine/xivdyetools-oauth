/**
 * Environment Variable Validation
 *
 * Validates required environment variables at startup to catch
 * configuration errors early rather than failing at request time.
 */

import type { Env } from '../types.js';

export interface EnvValidationResult {
  valid: boolean;
  errors: string[];
}

/**
 * Validates all required environment variables for the OAuth worker.
 *
 * Required variables:
 * - ENVIRONMENT: Runtime environment (development/production)
 * - DISCORD_CLIENT_ID: Discord OAuth application ID
 * - DISCORD_CLIENT_SECRET: Discord OAuth secret
 * - XIVAUTH_CLIENT_ID: XIVAuth OAuth application ID
 * - JWT_SECRET: Secret for signing JWTs
 * - JWT_EXPIRY: Token expiration time (must be parseable as number)
 * - FRONTEND_URL: Web app URL for redirects
 * - WORKER_URL: This worker's public URL
 * - DB: D1 database binding
 */
export function validateEnv(env: Env): EnvValidationResult {
  const errors: string[] = [];

  // Check required string environment variables
  const requiredStrings: Array<keyof Env> = [
    'ENVIRONMENT',
    'DISCORD_CLIENT_ID',
    'DISCORD_CLIENT_SECRET',
    'XIVAUTH_CLIENT_ID',
    'JWT_SECRET',
    'JWT_EXPIRY',
    'FRONTEND_URL',
    'WORKER_URL',
  ];

  for (const key of requiredStrings) {
    const value = env[key];
    if (!value || typeof value !== 'string' || value.trim() === '') {
      errors.push(`Missing or empty required env var: ${key}`);
    }
  }

  // OAUTH-MED-001: Validate JWT_SECRET has sufficient length for security
  if (env.JWT_SECRET && typeof env.JWT_SECRET === 'string') {
    if (env.JWT_SECRET.length < 32) {
      errors.push('JWT_SECRET must be at least 32 characters for security');
    }
  }

  // Validate JWT_EXPIRY is a valid number
  if (env.JWT_EXPIRY) {
    const expiry = parseInt(env.JWT_EXPIRY, 10);
    if (isNaN(expiry) || expiry <= 0) {
      errors.push(`JWT_EXPIRY must be a positive number, got: ${env.JWT_EXPIRY}`);
    }
  }

  // Validate URL format for URL variables
  const urlVars: Array<keyof Env> = ['FRONTEND_URL', 'WORKER_URL'];
  for (const key of urlVars) {
    const value = env[key];
    if (value && typeof value === 'string') {
      try {
        const url = new URL(value);
        // Ensure URLs use HTTPS in production
        if (env.ENVIRONMENT === 'production' && url.protocol !== 'https:') {
          errors.push(`${key} must use HTTPS in production: ${value}`);
        }
      } catch {
        errors.push(`Invalid URL for ${key}: ${value}`);
      }
    }
  }

  // Check D1 database binding
  if (!env.DB) {
    errors.push('Missing required D1 database binding: DB');
  }

  return {
    valid: errors.length === 0,
    errors,
  };
}

/**
 * Logs validation errors to console.
 * Used by the validation middleware for debugging.
 */
export function logValidationErrors(errors: string[]): void {
  console.error('Environment validation failed:');
  for (const error of errors) {
    console.error(`  - ${error}`);
  }
}
