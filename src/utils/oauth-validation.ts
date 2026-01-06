/**
 * OAuth Validation Utilities
 * Security validation functions for OAuth flow parameters
 */

import { STATE_EXPIRY_SECONDS } from '../constants/oauth.js';

/**
 * Validate code_verifier format per RFC 7636
 * Must be 43-128 characters using only unreserved characters: [A-Za-z0-9-._~]
 *
 * @param verifier - PKCE code verifier string
 * @returns true if valid, false otherwise
 */
export function validateCodeVerifier(verifier: string): boolean {
  const regex = /^[A-Za-z0-9\-._~]{43,128}$/;
  return regex.test(verifier);
}

/**
 * Validate state expiration timestamp
 * Checks that state parameter has not expired
 *
 * @param state - State object with optional exp field
 * @throws Error if state is expired or missing expiration
 */
export function validateStateExpiration(state: { exp?: number; iat?: number }): void {
  const now = Math.floor(Date.now() / 1000);

  if (!state.exp) {
    throw new Error('State missing expiration timestamp');
  }

  if (state.exp < now) {
    throw new Error('OAuth state expired. Please try logging in again.');
  }
}

/**
 * Validate redirect URI against allowlist
 * Ensures redirect URI origin is in the list of permitted origins
 *
 * @param uri - Redirect URI to validate
 * @param allowedOrigins - Array of permitted origin URLs
 * @throws Error if redirect URI is invalid or not allowed
 */
export function validateRedirectUri(uri: string, allowedOrigins: string[]): void {
  let parsedUri: URL;
  try {
    parsedUri = new URL(uri);
  } catch {
    throw new Error('Invalid redirect URI format');
  }

  const isAllowed = allowedOrigins.some((allowed) => {
    try {
      return new URL(allowed).origin === parsedUri.origin;
    } catch {
      return false;
    }
  });

  if (!isAllowed) {
    throw new Error('Redirect URI not in allowlist');
  }
}

/**
 * Validate that token response contains required scopes
 * Ensures the OAuth token has all necessary permissions
 *
 * @param tokenScope - Scope string from token response (space-separated)
 * @param requiredScopes - Array of required scope strings
 * @throws Error if required scopes are missing
 */
export function validateScopes(
  tokenScope: string | undefined,
  requiredScopes: string[]
): void {
  if (!tokenScope) {
    throw new Error('Token response missing scope field');
  }

  const scopes = tokenScope.split(' ');
  const missingScopes = requiredScopes.filter((req) => !scopes.includes(req));

  if (missingScopes.length > 0) {
    throw new Error(`Token missing required scopes: ${missingScopes.join(', ')}`);
  }
}
