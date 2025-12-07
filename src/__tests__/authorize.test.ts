/**
 * Authorize Handler Tests
 * Tests for the OAuth authorization flow initiation
 */

import { describe, it, expect } from 'vitest';
import { SELF } from './mocks/cloudflare-test.js';

describe('Authorize Handler', () => {
    describe('GET /auth/discord', () => {
        it('should require code_challenge parameter', async () => {
            const response = await SELF.fetch('http://localhost/auth/discord?code_verifier=test123');
            const json = await response.json();

            expect(response.status).toBe(400);
            expect(json.error).toBe('Missing code_challenge');
        });

        it('should require code_verifier parameter', async () => {
            const response = await SELF.fetch('http://localhost/auth/discord?code_challenge=test123');
            const json = await response.json();

            expect(response.status).toBe(400);
            expect(json.error).toBe('Missing code_verifier');
        });

        it('should reject invalid code_challenge_method', async () => {
            const params = new URLSearchParams({
                code_challenge: 'challenge123',
                code_verifier: 'verifier123',
                code_challenge_method: 'plain',
            });

            const response = await SELF.fetch(`http://localhost/auth/discord?${params}`);
            const json = await response.json();

            expect(response.status).toBe(400);
            expect(json.error).toBe('Invalid code_challenge_method');
            expect(json.message).toContain('S256');
        });

        it('should accept S256 code_challenge_method', async () => {
            const params = new URLSearchParams({
                code_challenge: 'challenge123',
                code_verifier: 'verifier123',
                code_challenge_method: 'S256',
            });

            const response = await SELF.fetch(`http://localhost/auth/discord?${params}`, {
                redirect: 'manual',
            });

            expect(response.status).toBe(302);
        });

        it('should reject disallowed redirect_uri', async () => {
            const params = new URLSearchParams({
                code_challenge: 'challenge123',
                code_verifier: 'verifier123',
                redirect_uri: 'http://evil.com/callback',
            });

            const response = await SELF.fetch(`http://localhost/auth/discord?${params}`);
            const json = await response.json();

            expect(response.status).toBe(400);
            expect(json.error).toBe('Invalid redirect_uri');
        });

        it('should allow localhost redirect_uri', async () => {
            const params = new URLSearchParams({
                code_challenge: 'challenge123',
                code_verifier: 'verifier123',
                redirect_uri: 'http://localhost:5173/auth/callback',
            });

            const response = await SELF.fetch(`http://localhost/auth/discord?${params}`, {
                redirect: 'manual',
            });

            expect(response.status).toBe(302);
        });

        it('should redirect to Discord OAuth URL', async () => {
            const params = new URLSearchParams({
                code_challenge: 'challenge123',
                code_verifier: 'verifier123',
            });

            const response = await SELF.fetch(`http://localhost/auth/discord?${params}`, {
                redirect: 'manual',
            });

            expect(response.status).toBe(302);

            const location = response.headers.get('location');
            expect(location).toContain('https://discord.com/oauth2/authorize');
            expect(location).toContain('client_id=');
            expect(location).toContain('code_challenge=challenge123');
        });

        it('should include scope=identify in Discord URL', async () => {
            const params = new URLSearchParams({
                code_challenge: 'challenge123',
                code_verifier: 'verifier123',
            });

            const response = await SELF.fetch(`http://localhost/auth/discord?${params}`, {
                redirect: 'manual',
            });

            const location = response.headers.get('location');
            expect(location).toContain('scope=identify');
        });

        it('should encode state with PKCE and redirect info', async () => {
            const params = new URLSearchParams({
                code_challenge: 'challenge123',
                code_verifier: 'verifier123',
                return_path: '/settings',
            });

            const response = await SELF.fetch(`http://localhost/auth/discord?${params}`, {
                redirect: 'manual',
            });

            const location = new URL(response.headers.get('location')!);
            const state = location.searchParams.get('state');
            expect(state).toBeTruthy();

            // Decode base64 state
            const decodedState = JSON.parse(atob(state!));
            expect(decodedState.code_challenge).toBe('challenge123');
            expect(decodedState.code_verifier).toBe('verifier123');
            expect(decodedState.return_path).toBe('/settings');
        });

        it('should use default return_path when not provided', async () => {
            const params = new URLSearchParams({
                code_challenge: 'challenge123',
                code_verifier: 'verifier123',
            });

            const response = await SELF.fetch(`http://localhost/auth/discord?${params}`, {
                redirect: 'manual',
            });

            const location = new URL(response.headers.get('location')!);
            const state = location.searchParams.get('state');
            const decodedState = JSON.parse(atob(state!));

            expect(decodedState.return_path).toBe('/');
        });

        it('should include code_challenge_method in Discord URL', async () => {
            const params = new URLSearchParams({
                code_challenge: 'challenge123',
                code_verifier: 'verifier123',
            });

            const response = await SELF.fetch(`http://localhost/auth/discord?${params}`, {
                redirect: 'manual',
            });

            const location = response.headers.get('location');
            expect(location).toContain('code_challenge_method=S256');
        });

        it('should allow xivdyetools.projectgalatine.com redirect', async () => {
            const params = new URLSearchParams({
                code_challenge: 'challenge123',
                code_verifier: 'verifier123',
                redirect_uri: 'https://xivdyetools.projectgalatine.com/auth/callback',
            });

            const response = await SELF.fetch(`http://localhost/auth/discord?${params}`, {
                redirect: 'manual',
            });

            expect(response.status).toBe(302);
        });
    });
});
