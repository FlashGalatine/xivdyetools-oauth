# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Cloudflare Worker that handles Discord OAuth authentication for the XIV Dye Tools ecosystem. Issues JWTs for authenticated users that can be verified by other services (web app, presets worker).

## Commands

```bash
npm run dev                  # Start local dev server (localhost:8788)
npm run dev -- --env development  # Run with development environment
npm run deploy               # Deploy to Cloudflare (production)
npm run type-check           # TypeScript validation
```

### Secrets Management

```bash
wrangler secret put DISCORD_CLIENT_SECRET  # Set Discord OAuth secret
wrangler secret put JWT_SECRET             # Set JWT signing key (openssl rand -hex 32)
```

### Pre-commit Checklist
```bash
npm run type-check
```

## Architecture

```
src/
├── index.ts                 # Hono app, middleware, route mounting
├── types.ts                 # TypeScript interfaces (Env, Discord types, JWT payload)
├── handlers/
│   ├── authorize.ts         # GET /auth/discord - Initiates OAuth with PKCE
│   ├── callback.ts          # GET|POST /auth/callback - Token exchange, JWT issuance
│   └── refresh.ts           # POST /auth/refresh, GET /auth/me, POST /auth/revoke
└── services/
    └── jwt-service.ts       # JWT creation/verification using Web Crypto API (HS256)
```

### OAuth Flow

1. Frontend generates PKCE code_verifier and code_challenge
2. `GET /auth/discord` - Redirects to Discord with PKCE challenge
3. Discord redirects back to `GET /auth/callback` with authorization code
4. Worker exchanges code for Discord tokens (with PKCE verifier)
5. Worker fetches Discord user info and creates JWT
6. Redirects to frontend with JWT in query params

### API Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/auth/discord` | GET | Start OAuth flow (requires PKCE params) |
| `/auth/callback` | GET | Discord redirect handler |
| `/auth/callback` | POST | SPA token exchange (code + code_verifier) |
| `/auth/refresh` | POST | Refresh JWT (24h grace period) |
| `/auth/me` | GET | Get user info from JWT (Bearer token) |
| `/auth/revoke` | POST | Logout (client-side token clear) |

## Environment Variables

### Configuration (wrangler.toml)

| Variable | Description |
|----------|-------------|
| `ENVIRONMENT` | "production" or "development" |
| `DISCORD_CLIENT_ID` | Discord application client ID |
| `FRONTEND_URL` | Allowed CORS origin and redirect target |
| `WORKER_URL` | This worker's URL (for JWT issuer claim) |
| `JWT_EXPIRY` | Token lifetime in seconds (default: 3600) |

### Secrets (wrangler secret put)

| Secret | Description |
|--------|-------------|
| `DISCORD_CLIENT_SECRET` | Discord OAuth client secret |
| `JWT_SECRET` | Shared secret for HS256 JWT signing |

## Key Implementation Details

- **PKCE Required**: All OAuth flows require code_challenge and code_verifier for security
- **JWT Claims**: Includes Discord user ID (sub), username, global_name, avatar
- **Refresh Grace Period**: Expired tokens can be refreshed within 24 hours
- **CORS**: Allows localhost:* for development, FRONTEND_URL for production

## Testing

```bash
npm run test                 # Run all tests (if configured)
npx vitest run src/handlers/callback.test.ts  # Single file
```

Test files use `@xivdyetools/test-utils` for JWT and auth context mocking.

## Security Patterns

### PKCE Validation

All OAuth flows enforce PKCE (Proof Key for Code Exchange):
- **Code challenge**: 43-128 base64url characters (`/^[A-Za-z0-9\-_]{43,128}$/`)
- **Code verifier**: 43-128 unreserved characters (`/^[A-Za-z0-9\-._~]{43,128}$/`)
- Verifier sent only via POST body (never in URL)

### State Parameter Protection

HMAC-SHA256 signed state parameters prevent CSRF:
- Format: `base64url(json).signature`
- Expiration: 10 minutes (`STATE_EXPIRY_SECONDS = 600`)
- Validates signature before processing callback

### JWT Security (HS256)

- Uses Web Crypto API with HMAC-SHA256
- Includes JWT ID (jti) for revocation tracking
- Token revocation via KV-based blacklist with TTL matching expiry
- Revocation check on `/auth/me` and token refresh

### Redirect URI Validation

Prevents open redirect attacks:
- Whitelisted allowed origins only
- Validates both URL format and origin match
- Rejects unknown redirect targets

### Request Timeouts

Prevents worker hang on slow external APIs:
- Token exchange: 10 seconds
- User info fetch: 5 seconds

### Scope Validation

- Discord requires 'identify' scope
- XIVAuth requires 'user' and 'character' scopes
- Tokens missing required scopes are rejected

## Related Projects

**Dependencies:**
- `@xivdyetools/types` - Shared type definitions
- `@xivdyetools/logger` - Structured logging

**Consumers (share JWT_SECRET):**
- xivdyetools-presets-api - Verifies JWTs for web auth
- xivdyetools-web-app - Initiates OAuth flow, stores tokens

## Deployment Checklist

1. Ensure secrets are set:
   - `wrangler secret put DISCORD_CLIENT_SECRET`
   - `wrangler secret put JWT_SECRET`
2. Verify `wrangler.toml` has correct `FRONTEND_URL` and `WORKER_URL`
3. Deploy: `npm run deploy`
4. Test OAuth flow from web app (staging → production)
5. Verify `/auth/me` returns user info with valid JWT
