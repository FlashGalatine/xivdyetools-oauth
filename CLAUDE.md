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

Configured in `wrangler.toml`:
- `ENVIRONMENT` - "production" or "development"
- `DISCORD_CLIENT_ID` - Discord application client ID
- `FRONTEND_URL` - Allowed CORS origin and redirect target
- `WORKER_URL` - This worker's URL (for JWT issuer claim)
- `JWT_EXPIRY` - Token lifetime in seconds (default: 3600)

Secrets (set via `wrangler secret put`):
- `DISCORD_CLIENT_SECRET` - Discord OAuth client secret
- `JWT_SECRET` - Shared secret for HS256 JWT signing

## Key Implementation Details

- **PKCE Required**: All OAuth flows require code_challenge and code_verifier for security
- **JWT Claims**: Includes Discord user ID (sub), username, global_name, avatar
- **Refresh Grace Period**: Expired tokens can be refreshed within 24 hours
- **CORS**: Allows localhost:* for development, FRONTEND_URL for production
