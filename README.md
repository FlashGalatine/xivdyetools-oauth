# XIV Dye Tools OAuth Worker

**v2.0.0-beta** | Cloudflare Worker that handles OAuth authentication for the XIV Dye Tools ecosystem.

[![TypeScript](https://img.shields.io/badge/TypeScript-5.3%2B-blue)](https://www.typescriptlang.org/)
[![Cloudflare Workers](https://img.shields.io/badge/Cloudflare-Workers-F38020)](https://workers.cloudflare.com/)

## Overview

This Worker provides multi-provider OAuth authentication for the XIV Dye Tools web application. It supports both **Discord** and **XIVAuth** as authentication providers, with D1 database for user management and account merging.

## Features

🔐 **PKCE-Secured OAuth** - Proof Key for Code Exchange for secure authorization
🎫 **JWT Issuance** - JSON Web Tokens with HS256 signing
🔄 **Token Refresh** - 24-hour grace period for expired token refresh
🌐 **CORS Support** - Localhost allowed for development, configurable for production
⚡ **Edge Deployment** - Global low-latency via Cloudflare Workers
🎮 **XIVAuth Support** - Login with FFXIV character (via XIVAuth.net)
🗄️ **D1 Database** - User management and account merging
🔗 **Account Merging** - Link Discord and XIVAuth accounts automatically

## API Endpoints

### Discord OAuth
| Endpoint | Method | Description |
|----------|--------|-------------|
| `/auth/discord` | GET | Start Discord OAuth flow (requires PKCE params) |
| `/auth/callback` | GET | Discord redirect handler |
| `/auth/callback` | POST | SPA token exchange (code + code_verifier) |

### XIVAuth OAuth
| Endpoint | Method | Description |
|----------|--------|-------------|
| `/auth/xivauth` | GET | Start XIVAuth OAuth flow (requires PKCE params) |
| `/auth/xivauth/callback` | GET | XIVAuth redirect handler |
| `/auth/xivauth/callback` | POST | SPA token exchange (code + code_verifier) |

### Common Endpoints
| Endpoint | Method | Description |
|----------|--------|-------------|
| `/auth/refresh` | POST | Refresh JWT (24h grace period) |
| `/auth/me` | GET | Get user info from JWT (Bearer token) |
| `/auth/revoke` | POST | Logout (client-side token clear) |

## OAuth Flow

```
┌──────────────┐     ┌───────────────┐     ┌─────────────┐
│   Frontend   │     │  OAuth Worker │     │   Discord   │
└──────┬───────┘     └───────┬───────┘     └──────┬──────┘
       │                     │                    │
       │  1. Generate PKCE   │                    │
       │     code_verifier   │                    │
       │     code_challenge  │                    │
       │                     │                    │
       │  2. GET /auth/discord ──────────────────►│
       │     + code_challenge                     │
       │                     │                    │
       │                     │◄───── 3. Redirect ─┤
       │                     │     with auth code │
       │                     │                    │
       │  4. Exchange code   │                    │
       │     + code_verifier │                    │
       │                     │                    │
       │◄──── 5. JWT ────────┤                    │
       │                     │                    │
```

## Development

### Prerequisites

- Node.js 18+
- Cloudflare account with Workers enabled
- Discord application with OAuth2 configured

### Setup

1. Install dependencies:
   ```bash
   npm install
   ```

2. Set up secrets:
   ```bash
   wrangler secret put DISCORD_CLIENT_SECRET
   wrangler secret put XIVAUTH_CLIENT_SECRET  # Optional for public client mode
   wrangler secret put JWT_SECRET  # Generate with: openssl rand -hex 32
   ```

3. Set up D1 database:
   ```bash
   wrangler d1 create xivdyetools-users
   # Update wrangler.toml with generated database ID
   wrangler d1 execute xivdyetools-users --file=./schema/users.sql --remote
   ```

4. Start local development server:
   ```bash
   npm run dev
   ```

### Commands

| Command | Description |
|---------|-------------|
| `npm run dev` | Start local dev server (localhost:8788) |
| `npm run deploy` | Deploy to Cloudflare |
| `npm run type-check` | TypeScript validation |

## Environment Variables

### Configured in `wrangler.toml`

| Variable | Description |
|----------|-------------|
| `ENVIRONMENT` | "production" or "development" |
| `DISCORD_CLIENT_ID` | Discord application client ID |
| `XIVAUTH_CLIENT_ID` | XIVAuth application client ID |
| `FRONTEND_URL` | Allowed CORS origin and redirect target |
| `WORKER_URL` | This worker's URL (for JWT issuer claim) |
| `JWT_EXPIRY` | Token lifetime in seconds (default: 3600) |

### D1 Database Binding

| Binding | Description |
|---------|-------------|
| `DB` | D1 database for user management |

### Secrets (via `wrangler secret put`)

| Secret | Description |
|--------|-------------|
| `DISCORD_CLIENT_SECRET` | Discord OAuth client secret |
| `XIVAUTH_CLIENT_SECRET` | XIVAuth OAuth client secret (optional for public client) |
| `JWT_SECRET` | Shared secret for HS256 JWT signing |

## JWT Claims

Issued tokens include:

```json
{
  "sub": "internal_user_uuid",
  "username": "username",
  "global_name": "Display Name",
  "avatar": "avatar_hash",
  "auth_provider": "discord|xivauth",
  "discord_id": "discord_snowflake",
  "xivauth_id": "xivauth_uuid",
  "primary_character": {
    "name": "Character Name",
    "server": "Server Name",
    "verified": true
  },
  "iss": "worker_url",
  "iat": 1234567890,
  "exp": 1234571490,
  "jti": "unique_token_id"
}
```

> Note: `primary_character` is only included for XIVAuth users.

## Architecture

```
src/
├── index.ts              # Hono app, middleware, route mounting
├── types.ts              # TypeScript interfaces
├── handlers/
│   ├── authorize.ts      # GET /auth/discord - Initiates Discord OAuth
│   ├── callback.ts       # Discord token exchange, JWT issuance
│   ├── xivauth.ts        # XIVAuth OAuth endpoints
│   └── refresh.ts        # Token refresh, user info, revoke
└── services/
    ├── jwt-service.ts    # JWT creation/verification (Web Crypto API)
    └── user-service.ts   # D1 user management and account merging

schema/
└── users.sql             # D1 database schema
```

## Related Projects

- **[xivdyetools-web-app](https://github.com/FlashGalatine/xivdyetools)** - Web app that uses this OAuth
- **[xivdyetools-presets-api](https://github.com/FlashGalatine/xivdyetools-presets-api)** - API that verifies these JWTs

## License

MIT © 2025 Flash Galatine

See [LICENSE](./LICENSE) for full details.

## Legal Notice

**This is a fan-made tool and is not affiliated with or endorsed by Square Enix Co., Ltd. FINAL FANTASY is a registered trademark of Square Enix Holdings Co., Ltd.**

## Support

- **Issues**: [GitHub Issues](https://github.com/FlashGalatine/xivdyetools-oauth/issues)
- **Discord**: [Join Server](https://discord.gg/rzxDHNr6Wv)

---

**Made with ❤️ for the FFXIV community**
