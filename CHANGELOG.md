# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.1.0] - 2025-12-07

### Added

#### Testing Infrastructure
- **Comprehensive Test Suite**: 82 tests covering all handlers and services
- **Vitest Configuration**: Testing framework with v8 coverage provider
- **96.6% Code Coverage**: Exceeds 90% target across all metrics
  - 100% coverage on jwt-service.ts, authorize.ts, callback.ts
  - 94%+ coverage on refresh.ts and index.ts
- **Test Scripts**: `npm test`, `npm run test:watch`, `npm run test:coverage`

### Changed
- Added test-related dependencies (vitest, @vitest/coverage-v8)
- Updated tsconfig.json to include @cloudflare/vitest-pool-workers types

## [1.0.0] - 2025-12-07

### Added

#### Authentication Flow
- **PKCE-Secured OAuth**: Proof Key for Code Exchange (PKCE) required for all OAuth flows
- **Discord OAuth Integration**: Full Discord OAuth2 authorization code flow
- **JWT Issuance**: JSON Web Tokens with HS256 signing for authenticated sessions

#### Endpoints
- `GET /auth/discord` - Initiate OAuth flow with PKCE challenge
- `GET /auth/callback` - Handle Discord redirect and token exchange
- `POST /auth/callback` - SPA token exchange (code + code_verifier)
- `POST /auth/refresh` - Refresh JWT within 24-hour grace period
- `GET /auth/me` - Get user info from JWT (Bearer token)
- `POST /auth/revoke` - Logout (client-side token clear)

#### Security
- **PKCE Enforcement**: All flows require code_challenge and code_verifier
- **JWT Claims**: Discord user ID (sub), username, global_name, avatar
- **Refresh Grace Period**: Expired tokens can be refreshed within 24 hours
- **CORS Configuration**: Localhost allowed for development, FRONTEND_URL for production

#### Infrastructure
- **Cloudflare Workers**: Edge deployment with global low-latency
- **Web Crypto API**: Native HS256 JWT signing without external dependencies
- **Hono Framework**: Lightweight routing and middleware
