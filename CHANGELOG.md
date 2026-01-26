# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [2.3.2] - 2026-01-25

### Refactored

- **OAUTH-REF-003**: Deduplicated base64URL decode function (REFACTOR-001)
  - Exported `base64UrlDecode` from `jwt-service.ts`
  - Updated `state-signing.ts` to import from jwt-service instead of duplicating
  - Reduces code duplication and ensures single source of truth within oauth project

---

## [2.3.1] - 2026-01-25

### Security

- **FINDING-004**: Updated `hono` to ^4.11.4 to fix JWT algorithm confusion vulnerability (CVSS 8.2)
- **FINDING-005**: Updated `wrangler` to ^4.59.1 to fix OS command injection in `wrangler pages deploy`
- **FINDING-006**: Updated `devalue` transitive dependency to fix DoS vulnerability (CVSS 7.5)

---

## [2.3.0] - 2026-01-19

### Fixed

- **OAUTH-BUG-001**: Fixed potential call stack overflow in JWT service. Replaced string spread with `charCodeAt` (which could fail on large arrays) with `Array.from().map().join()` pattern for safer encoding

### Refactored

- **OAUTH-REF-002**: Consolidated OAuth validation utilities
  - Created `src/utils/oauth-validation.ts` with shared helpers
  - `validateCodeChallenge()` - RFC 7636 format validation
  - `validateRedirectUri()` - Origin allowlist validation
  - `ALLOWED_REDIRECT_ORIGINS` constant in `constants/oauth.ts`
  - Refactored both Discord and XIVAuth handlers to use shared utilities

---

## [2.2.2] - 2025-12-24

### Changed

- Updated `@xivdyetools/types` to ^1.1.1 for ecosystem consistency
- Updated `@xivdyetools/logger` to ^1.0.2 for ecosystem consistency

### Fixed

- Fixed type errors related to JWT payload requiring `auth_provider` field
- Fixed type errors related to XIVAuthCharacter using `home_world` instead of `server`
- Added missing JWT payload fields in token refresh (`discord_id`, `xivauth_id`, `primary_character`)

---

## [2.2.1] - 2025-12-24

### Fixed

#### Security Audit - High Priority Issues Resolved

- **OAUTH-HIGH-001**: Added timeouts to external Discord API calls
  - Token exchange request: 10 second timeout
  - User info fetch: 5 second timeout
  - Prevents worker hang if Discord API is slow or unresponsive

---

## [2.2.0] - 2025-12-24

### Fixed

#### Security Audit - Critical Issues Resolved

- **OAUTH-CRITICAL-001**: Separated base64 decoding from JSON parsing in OAuth state handling
  - Better error diagnostics: "Invalid state encoding" vs "Invalid state format"
  - Helps distinguish between corrupted state and malformed data
- **OAUTH-CRITICAL-002**: Fixed open redirect vulnerability in OAuth callback
  - Validates redirect_uri origin against allowed origins (FRONTEND_URL)
  - Blocks redirects to untrusted domains after successful authentication
  - Allows localhost origins only in development environment

---

## [2.1.0] - 2025-12-14

### Added

- **Structured Logging**: Added structured request logger middleware using `@xivdyetools/logger/worker`
- **Shared Package Integration**: Migrated to `@xivdyetools/types` and `@xivdyetools/logger` for ecosystem consistency
- **Test Utils Integration**: Migrated tests to use `@xivdyetools/test-utils` shared package

### Changed

- **JWT Utilities**: Extracted shared JWT utilities for better code organization (OAUTH-REF-002)

### Fixed

- **Security**: Added PKCE parameter format validation per RFC 7636
- **Security**: Added state expiration and scope validation
- **Security**: Added cross-cutting security improvements
- **CORS**: Restricted localhost CORS to specific ports (OAUTH-SEC-001)
- **Medium Severity**: Addressed MEDIUM severity audit findings
- **Tests**: Updated tests to use valid PKCE values per RFC 7636

### Deprecated

#### Type Re-exports
The following re-exports from `src/types.ts` are deprecated and will be removed in the next major version:

- **Auth Provider Types**: Import from `@xivdyetools/types` instead
- **JWT Types** (JWTPayload, OAuthState, etc.): Import from `@xivdyetools/types` instead
- **Discord Types** (DiscordTokenResponse, DiscordUser): Import from `@xivdyetools/types` instead
- **XIVAuth Types**: Import from `@xivdyetools/types` instead
- **Response Types** (AuthResponse, RefreshResponse, etc.): Import from `@xivdyetools/types` instead

**Note:** Project-specific types (Env, UserRow) remain unchanged.

**Migration Guide:**
```typescript
// Before (deprecated)
import { AuthProvider, JWTPayload, AuthResponse } from './types';

// After (recommended)
import type { AuthProvider, JWTPayload, AuthResponse } from '@xivdyetools/types';
```

---

## [2.0.1-beta] - 2025-12-13

### Fixed

#### XIVAuth Integration Bug Fixes
- **406 Not Acceptable Error**: Added required `Accept: application/json` header to XIVAuth API calls (Rails API requirement)
- **Response Format Mismatch**: Updated types and handler to match actual XIVAuth API response structure
  - XIVAuth user endpoint returns `social_identities[]` array, not `social.discord` object
  - XIVAuth user endpoint does NOT return `username` or `avatar_url` fields
  - `verified_characters` is a boolean, not an array
- **Separate Characters Fetch**: Characters must be fetched from `/api/v1/characters` endpoint (not included in user response)
- **D1 Database Error**: Fixed `undefined` values being passed to D1 by providing proper fallbacks
- **Username Handling**: Now uses primary character name as username, or `XIVAuth User {id}` as fallback
- **Field Mapping**: Properly map XIVAuth's `home_world` field to `server`

### Changed
- Updated `XIVAuthUser` type to match actual API response structure
- Added `XIVAuthSocialIdentity` type for the social identities array
- Added `XIVAuthCharacterRegistration` type for characters endpoint response
- Enhanced logging for debugging XIVAuth integration issues

## [2.0.0-beta] - 2025-12-13

### Added

#### XIVAuth OAuth Provider
- **XIVAuth Integration**: Second OAuth provider alongside Discord
- **GET /auth/xivauth**: Initiate XIVAuth OAuth flow with PKCE
- **GET /auth/xivauth/callback**: Handle XIVAuth redirect
- **POST /auth/xivauth/callback**: Exchange code for tokens with PKCE verification
- **Scopes Supported**: `user`, `user:social`, `character`, `refresh`
- **Character Info**: Primary FFXIV character included in JWT for XIVAuth users

#### D1 Database Integration
- **User Management**: Cloudflare D1 database for persistent user storage
- **User Service**: `findOrCreateUser()`, `findUserById()`, `storeCharacters()`
- **Account Merging**: Automatic account linking when Discord ID matches between providers
- **Schema**: `users` table (id, discord_id, xivauth_id, auth_provider, username, avatar_url)
- **Schema**: `xivauth_characters` table (lodestone_id, name, server, verified)

#### Multi-Provider JWT Support
- **createJWTForUser()**: New JWT creation function supporting both providers
- **Extended Payload**: `auth_provider`, `discord_id`, `xivauth_id`, `primary_character` claims
- **Provider Detection**: Automatic provider identification from token

### Changed

- **Discord Callback**: Updated to use D1 database and `createJWTForUser()`
- **Internal User IDs**: JWT `sub` claim now uses internal UUID instead of Discord ID
- **Optional Client Secret**: XIVAuth supports public client mode (PKCE-only)

### Technical Details

- **Cloudflare D1**: SQLite-compatible database at the edge
- **PKCE Security**: Required for both Discord and XIVAuth flows
- **Confidential Client**: Optional client secret for XIVAuth (recommended for server-side)

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
