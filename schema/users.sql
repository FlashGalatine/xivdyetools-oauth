-- XIV Dye Tools Users Database Schema
-- Supports multiple OAuth providers (Discord, XIVAuth)

-- Users table: stores authenticated users from any provider
CREATE TABLE IF NOT EXISTS users (
  id TEXT PRIMARY KEY,                      -- UUID v4, our internal user ID
  discord_id TEXT,                          -- Discord snowflake (nullable)
  xivauth_id TEXT,                          -- XIVAuth UUID (nullable)
  auth_provider TEXT NOT NULL,              -- Last used: 'discord' | 'xivauth'
  username TEXT NOT NULL,                   -- Display name
  avatar_url TEXT,                          -- Avatar URL
  created_at TEXT DEFAULT (datetime('now')),
  updated_at TEXT DEFAULT (datetime('now')),

  -- Constraint: at least one provider ID must be set
  CHECK (discord_id IS NOT NULL OR xivauth_id IS NOT NULL)
);

-- Indexes for fast lookups by provider ID
CREATE UNIQUE INDEX IF NOT EXISTS idx_users_discord_id ON users(discord_id) WHERE discord_id IS NOT NULL;
CREATE UNIQUE INDEX IF NOT EXISTS idx_users_xivauth_id ON users(xivauth_id) WHERE xivauth_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_users_auth_provider ON users(auth_provider);

-- XIVAuth characters table (stores FFXIV character info for XIVAuth users)
CREATE TABLE IF NOT EXISTS xivauth_characters (
  user_id TEXT NOT NULL,
  lodestone_id INTEGER NOT NULL,            -- FFXIV Lodestone character ID
  name TEXT NOT NULL,                       -- Character name (e.g., "Firstname Lastname")
  server TEXT NOT NULL,                     -- Server name (e.g., "Gilgamesh")
  verified INTEGER DEFAULT 0,               -- SQLite boolean: 1 = verified on Lodestone
  PRIMARY KEY (user_id, lodestone_id),
  FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

-- Index for looking up characters by user
CREATE INDEX IF NOT EXISTS idx_characters_user_id ON xivauth_characters(user_id);
