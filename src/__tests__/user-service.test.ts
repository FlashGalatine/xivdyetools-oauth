/**
 * User Service Tests
 * Tests for user database operations: findOrCreate, find by ID, store/get characters
 */

import { describe, it, expect, beforeEach } from 'vitest';
import {
    findOrCreateUser,
    findUserById,
    findUserByDiscordId,
    findUserByXIVAuthId,
    storeCharacters,
    getCharacters,
} from '../services/user-service.js';
import type { UserRow, XIVAuthCharacter } from '../types.js';

/**
 * Creates a mock D1Database for testing user service operations
 * This is a more complete mock than the one in cloudflare-test.ts
 */
const createTestDB = () => {
    const users = new Map<string, UserRow>();
    const characters = new Map<string, XIVAuthCharacter[]>();

    const createStatement = (sql: string) => {
        let boundParams: unknown[] = [];

        const statement = {
            bind: (...params: unknown[]) => {
                boundParams = params;
                return statement;
            },
            first: async <T>(): Promise<T | null> => {
                // SELECT by xivauth_id
                if (sql.includes('SELECT') && sql.includes('xivauth_id = ?')) {
                    const xivauthId = boundParams[0] as string;
                    for (const user of users.values()) {
                        if (user.xivauth_id === xivauthId) {
                            return user as T;
                        }
                    }
                    return null;
                }
                // SELECT by discord_id
                if (sql.includes('SELECT') && sql.includes('discord_id = ?')) {
                    const discordId = boundParams[0] as string;
                    for (const user of users.values()) {
                        if (user.discord_id === discordId) {
                            return user as T;
                        }
                    }
                    return null;
                }
                // SELECT by id (used in updateUser and findUserById)
                if (sql.includes('SELECT') && sql.includes('WHERE id = ?')) {
                    const userId = boundParams[boundParams.length - 1] as string;
                    return (users.get(userId) as T) || null;
                }
                return null;
            },
            run: async () => {
                // INSERT new user
                if (sql.includes('INSERT INTO users')) {
                    const [id, discord_id, xivauth_id, auth_provider, username, avatar_url] =
                        boundParams as [string, string | null, string | null, string, string, string | null];
                    const now = new Date().toISOString();
                    users.set(id, {
                        id,
                        discord_id,
                        xivauth_id,
                        auth_provider,
                        username,
                        avatar_url,
                        created_at: now,
                        updated_at: now,
                    });
                    return { success: true, meta: {} };
                }
                // UPDATE user
                if (sql.includes('UPDATE users')) {
                    const userId = boundParams[boundParams.length - 1] as string;
                    const existing = users.get(userId);
                    if (existing) {
                        // Parse the SET clause to get field values
                        // The bound params are in order: field values, then userId
                        const setFields = sql.match(/SET (.+) WHERE/)?.[1] || '';
                        const fieldNames = setFields.split(', ').map(f => f.split(' = ')[0]);

                        let paramIndex = 0;
                        for (const field of fieldNames) {
                            if (field === "updated_at") continue; // Skip datetime('now')
                            const value = boundParams[paramIndex] as string | null;
                            (existing as Record<string, unknown>)[field] = value;
                            paramIndex++;
                        }
                        existing.updated_at = new Date().toISOString();
                    }
                    return { success: true, meta: {} };
                }
                // DELETE characters
                if (sql.includes('DELETE FROM xivauth_characters')) {
                    const userId = boundParams[0] as string;
                    characters.delete(userId);
                    return { success: true, meta: {} };
                }
                // INSERT character
                if (sql.includes('INSERT INTO xivauth_characters')) {
                    const [userId, lodestone_id, name, server, verified] = boundParams as [
                        string,
                        number,
                        string,
                        string,
                        number
                    ];
                    const userChars = characters.get(userId) || [];
                    userChars.push({
                        id: lodestone_id,
                        name,
                        server,
                        verified: verified === 1,
                    });
                    characters.set(userId, userChars);
                    return { success: true, meta: {} };
                }
                return { success: true, meta: {} };
            },
            all: async <T>(): Promise<D1Result<T>> => {
                // SELECT characters for user
                if (sql.includes('SELECT') && sql.includes('xivauth_characters')) {
                    const userId = boundParams[0] as string;
                    const userChars = characters.get(userId) || [];
                    const results = userChars.map((c) => ({
                        lodestone_id: c.id,
                        name: c.name,
                        server: c.server,
                        verified: c.verified ? 1 : 0,
                    }));
                    return { results: results as T[], success: true, meta: {} as D1Meta };
                }
                return { results: [] as T[], success: true, meta: {} as D1Meta };
            },
        };
        return statement;
    };

    return {
        _users: users,
        _characters: characters,
        prepare: (sql: string) => createStatement(sql),
        exec: async () => ({ count: 0, duration: 0 }),
        batch: async () => [],
        dump: async () => new ArrayBuffer(0),
    } as unknown as D1Database & {
        _users: Map<string, UserRow>;
        _characters: Map<string, XIVAuthCharacter[]>;
    };
};

describe('User Service', () => {
    let db: ReturnType<typeof createTestDB>;

    beforeEach(() => {
        db = createTestDB();
    });

    describe('findOrCreateUser', () => {
        it('should create a new user when none exists', async () => {
            const user = await findOrCreateUser(db, {
                discord_id: '123456789',
                username: 'testuser',
                avatar_url: 'https://cdn.discordapp.com/avatars/123/abc.png',
                auth_provider: 'discord',
            });

            expect(user.id).toBeTruthy();
            expect(user.id).toMatch(/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i);
            expect(user.discord_id).toBe('123456789');
            expect(user.username).toBe('testuser');
            expect(user.auth_provider).toBe('discord');
        });

        it('should find existing user by xivauth_id', async () => {
            // Create user first
            const created = await findOrCreateUser(db, {
                xivauth_id: 'xivauth-uuid',
                username: 'original',
                auth_provider: 'xivauth',
            });

            // Try to create again - should find existing
            const found = await findOrCreateUser(db, {
                xivauth_id: 'xivauth-uuid',
                username: 'updated',
                auth_provider: 'xivauth',
            });

            expect(found.id).toBe(created.id);
            expect(found.username).toBe('updated');
        });

        it('should find existing user by discord_id', async () => {
            // Create user with Discord
            const created = await findOrCreateUser(db, {
                discord_id: '987654321',
                username: 'discorduser',
                auth_provider: 'discord',
            });

            // Try to find by discord_id
            const found = await findOrCreateUser(db, {
                discord_id: '987654321',
                username: 'discorduser_updated',
                auth_provider: 'discord',
            });

            expect(found.id).toBe(created.id);
        });

        it('should merge accounts when XIVAuth user has linked Discord', async () => {
            // Create user via Discord first
            const discordUser = await findOrCreateUser(db, {
                discord_id: '111222333',
                username: 'discorduser',
                avatar_url: 'https://cdn.discordapp.com/avatars/111/def.png',
                auth_provider: 'discord',
            });

            // Now login via XIVAuth with same Discord ID linked
            const mergedUser = await findOrCreateUser(db, {
                xivauth_id: 'new-xivauth-id',
                discord_id: '111222333', // Same Discord ID
                username: 'Character Name',
                auth_provider: 'xivauth',
            });

            // Should be same user
            expect(mergedUser.id).toBe(discordUser.id);
            // Should have both IDs
            expect(mergedUser.xivauth_id).toBe('new-xivauth-id');
            expect(mergedUser.discord_id).toBe('111222333');
        });

        it('should handle null optional fields', async () => {
            const user = await findOrCreateUser(db, {
                discord_id: '555666777',
                username: 'user',
                avatar_url: null,
                auth_provider: 'discord',
            });

            expect(user.avatar_url).toBeNull();
            expect(user.xivauth_id).toBeNull();
        });

        it('should preserve existing xivauth_id when logging in via Discord', async () => {
            // Create user via XIVAuth first
            const xivauthUser = await findOrCreateUser(db, {
                xivauth_id: 'original-xivauth-id',
                discord_id: '444555666',
                username: 'xivauthuser',
                auth_provider: 'xivauth',
            });

            // Login via Discord with same Discord ID
            const discordLogin = await findOrCreateUser(db, {
                discord_id: '444555666',
                username: 'discordlogin',
                auth_provider: 'discord',
            });

            // Should preserve xivauth_id
            expect(discordLogin.id).toBe(xivauthUser.id);
            expect(discordLogin.xivauth_id).toBe('original-xivauth-id');
        });
    });

    describe('findUserById', () => {
        it('should find user by internal ID', async () => {
            const created = await findOrCreateUser(db, {
                discord_id: '123',
                username: 'test',
                auth_provider: 'discord',
            });

            const found = await findUserById(db, created.id);

            expect(found).not.toBeNull();
            expect(found!.id).toBe(created.id);
            expect(found!.username).toBe('test');
        });

        it('should return null for non-existent ID', async () => {
            const found = await findUserById(db, 'non-existent-uuid');

            expect(found).toBeNull();
        });
    });

    describe('findUserByDiscordId', () => {
        it('should find user by Discord ID', async () => {
            await findOrCreateUser(db, {
                discord_id: 'discord-123',
                username: 'discordtest',
                auth_provider: 'discord',
            });

            const found = await findUserByDiscordId(db, 'discord-123');

            expect(found).not.toBeNull();
            expect(found!.discord_id).toBe('discord-123');
        });

        it('should return null for non-existent Discord ID', async () => {
            const found = await findUserByDiscordId(db, 'non-existent-discord');

            expect(found).toBeNull();
        });
    });

    describe('findUserByXIVAuthId', () => {
        it('should find user by XIVAuth ID', async () => {
            await findOrCreateUser(db, {
                xivauth_id: 'xivauth-456',
                username: 'xivauthtest',
                auth_provider: 'xivauth',
            });

            const found = await findUserByXIVAuthId(db, 'xivauth-456');

            expect(found).not.toBeNull();
            expect(found!.xivauth_id).toBe('xivauth-456');
        });

        it('should return null for non-existent XIVAuth ID', async () => {
            const found = await findUserByXIVAuthId(db, 'non-existent-xivauth');

            expect(found).toBeNull();
        });
    });

    describe('storeCharacters', () => {
        it('should store characters for a user', async () => {
            const user = await findOrCreateUser(db, {
                xivauth_id: 'user-with-chars',
                username: 'charuser',
                auth_provider: 'xivauth',
            });

            const characters: XIVAuthCharacter[] = [
                { id: 12345678, name: 'Main Character', server: 'Excalibur', verified: true },
                { id: 87654321, name: 'Alt Character', server: 'Balmung', verified: false },
            ];

            await storeCharacters(db, user.id, characters);

            // Verify characters were stored
            const stored = await getCharacters(db, user.id);
            expect(stored).toHaveLength(2);
            expect(stored[0].name).toBe('Main Character');
            expect(stored[1].name).toBe('Alt Character');
        });

        it('should replace existing characters', async () => {
            const user = await findOrCreateUser(db, {
                xivauth_id: 'user-replace-chars',
                username: 'replaceuser',
                auth_provider: 'xivauth',
            });

            // Store initial characters
            await storeCharacters(db, user.id, [
                { id: 11111111, name: 'Old Character', server: 'Gilgamesh', verified: true },
            ]);

            // Store new characters (should replace)
            await storeCharacters(db, user.id, [
                { id: 22222222, name: 'New Character', server: 'Cactuar', verified: false },
            ]);

            const stored = await getCharacters(db, user.id);
            expect(stored).toHaveLength(1);
            expect(stored[0].name).toBe('New Character');
        });

        it('should handle empty character array', async () => {
            const user = await findOrCreateUser(db, {
                xivauth_id: 'user-no-chars',
                username: 'nochars',
                auth_provider: 'xivauth',
            });

            await storeCharacters(db, user.id, []);

            const stored = await getCharacters(db, user.id);
            expect(stored).toHaveLength(0);
        });
    });

    describe('getCharacters', () => {
        it('should return empty array for user with no characters', async () => {
            const user = await findOrCreateUser(db, {
                discord_id: 'discord-no-chars',
                username: 'nocharuser',
                auth_provider: 'discord',
            });

            const chars = await getCharacters(db, user.id);

            expect(chars).toEqual([]);
        });

        it('should return characters with correct structure', async () => {
            const user = await findOrCreateUser(db, {
                xivauth_id: 'user-structured-chars',
                username: 'structuser',
                auth_provider: 'xivauth',
            });

            await storeCharacters(db, user.id, [
                { id: 99999999, name: 'Test Character', server: 'Tonberry', verified: true },
            ]);

            const chars = await getCharacters(db, user.id);

            expect(chars).toHaveLength(1);
            expect(chars[0]).toMatchObject({
                id: 99999999,
                name: 'Test Character',
                server: 'Tonberry',
                verified: true,
            });
        });
    });
});

/**
 * Test updateUser error handling - when user not found after update
 * This tests line 127-129 of user-service.ts
 */
describe('User Service - Error Handling', () => {
    it('should throw error if user not found after update', async () => {
        // Create a mock DB that returns null on SELECT after UPDATE
        const errorDB = {
            prepare: (sql: string) => ({
                bind: () => ({
                    first: async () => {
                        // Return user on first SELECT (by discord_id), null on second SELECT (by id)
                        if (sql.includes('discord_id = ?')) {
                            return {
                                id: 'existing-user-id',
                                discord_id: 'test-discord',
                                xivauth_id: null,
                                auth_provider: 'discord',
                                username: 'test',
                                avatar_url: null,
                                created_at: new Date().toISOString(),
                                updated_at: new Date().toISOString(),
                            };
                        }
                        // Return null after update to trigger the error
                        return null;
                    },
                    run: async () => ({ success: true, meta: {} }),
                    all: async () => ({ results: [], success: true, meta: {} }),
                }),
            }),
            exec: async () => ({ count: 0, duration: 0 }),
            batch: async () => [],
            dump: async () => new ArrayBuffer(0),
        } as unknown as D1Database;

        // This should throw because user is not found after update
        await expect(
            findOrCreateUser(errorDB, {
                discord_id: 'test-discord',
                username: 'updated',
                auth_provider: 'discord',
            })
        ).rejects.toThrow('User existing-user-id not found after update');
    });
});

/**
 * Test race condition handling in findOrCreateUser
 * Tests lines 95-123 of user-service.ts
 */
describe('User Service - Race Condition Handling', () => {
    it('should handle UNIQUE constraint violation and retry lookup by xivauth_id', async () => {
        let insertCallCount = 0;
        let selectByXivauthCallCount = 0;

        const raceDB = {
            prepare: (sql: string) => ({
                bind: (...params: unknown[]) => ({
                    first: async () => {
                        // First lookup by xivauth_id returns null (simulating no existing user)
                        if (sql.includes('xivauth_id = ?')) {
                            selectByXivauthCallCount++;
                            // First call returns null, second call (after retry) returns user
                            if (selectByXivauthCallCount === 1) {
                                return null;
                            }
                            return {
                                id: 'race-created-user',
                                discord_id: null,
                                xivauth_id: 'race-xivauth-id',
                                auth_provider: 'xivauth',
                                username: 'race-user',
                                avatar_url: null,
                                created_at: new Date().toISOString(),
                                updated_at: new Date().toISOString(),
                            };
                        }
                        // For SELECT by id (after update)
                        if (sql.includes('WHERE id = ?')) {
                            return {
                                id: params[params.length - 1] as string,
                                discord_id: null,
                                xivauth_id: 'race-xivauth-id',
                                auth_provider: 'xivauth',
                                username: 'updated-name',
                                avatar_url: null,
                                created_at: new Date().toISOString(),
                                updated_at: new Date().toISOString(),
                            };
                        }
                        return null;
                    },
                    run: async () => {
                        if (sql.includes('INSERT INTO users')) {
                            insertCallCount++;
                            // First insert fails with UNIQUE constraint
                            throw new Error('UNIQUE constraint failed: users.xivauth_id');
                        }
                        return { success: true, meta: {} };
                    },
                    all: async () => ({ results: [], success: true, meta: {} as D1Meta }),
                }),
            }),
            exec: async () => ({ count: 0, duration: 0 }),
            batch: async () => [],
            dump: async () => new ArrayBuffer(0),
        } as unknown as D1Database;

        const user = await findOrCreateUser(raceDB, {
            xivauth_id: 'race-xivauth-id',
            username: 'new-user',
            auth_provider: 'xivauth',
        });

        // Should have retried the lookup and found the user
        expect(user.xivauth_id).toBe('race-xivauth-id');
        expect(insertCallCount).toBe(1);
        expect(selectByXivauthCallCount).toBe(2);
    });

    it('should handle UNIQUE constraint violation and retry lookup by discord_id', async () => {
        let insertCallCount = 0;
        let selectByDiscordCallCount = 0;

        const raceDB = {
            prepare: (sql: string) => ({
                bind: (...params: unknown[]) => ({
                    first: async () => {
                        // First lookup by discord_id returns null
                        if (sql.includes('discord_id = ?')) {
                            selectByDiscordCallCount++;
                            if (selectByDiscordCallCount === 1) {
                                return null;
                            }
                            // Second call (retry) finds the user
                            return {
                                id: 'race-discord-user',
                                discord_id: 'race-discord-id',
                                xivauth_id: null,
                                auth_provider: 'discord',
                                username: 'race-user',
                                avatar_url: null,
                                created_at: new Date().toISOString(),
                                updated_at: new Date().toISOString(),
                            };
                        }
                        // For SELECT by id (after update)
                        if (sql.includes('WHERE id = ?')) {
                            return {
                                id: params[params.length - 1] as string,
                                discord_id: 'race-discord-id',
                                xivauth_id: null,
                                auth_provider: 'discord',
                                username: 'updated-name',
                                avatar_url: null,
                                created_at: new Date().toISOString(),
                                updated_at: new Date().toISOString(),
                            };
                        }
                        return null;
                    },
                    run: async () => {
                        if (sql.includes('INSERT INTO users')) {
                            insertCallCount++;
                            throw new Error('UNIQUE_VIOLATION: duplicate key value');
                        }
                        return { success: true, meta: {} };
                    },
                    all: async () => ({ results: [], success: true, meta: {} as D1Meta }),
                }),
            }),
            exec: async () => ({ count: 0, duration: 0 }),
            batch: async () => [],
            dump: async () => new ArrayBuffer(0),
        } as unknown as D1Database;

        const user = await findOrCreateUser(raceDB, {
            discord_id: 'race-discord-id',
            username: 'new-user',
            auth_provider: 'discord',
        });

        // Should have retried and found the user
        expect(user.discord_id).toBe('race-discord-id');
        expect(insertCallCount).toBe(1);
        expect(selectByDiscordCallCount).toBe(2);
    });

    it('should rethrow non-constraint errors', async () => {
        const errorDB = {
            prepare: (sql: string) => ({
                bind: () => ({
                    first: async () => null,
                    run: async () => {
                        if (sql.includes('INSERT INTO users')) {
                            throw new Error('Database connection lost');
                        }
                        return { success: true, meta: {} };
                    },
                    all: async () => ({ results: [], success: true, meta: {} as D1Meta }),
                }),
            }),
            exec: async () => ({ count: 0, duration: 0 }),
            batch: async () => [],
            dump: async () => new ArrayBuffer(0),
        } as unknown as D1Database;

        await expect(
            findOrCreateUser(errorDB, {
                discord_id: 'test-discord',
                username: 'test',
                auth_provider: 'discord',
            })
        ).rejects.toThrow('Database connection lost');
    });

    it('should rethrow constraint error if user still not found after retry', async () => {
        const errorDB = {
            prepare: (sql: string) => ({
                bind: () => ({
                    first: async () => null, // Always return null - user never found
                    run: async () => {
                        if (sql.includes('INSERT INTO users')) {
                            throw new Error('UNIQUE constraint failed: users.discord_id');
                        }
                        return { success: true, meta: {} };
                    },
                    all: async () => ({ results: [], success: true, meta: {} as D1Meta }),
                }),
            }),
            exec: async () => ({ count: 0, duration: 0 }),
            batch: async () => [],
            dump: async () => new ArrayBuffer(0),
        } as unknown as D1Database;

        await expect(
            findOrCreateUser(errorDB, {
                discord_id: 'missing-discord',
                username: 'test',
                auth_provider: 'discord',
            })
        ).rejects.toThrow('UNIQUE constraint failed');
    });
});
