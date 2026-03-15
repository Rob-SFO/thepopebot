import { randomUUID } from 'crypto';
import { eq } from 'drizzle-orm';
import { getDb } from './index.js';
import { settings } from './schema.js';
import { encrypt, decrypt } from './crypto.js';

/**
 * Create a new named OAuth token.
 * @param {string} name - Human-readable name
 * @param {string} rawToken - Plaintext OAuth token
 * @param {string} userId - Creator user ID
 * @returns {{ id: string, name: string, createdAt: number, lastUsedAt: null }}
 */
export function createOAuthToken(name, rawToken, userId) {
  const db = getDb();
  const now = Date.now();
  const id = randomUUID();

  const record = {
    id,
    type: 'oauth_token',
    key: randomUUID(),
    value: JSON.stringify({ name, token: encrypt(rawToken) }),
    createdBy: userId || null,
    lastUsedAt: null,
    createdAt: now,
    updatedAt: now,
  };

  db.insert(settings).values(record).run();

  return { id, name, createdAt: now, lastUsedAt: null };
}

/**
 * List all OAuth tokens (metadata only, no decryption).
 * @returns {{ id: string, name: string, createdAt: number, lastUsedAt: number|null }[]}
 */
export function listOAuthTokens() {
  const db = getDb();
  const rows = db
    .select()
    .from(settings)
    .where(eq(settings.type, 'oauth_token'))
    .all();

  return rows.map((row) => {
    const parsed = JSON.parse(row.value);
    return {
      id: row.id,
      name: parsed.name,
      createdAt: row.createdAt,
      lastUsedAt: row.lastUsedAt,
    };
  });
}

/**
 * Delete an OAuth token by ID.
 * @param {string} id
 */
export function deleteOAuthTokenById(id) {
  const db = getDb();
  db.delete(settings).where(eq(settings.id, id)).run();
}

/**
 * Get the next OAuth token using LRU rotation.
 * Picks the least-recently-used token, updates its lastUsedAt, returns plaintext.
 * @returns {string|null} Plaintext token or null if none exist
 */
export function getNextOAuthToken() {
  const db = getDb();
  const rows = db
    .select()
    .from(settings)
    .where(eq(settings.type, 'oauth_token'))
    .all();

  if (rows.length === 0) return null;

  // Sort by lastUsedAt ASC, nulls first (never used = highest priority)
  rows.sort((a, b) => {
    if (a.lastUsedAt === null && b.lastUsedAt === null) return 0;
    if (a.lastUsedAt === null) return -1;
    if (b.lastUsedAt === null) return 1;
    return a.lastUsedAt - b.lastUsedAt;
  });

  const picked = rows[0];
  const now = Date.now();

  // Update lastUsedAt column
  db.update(settings)
    .set({ lastUsedAt: now, updatedAt: now })
    .where(eq(settings.id, picked.id))
    .run();

  // Decrypt and return the token
  const parsed = JSON.parse(picked.value);
  return decrypt(parsed.token);
}

/**
 * Get count of OAuth tokens.
 * @returns {number}
 */
export function getOAuthTokenCount() {
  const db = getDb();
  const rows = db
    .select({ id: settings.id })
    .from(settings)
    .where(eq(settings.type, 'oauth_token'))
    .all();
  return rows.length;
}
