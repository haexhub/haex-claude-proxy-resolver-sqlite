/**
 * Test-only helpers: create a fresh SQLite file that mirrors the Hermes
 * `llm_credentials` table + `proxy_credentials_v1` view (the stable read
 * surface from `haex-claude-proxy/src/resolvers/types.md` / the Hermes
 * `schema.sql`). Insert rows with the AES-GCM crypto from `src/crypto.js`
 * so a round-trip via the plugin is realistic.
 *
 * We re-declare the schema here instead of pulling it from Hermes to
 * keep the plugin standalone — if the Hermes schema ever drifts, this
 * file is the canary.
 */
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { randomBytes } from "node:crypto";

import Database from "better-sqlite3";

import { encrypt } from "../src/crypto.js";

export const SCHEMA = `
CREATE TABLE llm_credentials (
  id INTEGER PRIMARY KEY,
  provider TEXT NOT NULL,
  mode TEXT NOT NULL,
  display_name TEXT NOT NULL,
  base_url TEXT,
  is_active INTEGER NOT NULL DEFAULT 0,
  api_key_iv TEXT,
  api_key_tag TEXT,
  api_key_data TEXT,
  oauth_status TEXT,
  oauth_authorized_at INTEGER,
  oauth_iv TEXT,
  oauth_tag TEXT,
  oauth_data TEXT,
  created_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL
);

CREATE UNIQUE INDEX llm_credentials_active_uq
  ON llm_credentials(is_active) WHERE is_active = 1;

CREATE VIEW proxy_credentials_v1 AS
  SELECT
    id, provider, mode, base_url,
    api_key_iv, api_key_tag, api_key_data,
    oauth_iv, oauth_tag, oauth_data, oauth_status, oauth_authorized_at
  FROM llm_credentials
  WHERE is_active = 1;
`;

/**
 * Create a fresh SQLite file with the Hermes-compatible schema.
 * Returns the path + a cleanup function that closes any open handles
 * and removes the file.
 */
export async function makeDbFixture() {
  const dir = await fs.mkdtemp(path.join(os.tmpdir(), "sqlite-resolver-test-"));
  const dbPath = path.join(dir, "hermes.db");
  const db = new Database(dbPath);
  db.exec(SCHEMA);
  db.close();
  return {
    dbPath,
    async cleanup() {
      await fs.rm(dir, { recursive: true, force: true });
    },
  };
}

export function masterKeyHex() {
  return randomBytes(32).toString("hex");
}

/**
 * Insert an `api_key` credential row, active by default.
 */
export function insertApiKeyRow(dbPath, keyHex, fields) {
  const db = new Database(dbPath);
  const key = Buffer.from(keyHex, "hex");
  const ct = encrypt(key, fields.apiKey);
  const now = Math.floor(Date.now() / 1000);
  const stmt = db.prepare(`
    INSERT INTO llm_credentials (
      provider, mode, display_name, base_url, is_active,
      api_key_iv, api_key_tag, api_key_data,
      created_at, updated_at
    ) VALUES (?, 'api_key', ?, ?, ?, ?, ?, ?, ?, ?)
  `);
  const info = stmt.run(
    fields.provider,
    fields.displayName ?? "test",
    fields.baseUrl ?? null,
    fields.isActive === false ? 0 : 1,
    ct.iv,
    ct.tag,
    ct.data,
    now,
    now,
  );
  db.close();
  return Number(info.lastInsertRowid);
}

/**
 * Insert an `oauth_claude` credential row, active by default.
 */
export function insertOauthRow(dbPath, keyHex, fields) {
  const db = new Database(dbPath);
  const key = Buffer.from(keyHex, "hex");
  const ct = encrypt(key, fields.plaintext);
  const now = Math.floor(Date.now() / 1000);
  const stmt = db.prepare(`
    INSERT INTO llm_credentials (
      provider, mode, display_name, is_active,
      oauth_iv, oauth_tag, oauth_data, oauth_status, oauth_authorized_at,
      created_at, updated_at
    ) VALUES ('anthropic', 'oauth_claude', ?, ?, ?, ?, ?, ?, ?, ?, ?)
  `);
  const info = stmt.run(
    fields.displayName ?? "claude-oauth",
    fields.isActive === false ? 0 : 1,
    ct.iv,
    ct.tag,
    ct.data,
    fields.status ?? "authorized",
    now,
    now,
    now,
  );
  db.close();
  return Number(info.lastInsertRowid);
}

export function selectOauthRow(dbPath, id) {
  const db = new Database(dbPath);
  const row = db
    .prepare("SELECT * FROM llm_credentials WHERE id = ?")
    .get(id);
  db.close();
  return row;
}
