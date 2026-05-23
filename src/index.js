/**
 * SQLite + AES-GCM credential resolver plugin for haex-claude-proxy.
 *
 * Single-user — there is no session-token lookup. Every inbound request
 * gets routed to whichever row in `proxy_credentials_v1` is currently
 * active (the partial unique index on `is_active = 1` guarantees at most
 * one). When that row is missing the resolver returns a configuration
 * error so the proxy surfaces "no credential configured" rather than
 * silently routing nowhere.
 *
 * Modes:
 *   - `api_key`: returns the decrypted key + provider + optional base_url
 *     for the proxy's direct-forward path.
 *   - `oauth_claude`: stages the decrypted credentials.json into a
 *     per-request tmpfs `$HOME` and returns its path; the proxy spawns
 *     `claude` against that HOME.
 *
 * `writeback(ctx, refreshedPlaintext)` re-encrypts and updates the row
 * when the spawned CLI rotated the OAuth token. We carry the original
 * plaintext on the result object so the diff check is local — no extra
 * DB round-trip in the common no-refresh case.
 *
 * Concurrency: opens the DB in WAL mode + 5s busy-timeout. Hermes writes
 * to the same file from Python; SQLite's writer-only lock plus WAL gives
 * coexistence under the realistic refresh cadence (hours, not seconds).
 *
 * Contract: see haex-claude-proxy/src/resolvers/types.md.
 */
import path from "node:path";
import { randomBytes } from "node:crypto";

import Database from "better-sqlite3";

import { decrypt, encrypt, parseMasterKey } from "./crypto.js";
import { writeCredentialsHome } from "./temp-home.js";

/**
 * @param {NodeJS.ProcessEnv | Record<string, string|undefined>} env
 * @returns {{ name: "sqlite", resolve: Function, writeback: Function, _db?: any }}
 */
export function create(env) {
  const dbPath = env.HERMES_DB_PATH;
  if (!dbPath) {
    throw new Error(
      "haex-claude-proxy-resolver-sqlite requires HERMES_DB_PATH — point it at the Hermes SQLite file",
    );
  }
  const masterKey = parseMasterKey(env.HERMES_SECRET_KEY);
  const credsRoot = env.CREDENTIALS_ROOT ?? "/run/credentials";

  // `readonly` would be safer, but writeback() needs the same handle to
  // update the OAuth ciphertext on refresh. WAL + busy_timeout lets us
  // share the file with Hermes (Python writer) without deadlocking.
  const db = new Database(dbPath, { fileMustExist: true });
  db.pragma("journal_mode = WAL");
  db.pragma("busy_timeout = 5000");
  db.pragma("foreign_keys = ON");

  const selectActive = db.prepare(`
    SELECT id, provider, mode, base_url,
           api_key_iv, api_key_tag, api_key_data,
           oauth_iv, oauth_tag, oauth_data, oauth_status
    FROM proxy_credentials_v1
    LIMIT 1
  `);

  const updateOauthBlob = db.prepare(`
    UPDATE llm_credentials
    SET oauth_iv = @iv,
        oauth_tag = @tag,
        oauth_data = @data,
        oauth_status = 'authorized',
        oauth_authorized_at = @ts,
        updated_at = @ts
    WHERE id = @id
  `);

  return {
    name: "sqlite",

    async resolve(_req) {
      const row = selectActive.get();
      if (!row) {
        return {
          error: {
            status: 503,
            type: "configuration_error",
            message:
              "no active LLM credential in the Hermes DB — pick one via /settings/llm in the Hermes UI",
          },
        };
      }
      if (row.mode === "api_key") {
        if (!row.api_key_iv || !row.api_key_tag || !row.api_key_data) {
          return {
            error: {
              status: 500,
              type: "configuration_error",
              message: `credential ${row.id} mode=api_key but ciphertext columns are missing`,
            },
          };
        }
        let apiKey;
        try {
          apiKey = decrypt(masterKey, {
            iv: row.api_key_iv,
            tag: row.api_key_tag,
            data: row.api_key_data,
          });
        } catch (e) {
          return {
            error: {
              status: 500,
              type: "api_error",
              message: `decrypt failed for credential ${row.id}: ${e.message}`,
            },
          };
        }
        return {
          mode: "api_key",
          credId: String(row.id),
          provider: row.provider,
          apiKey,
          baseUrl: row.base_url ?? null,
        };
      }
      if (row.mode === "oauth_claude") {
        if (row.oauth_status !== "authorized") {
          return {
            error: {
              status: 503,
              type: "authentication_error",
              message: `oauth credential ${row.id} is in state '${row.oauth_status}', not 'authorized'`,
            },
          };
        }
        if (!row.oauth_iv || !row.oauth_tag || !row.oauth_data) {
          return {
            error: {
              status: 500,
              type: "configuration_error",
              message: `credential ${row.id} mode=oauth_claude but ciphertext columns are missing`,
            },
          };
        }
        let plaintext;
        try {
          plaintext = decrypt(masterKey, {
            iv: row.oauth_iv,
            tag: row.oauth_tag,
            data: row.oauth_data,
          });
        } catch (e) {
          return {
            error: {
              status: 500,
              type: "api_error",
              message: `decrypt failed for credential ${row.id}: ${e.message}`,
            },
          };
        }
        const spawnId = randomBytes(12).toString("hex");
        const home = path.join(credsRoot, spawnId);
        try {
          await writeCredentialsHome(home, plaintext);
        } catch (e) {
          return {
            error: {
              status: 500,
              type: "api_error",
              message: `failed to stage credentials at ${home}: ${e.message}`,
            },
          };
        }
        return {
          mode: "oauth_claude",
          home,
          credId: String(row.id),
          // Internal: kept on the result so writeback can detect a real
          // refresh without re-decrypting from DB. Prefix `_` per the
          // resolver-contract convention for plugin-internal fields.
          _originalPlaintext: plaintext,
          _credIdNumber: row.id,
        };
      }
      return {
        error: {
          status: 500,
          type: "configuration_error",
          message: `unknown credential mode '${row.mode}' for id ${row.id}`,
        },
      };
    },

    async writeback(ctx, refreshedPlaintext) {
      if (ctx.mode !== "oauth_claude") return;
      if (!refreshedPlaintext) return;
      if (refreshedPlaintext === ctx._originalPlaintext) return;
      const blob = encrypt(masterKey, refreshedPlaintext);
      const now = Math.floor(Date.now() / 1000);
      updateOauthBlob.run({
        iv: blob.iv,
        tag: blob.tag,
        data: blob.data,
        ts: now,
        id: ctx._credIdNumber,
      });
    },

    // Test-only: lets the test suite close the DB handle so the temp
    // file can be unlinked on POSIX. Not part of the resolver contract.
    _db: db,
  };
}
