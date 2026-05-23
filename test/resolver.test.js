import { test } from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";

import { create } from "../src/index.js";
import { decrypt } from "../src/crypto.js";
import {
  insertApiKeyRow,
  insertOauthRow,
  makeDbFixture,
  masterKeyHex,
  selectOauthRow,
} from "./fixtures.js";

function makeEnv(dbPath, keyHex, credsRoot) {
  return {
    HERMES_DB_PATH: dbPath,
    HERMES_SECRET_KEY: keyHex,
    CREDENTIALS_ROOT: credsRoot,
  };
}

async function makeCredsRoot() {
  return fs.mkdtemp(path.join(os.tmpdir(), "sqlite-resolver-creds-"));
}

test("create: rejects missing HERMES_DB_PATH", () => {
  assert.throws(() => create({ HERMES_SECRET_KEY: masterKeyHex() }), /HERMES_DB_PATH/);
});

test("create: rejects missing HERMES_SECRET_KEY", async () => {
  const { dbPath, cleanup } = await makeDbFixture();
  try {
    assert.throws(() => create({ HERMES_DB_PATH: dbPath }), /master key/);
  } finally {
    await cleanup();
  }
});

test("resolve: returns 503 when no active credential", async () => {
  const { dbPath, cleanup } = await makeDbFixture();
  const keyHex = masterKeyHex();
  try {
    const resolver = create(makeEnv(dbPath, keyHex));
    const result = await resolver.resolve({});
    resolver._db.close();
    assert.equal(result.error.status, 503);
    assert.equal(result.error.type, "configuration_error");
  } finally {
    await cleanup();
  }
});

test("resolve: api_key returns decrypted key + provider + baseUrl", async () => {
  const { dbPath, cleanup } = await makeDbFixture();
  const keyHex = masterKeyHex();
  try {
    insertApiKeyRow(dbPath, keyHex, {
      provider: "openai",
      apiKey: "sk-fresh-12345",
      baseUrl: "https://api.openai.com/v1",
    });
    const resolver = create(makeEnv(dbPath, keyHex));
    const result = await resolver.resolve({});
    resolver._db.close();
    assert.equal(result.mode, "api_key");
    assert.equal(result.apiKey, "sk-fresh-12345");
    assert.equal(result.provider, "openai");
    assert.equal(result.baseUrl, "https://api.openai.com/v1");
    assert.equal(typeof result.credId, "string");
  } finally {
    await cleanup();
  }
});

test("resolve: api_key with NULL base_url returns null baseUrl", async () => {
  const { dbPath, cleanup } = await makeDbFixture();
  const keyHex = masterKeyHex();
  try {
    insertApiKeyRow(dbPath, keyHex, {
      provider: "anthropic",
      apiKey: "ant-key",
    });
    const resolver = create(makeEnv(dbPath, keyHex));
    const result = await resolver.resolve({});
    resolver._db.close();
    assert.equal(result.mode, "api_key");
    assert.equal(result.baseUrl, null);
  } finally {
    await cleanup();
  }
});

test("resolve: api_key with wrong master key returns 500 api_error", async () => {
  const { dbPath, cleanup } = await makeDbFixture();
  const writerKey = masterKeyHex();
  const readerKey = masterKeyHex();
  try {
    insertApiKeyRow(dbPath, writerKey, { provider: "openai", apiKey: "sk-x" });
    const resolver = create(makeEnv(dbPath, readerKey));
    const result = await resolver.resolve({});
    resolver._db.close();
    assert.equal(result.error.status, 500);
    assert.equal(result.error.type, "api_error");
    assert.match(result.error.message, /decrypt failed/);
  } finally {
    await cleanup();
  }
});

test("resolve: oauth_claude stages credentials.json into per-request HOME", async () => {
  const { dbPath, cleanup } = await makeDbFixture();
  const keyHex = masterKeyHex();
  const credsRoot = await makeCredsRoot();
  const plaintext = JSON.stringify({
    claudeAiOauth: { accessToken: "tok-abc", expiresAt: 1700000000000 },
  });
  try {
    insertOauthRow(dbPath, keyHex, { plaintext });
    const resolver = create(makeEnv(dbPath, keyHex, credsRoot));
    const result = await resolver.resolve({});
    assert.equal(result.mode, "oauth_claude");
    assert.equal(typeof result.home, "string");
    assert.equal(path.dirname(result.home), credsRoot);

    const written = await fs.readFile(
      path.join(result.home, ".claude", ".credentials.json"),
      "utf8",
    );
    assert.equal(written, plaintext);
    resolver._db.close();
  } finally {
    await fs.rm(credsRoot, { recursive: true, force: true });
    await cleanup();
  }
});

test("resolve: oauth_claude returns 503 when status is pending", async () => {
  const { dbPath, cleanup } = await makeDbFixture();
  const keyHex = masterKeyHex();
  try {
    insertOauthRow(dbPath, keyHex, {
      plaintext: "{}",
      status: "pending",
    });
    const resolver = create(makeEnv(dbPath, keyHex));
    const result = await resolver.resolve({});
    resolver._db.close();
    assert.equal(result.error.status, 503);
    assert.equal(result.error.type, "authentication_error");
    assert.match(result.error.message, /not 'authorized'/);
  } finally {
    await cleanup();
  }
});

test("writeback: re-encrypts and updates the row when plaintext changed", async () => {
  const { dbPath, cleanup } = await makeDbFixture();
  const keyHex = masterKeyHex();
  const credsRoot = await makeCredsRoot();
  const original = JSON.stringify({ access: "old", expiresAt: 1 });
  const refreshed = JSON.stringify({ access: "new", expiresAt: 2 });
  try {
    const id = insertOauthRow(dbPath, keyHex, { plaintext: original });
    const resolver = create(makeEnv(dbPath, keyHex, credsRoot));
    const ctx = await resolver.resolve({});
    await resolver.writeback(ctx, refreshed);
    resolver._db.close();

    const row = selectOauthRow(dbPath, id);
    const got = decrypt(Buffer.from(keyHex, "hex"), {
      iv: row.oauth_iv,
      tag: row.oauth_tag,
      data: row.oauth_data,
    });
    assert.equal(got, refreshed);
    assert.equal(row.oauth_status, "authorized");
    assert.ok(row.oauth_authorized_at > 0);
  } finally {
    await fs.rm(credsRoot, { recursive: true, force: true });
    await cleanup();
  }
});

test("writeback: no-op when plaintext unchanged", async () => {
  const { dbPath, cleanup } = await makeDbFixture();
  const keyHex = masterKeyHex();
  const credsRoot = await makeCredsRoot();
  const original = JSON.stringify({ access: "tok" });
  try {
    const id = insertOauthRow(dbPath, keyHex, { plaintext: original });
    const beforeRow = selectOauthRow(dbPath, id);

    const resolver = create(makeEnv(dbPath, keyHex, credsRoot));
    const ctx = await resolver.resolve({});
    await resolver.writeback(ctx, original);
    resolver._db.close();

    const afterRow = selectOauthRow(dbPath, id);
    // Ciphertext columns untouched — same IV would indicate no update,
    // since encrypt() draws a fresh random IV per call.
    assert.equal(afterRow.oauth_iv, beforeRow.oauth_iv);
    assert.equal(afterRow.oauth_tag, beforeRow.oauth_tag);
    assert.equal(afterRow.oauth_data, beforeRow.oauth_data);
  } finally {
    await fs.rm(credsRoot, { recursive: true, force: true });
    await cleanup();
  }
});

test("writeback: no-op on api_key contexts", async () => {
  const { dbPath, cleanup } = await makeDbFixture();
  const keyHex = masterKeyHex();
  try {
    insertApiKeyRow(dbPath, keyHex, { provider: "openai", apiKey: "k" });
    const resolver = create(makeEnv(dbPath, keyHex));
    const ctx = await resolver.resolve({});
    // Should simply return without throwing.
    await resolver.writeback(ctx, "new-thing");
    resolver._db.close();
  } finally {
    await cleanup();
  }
});
