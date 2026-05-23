import { test } from "node:test";
import assert from "node:assert/strict";
import { randomBytes } from "node:crypto";

import { decrypt, encrypt, parseMasterKey } from "../src/crypto.js";

test("parseMasterKey: accepts 64 hex chars", () => {
  const key = parseMasterKey("a".repeat(64));
  assert.equal(key.length, 32);
});

test("parseMasterKey: rejects wrong length", () => {
  assert.throws(() => parseMasterKey("a".repeat(32)), /64 hex chars/);
});

test("parseMasterKey: rejects non-hex", () => {
  assert.throws(() => parseMasterKey("z".repeat(64)), /64 hex chars/);
});

test("parseMasterKey: rejects undefined", () => {
  assert.throws(() => parseMasterKey(undefined), /64 hex chars/);
});

test("encrypt/decrypt round-trip", () => {
  const key = randomBytes(32);
  const blob = encrypt(key, "hello world");
  assert.equal(decrypt(key, blob), "hello world");
  // iv/tag/data are all hex strings.
  assert.match(blob.iv, /^[0-9a-f]+$/);
  assert.match(blob.tag, /^[0-9a-f]+$/);
  assert.match(blob.data, /^[0-9a-f]+$/);
});

test("decrypt: tag mismatch raises", () => {
  const key = randomBytes(32);
  const blob = encrypt(key, "secret");
  const tampered = { ...blob, tag: "f".repeat(blob.tag.length) };
  assert.throws(() => decrypt(key, tampered));
});

test("decrypt: wrong key raises", () => {
  const blob = encrypt(randomBytes(32), "secret");
  assert.throws(() => decrypt(randomBytes(32), blob));
});
