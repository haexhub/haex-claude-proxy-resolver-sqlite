/**
 * AES-256-GCM at-rest crypto, mirroring Hermes's `src/hermes/crypto.py`.
 * The 32-byte master key arrives as 64 hex chars in `HERMES_SECRET_KEY`
 * and must be identical to the value Hermes used to write the
 * ciphertext — anything else and `decrypt` raises on the auth-tag check.
 *
 * The stored shape is the three-column form Hermes uses:
 *   { iv: hex(12B), tag: hex(16B), data: hex(N) }
 */
import crypto from "node:crypto";

/**
 * Parse the env-supplied master key.
 * @param {string|undefined} hex
 * @returns {Buffer}
 */
export function parseMasterKey(hex) {
  if (!/^[0-9a-fA-F]{64}$/.test(hex ?? "")) {
    throw new Error(
      "master key must be 64 hex chars (32 bytes) — set HERMES_SECRET_KEY to Hermes's value",
    );
  }
  return Buffer.from(hex, "hex");
}

/**
 * Encrypt UTF-8 plaintext.
 * @param {Buffer} key
 * @param {string} plaintext
 * @returns {{iv: string, tag: string, data: string}}
 */
export function encrypt(key, plaintext) {
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv("aes-256-gcm", key, iv);
  const data = Buffer.concat([cipher.update(plaintext, "utf8"), cipher.final()]);
  return {
    iv: iv.toString("hex"),
    tag: cipher.getAuthTag().toString("hex"),
    data: data.toString("hex"),
  };
}

/**
 * Decrypt to UTF-8 plaintext. Throws on auth-tag mismatch.
 * @param {Buffer} key
 * @param {{iv: string, tag: string, data: string}} blob
 * @returns {string}
 */
export function decrypt(key, blob) {
  const decipher = crypto.createDecipheriv(
    "aes-256-gcm",
    key,
    Buffer.from(blob.iv, "hex"),
  );
  decipher.setAuthTag(Buffer.from(blob.tag, "hex"));
  return Buffer.concat([
    decipher.update(Buffer.from(blob.data, "hex")),
    decipher.final(),
  ]).toString("utf8");
}
