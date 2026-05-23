/**
 * Per-spawn `$HOME` staging for the `claude` subprocess.
 *
 * The proxy spawns `claude` once per inbound /messages request and
 * points it at `$HOME = <credsRoot>/<spawnId>`. We materialise the
 * OAuth credentials.json into `$HOME/.claude/.credentials.json` so the
 * CLI can read it; the proxy `rm -rf`s `$HOME` after spawn exit unless
 * the resolver returned `persistent: true`.
 *
 * File mode 0600, dir mode 0700 — these are short-lived tokens; we want
 * them invisible to anything else on the host.
 */
import fs from "node:fs/promises";
import path from "node:path";

export async function writeCredentialsHome(home, plaintextJson) {
  const claudeDir = path.join(home, ".claude");
  await fs.mkdir(claudeDir, { recursive: true, mode: 0o700 });
  await fs.writeFile(
    path.join(claudeDir, ".credentials.json"),
    plaintextJson,
    { mode: 0o600 },
  );
}

export async function removeCredentialsHome(home) {
  await fs.rm(home, { recursive: true, force: true });
}
