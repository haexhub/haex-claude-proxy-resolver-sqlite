# haex-claude-proxy-resolver-sqlite

SQLite + AES-GCM credential resolver plugin for [haex-claude-proxy](https://github.com/haexhub/haex-claude-proxy). Reads the active `llm_credentials` row from a Hermes SQLite database, decrypts in-process, and either:

- stages the OAuth credentials.json into a per-request tmpfs `$HOME` for the spawned `claude` subprocess, or
- hands back the decrypted API key + base URL for direct-forward mode.

Single-user — there is no session-token lookup. The proxy serves whichever credential is `is_active = 1` in the Hermes DB.

## Environment

| Variable             | Required | Description                                                                                    |
| -------------------- | -------- | ---------------------------------------------------------------------------------------------- |
| `HERMES_DB_PATH`     | yes      | Path to the Hermes SQLite file. Must be writable when OAuth refresh is expected.               |
| `HERMES_SECRET_KEY`  | yes      | 64 hex chars (32 bytes). Must match the value Hermes used to write the ciphertext.             |
| `CREDENTIALS_ROOT`   | no       | Where to stage per-request OAuth `$HOME`s. Defaults to `/run/credentials`.                     |

Set `PROXY_RESOLVER=haex-claude-proxy-resolver-sqlite` in the proxy's env to activate.
