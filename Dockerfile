# syntax=docker/dockerfile:1.7
#
# Image:  ghcr.io/haexhub/haex-claude-proxy-resolver-sqlite:<tag>
# Built:  by .github/workflows/build-image.yml on push to main
# Built on: ghcr.io/haexhub/haex-claude-proxy (proxy core, file/token-map
#           builtins) + this plugin in /app/node_modules so the proxy's
#           dynamic import('haex-claude-proxy-resolver-sqlite') resolves.
#
# The proxy core ships only generic resolvers. This image bakes the
# Hermes-flavoured SQLite+AES-GCM resolver in so a Hermes deployment
# doesn't need a host-side bind-mount of the plugin source. PROXY_RESOLVER
# is preset for convenience — overrideable at runtime.
#
# Runtime requirements (set by the deployment):
#   - HERMES_DB_PATH      sqlite file the plugin opens (shared volume
#                         with hermes-server, e.g. /data/hermes.db)
#   - HERMES_SECRET_KEY   64 hex chars; same key Hermes uses to seal
#                         llm_credentials. Mismatch → every chat
#                         request 503s.
#   - CREDENTIALS_ROOT    tmpfs mount (defaulted to /run/credentials
#                         by the proxy core).

FROM ghcr.io/haexhub/haex-claude-proxy:latest

# Base image ends with `USER node`; /app is owned by root, so the
# plugin install would EACCES on /app/node_modules. Swap back to root
# for the install layer and drop back to node for runtime.
USER root
WORKDIR /app

# Stage the plugin as a local package, then npm-install it into /app
# so the proxy core's `import("haex-claude-proxy-resolver-sqlite")`
# resolves through standard Node module resolution. npm handles the
# better-sqlite3 native binding (prebuilds for linux-x64 + linux-arm64
# ship from better-sqlite3 itself; no node-gyp toolchain needed here).
#
# `--install-links` forces npm to COPY the local package into
# node_modules instead of symlinking (the default for `npm install
# <path>`). Without it, /app/node_modules/haex-claude-proxy-resolver-
# sqlite would just be a symlink back to /tmp/plugin — which we delete
# in the same RUN, leaving a dangling link and a runtime
# `MODULE_NOT_FOUND` when the proxy boots.
COPY package.json package-lock.json* /tmp/plugin/
COPY src/ /tmp/plugin/src/
RUN npm install --omit=dev --no-audit --no-fund --install-links /tmp/plugin \
 && rm -rf /tmp/plugin /root/.npm \
 && chown -R node:node /app/node_modules

USER node
ENV PROXY_RESOLVER=haex-claude-proxy-resolver-sqlite
