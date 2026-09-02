# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
# Stage 1 — build the SPA.
#
# `--platform=$BUILDPLATFORM` pins this stage to the machine doing the building, NOT to the
# image being built, and it is load-bearing rather than an optimisation. Without it buildx
# runs the whole stage once per target platform, so the arm64 image ran `npm ci` and
# `npm run build` under QEMU emulation — node and rollup are about the worst possible
# workload for that. The v0.2.0 release build was killed by GitHub's six-hour job timeout
# at exactly 06:00:00, having published the BFF image and not this one.
#
# It is safe because the output of this stage is `dist/`: HTML, one JS bundle, one
# stylesheet and the woff/woff2 faces. Nothing in it is architecture-specific — no `.node`
# addons, no shared objects — so a bundle built on amd64 is byte-identical to one built on
# arm64 and both nginx images can copy the same artefact. Only stage 2 is per-architecture,
# which is correct: that one really does ship an arm64 nginx.
#
# If a future dependency starts emitting a native artefact INTO `dist/`, this stops being
# safe and the build has to go back to per-platform (or to a native arm64 runner). Nothing
# checks that automatically; it is a property of what Vite emits.
FROM --platform=$BUILDPLATFORM node:20-alpine AS build
WORKDIR /web
COPY package.json package-lock.json ./
RUN npm ci
COPY . .
RUN npm run build

# Stage 2 — serve static assets + proxy /api and /auth to the BFF.
# Unprivileged image: runs as non-root uid 101 and listens on 8080 (matching
# nginx.conf), so it satisfies a strict runAsNonRoot policy without extra config.
FROM nginxinc/nginx-unprivileged:1.27-alpine
COPY nginx.conf /etc/nginx/conf.d/default.conf
COPY --from=build /web/dist /usr/share/nginx/html
EXPOSE 8080
