# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
# Stage 1 — build the SPA
FROM node:20-alpine AS build
WORKDIR /web
COPY package.json package-lock.json* ./
RUN npm install
COPY . .
RUN npm run build

# Stage 2 — serve static assets + proxy /api and /auth to the BFF.
# Unprivileged image: runs as non-root uid 101 and listens on 8080 (matching
# nginx.conf), so it satisfies a strict runAsNonRoot policy without extra config.
FROM nginxinc/nginx-unprivileged:1.27-alpine
COPY nginx.conf /etc/nginx/conf.d/default.conf
COPY --from=build /web/dist /usr/share/nginx/html
EXPOSE 8080
