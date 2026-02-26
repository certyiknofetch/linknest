# ── LinkNest Server ──────────────────────────────────────────
# Multi-stage production Dockerfile
# Supports: linux/amd64, linux/arm64
# ─────────────────────────────────────────────────────────────

FROM node:20-alpine AS builder

WORKDIR /app

# Install production dependencies only
COPY package.json package-lock.json ./
RUN npm ci --omit=dev

# ─────────────────────────────────────────────────────────────

FROM node:20-alpine

LABEL maintainer="certyiknofetch"
LABEL org.opencontainers.image.source="https://github.com/certyiknofetch/linknest"
LABEL org.opencontainers.image.description="LinkNest - Cross-browser bookmark sync server"

# Security: run as non-root
RUN addgroup -S linknest && adduser -S linknest -G linknest

WORKDIR /app

# Copy dependencies from builder
COPY --from=builder /app/node_modules ./node_modules

# Copy application source
COPY package.json ./
COPY src ./src

# Set ownership
RUN chown -R linknest:linknest /app

USER linknest

# Default port
ENV PORT=3000
EXPOSE 3000

# Health check
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD wget -qO- http://localhost:3000/api/health || exit 1

CMD ["node", "src/index.js"]
