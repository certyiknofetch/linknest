# LinkNest — Cross-Browser Bookmark Sync

<p align="center">
  <img src="icon128.png" width="100">
</p>


<p align="center">
  <strong>Sync your bookmarks across Chrome, Firefox, Edge, Brave.</strong><br />
  Self-hosted server · Browser extension · PostgreSQL / MongoDB
</p>

---

## Table of Contents

- [Features](#features)
- [Quick Start with Docker](#quick-start-with-docker)
- [Docker Compose — with Database](#docker-compose--with-database)
- [Docker Compose — External Database](#docker-compose--external-database)
- [Environment Variables](#environment-variables)
- [Extension Setup](#extension-setup)
- [Reverse Proxy (Nginx Proxy Manager)](#reverse-proxy-nginx-proxy-manager)
- [Security](#security)
- [Troubleshooting](#troubleshooting)
- [License](#license)

---


## Features

| Category | Details |
|---|---|
| **Sync** | Bidirectional merge sync (push + pull), soft-delete propagation, auto-sync with periodic alarms and change listeners |
| **Browsers** | Chrome, Firefox, Edge, Brave, Opera, Vivaldi — any Chromium MV3 or Firefox MV2 browser |
| **Auth** | JWT access + rotating refresh tokens with reuse detection, family-based revocation |
| **2FA** | TOTP setup with QR code + manual secret, backup codes, enforced login challenge |
| **Database** | PostgreSQL (recommended) or MongoDB — switchable via `DB_PROVIDER` |
| **Security** | OWASP-aligned: Helmet, rate limiting, bcrypt, HTTPS enforcement, encrypted 2FA secrets (AES-256-GCM) |
| **Deployment** | Docker multi-arch (`amd64` + `arm64`), Docker Compose, or bare Node.js |
| **UI Protection** | Server URL locked behind identity verification, Clear Server requires TOTP/password |

---

## Quick Start with Docker

```bash
docker run -d \
  --name linknest \
  -p 3000:3000 \
  -e DB_PROVIDER=postgres \
  -e POSTGRES_URL=postgresql://user:pass@your-db-host:5432/linknest \
  -e JWT_SECRET=$(openssl rand -base64 32) \
  -e REFRESH_JWT_SECRET=$(openssl rand -base64 32) \
  -e TWO_FACTOR_CHALLENGE_SECRET=$(openssl rand -base64 32) \
  -e TWO_FACTOR_ENCRYPTION_KEY=$(openssl rand -base64 32) \
  -e REQUIRE_HTTPS=true \
  -e CORS_ORIGINS=https://your-domain.com \
  certyiknofetch/linknest:1.1
```

The image supports **linux/amd64** and **linux/arm64** (Apple Silicon, Raspberry Pi, AWS Graviton).

```bash
# Pull the latest
docker pull certyiknofetch/linknest:latest

# Or a specific version
docker pull certyiknofetch/linknest:1.1
```

---

## Docker Compose — with Database

Full stack with a bundled PostgreSQL instance:

```bash
git clone https://github.com/certyiknofetch/linknest.git
cd linknest
cp server/.env.example .env
```

Edit `.env` with your secrets (see [Environment Variables](#environment-variables)), then:

```bash
docker compose up -d
```

**`docker-compose.yml`:**

```yaml
services:
  linknest:
    image: certyiknofetch/linknest:1.1
    container_name: linknest-server
    restart: unless-stopped
    ports:
      - "3000:3000"
    env_file: .env
    environment:
      - DB_PROVIDER=postgres
      - POSTGRES_URL=postgresql://linknest:${POSTGRES_PASSWORD:-changeme}@db:5432/linknest
      - POSTGRES_SSL=false
    depends_on:
      db:
        condition: service_healthy

  db:
    image: postgres:16-alpine
    container_name: linknest-db
    restart: unless-stopped
    volumes:
      - linknest_pgdata:/var/lib/postgresql/data
    environment:
      POSTGRES_USER: linknest
      POSTGRES_PASSWORD: ${POSTGRES_PASSWORD:-changeme}
      POSTGRES_DB: linknest
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U linknest -d linknest"]
      interval: 10s
      timeout: 5s
      retries: 5

volumes:
  linknest_pgdata:
```

---


## Docker Compose — External Database

Use this when you already have a PostgreSQL or MongoDB instance:

```bash
docker compose -f docker-compose.no-db.yml up -d
```

Set `POSTGRES_URL` or `MONGODB_URI` in your `.env` file pointing to your existing database.

---


## Environment Variables

Create a `.env` file from the example:

```bash
cp server/.env.example .env
```

| Variable | Required | Default | Description |
|---|---|---|---|
| `PORT` | No | `3000` | Server listen port |
| `DB_PROVIDER` | **Yes** | `mongodb` | Database type: `postgres` or `mongodb` |
| `POSTGRES_URL` | If postgres | — | PostgreSQL connection string |
| `POSTGRES_SSL` | No | `false` | Enable SSL for PostgreSQL connection |
| `POSTGRES_SSL_REJECT_UNAUTHORIZED` | No | `false` | Reject unauthorized SSL certificates |
| `MONGODB_URI` | If mongodb | — | MongoDB connection string |
| `JWT_SECRET` | **Yes** | — | Secret for signing access tokens |
| `ACCESS_JWT_EXPIRES_IN` | No | `15m` | Access token lifetime |
| `REFRESH_JWT_SECRET` | **Yes** | — | Secret for signing refresh tokens |
| `REFRESH_JWT_EXPIRES_IN` | No | `30d` | Refresh token lifetime |
| `TWO_FACTOR_CHALLENGE_SECRET` | **Yes** | — | Secret for 2FA challenge tokens |
| `TWO_FACTOR_CHALLENGE_EXPIRES_IN` | No | `5m` | 2FA challenge window |
| `TWO_FACTOR_ENCRYPTION_KEY` | **Yes** | — | AES-256-GCM key for TOTP secret encryption |
| `REQUIRE_HTTPS` | No | `true` | Reject non-HTTPS requests (except localhost) |
| `CORS_ORIGINS` | No | — | Comma-separated allowed origins |

### Generating Secrets

```bash
# Generate strong random secrets (run each one separately)
openssl rand -base64 32   # JWT_SECRET
openssl rand -base64 32   # REFRESH_JWT_SECRET
openssl rand -base64 32   # TWO_FACTOR_CHALLENGE_SECRET
openssl rand -base64 32   # TWO_FACTOR_ENCRYPTION_KEY
```

---

## Extension Setup

### Chromium Browsers (Chrome, Edge, Brave, Opera, Vivaldi)

1. Download or build `linknest-chromium.zip`
2. Extract to a folder
3. Open `chrome://extensions/` (or `edge://extensions/`, etc.)
4. Enable **Developer Mode**
5. Click **Load unpacked** → select the extracted folder
6. Click the LinkNest icon → go to **Settings** → set your server URL
7. Register or login

### Firefox

1. Download or build `linknest-firefox.zip`
2. Extract to a folder
3. Open `about:debugging#/runtime/this-firefox`
4. Click **Load Temporary Add-on** → select `manifest.json` from the extracted folder
5. Click the LinkNest icon → go to **Settings** → set your server URL
6. Register or login

> **Note:** Firefox temporary add-ons are removed on restart. For permanent installation, use `about:addons` with a signed `.xpi` file or use Firefox Developer Edition with `xpinstall.signatures.required` set to `false`.

### Building Extension ZIPs

```bash
# From the project root
rm -rf dist && mkdir -p dist/chromium dist/firefox

# Chromium
cp -R extension/. dist/chromium/
rm -f dist/chromium/manifest.firefox.json
(cd dist/chromium && zip -qr ../linknest-chromium.zip .)

# Firefox
cp -R extension/. dist/firefox/
cp extension/manifest.firefox.json dist/firefox/manifest.json
rm -f dist/firefox/manifest.firefox.json
(cd dist/firefox && zip -qr ../linknest-firefox.zip .)
```

---

## Reverse Proxy (Nginx Proxy Manager)

If you're running LinkNest behind a reverse proxy:

1. Add a new **Proxy Host** in Nginx Proxy Manager
2. **Domain**: `linknest.yourdomain.com`
3. **Forward Hostname**: `linknest-server` (Docker service name) or `localhost`
4. **Forward Port**: `3000`
5. **SSL**: Request a Let's Encrypt certificate

Set in `.env`:
```
CORS_ORIGINS=https://linknest.yourdomain.com
REQUIRE_HTTPS=true
```

---
