const { Pool } = require('pg');

const isPostgres = (process.env.DB_PROVIDER || 'mongodb').toLowerCase() === 'postgres';

let pool = null;

function getPool() {
  if (!isPostgres) {
    throw new Error('PostgreSQL pool requested while DB_PROVIDER is not postgres.');
  }

  if (!pool) {
    const connectionString = process.env.POSTGRES_URL;
    if (!connectionString) {
      throw new Error('POSTGRES_URL is required when DB_PROVIDER=postgres.');
    }

    pool = new Pool({
      connectionString,
      ssl:
        process.env.POSTGRES_SSL === 'true'
          ? {
              rejectUnauthorized: process.env.POSTGRES_SSL_REJECT_UNAUTHORIZED === 'true',
            }
          : false,
    });
  }

  return pool;
}

async function pgQuery(text, params = []) {
  const client = getPool();
  return client.query(text, params);
}

async function initPostgres() {
  const client = getPool();
  await client.query('SELECT 1');

  await client.query('CREATE EXTENSION IF NOT EXISTS pgcrypto');

  await client.query(`
    CREATE TABLE IF NOT EXISTS users (
      id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
      email TEXT NOT NULL UNIQUE,
      password_hash TEXT NOT NULL,
      name TEXT NOT NULL DEFAULT '',
      last_synced_at TIMESTAMPTZ,
      refresh_tokens JSONB NOT NULL DEFAULT '[]'::jsonb,
      two_factor JSONB NOT NULL DEFAULT '{"enabled": false, "method": "totp", "secretEncrypted": "", "enabledAt": null, "backupCodes": [], "pendingSecretEncrypted": "", "pendingCreatedAt": null, "webauthnCredentials": []}'::jsonb,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    )
  `);

  await client.query(`
    CREATE TABLE IF NOT EXISTS bookmarks (
      id BIGSERIAL PRIMARY KEY,
      user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      bookmark_hash TEXT NOT NULL,
      title TEXT NOT NULL,
      url TEXT NOT NULL,
      folder_path TEXT NOT NULL DEFAULT '',
      favicon TEXT NOT NULL DEFAULT '',
      source_browser TEXT NOT NULL DEFAULT 'unknown',
      position_index INTEGER NOT NULL DEFAULT 0,
      is_deleted BOOLEAN NOT NULL DEFAULT false,
      deleted_at TIMESTAMPTZ,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      UNIQUE(user_id, bookmark_hash)
    )
  `);

  await client.query('CREATE INDEX IF NOT EXISTS idx_bookmarks_user_updated ON bookmarks (user_id, updated_at)');
  await client.query('CREATE INDEX IF NOT EXISTS idx_bookmarks_user_deleted ON bookmarks (user_id, is_deleted)');
}

module.exports = {
  isPostgres,
  pgQuery,
  initPostgres,
};
