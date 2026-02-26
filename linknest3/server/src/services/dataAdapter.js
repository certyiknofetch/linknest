const bcrypt = require('bcryptjs');
const User = require('../models/User');
const Bookmark = require('../models/Bookmark');
const { isPostgres, pgQuery } = require('../config/postgres');

function getUserId(user) {
  return isPostgres ? user.id : user._id;
}

function normalizeTwoFactor(twoFactor = {}) {
  return {
    enabled: Boolean(twoFactor.enabled),
    method: twoFactor.method || 'totp',
    secretEncrypted: twoFactor.secretEncrypted || '',
    enabledAt: twoFactor.enabledAt || null,
    backupCodes: Array.isArray(twoFactor.backupCodes) ? twoFactor.backupCodes : [],
    pendingSecretEncrypted: twoFactor.pendingSecretEncrypted || '',
    pendingCreatedAt: twoFactor.pendingCreatedAt || null,
    webauthnCredentials: Array.isArray(twoFactor.webauthnCredentials)
      ? twoFactor.webauthnCredentials
      : [],
  };
}

function normalizeRefreshTokens(tokens = []) {
  return Array.isArray(tokens) ? tokens : [];
}

function mapUserRow(row) {
  if (!row) return null;

  return {
    id: row.id,
    email: row.email,
    name: row.name || '',
    passwordHash: row.password_hash,
    lastSyncedAt: row.last_synced_at,
    refreshTokens: normalizeRefreshTokens(row.refresh_tokens),
    twoFactor: normalizeTwoFactor(row.two_factor),
    createdAt: row.created_at,
    updatedAt: row.updated_at,
  };
}

async function findUserByEmail(email, { includePassword = false } = {}) {
  if (!isPostgres) {
    const query = User.findOne({ email });
    if (includePassword) query.select('+password');
    return query;
  }

  const { rows } = await pgQuery('SELECT * FROM users WHERE email = $1 LIMIT 1', [email]);
  const user = mapUserRow(rows[0]);
  if (!user) return null;
  if (!includePassword) delete user.passwordHash;
  return user;
}

async function findUserById(id, { includePassword = false } = {}) {
  if (!isPostgres) {
    const query = User.findById(id);
    if (includePassword) query.select('+password');
    return query;
  }

  const { rows } = await pgQuery('SELECT * FROM users WHERE id = $1 LIMIT 1', [id]);
  const user = mapUserRow(rows[0]);
  if (!user) return null;
  if (!includePassword) delete user.passwordHash;
  return user;
}

async function createUser({ email, password, name = '' }) {
  if (!isPostgres) {
    return User.create({ email, password, name });
  }

  const passwordHash = await bcrypt.hash(password, 12);
  const { rows } = await pgQuery(
    `
      INSERT INTO users (email, password_hash, name)
      VALUES ($1, $2, $3)
      RETURNING *
    `,
    [email, passwordHash, name || '']
  );

  return mapUserRow(rows[0]);
}

async function verifyUserPassword(user, password) {
  if (!user) return false;
  if (!isPostgres) return user.comparePassword(password);
  return bcrypt.compare(password, user.passwordHash);
}

async function saveUser(user) {
  if (!isPostgres) {
    await user.save();
    return user;
  }

  const { rows } = await pgQuery(
    `
      UPDATE users
      SET
        name = $2,
        last_synced_at = $3,
        refresh_tokens = $4::jsonb,
        two_factor = $5::jsonb,
        updated_at = NOW()
      WHERE id = $1
      RETURNING *
    `,
    [
      user.id,
      user.name || '',
      user.lastSyncedAt || null,
      JSON.stringify(normalizeRefreshTokens(user.refreshTokens)),
      JSON.stringify(normalizeTwoFactor(user.twoFactor)),
    ]
  );

  return mapUserRow(rows[0]);
}

async function updateUserLastSyncedAt(userId, timestamp = new Date()) {
  if (!isPostgres) {
    await User.findByIdAndUpdate(userId, { lastSyncedAt: timestamp });
    return;
  }

  await pgQuery('UPDATE users SET last_synced_at = $2, updated_at = NOW() WHERE id = $1', [userId, timestamp]);
}

function mapBookmarkRow(row) {
  return {
    id: row.id,
    user: row.user_id,
    bookmarkHash: row.bookmark_hash,
    title: row.title,
    url: row.url,
    folderPath: row.folder_path,
    favicon: row.favicon,
    sourceBrowser: row.source_browser,
    index: row.position_index,
    isDeleted: row.is_deleted,
    deletedAt: row.deleted_at,
    createdAt: row.created_at,
    updatedAt: row.updated_at,
  };
}

async function listBookmarks(userId, { since = null, includeDeleted = false } = {}) {
  if (!isPostgres) {
    const query = { user: userId };
    if (since) {
      query.updatedAt = { $gt: new Date(since) };
    } else if (!includeDeleted) {
      query.isDeleted = false;
    }

    const bookmarks = await Bookmark.find(query).sort({ folderPath: 1, index: 1 }).lean();
    return bookmarks;
  }

  let sql = 'SELECT * FROM bookmarks WHERE user_id = $1';
  const params = [userId];

  if (since) {
    sql += ' AND updated_at > $2';
    params.push(new Date(since));
  } else if (!includeDeleted) {
    sql += ' AND is_deleted = false';
  }

  sql += ' ORDER BY folder_path ASC, position_index ASC';
  const { rows } = await pgQuery(sql, params);
  return rows.map(mapBookmarkRow);
}

async function softDeleteBookmarksByHashes(userId, hashes = []) {
  if (!hashes.length) return 0;

  if (!isPostgres) {
    const result = await Bookmark.updateMany(
      {
        user: userId,
        bookmarkHash: { $in: hashes },
        isDeleted: false,
      },
      {
        isDeleted: true,
        deletedAt: new Date(),
      }
    );
    return result.modifiedCount || 0;
  }

  const { rowCount } = await pgQuery(
    `
      UPDATE bookmarks
      SET is_deleted = true, deleted_at = NOW(), updated_at = NOW()
      WHERE user_id = $1 AND bookmark_hash = ANY($2::text[]) AND is_deleted = false
    `,
    [userId, hashes]
  );

  return rowCount || 0;
}

async function findBookmarkByHash(userId, bookmarkHash) {
  if (!isPostgres) {
    return Bookmark.findOne({ user: userId, bookmarkHash });
  }

  const { rows } = await pgQuery(
    'SELECT * FROM bookmarks WHERE user_id = $1 AND bookmark_hash = $2 LIMIT 1',
    [userId, bookmarkHash]
  );

  return rows[0] ? mapBookmarkRow(rows[0]) : null;
}

/**
 * Find a non-deleted bookmark by URL for URL-level dedup.
 * If the same URL already exists (in any folder), we should update
 * rather than create a duplicate.
 */
async function findBookmarkByUrl(userId, url) {
  if (!isPostgres) {
    return Bookmark.findOne({ user: userId, url, isDeleted: false });
  }

  const { rows } = await pgQuery(
    'SELECT * FROM bookmarks WHERE user_id = $1 AND url = $2 AND is_deleted = false LIMIT 1',
    [userId, url]
  );

  return rows[0] ? mapBookmarkRow(rows[0]) : null;
}

async function createBookmark(userId, bookmark, sourceBrowser) {
  if (!isPostgres) {
    // Use upsert to handle concurrent sync race conditions safely.
    // If two browsers push the same bookmark simultaneously, the second
    // write becomes an update instead of throwing a duplicate-key error.
    await Bookmark.findOneAndUpdate(
      { user: userId, bookmarkHash: bookmark.bookmarkHash },
      {
        $set: {
          title: bookmark.title,
          url: bookmark.url,
          folderPath: bookmark.folderPath || '',
          favicon: bookmark.favicon || '',
          sourceBrowser,
          index: bookmark.index || 0,
          isDeleted: bookmark.isDeleted || false,
          deletedAt: bookmark.isDeleted ? new Date() : null,
        },
      },
      { upsert: true, new: true }
    );
    return;
  }

  await pgQuery(
    `
      INSERT INTO bookmarks
        (user_id, bookmark_hash, title, url, folder_path, favicon, source_browser, position_index, is_deleted, deleted_at)
      VALUES
        ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
      ON CONFLICT (user_id, bookmark_hash) DO UPDATE SET
        title = EXCLUDED.title,
        url = EXCLUDED.url,
        folder_path = EXCLUDED.folder_path,
        favicon = EXCLUDED.favicon,
        source_browser = EXCLUDED.source_browser,
        position_index = EXCLUDED.position_index,
        is_deleted = EXCLUDED.is_deleted,
        deleted_at = EXCLUDED.deleted_at,
        updated_at = NOW()
    `,
    [
      userId,
      bookmark.bookmarkHash,
      bookmark.title,
      bookmark.url,
      bookmark.folderPath || '',
      bookmark.favicon || '',
      sourceBrowser,
      bookmark.index || 0,
      Boolean(bookmark.isDeleted),
      bookmark.isDeleted ? new Date() : null,
    ]
  );
}

async function updateBookmark(userId, bookmarkHash, incoming, sourceBrowser) {
  if (!isPostgres) {
    const existing = await Bookmark.findOne({ user: userId, bookmarkHash });
    if (!existing) return null;

    existing.title = incoming.title;
    existing.url = incoming.url;
    existing.folderPath = incoming.folderPath || existing.folderPath;
    existing.favicon = incoming.favicon || existing.favicon;
    existing.index = incoming.index ?? existing.index;
    existing.isDeleted = incoming.isDeleted || false;
    existing.deletedAt = incoming.isDeleted ? new Date() : null;
    existing.sourceBrowser = sourceBrowser || existing.sourceBrowser;
    await existing.save();
    return existing;
  }

  const { rows } = await pgQuery(
    `
      UPDATE bookmarks
      SET
        title = $3,
        url = $4,
        folder_path = $5,
        favicon = $6,
        position_index = $7,
        is_deleted = $8,
        deleted_at = $9,
        source_browser = $10,
        updated_at = NOW()
      WHERE user_id = $1 AND bookmark_hash = $2
      RETURNING *
    `,
    [
      userId,
      bookmarkHash,
      incoming.title,
      incoming.url,
      incoming.folderPath || '',
      incoming.favicon || '',
      incoming.index ?? 0,
      Boolean(incoming.isDeleted),
      incoming.isDeleted ? new Date() : null,
      sourceBrowser || 'unknown',
    ]
  );

  return rows[0] ? mapBookmarkRow(rows[0]) : null;
}

async function softDeleteBookmark(userId, bookmarkHash) {
  if (!isPostgres) {
    return Bookmark.findOneAndUpdate(
      {
        user: userId,
        bookmarkHash,
      },
      {
        isDeleted: true,
        deletedAt: new Date(),
      },
      { new: true }
    );
  }

  const { rows } = await pgQuery(
    `
      UPDATE bookmarks
      SET is_deleted = true, deleted_at = NOW(), updated_at = NOW()
      WHERE user_id = $1 AND bookmark_hash = $2
      RETURNING *
    `,
    [userId, bookmarkHash]
  );

  return rows[0] ? mapBookmarkRow(rows[0]) : null;
}

async function softDeleteAllBookmarks(userId) {
  // Hard-delete so a "Clear Server & Re-push" gives a truly clean slate.
  // Soft-deleted zombies with stale hashes would otherwise persist forever
  // and bloat the sync response when includeDeleted is true.
  if (!isPostgres) {
    await Bookmark.deleteMany({ user: userId });
    return;
  }

  await pgQuery(
    `DELETE FROM bookmarks WHERE user_id = $1`,
    [userId]
  );
}

module.exports = {
  isPostgres,
  getUserId,
  normalizeTwoFactor,
  findUserByEmail,
  findUserById,
  createUser,
  verifyUserPassword,
  saveUser,
  updateUserLastSyncedAt,
  listBookmarks,
  softDeleteBookmarksByHashes,
  findBookmarkByHash,
  findBookmarkByUrl,
  createBookmark,
  updateBookmark,
  softDeleteBookmark,
  softDeleteAllBookmarks,
};
