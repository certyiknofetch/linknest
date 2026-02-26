const express = require('express');
const jwt = require('jsonwebtoken');
const rateLimit = require('express-rate-limit');
const {
  getUserId,
  listBookmarks,
  softDeleteBookmarksByHashes,
  findBookmarkByHash,
  createBookmark,
  updateBookmark,
  updateUserLastSyncedAt,
  softDeleteBookmark,
  softDeleteAllBookmarks,
} = require('../services/dataAdapter');
const { protect } = require('../middleware/auth');

const router = express.Router();

// Strict rate limiter for destructive bulk-delete (3 per 15 min)
const deleteAllLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 3,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'Too many reset attempts. Please try again later.' },
});

const MAX_BOOKMARKS_PER_SYNC = 20000;
const MAX_TEXT_FIELD_LENGTH = 512;

function isValidDateString(value) {
  if (!value || typeof value !== 'string') return false;
  const parsed = new Date(value);
  return !Number.isNaN(parsed.getTime());
}

function isValidUrl(value) {
  if (typeof value !== 'string' || value.length === 0) return false;
  try {
    const parsed = new URL(value);
    return parsed.protocol === 'http:' || parsed.protocol === 'https:';
  } catch {
    return false;
  }
}

function safeString(value, defaultValue = '') {
  if (typeof value !== 'string') return defaultValue;
  return value.trim().slice(0, MAX_TEXT_FIELD_LENGTH);
}

function sanitizeClientBookmark(bookmark) {
  if (!bookmark || typeof bookmark !== 'object') return null;

  const bookmarkHash = safeString(bookmark.bookmarkHash);
  const title = safeString(bookmark.title);
  const folderPath = safeString(bookmark.folderPath);
  const favicon = safeString(bookmark.favicon);

  if (!bookmarkHash || !isValidUrl(bookmark.url)) {
    return null;
  }

  return {
    bookmarkHash,
    title,
    url: bookmark.url,
    folderPath,
    favicon,
    index: Number.isInteger(bookmark.index) && bookmark.index >= 0 ? bookmark.index : 0,
    isDeleted: Boolean(bookmark.isDeleted),
  };
}

function isMeaningfulChange(existing, incoming) {
  // NOTE: `index` is intentionally excluded. Different browsers assign
  // different indices to the same bookmark (depending on folder contents),
  // which causes an infinite update ping-pong between browsers.
  return (
    existing.title !== incoming.title ||
    existing.url !== incoming.url ||
    existing.folderPath !== incoming.folderPath ||
    existing.favicon !== incoming.favicon ||
    existing.isDeleted !== incoming.isDeleted
  );
}

// All routes require authentication
router.use(protect);

// GET /api/bookmarks - Get all bookmarks for the user
router.get('/', async (req, res) => {
  try {
    const { since } = req.query;
    const userId = getUserId(req.user);

    if (since && !isValidDateString(since)) {
      return res.status(400).json({ error: 'Invalid since timestamp.' });
    }

    const bookmarks = await listBookmarks(userId, {
      since: since || null,
      includeDeleted: Boolean(since),
    });

    return res.json({
      bookmarks,
      serverTime: new Date().toISOString(),
    });
  } catch (error) {
    return res.status(500).json({ error: error.message });
  }
});

// POST /api/bookmarks/sync - Full sync endpoint (push + pull)
router.post('/sync', async (req, res) => {
  try {
    const {
      bookmarks: clientBookmarks,
      deletedBookmarkHashes,
      lastSyncTime,
      browserName,
    } = req.body;

    if (!Array.isArray(clientBookmarks)) {
      return res.status(400).json({ error: 'bookmarks must be an array.' });
    }

    if (clientBookmarks.length > MAX_BOOKMARKS_PER_SYNC) {
      return res.status(413).json({ error: 'Too many bookmarks in a single sync request.' });
    }

    if (lastSyncTime && !isValidDateString(lastSyncTime)) {
      return res.status(400).json({ error: 'Invalid lastSyncTime timestamp.' });
    }

    const userId = getUserId(req.user);
    const sourceBrowser = safeString(browserName || 'unknown', 'unknown');

    const sanitizedBookmarks = clientBookmarks
      .map((bookmark) => sanitizeClientBookmark(bookmark))
      .filter(Boolean);

    const deletedHashes = Array.isArray(deletedBookmarkHashes)
      ? deletedBookmarkHashes
          .filter((value) => typeof value === 'string')
          .map((value) => value.trim())
          .filter((value) => value.length > 0)
          .slice(0, MAX_BOOKMARKS_PER_SYNC)
      : [];

    const results = {
      created: 0,
      updated: 0,
      deleted: 0,
      conflicts: [],
    };

    if (deletedHashes.length > 0) {
      results.deleted += await softDeleteBookmarksByHashes(userId, deletedHashes);
    }

    for (const bookmark of sanitizedBookmarks) {
      const existing = await findBookmarkByHash(userId, bookmark.bookmarkHash);

      if (!existing) {
        // No hash match — this is a new bookmark. Create it.
        // The same URL in different folders is allowed (different hashes).
        // True duplicates (same URL + same folder) are prevented by the
        // UNIQUE(user_id, bookmark_hash) constraint in the database.
        await createBookmark(userId, bookmark, sourceBrowser);
        results.created += 1;
        continue;
      }

      const incoming = {
        title: bookmark.title,
        url: bookmark.url,
        folderPath: bookmark.folderPath || existing.folderPath,
        favicon: bookmark.favicon || existing.favicon,
        index: bookmark.index ?? existing.index,
        isDeleted: bookmark.isDeleted || false,
      };

      if (isMeaningfulChange(existing, incoming)) {
        await updateBookmark(userId, bookmark.bookmarkHash, incoming, sourceBrowser);
        results.updated += 1;
      }
    }

    // Always return the FULL non-deleted bookmark set.
    // Using a `since` filter here caused a bug: if Browser A pushed bookmarks
    // and then Browser B synced, Browser B's next sync would skip those
    // bookmarks because they hadn't changed since Browser B's lastSyncTime.
    // Returning the full set ensures every browser sees every bookmark.
    const serverBookmarks = await listBookmarks(userId, {
      since: null,
      includeDeleted: false,
    });

    await updateUserLastSyncedAt(userId, new Date());

    return res.json({
      results,
      bookmarks: serverBookmarks,
      serverTime: new Date().toISOString(),
    });
  } catch (error) {
    return res.status(500).json({ error: error.message });
  }
});

// DELETE /api/bookmarks/:bookmarkHash - Soft-delete a bookmark
router.delete('/:bookmarkHash', async (req, res) => {
  try {
    const userId = getUserId(req.user);
    const bookmarkHash = safeString(req.params.bookmarkHash);
    const bookmark = await softDeleteBookmark(userId, bookmarkHash);

    if (!bookmark) {
      return res.status(404).json({ error: 'Bookmark not found.' });
    }

    return res.json({ message: 'Bookmark deleted.', bookmark });
  } catch (error) {
    return res.status(500).json({ error: error.message });
  }
});

// DELETE /api/bookmarks - Delete all bookmarks for user (reset)
// Requires a verified action token for safety
router.delete('/', deleteAllLimiter, async (req, res) => {
  try {
    // Verify action token — issued by /auth/verify-action
    const actionToken = req.headers['x-action-token'];
    if (!actionToken) {
      return res.status(403).json({ error: 'Action verification required. Please confirm your identity.' });
    }

    let decoded;
    try {
      decoded = jwt.verify(actionToken, process.env.JWT_SECRET);
    } catch {
      return res.status(403).json({ error: 'Invalid or expired action token. Please verify your identity again.' });
    }

    if (decoded.type !== 'action_verify') {
      return res.status(403).json({ error: 'Invalid action token type.' });
    }

    const userId = getUserId(req.user);
    if (String(decoded.id) !== String(userId)) {
      return res.status(403).json({ error: 'Action token does not match authenticated user.' });
    }

    await softDeleteAllBookmarks(userId);
    return res.json({ message: 'All bookmarks deleted.' });
  } catch (error) {
    return res.status(500).json({ error: error.message });
  }
});

module.exports = router;
