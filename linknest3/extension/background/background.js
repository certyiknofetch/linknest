/**
 * LinkNest - Background Service Worker
 * Handles bookmark change detection, periodic sync, and message passing
 */

// ===== Constants =====
const DEFAULT_SERVER_URL = '';
const DEFAULT_SYNC_INTERVAL = 15; // minutes

// Cross-browser API: Firefox MV2 'browser.*' returns Promises;
// Chrome MV3 'chrome.*' returns Promises. Firefox's 'chrome.*' does NOT.
const api = (typeof browser !== 'undefined' && browser.runtime) ? browser : chrome;

// ===== Cross-Browser Root Folder Normalization =====
// Different browsers use different names for root bookmark folders.
// We normalize them to canonical names so the same bookmark gets the same
// hash (and folderPath) regardless of which browser pushes it.

const ROOT_FOLDER_ALIASES = {
  'bookmarks bar': 'Toolbar',
  'bookmarks toolbar': 'Toolbar',
  'toolbar bookmarks': 'Toolbar',
  'favourites bar': 'Toolbar',
  'other bookmarks': 'Other',
  'other favourites': 'Other',
  'mobile bookmarks': 'Mobile',
  'bookmarks menu': 'Other',   // Firefox Menu → Other (Chrome has no Menu root)
};

const CANONICAL_ROOTS = new Set(['Toolbar', 'Other', 'Mobile']);

/**
 * Map a browser-specific root folder name to its canonical form.
 * Returns null if the name is not a known root folder.
 */
function normalizeRootFolderName(name) {
  if (!name) return null;
  return ROOT_FOLDER_ALIASES[name.toLowerCase().trim()] || null;
}

// ===== Storage Helpers =====

async function getStorage(keys) {
  return api.storage.local.get(keys);
}

async function setStorage(data) {
  return api.storage.local.set(data);
}

async function removeStorage(keys) {
  return api.storage.local.remove(keys);
}

// ===== API Helpers =====

let refreshInFlight = null;

async function getServerUrl() {
  const { serverUrl } = await getStorage(['serverUrl']);
  if (!serverUrl) {
    throw new Error('Server URL not configured. Please set it in Settings.');
  }

  try {
    const parsed = new URL(serverUrl);
    const isLocalhost = parsed.hostname === 'localhost' || parsed.hostname === '127.0.0.1';
    if (!isLocalhost && parsed.protocol !== 'https:') {
      throw new Error('Insecure server URL. Please use HTTPS.');
    }
    return serverUrl;
  } catch (e) {
    throw e.message ? e : new Error('Invalid server URL configuration.');
  }
}

async function parseJsonResponse(response) {
  try {
    return await response.json();
  } catch {
    return {};
  }
}

async function refreshAccessToken() {
  if (refreshInFlight) {
    return refreshInFlight;
  }

  refreshInFlight = (async () => {
    const serverUrl = await getServerUrl();
    const { refreshToken } = await getStorage(['refreshToken']);

    if (!refreshToken) {
      throw new Error('No refresh token available. Please log in again.');
    }

    const response = await fetch(`${serverUrl}/api/auth/refresh`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({ refreshToken }),
    });

    const data = await parseJsonResponse(response);
    if (!response.ok) {
      throw new Error(data.error || 'Session refresh failed. Please log in again.');
    }

    const nextAccessToken = data.accessToken || data.token;
    const nextRefreshToken = data.refreshToken || refreshToken;
    if (!nextAccessToken) {
      throw new Error('Refresh response did not include an access token.');
    }

    await setStorage({
      token: nextAccessToken,
      refreshToken: nextRefreshToken,
    });

    return nextAccessToken;
  })().finally(() => {
    refreshInFlight = null;
  });

  return refreshInFlight;
}

async function apiRequest(endpoint, options = {}, allowRefresh = true) {
  const serverUrl = await getServerUrl();
  const { token } = await getStorage(['token']);

  const headers = {
    'Content-Type': 'application/json',
    ...(token ? { Authorization: `Bearer ${token}` } : {}),
    ...options.headers,
  };

  const response = await fetch(`${serverUrl}/api${endpoint}`, {
    ...options,
    headers,
  });

  if (response.status === 401 && allowRefresh && endpoint !== '/auth/refresh') {
    try {
      await refreshAccessToken();
      return apiRequest(endpoint, options, false);
    } catch {
      await removeStorage(['token', 'refreshToken', 'user']);
      throw new Error('Session expired. Please log in again.');
    }
  }

  const data = await parseJsonResponse(response);

  if (!response.ok) {
    throw new Error(data.error || `Request failed (${response.status})`);
  }

  return data;
}

// ===== Bookmark Tree Helpers =====

/**
 * Flatten bookmark tree into an array of bookmark objects
 * Preserves folder structure as folderPath with normalized root names
 */
function flattenBookmarks(nodes, path = '') {
  const bookmarks = [];

  for (const node of nodes) {
    if (node.url) {
      // It's a bookmark
      bookmarks.push({
        bookmarkHash: generateHash(node.url + '|' + (path || 'root')),
        title: node.title || '',
        url: node.url,
        folderPath: path,
        index: node.index || 0,
        localId: node.id,
      });
    }

    if (node.children) {
      // It's a folder — normalize root-level browser folder names to canonical
      // names so the same bookmark gets the same hash across Chrome and Firefox.
      let folderName = node.title;
      if (!path) {
        const canonical = normalizeRootFolderName(folderName);
        if (canonical) folderName = canonical;
      }
      const folderPath = path ? `${path}/${folderName}` : folderName;
      bookmarks.push(...flattenBookmarks(node.children, folderPath));
    }
  }

  return bookmarks;
}

/**
 * Simple hash function to create a bookmark identifier
 * Based on URL + folder path for uniqueness
 */
function generateHash(str) {
  let hash = 0;
  for (let i = 0; i < str.length; i++) {
    const char = str.charCodeAt(i);
    hash = (hash << 5) - hash + char;
    hash |= 0; // Convert to 32-bit integer
  }
  return 'bm_' + Math.abs(hash).toString(36);
}

/**
 * Get all local bookmarks as a flat array
 */
async function getLocalBookmarks() {
  const tree = await api.bookmarks.getTree();
  return flattenBookmarks(tree);
}

function buildBookmarkMap(bookmarks) {
  const map = new Map();
  for (const bookmark of bookmarks) {
    map.set(bookmark.bookmarkHash, bookmark);
  }
  return map;
}

function getDeletedHashes(previousHashes = [], currentBookmarks = []) {
  if (!Array.isArray(previousHashes) || previousHashes.length === 0) {
    return [];
  }

  const currentHashes = new Set(currentBookmarks.map((bookmark) => bookmark.bookmarkHash));
  return previousHashes.filter((bookmarkHash) => !currentHashes.has(bookmarkHash));
}

async function applyServerBookmark(localBookmark, serverBookmark) {
  if (serverBookmark.isDeleted) {
    if (localBookmark) {
      await api.bookmarks.remove(localBookmark.localId);
      return { created: 0, updated: 0, deleted: 1 };
    }

    return { created: 0, updated: 0, deleted: 0 };
  }

  if (!localBookmark) {
    const parentId = await ensureFolderPath(serverBookmark.folderPath);
    await api.bookmarks.create({
      parentId,
      title: serverBookmark.title,
      url: serverBookmark.url,
      index: typeof serverBookmark.index === 'number' ? serverBookmark.index : undefined,
    });
    return { created: 1, updated: 0, deleted: 0 };
  }

  const titleChanged = localBookmark.title !== serverBookmark.title;
  const urlChanged = localBookmark.url !== serverBookmark.url;
  const folderChanged = (localBookmark.folderPath || '') !== (serverBookmark.folderPath || '');

  if (titleChanged || urlChanged) {
    await api.bookmarks.update(localBookmark.localId, {
      title: serverBookmark.title,
      url: serverBookmark.url,
    });
  }

  // Only move if the folder actually changed. Index is intentionally excluded
  // because different browsers have different item counts in folders, causing
  // perpetual index ping-pong between browsers.
  if (folderChanged) {
    const parentId = await ensureFolderPath(serverBookmark.folderPath);
    await api.bookmarks.move(localBookmark.localId, { parentId });
  }

  return {
    created: 0,
    updated: titleChanged || urlChanged || folderChanged ? 1 : 0,
    deleted: 0,
  };
}

/**
 * Find or create a folder path in the bookmark tree.
 * Handles canonical root names (Toolbar, Other, Mobile, Menu) and
 * legacy browser-specific names (Bookmarks Bar, Bookmarks Toolbar, etc.)
 * by mapping them to the browser's actual root bookmark folder.
 */
async function ensureFolderPath(folderPath) {
  const tree = await api.bookmarks.getTree();
  const rootChildren = tree[0].children;

  if (!folderPath) {
    // Default to "Other Bookmarks"
    const otherBookmarks = rootChildren.find(
      (c) => normalizeRootFolderName(c.title) === 'Other'
    );
    return otherBookmarks?.id || rootChildren[1]?.id || '2';
  }

  const parts = folderPath.split('/').filter(Boolean);
  // Default parent is the toolbar / bookmarks bar
  const defaultToolbar = rootChildren.find(
    (c) => normalizeRootFolderName(c.title) === 'Toolbar'
  );
  let parentId = defaultToolbar?.id || rootChildren[0]?.id || '1';

  for (let i = 0; i < parts.length; i++) {
    const part = parts[i];

    // For the first path component, map canonical or browser-specific root
    // names to the browser's actual root folder
    if (i === 0) {
      let canonical = CANONICAL_ROOTS.has(part) ? part : normalizeRootFolderName(part);
      // Legacy: old server data may have 'Menu' paths from before the
      // normalization change. Map to 'Other' so those bookmarks land
      // in the correct root folder on browsers without a Menu root.
      if (part === 'Menu') canonical = 'Other';
      if (canonical) {
        const rootFolder = rootChildren.find(
          (c) => normalizeRootFolderName(c.title) === canonical
        );
        if (rootFolder) {
          parentId = rootFolder.id;
          continue;
        }
      }
    }

    // Search for existing subfolder
    const children = await api.bookmarks.getChildren(parentId);
    const existing = children.find((c) => c.title === part && !c.url);

    if (existing) {
      parentId = existing.id;
    } else {
      // Create the folder
      const newFolder = await api.bookmarks.create({
        parentId,
        title: part,
      });
      parentId = newFolder.id;
    }
  }

  return parentId;
}

// ===== Sync Engine =====

/**
 * Full bidirectional sync
 * 1. Read local bookmarks
 * 2. Push to server
 * 3. Server returns merged result
 * 4. Apply missing bookmarks locally
 */
async function performSync() {
  const { token, refreshToken, browserName, lastSyncTime, lastLocalBookmarkHashes } = await getStorage([
    'token',
    'refreshToken',
    'browserName',
    'lastSyncTime',
    'lastLocalBookmarkHashes',
  ]);

  if (!token && !refreshToken) throw new Error('Not authenticated');

  // Step 1: Get local bookmarks and detect local deletions
  const localBookmarks = await getLocalBookmarks();
  const deletedBookmarkHashes = getDeletedHashes(lastLocalBookmarkHashes, localBookmarks);

  // Step 2: Push to server and get merged result
  const response = await apiRequest('/bookmarks/sync', {
    method: 'POST',
    body: JSON.stringify({
      bookmarks: localBookmarks,
      deletedBookmarkHashes,
      lastSyncTime: lastSyncTime || null,
      browserName: browserName || 'Unknown',
    }),
  });

  // Step 3: Apply server bookmarks locally
  // Build maps by hash AND by URL for proper matching.
  // A server bookmark may have a different hash (different folder) but same URL
  // as a local bookmark — we should update, not duplicate.
  const localBookmarksByHash = buildBookmarkMap(localBookmarks);
  const localBookmarksByUrl = new Map();
  for (const bm of localBookmarks) {
    if (!localBookmarksByUrl.has(bm.url)) {
      localBookmarksByUrl.set(bm.url, bm);
    }
  }
  let pulled = 0;
  let remoteUpdated = 0;
  let removed = 0;

  isApplyingRemoteChanges = true;

  for (const serverBm of response.bookmarks) {
    try {
      // First try exact hash match, then fall back to URL match
      let localBookmark = localBookmarksByHash.get(serverBm.bookmarkHash);
      if (!localBookmark && localBookmarksByUrl.has(serverBm.url)) {
        localBookmark = localBookmarksByUrl.get(serverBm.url);
      }
      const result = await applyServerBookmark(localBookmark, serverBm);
      pulled += result.created;
      remoteUpdated += result.updated;
      removed += result.deleted;
    } catch (err) {
      console.warn(`Failed to apply server bookmark: ${serverBm.url}`, err);
    }
  }

  isApplyingRemoteChanges = false;

  // Update sync state
  const finalLocalBookmarks = await getLocalBookmarks();
  await setStorage({
    lastSyncTime: response.serverTime,
    lastLocalBookmarkHashes: finalLocalBookmarks.map((bookmark) => bookmark.bookmarkHash),
  });

  return {
    success: true,
    created: response.results.created,
    updated: response.results.updated,
    pulled,
    remoteUpdated,
    removed,
  };
}

/**
 * Push-only: send local bookmarks to server
 */
async function pushBookmarks() {
  const { browserName, lastLocalBookmarkHashes } = await getStorage([
    'browserName',
    'lastLocalBookmarkHashes',
  ]);
  const localBookmarks = await getLocalBookmarks();
  const deletedBookmarkHashes = getDeletedHashes(lastLocalBookmarkHashes, localBookmarks);

  const response = await apiRequest('/bookmarks/sync', {
    method: 'POST',
    body: JSON.stringify({
      bookmarks: localBookmarks,
      deletedBookmarkHashes,
      browserName: browserName || 'Unknown',
    }),
  });

  await setStorage({
    lastSyncTime: response.serverTime,
    lastLocalBookmarkHashes: localBookmarks.map((bookmark) => bookmark.bookmarkHash),
  });

  return {
    success: true,
    count: localBookmarks.length,
  };
}

/**
 * Pull-only: fetch bookmarks from server and add missing ones locally
 */
async function pullBookmarks() {
  const response = await apiRequest('/bookmarks');
  const localBookmarks = await getLocalBookmarks();
  const localBookmarksByHash = buildBookmarkMap(localBookmarks);
  const localBookmarksByUrl = new Map();
  for (const bm of localBookmarks) {
    if (!localBookmarksByUrl.has(bm.url)) {
      localBookmarksByUrl.set(bm.url, bm);
    }
  }

  let added = 0;
  let updated = 0;
  let deleted = 0;

  isApplyingRemoteChanges = true;
  for (const serverBm of response.bookmarks) {
    try {
      let localBookmark = localBookmarksByHash.get(serverBm.bookmarkHash);
      if (!localBookmark && localBookmarksByUrl.has(serverBm.url)) {
        localBookmark = localBookmarksByUrl.get(serverBm.url);
      }
      const result = await applyServerBookmark(localBookmark, serverBm);
      added += result.created;
      updated += result.updated;
      deleted += result.deleted;
    } catch (err) {
      console.warn(`Failed to apply server bookmark: ${serverBm.url}`, err);
    }
  }

  isApplyingRemoteChanges = false;

  const finalLocalBookmarks = await getLocalBookmarks();
  await setStorage({
    lastSyncTime: response.serverTime,
    lastLocalBookmarkHashes: finalLocalBookmarks.map((bookmark) => bookmark.bookmarkHash),
  });

  return {
    success: true,
    count: added,
    updated,
    deleted,
  };
}

// ===== Message Handling =====

async function handleMessage(message) {
  try {
    switch (message.action) {
      case 'sync':
        return await performSync();

      case 'push':
        return await pushBookmarks();

      case 'pull':
        return await pullBookmarks();

      case 'updateSettings':
        await setupAlarm(message.settings);
        return { success: true };

      default:
        return { error: 'Unknown action' };
    }
  } catch (err) {
    console.error(`LinkNest background [${message.action}] error:`, err);
    return { success: false, error: err.message || String(err) || 'Unknown background error' };
  }
}

// Firefox MV2: browser.runtime.onMessage listener must RETURN a Promise.
// Chrome MV3: api.runtime.onMessage uses sendResponse + return true.
if (typeof browser !== 'undefined' && browser.runtime && browser.runtime.onMessage) {
  // Firefox: use browser API — listener returns a Promise directly
  browser.runtime.onMessage.addListener((message) => {
    return handleMessage(message);
  });
} else {
  // Chrome: use chrome API — listener uses sendResponse callback
  api.runtime.onMessage.addListener((message, sender, sendResponse) => {
    handleMessage(message).then(sendResponse);
    return true; // keep channel open for async sendResponse
  });
}

// ===== Bookmark Change Listeners =====

let syncDebounceTimer = null;
let isApplyingRemoteChanges = false;

function debouncedSync() {
  if (isApplyingRemoteChanges) {
    return;
  }

  if (syncDebounceTimer) clearTimeout(syncDebounceTimer);
  syncDebounceTimer = setTimeout(async () => {
    const { autoSync, token } = await getStorage(['autoSync', 'token']);
    if (autoSync !== false && token) {
      try {
        await performSync();
        console.log('LinkNest: Auto-sync completed after bookmark change');
      } catch (err) {
        console.warn('LinkNest: Auto-sync failed:', err.message);
      }
    }
  }, 5000); // Wait 5 seconds after last change before syncing
}

api.bookmarks.onCreated.addListener(() => debouncedSync());
api.bookmarks.onRemoved.addListener(() => debouncedSync());
api.bookmarks.onChanged.addListener(() => debouncedSync());
api.bookmarks.onMoved.addListener(() => debouncedSync());

// ===== Periodic Sync via Alarms =====

async function setupAlarm(settings) {
  // Clear existing alarm
  await api.alarms.clear('linknest-sync');

  const autoSync = settings?.autoSync !== false;
  const interval = parseInt(settings?.syncInterval) || DEFAULT_SYNC_INTERVAL;

  if (autoSync) {
    api.alarms.create('linknest-sync', {
      periodInMinutes: interval,
    });
    console.log(`LinkNest: Sync alarm set for every ${interval} minutes`);
  }
}

api.alarms.onAlarm.addListener(async (alarm) => {
  if (alarm.name === 'linknest-sync') {
    const { token } = await getStorage(['token']);
    if (token) {
      try {
        await performSync();
        console.log('LinkNest: Periodic sync completed');
      } catch (err) {
        console.warn('LinkNest: Periodic sync failed:', err.message);
      }
    }
  }
});

// ===== Extension Install / Startup =====

api.runtime.onInstalled.addListener(async () => {
  console.log('LinkNest extension installed');
  await setupAlarm();
});

api.runtime.onStartup.addListener(async () => {
  console.log('LinkNest extension started');
  const settings = await getStorage(['autoSync', 'syncInterval']);
  await setupAlarm(settings);
});
