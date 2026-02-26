/**
 * LinkNest - Popup Script
 * Handles UI interactions, auth flow, and sync triggers
 */

// ===== DOM Elements =====
const loginView = document.getElementById('loginView');
const dashboardView = document.getElementById('dashboardView');
const settingsView = document.getElementById('settingsView');

const authForm = document.getElementById('authForm');
const authTabs = document.getElementById('authTabs');
const nameField = document.getElementById('nameField');
const twoFactorField = document.getElementById('twoFactorField');
const twoFactorCode = document.getElementById('twoFactorCode');
const cancelTwoFactorBtn = document.getElementById('cancelTwoFactorBtn');
const authError = document.getElementById('authError');
const authSubmit = document.getElementById('authSubmit');
const authBtnText = document.getElementById('authBtnText');
const authSpinner = document.getElementById('authSpinner');

const userEmail = document.getElementById('userEmail');
const userAvatar = document.getElementById('userAvatar');
const syncStatus = document.getElementById('syncStatus');
const localCount = document.getElementById('localCount');
const serverCount = document.getElementById('serverCount');
const browserNameEl = document.getElementById('browserName');

const syncNowBtn = document.getElementById('syncNowBtn');
const syncBtnText = document.getElementById('syncBtnText');
const syncSpinner = document.getElementById('syncSpinner');
const pushBtn = document.getElementById('pushBtn');
const pullBtn = document.getElementById('pullBtn');
const logoutBtn = document.getElementById('logoutBtn');
const clearServerBtn = document.getElementById('clearServerBtn');

const settingsBtn = document.getElementById('settingsBtn');
const backBtn = document.getElementById('backBtn');
const saveSettingsBtn = document.getElementById('saveSettingsBtn');

// Server URL lock elements
const serverUrlLockBtn = document.getElementById('serverUrlLockBtn');
const lockIconLocked = document.getElementById('lockIconLocked');
const lockIconUnlocked = document.getElementById('lockIconUnlocked');

// Clear Server verification elements
const clearServerVerify = document.getElementById('clearServerVerify');
const clearVerifyPrompt = document.getElementById('clearVerifyPrompt');
const clearVerifyInput = document.getElementById('clearVerifyInput');
const clearVerifyBtn = document.getElementById('clearVerifyBtn');
const clearVerifyCancelBtn = document.getElementById('clearVerifyCancelBtn');
const clearVerifyError = document.getElementById('clearVerifyError');

const syncLog = document.getElementById('syncLog');
const logEntries = document.getElementById('logEntries');

let currentAuthMode = 'login';
let pendingTwoFactorChallenge = null;
let serverUrlLockTimeout = null;

const DEFAULT_SERVER_URL = '';

// ===== Utility Functions =====

/**
 * Cross-browser sendMessage wrapper.
 * Firefox MV2 'chrome.runtime.sendMessage' is callback-based;
 * 'browser.runtime.sendMessage' returns a Promise.
 * Chrome MV3 'chrome.runtime.sendMessage' returns a Promise.
 */
function sendMessageToBackground(msg) {
  if (typeof browser !== 'undefined' && browser.runtime && browser.runtime.sendMessage) {
    return browser.runtime.sendMessage(msg);
  }
  return chrome.runtime.sendMessage(msg);
}

function showView(view) {
  [loginView, dashboardView, settingsView].forEach((v) => v.classList.add('hidden'));
  view.classList.remove('hidden');
}

function showError(el, message) {
  el.textContent = message;
  el.classList.remove('hidden');
}

function hideError(el) {
  el.classList.add('hidden');
}

function setLoading(btn, spinner, textEl, loading, text) {
  btn.disabled = loading;
  spinner.classList.toggle('hidden', !loading);
  textEl.textContent = text || textEl.textContent;
}

function resetTwoFactorState() {
  pendingTwoFactorChallenge = null;
  twoFactorField.classList.add('hidden');
  twoFactorCode.value = '';
  document.getElementById('email').disabled = false;
  document.getElementById('password').disabled = false;
  nameField.classList.toggle('hidden', currentAuthMode === 'login');
  authTabs.classList.remove('hidden');
  authBtnText.textContent = currentAuthMode === 'login' ? 'Login' : 'Register';
}

function addLogEntry(message, type = 'info') {
  syncLog.classList.remove('hidden');
  const entry = document.createElement('div');
  entry.className = `log-entry ${type}`;
  const time = new Date().toLocaleTimeString();
  entry.innerHTML = `<span>${message}</span><span class="log-time">${time}</span>`;
  logEntries.prepend(entry);

  // Keep only last 20 entries
  while (logEntries.children.length > 20) {
    logEntries.removeChild(logEntries.lastChild);
  }
}

function detectBrowser() {
  const ua = navigator.userAgent;
  if (ua.includes('Firefox')) return 'Firefox';
  if (ua.includes('Edg/')) return 'Edge';
  if (ua.includes('Brave')) return 'Brave';
  if (ua.includes('OPR') || ua.includes('Opera')) return 'Opera';
  if (ua.includes('Chrome')) return 'Chrome';
  if (ua.includes('Safari')) return 'Safari';
  return 'Unknown';
}

// ===== Storage Helpers =====

async function getStorage(keys) {
  return new Promise((resolve) => {
    chrome.storage.local.get(keys, resolve);
  });
}

async function setStorage(data) {
  return new Promise((resolve) => {
    chrome.storage.local.set(data, resolve);
  });
}

async function removeStorage(keys) {
  return new Promise((resolve) => {
    chrome.storage.local.remove(keys, resolve);
  });
}

/**
 * Cross-browser bookmarks.getTree wrapper.
 * Firefox MV2 'chrome.bookmarks.getTree()' is callback-based (returns undefined).
 * 'browser.bookmarks.getTree()' returns a Promise.
 * Chrome MV3 'chrome.bookmarks.getTree()' returns a Promise.
 */
function getBookmarksTree() {
  if (typeof browser !== 'undefined' && browser.bookmarks && browser.bookmarks.getTree) {
    return browser.bookmarks.getTree();
  }
  // Chrome MV3: returns a Promise
  return chrome.bookmarks.getTree();
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
      // Session is gone — show login view immediately
      resetTwoFactorState();
      showView(loginView);
      authForm.reset();
      hideError(authError);
      throw new Error('Session expired. Please log in again.');
    }
  }

  const data = await parseJsonResponse(response);

  if (!response.ok) {
    throw new Error(data.error || `Request failed (${response.status})`);
  }

  return data;
}

// ===== Auth =====

authTabs.addEventListener('click', (e) => {
  const tab = e.target.closest('.tab');
  if (!tab) return;

  currentAuthMode = tab.dataset.tab;
  resetTwoFactorState();
  authTabs.querySelectorAll('.tab').forEach((t) => t.classList.remove('active'));
  tab.classList.add('active');

  nameField.classList.toggle('hidden', currentAuthMode === 'login');
  authBtnText.textContent = currentAuthMode === 'login' ? 'Login' : 'Register';
  hideError(authError);
});

cancelTwoFactorBtn.addEventListener('click', () => {
  resetTwoFactorState();
  hideError(authError);
});

authForm.addEventListener('submit', async (e) => {
  e.preventDefault();
  hideError(authError);

  const email = document.getElementById('email').value.trim();
  const password = document.getElementById('password').value;
  const name = document.getElementById('name').value.trim();
  const enteredTwoFactorCode = twoFactorCode.value.trim();

  if (!email || !password) {
    showError(authError, 'Please fill in all fields.');
    return;
  }

  setLoading(authSubmit, authSpinner, authBtnText, true);

  try {
    let endpoint = currentAuthMode === 'login' ? '/auth/login' : '/auth/register';
    let body = { email, password };

    if (pendingTwoFactorChallenge) {
      endpoint = '/auth/2fa/verify-login';
      body = {
        challengeToken: pendingTwoFactorChallenge,
        totpCode: enteredTwoFactorCode,
      };

      if (!enteredTwoFactorCode) {
        throw new Error('Please enter your authenticator code.');
      }
    } else if (currentAuthMode === 'register' && name) {
      body.name = name;
    }

    const data = await apiRequest(endpoint, {
      method: 'POST',
      body: JSON.stringify(body),
    });

    if (data.requiresTwoFactor) {
      pendingTwoFactorChallenge = data.challengeToken;
      twoFactorField.classList.remove('hidden');
      authTabs.classList.add('hidden');
      nameField.classList.add('hidden');
      document.getElementById('email').disabled = true;
      document.getElementById('password').disabled = true;
      authBtnText.textContent = 'Verify 2FA';
      twoFactorCode.focus();
      return;
    }

    // Save auth data
    await setStorage({
      token: data.accessToken || data.token,
      refreshToken: data.refreshToken || null,
      user: data.user,
    });

    resetTwoFactorState();

    showDashboard(data.user);
  } catch (err) {
    showError(authError, err.message);
  } finally {
    setLoading(authSubmit, authSpinner, authBtnText, false, currentAuthMode === 'login' ? 'Login' : 'Register');
  }
});

// ===== Dashboard =====

async function showDashboard(user) {
  showView(dashboardView);

  userEmail.textContent = user.email;
  userAvatar.textContent = (user.name || user.email)[0].toUpperCase();

  const browser = detectBrowser();
  browserNameEl.textContent = browser;
  await setStorage({ browserName: browser });

  await refreshStats();
}

async function refreshStats() {
  try {
    // Get local bookmark count
    const tree = await getBookmarksTree();
    const count = countBookmarks(tree);
    localCount.textContent = count;

    // Get server count
    const { lastSyncTime } = await getStorage(['lastSyncTime']);
    if (lastSyncTime) {
      syncStatus.textContent = `Last synced: ${new Date(lastSyncTime).toLocaleString()}`;
    }

    try {
      const data = await apiRequest('/bookmarks');
      serverCount.textContent = data.bookmarks.length;
    } catch {
      serverCount.textContent = '?';
    }
  } catch (err) {
    console.error('Failed to refresh stats:', err);
  }
}

function countBookmarks(nodes) {
  let count = 0;
  for (const node of nodes) {
    if (node.url) count++;
    if (node.children) count += countBookmarks(node.children);
  }
  return count;
}

// ===== Sync Actions =====

syncNowBtn.addEventListener('click', async () => {
  setLoading(syncNowBtn, syncSpinner, syncBtnText, true, 'Syncing...');
  try {
    // Send message to background script to perform sync
    const response = await sendMessageToBackground({ action: 'sync' });
    if (response?.success) {
      addLogEntry(`Synced: ${response.created || 0} new, ${response.updated || 0} updated`, 'success');
      await setStorage({ lastSyncTime: new Date().toISOString() });
      await refreshStats();
    } else {
      const errMsg = response?.error || response?.message || 'Sync failed (no details)';
      throw new Error(errMsg);
    }
  } catch (err) {
    addLogEntry(`Error: ${err.message}`, 'error');
    console.error('LinkNest sync error:', err);
  } finally {
    setLoading(syncNowBtn, syncSpinner, syncBtnText, false, 'Sync Now');
  }
});

pushBtn.addEventListener('click', async () => {
  pushBtn.disabled = true;
  try {
    const response = await sendMessageToBackground({ action: 'push' });
    if (response?.success) {
      addLogEntry(`Pushed ${response.count || 0} bookmarks to cloud`, 'success');
      await refreshStats();
    } else {
      const errMsg = response?.error || response?.message || 'Push failed (no details)';
      throw new Error(errMsg);
    }
  } catch (err) {
    addLogEntry(`Push error: ${err.message}`, 'error');
    console.error('LinkNest push error:', err);
  } finally {
    pushBtn.disabled = false;
  }
});

pullBtn.addEventListener('click', async () => {
  pullBtn.disabled = true;
  try {
    const response = await sendMessageToBackground({ action: 'pull' });
    if (response?.success) {
      addLogEntry(`Pulled ${response.count || 0} bookmarks from cloud`, 'success');
      await refreshStats();
    } else {
      const errMsg = response?.error || response?.message || 'Pull failed (no details)';
      throw new Error(errMsg);
    }
  } catch (err) {
    addLogEntry(`Pull error: ${err.message}`, 'error');
    console.error('LinkNest pull error:', err);
  } finally {
    pullBtn.disabled = false;
  }
});

// ===== Server URL Lock =====

function lockServerUrl() {
  const serverUrlInput = document.getElementById('serverUrl');
  serverUrlInput.disabled = true;
  serverUrlInput.classList.add('input-locked');
  lockIconLocked.classList.remove('hidden');
  lockIconUnlocked.classList.add('hidden');
  serverUrlLockBtn.title = 'Unlock to edit';
  if (serverUrlLockTimeout) {
    clearTimeout(serverUrlLockTimeout);
    serverUrlLockTimeout = null;
  }
}

function unlockServerUrl() {
  const serverUrlInput = document.getElementById('serverUrl');
  serverUrlInput.disabled = false;
  serverUrlInput.classList.remove('input-locked');
  lockIconLocked.classList.add('hidden');
  lockIconUnlocked.classList.remove('hidden');
  serverUrlLockBtn.title = 'Click to lock';
  serverUrlInput.focus();
  // Auto-lock after 30 seconds
  if (serverUrlLockTimeout) clearTimeout(serverUrlLockTimeout);
  serverUrlLockTimeout = setTimeout(lockServerUrl, 30000);
}

serverUrlLockBtn.addEventListener('click', () => {
  const serverUrlInput = document.getElementById('serverUrl');
  if (serverUrlInput.disabled) {
    unlockServerUrl();
  } else {
    lockServerUrl();
  }
});

// ===== Clear Server & Re-push =====

clearServerBtn.addEventListener('click', async () => {
  // Show verification section instead of confirm()
  clearServerVerify.classList.remove('hidden');
  clearServerBtn.classList.add('hidden');
  hideError(clearVerifyError);
  clearVerifyInput.value = '';

  // Check if 2FA is enabled to show the right input
  try {
    const data = await apiRequest('/auth/2fa/status');
    const has2FA = data.twoFactor && data.twoFactor.enabled;

    if (has2FA) {
      clearVerifyInput.type = 'text';
      clearVerifyInput.placeholder = '123456';
      clearVerifyInput.inputMode = 'numeric';
      clearVerifyInput.maxLength = 6;
      clearVerifyPrompt.textContent = 'Enter your authenticator code:';
    } else {
      clearVerifyInput.type = 'password';
      clearVerifyInput.placeholder = 'Enter your password';
      clearVerifyInput.inputMode = '';
      clearVerifyInput.maxLength = 128;
      clearVerifyPrompt.textContent = 'Enter your password to continue:';
    }
  } catch {
    // Fallback to password
    clearVerifyInput.type = 'password';
    clearVerifyInput.placeholder = 'Enter your password';
    clearVerifyPrompt.textContent = 'Enter your password to continue:';
  }

  clearVerifyInput.focus();
});

clearVerifyBtn.addEventListener('click', async () => {
  const value = clearVerifyInput.value.trim();
  if (!value) {
    showError(clearVerifyError, 'Please enter your verification.');
    return;
  }

  clearVerifyBtn.disabled = true;
  hideError(clearVerifyError);

  try {
    // Build verify body based on input type
    const is2FA = clearVerifyInput.type === 'text';
    const body = is2FA ? { totpCode: value } : { password: value };

    // Step 1: Verify identity and get action token
    const verifyData = await apiRequest('/auth/verify-action', {
      method: 'POST',
      body: JSON.stringify(body),
    });

    const actionToken = verifyData.actionToken;

    // Step 2: Delete all server bookmarks with verified action token
    await apiRequest('/bookmarks', {
      method: 'DELETE',
      headers: { 'X-Action-Token': actionToken },
    });
    addLogEntry('Server bookmarks cleared', 'success');

    // Step 3: Clear local sync state
    await setStorage({ lastSyncTime: null, lastLocalBookmarkHashes: [] });

    // Step 4: Push fresh bookmarks
    const response = await sendMessageToBackground({ action: 'push' });
    if (response?.success) {
      addLogEntry(`Re-pushed ${response.count || 0} bookmarks to cloud`, 'success');
      await refreshStats();
    } else {
      throw new Error(response?.error || 'Push failed');
    }

    // Done — hide verification, show button
    clearServerVerify.classList.add('hidden');
    clearServerBtn.classList.remove('hidden');
  } catch (err) {
    showError(clearVerifyError, err.message);
  } finally {
    clearVerifyBtn.disabled = false;
  }
});

clearVerifyCancelBtn.addEventListener('click', () => {
  clearServerVerify.classList.add('hidden');
  clearServerBtn.classList.remove('hidden');
  hideError(clearVerifyError);
  clearVerifyInput.value = '';
});

// ===== Logout =====

logoutBtn.addEventListener('click', async () => {
  const { token, refreshToken } = await getStorage(['token', 'refreshToken']);
  const serverUrl = await getServerUrl();

  if (token) {
    try {
      await fetch(`${serverUrl}/api/auth/logout`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${token}`,
        },
        body: JSON.stringify({ refreshToken }),
      });
    } catch {
      // Ignore network errors on logout cleanup
    }
  }

  await removeStorage(['token', 'refreshToken', 'user', 'lastSyncTime', 'lastLocalBookmarkHashes']);
  resetTwoFactorState();
  showView(loginView);
  authForm.reset();
  hideError(authError);
});

// ===== Settings =====

settingsBtn.addEventListener('click', async () => {
  const { autoSync, syncInterval, serverUrl, token } = await getStorage([
    'autoSync',
    'syncInterval',
    'serverUrl',
    'token',
  ]);

  document.getElementById('autoSync').checked = autoSync !== false;
  document.getElementById('syncInterval').value = syncInterval || '15';
  document.getElementById('serverUrl').value = serverUrl || '';

  // Lock server URL when logged in
  if (token) {
    serverUrlLockBtn.classList.remove('hidden');
    lockServerUrl();
  } else {
    serverUrlLockBtn.classList.add('hidden');
    document.getElementById('serverUrl').disabled = false;
    document.getElementById('serverUrl').classList.remove('input-locked');
  }

  showView(settingsView);

  // Load 2FA status (async, non-blocking)
  refresh2faStatus();
});

backBtn.addEventListener('click', async () => {
  const { token, user } = await getStorage(['token', 'user']);
  if (token && user) {
    showDashboard(user);
  } else {
    showView(loginView);
  }
});

saveSettingsBtn.addEventListener('click', async () => {
  const autoSync = document.getElementById('autoSync').checked;
  const syncInterval = document.getElementById('syncInterval').value;
  const serverUrl = document.getElementById('serverUrl').value.replace(/\/+$/, '');

  try {
    const parsed = new URL(serverUrl);
    const isLocalhost = parsed.hostname === 'localhost' || parsed.hostname === '127.0.0.1';
    if (!isLocalhost && parsed.protocol !== 'https:') {
      showError(authError, 'Server URL must use HTTPS (except localhost).');
      return;
    }
  } catch {
    showError(authError, 'Please enter a valid server URL.');
    return;
  }

  await setStorage({ autoSync, syncInterval, serverUrl });

  // Re-lock server URL after save
  const { token: savedToken } = await getStorage(['token']);
  if (savedToken) {
    lockServerUrl();
  }

  // Notify background to update alarm
  sendMessageToBackground({
    action: 'updateSettings',
    settings: { autoSync, syncInterval, serverUrl },
  });

  // Go back
  const { token, user } = await getStorage(['token', 'user']);
  if (token && user) {
    showDashboard(user);
  } else {
    showView(loginView);
  }
});

// ===== 2FA Setup =====

const securitySection = document.getElementById('securitySection');
const twoFactorBadge = document.getElementById('twoFactorBadge');
const twoFactorEnableSection = document.getElementById('twoFactorEnableSection');
const twoFactorDisableSection = document.getElementById('twoFactorDisableSection');
const twoFactorSetupFlow = document.getElementById('twoFactorSetupFlow');
const backupCodesSection = document.getElementById('backupCodesSection');
const backupCodesList = document.getElementById('backupCodesList');
const backupCodesRemaining = document.getElementById('backupCodesRemaining');
const totpSecret = document.getElementById('totpSecret');
const totpQrImage = document.getElementById('totpQrImage');
const secretKeyBox = document.getElementById('secretKeyBox');
const toggleSecretBtn = document.getElementById('toggleSecretBtn');
const totpVerifyCode = document.getElementById('totpVerifyCode');
const setup2faBtn = document.getElementById('setup2faBtn');
const verify2faBtn = document.getElementById('verify2faBtn');
const disable2faBtn = document.getElementById('disable2faBtn');
const copySecretBtn = document.getElementById('copySecretBtn');
const dismissBackupCodesBtn = document.getElementById('dismissBackupCodesBtn');
const setup2faError = document.getElementById('setup2faError');
const disable2faVerify = document.getElementById('disable2faVerify');
const disable2faPrompt = document.getElementById('disable2faPrompt');
const disable2faInput = document.getElementById('disable2faInput');
const disable2faConfirmBtn = document.getElementById('disable2faConfirmBtn');
const disable2faCancelBtn = document.getElementById('disable2faCancelBtn');
const disable2faError = document.getElementById('disable2faError');

/**
 * Load 2FA status from server and update the Security section in Settings.
 * Only shows the section when the user is logged in.
 */
async function refresh2faStatus() {
  const { token } = await getStorage(['token']);
  if (!token) {
    securitySection.classList.add('hidden');
    return;
  }

  try {
    const data = await apiRequest('/auth/2fa/status');
    const info = data.twoFactor;

    securitySection.classList.remove('hidden');

    // Reset sub-sections
    twoFactorSetupFlow.classList.add('hidden');
    backupCodesSection.classList.add('hidden');
    setup2faError.classList.add('hidden');
    totpVerifyCode.value = '';

    if (info.enabled) {
      twoFactorBadge.textContent = 'On';
      twoFactorBadge.className = 'badge badge-on';
      twoFactorEnableSection.classList.add('hidden');
      twoFactorDisableSection.classList.remove('hidden');
      backupCodesRemaining.textContent = info.backupCodesCount ?? 0;
    } else {
      twoFactorBadge.textContent = 'Off';
      twoFactorBadge.className = 'badge badge-off';
      twoFactorEnableSection.classList.remove('hidden');
      twoFactorDisableSection.classList.add('hidden');
    }
  } catch {
    // Not logged in or network error — hide section
    securitySection.classList.add('hidden');
  }
}

// Start 2FA setup: request secret + QR from server
setup2faBtn.addEventListener('click', async () => {
  setup2faBtn.disabled = true;
  setup2faError.classList.add('hidden');

  try {
    const data = await apiRequest('/auth/2fa/totp/setup/start', { method: 'POST' });

    // Show QR code
    if (data.qrDataUrl) {
      totpQrImage.src = data.qrDataUrl;
      totpQrImage.classList.remove('hidden');
    } else {
      totpQrImage.classList.add('hidden');
    }

    // Set secret (hidden by default)
    totpSecret.textContent = data.secret;
    secretKeyBox.classList.add('hidden');
    toggleSecretBtn.innerHTML = '<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/><circle cx="12" cy="12" r="3"/></svg> Show secret key';

    twoFactorSetupFlow.classList.remove('hidden');
    twoFactorEnableSection.classList.add('hidden');
    totpVerifyCode.focus();
  } catch (err) {
    showError(setup2faError, err.message);
  } finally {
    setup2faBtn.disabled = false;
  }
});

// Toggle secret key visibility
toggleSecretBtn.addEventListener('click', () => {
  const isHidden = secretKeyBox.classList.contains('hidden');
  if (isHidden) {
    secretKeyBox.classList.remove('hidden');
    toggleSecretBtn.innerHTML = '<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M17.94 17.94A10.07 10.07 0 0 1 12 20c-7 0-11-8-11-8a18.45 18.45 0 0 1 5.06-5.94M9.9 4.24A9.12 9.12 0 0 1 12 4c7 0 11 8 11 8a18.5 18.5 0 0 1-2.16 3.19m-6.72-1.07a3 3 0 1 1-4.24-4.24"/><line x1="1" y1="1" x2="23" y2="23"/></svg> Hide secret key';
  } else {
    secretKeyBox.classList.add('hidden');
    toggleSecretBtn.innerHTML = '<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/><circle cx="12" cy="12" r="3"/></svg> Show secret key';
  }
});

// Copy secret to clipboard
copySecretBtn.addEventListener('click', async () => {
  const secret = totpSecret.textContent;
  if (!secret || secret === '—') return;

  try {
    await navigator.clipboard.writeText(secret);
    copySecretBtn.title = 'Copied!';
    setTimeout(() => { copySecretBtn.title = 'Copy secret'; }, 2000);
  } catch {
    // Fallback: select the text
    const range = document.createRange();
    range.selectNodeContents(totpSecret);
    const sel = window.getSelection();
    sel.removeAllRanges();
    sel.addRange(range);
  }
});

// Verify TOTP code and enable 2FA
verify2faBtn.addEventListener('click', async () => {
  const code = totpVerifyCode.value.trim();
  if (!code) {
    showError(setup2faError, 'Enter the 6-digit code from your authenticator.');
    return;
  }

  verify2faBtn.disabled = true;
  setup2faError.classList.add('hidden');

  try {
    const data = await apiRequest('/auth/2fa/totp/setup/verify', {
      method: 'POST',
      body: JSON.stringify({ code }),
    });

    // Show backup codes
    twoFactorSetupFlow.classList.add('hidden');
    backupCodesSection.classList.remove('hidden');
    backupCodesList.innerHTML = '';
    for (const bc of data.backupCodes) {
      const span = document.createElement('span');
      span.textContent = bc;
      backupCodesList.appendChild(span);
    }

    // Update badge
    twoFactorBadge.textContent = 'On';
    twoFactorBadge.className = 'badge badge-on';
  } catch (err) {
    showError(setup2faError, err.message);
  } finally {
    verify2faBtn.disabled = false;
  }
});

// Dismiss backup codes after user confirms they saved them
dismissBackupCodesBtn.addEventListener('click', async () => {
  backupCodesSection.classList.add('hidden');
  // 2FA is now active — after enabling, all refresh tokens are revoked
  // so the user needs to re-login. Force re-login.
  await removeStorage(['token', 'refreshToken', 'user', 'lastSyncTime', 'lastLocalBookmarkHashes']);
  resetTwoFactorState();
  showView(loginView);
  authForm.reset();
  hideError(authError);
  addLogEntry('2FA enabled — please log in again', 'success');
});

// Disable 2FA — show verification inline first
disable2faBtn.addEventListener('click', () => {
  disable2faBtn.classList.add('hidden');
  disable2faVerify.classList.remove('hidden');
  disable2faInput.value = '';
  hideError(disable2faError);
  disable2faInput.focus();
});

disable2faCancelBtn.addEventListener('click', () => {
  disable2faVerify.classList.add('hidden');
  disable2faBtn.classList.remove('hidden');
  disable2faInput.value = '';
  hideError(disable2faError);
});

disable2faConfirmBtn.addEventListener('click', async () => {
  const code = disable2faInput.value.trim();
  if (!code) {
    showError(disable2faError, 'Enter your authenticator code to continue.');
    return;
  }

  disable2faConfirmBtn.disabled = true;
  hideError(disable2faError);

  try {
    await apiRequest('/auth/2fa/disable', {
      method: 'POST',
      body: JSON.stringify({ totpCode: code }),
    });

    // 2FA disabled — all refresh tokens revoked, force re-login
    await removeStorage(['token', 'refreshToken', 'user', 'lastSyncTime', 'lastLocalBookmarkHashes']);
    resetTwoFactorState();
    showView(loginView);
    authForm.reset();
    hideError(authError);
    addLogEntry('2FA disabled — please log in again', 'success');
  } catch (err) {
    showError(disable2faError, err.message);
  } finally {
    disable2faConfirmBtn.disabled = false;
  }
});

// ===== Init =====

(async () => {
  const { token, user } = await getStorage(['token', 'user']);

  if (token && user) {
    // Verify token is still valid
    try {
      const data = await apiRequest('/auth/me');
      showDashboard(data.user);
    } catch {
      // Token expired, show login
      await removeStorage(['token', 'refreshToken', 'user']);
      resetTwoFactorState();
      showView(loginView);
    }
  } else {
    resetTwoFactorState();
    showView(loginView);
  }
})();
