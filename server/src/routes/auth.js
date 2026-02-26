const express = require('express');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const { authenticator } = require('otplib');
const QRCode = require('qrcode');
const { protect } = require('../middleware/auth');
const {
  getUserId,
  normalizeTwoFactor,
  findUserByEmail,
  findUserById,
  createUser,
  verifyUserPassword,
  saveUser,
} = require('../services/dataAdapter');

const router = express.Router();

authenticator.options = {
  step: 30,
  window: 1,
};

const ACCESS_EXPIRES_IN = process.env.ACCESS_JWT_EXPIRES_IN || '15m';
const REFRESH_EXPIRES_IN = process.env.REFRESH_JWT_EXPIRES_IN || '30d';
const REFRESH_SECRET = process.env.REFRESH_JWT_SECRET || process.env.JWT_SECRET;
const TWO_FACTOR_CHALLENGE_SECRET = process.env.TWO_FACTOR_CHALLENGE_SECRET || process.env.JWT_SECRET;
const TWO_FACTOR_CHALLENGE_EXPIRES_IN = process.env.TWO_FACTOR_CHALLENGE_EXPIRES_IN || '5m';
const MAX_REFRESH_TOKENS_PER_USER = 30;

function validatePasswordStrength(password) {
  if (typeof password !== 'string') {
    return 'Password is required.';
  }

  if (password.length < 10) {
    return 'Password must be at least 10 characters long.';
  }

  const hasUpper = /[A-Z]/.test(password);
  const hasLower = /[a-z]/.test(password);
  const hasDigit = /\d/.test(password);

  if (!hasUpper || !hasLower || !hasDigit) {
    return 'Password must include uppercase, lowercase, and a number.';
  }

  return null;
}

function userIdAsString(user) {
  return String(getUserId(user));
}

function getRefreshTokens(user) {
  return Array.isArray(user.refreshTokens) ? user.refreshTokens : [];
}

function setRefreshTokens(user, refreshTokens) {
  user.refreshTokens = refreshTokens;
}

function getTwoFactor(user) {
  return normalizeTwoFactor(user.twoFactor || {});
}

function setTwoFactor(user, twoFactor) {
  user.twoFactor = normalizeTwoFactor(twoFactor);
}

function ensureEncryptionKey() {
  const configuredKey = process.env.TWO_FACTOR_ENCRYPTION_KEY;
  if (!configuredKey || configuredKey.trim().length < 16) {
    throw new Error('TWO_FACTOR_ENCRYPTION_KEY must be set and strong.');
  }

  return crypto.createHash('sha256').update(configuredKey).digest();
}

function encryptSecret(plainText) {
  const key = ensureEncryptionKey();
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);

  let encrypted = cipher.update(plainText, 'utf8', 'base64');
  encrypted += cipher.final('base64');
  const tag = cipher.getAuthTag().toString('base64');

  return `${iv.toString('base64')}:${tag}:${encrypted}`;
}

function decryptSecret(payload) {
  if (!payload) return '';

  const key = ensureEncryptionKey();
  const [ivB64, tagB64, encrypted] = payload.split(':');
  if (!ivB64 || !tagB64 || !encrypted) {
    throw new Error('Invalid encrypted secret format.');
  }

  const decipher = crypto.createDecipheriv(
    'aes-256-gcm',
    key,
    Buffer.from(ivB64, 'base64')
  );
  decipher.setAuthTag(Buffer.from(tagB64, 'base64'));

  let decrypted = decipher.update(encrypted, 'base64', 'utf8');
  decrypted += decipher.final('utf8');
  return decrypted;
}

function signAccessToken(id) {
  return jwt.sign({ id, type: 'access' }, process.env.JWT_SECRET, {
    expiresIn: ACCESS_EXPIRES_IN,
  });
}

function signRefreshToken(id, tokenId, familyId) {
  return jwt.sign({ id, type: 'refresh', jti: tokenId, fid: familyId }, REFRESH_SECRET, {
    expiresIn: REFRESH_EXPIRES_IN,
  });
}

function signTwoFactorChallenge(userId, method) {
  return jwt.sign(
    {
      id: userId,
      type: '2fa_challenge',
      method,
    },
    TWO_FACTOR_CHALLENGE_SECRET,
    { expiresIn: TWO_FACTOR_CHALLENGE_EXPIRES_IN }
  );
}

function hashToken(token) {
  return crypto.createHash('sha256').update(token).digest('hex');
}

function hashBackupCode(code) {
  return crypto.createHash('sha256').update(code).digest('hex');
}

function generateBackupCodes(count = 10) {
  const backupCodes = [];
  for (let i = 0; i < count; i += 1) {
    backupCodes.push(crypto.randomBytes(4).toString('hex').toUpperCase());
  }
  return backupCodes;
}

function getClientMeta(req) {
  return {
    ip: req.ip || '',
    userAgent: req.get('user-agent') || '',
  };
}

function trimRefreshTokenHistory(user) {
  const sorted = [...getRefreshTokens(user)].sort(
    (a, b) => new Date(b.issuedAt).getTime() - new Date(a.issuedAt).getTime()
  );
  setRefreshTokens(user, sorted.slice(0, MAX_REFRESH_TOKENS_PER_USER));
}

async function issueTokenPair(user, req, familyId = null) {
  const userId = userIdAsString(user);
  const tokenId = crypto.randomUUID();
  const resolvedFamilyId = familyId || crypto.randomUUID();

  const accessToken = signAccessToken(userId);
  const refreshToken = signRefreshToken(userId, tokenId, resolvedFamilyId);
  const refreshDecoded = jwt.decode(refreshToken);
  const { ip, userAgent } = getClientMeta(req);

  const sessions = getRefreshTokens(user);
  sessions.push({
    tokenId,
    familyId: resolvedFamilyId,
    tokenHash: hashToken(refreshToken),
    issuedAt: new Date().toISOString(),
    expiresAt: new Date(refreshDecoded.exp * 1000).toISOString(),
    revokedAt: null,
    replacedByTokenId: null,
    ip,
    userAgent,
  });

  setRefreshTokens(user, sessions);
  trimRefreshTokenHistory(user);
  await saveUser(user);

  return {
    accessToken,
    refreshToken,
    accessTokenExpiresIn: ACCESS_EXPIRES_IN,
    refreshTokenExpiresIn: REFRESH_EXPIRES_IN,
    tokenId,
    familyId: resolvedFamilyId,
  };
}

function revokeAllActiveRefreshTokens(user) {
  const now = new Date().toISOString();
  const sessions = getRefreshTokens(user).map((session) => ({
    ...session,
    revokedAt: session.revokedAt || now,
  }));

  setRefreshTokens(user, sessions);
}

function consumeBackupCode(twoFactorState, backupCode) {
  const submittedHash = hashBackupCode(backupCode.trim().toUpperCase());
  let consumed = false;

  const backupCodes = (twoFactorState.backupCodes || []).map((entry) => {
    if (!consumed && !entry.usedAt && entry.codeHash === submittedHash) {
      consumed = true;
      return {
        ...entry,
        usedAt: new Date().toISOString(),
      };
    }

    return entry;
  });

  return {
    consumed,
    backupCodes,
  };
}

function sanitizeEmail(value) {
  return typeof value === 'string' ? value.trim().toLowerCase() : '';
}

// POST /api/auth/register
router.post('/register', async (req, res) => {
  try {
    const email = sanitizeEmail(req.body.email);
    const { password, name } = req.body;

    if (!email || !password) {
      return res.status(400).json({ error: 'Email and password are required.' });
    }

    const passwordError = validatePasswordStrength(password);
    if (passwordError) {
      return res.status(400).json({ error: passwordError });
    }

    const existingUser = await findUserByEmail(email);
    if (existingUser) {
      return res.status(409).json({ error: 'An account with this email already exists.' });
    }

    const user = await createUser({ email, password, name });
    const tokens = await issueTokenPair(user, req);

    return res.status(201).json({
      accessToken: tokens.accessToken,
      refreshToken: tokens.refreshToken,
      expiresIn: tokens.accessTokenExpiresIn,
      user: {
        id: userIdAsString(user),
        email: user.email,
        name: user.name,
        twoFactorEnabled: getTwoFactor(user).enabled,
      },
    });
  } catch (error) {
    return res.status(500).json({ error: error.message });
  }
});

// POST /api/auth/login
router.post('/login', async (req, res) => {
  try {
    const email = sanitizeEmail(req.body.email);
    const { password } = req.body;

    if (!email || !password) {
      return res.status(400).json({ error: 'Email and password are required.' });
    }

    const user = await findUserByEmail(email, { includePassword: true });
    if (!user || !(await verifyUserPassword(user, password))) {
      return res.status(401).json({ error: 'Invalid email or password.' });
    }

    const twoFactor = getTwoFactor(user);
    if (twoFactor.enabled) {
      const challengeToken = signTwoFactorChallenge(userIdAsString(user), twoFactor.method || 'totp');
      return res.status(202).json({
        requiresTwoFactor: true,
        method: twoFactor.method || 'totp',
        challengeToken,
      });
    }

    const tokens = await issueTokenPair(user, req);
    return res.json({
      accessToken: tokens.accessToken,
      refreshToken: tokens.refreshToken,
      expiresIn: tokens.accessTokenExpiresIn,
      user: {
        id: userIdAsString(user),
        email: user.email,
        name: user.name,
        twoFactorEnabled: twoFactor.enabled,
      },
    });
  } catch (error) {
    return res.status(500).json({ error: error.message });
  }
});

// POST /api/auth/2fa/verify-login
router.post('/2fa/verify-login', async (req, res) => {
  try {
    const { challengeToken, totpCode, backupCode } = req.body || {};
    if (!challengeToken || typeof challengeToken !== 'string') {
      return res.status(400).json({ error: 'challengeToken is required.' });
    }

    const decoded = jwt.verify(challengeToken, TWO_FACTOR_CHALLENGE_SECRET);
    if (decoded.type !== '2fa_challenge') {
      return res.status(401).json({ error: 'Invalid 2FA challenge.' });
    }

    const user = await findUserById(decoded.id, { includePassword: true });
    if (!user) {
      return res.status(401).json({ error: 'User no longer exists.' });
    }

    const twoFactor = getTwoFactor(user);
    if (!twoFactor.enabled) {
      return res.status(400).json({ error: '2FA is not enabled for this account.' });
    }

    if ((twoFactor.method || 'totp') !== 'totp') {
      return res.status(400).json({ error: 'WebAuthn login is optional and not configured in this build.' });
    }

    let verified = false;
    if (typeof totpCode === 'string' && totpCode.trim()) {
      const secret = decryptSecret(twoFactor.secretEncrypted);
      verified = authenticator.verify({ token: totpCode.trim(), secret });
    }

    if (!verified && typeof backupCode === 'string' && backupCode.trim()) {
      const consumeResult = consumeBackupCode(twoFactor, backupCode);
      if (consumeResult.consumed) {
        twoFactor.backupCodes = consumeResult.backupCodes;
        setTwoFactor(user, twoFactor);
        await saveUser(user);
        verified = true;
      }
    }

    if (!verified) {
      return res.status(401).json({ error: 'Invalid 2FA code.' });
    }

    const tokens = await issueTokenPair(user, req);
    return res.json({
      accessToken: tokens.accessToken,
      refreshToken: tokens.refreshToken,
      expiresIn: tokens.accessTokenExpiresIn,
      user: {
        id: userIdAsString(user),
        email: user.email,
        name: user.name,
        twoFactorEnabled: true,
      },
    });
  } catch {
    return res.status(401).json({ error: 'Invalid or expired 2FA challenge.' });
  }
});

// POST /api/auth/refresh
router.post('/refresh', async (req, res) => {
  try {
    const { refreshToken } = req.body;

    if (!refreshToken || typeof refreshToken !== 'string') {
      return res.status(400).json({ error: 'refreshToken is required.' });
    }

    const decoded = jwt.verify(refreshToken, REFRESH_SECRET);
    if (decoded.type !== 'refresh' || !decoded.jti || !decoded.fid) {
      return res.status(401).json({ error: 'Invalid refresh token.' });
    }

    const user = await findUserById(decoded.id, { includePassword: true });
    if (!user) {
      return res.status(401).json({ error: 'User no longer exists.' });
    }

    const tokenHash = hashToken(refreshToken);
    const sessions = getRefreshTokens(user);

    const existingSession = sessions.find(
      (session) =>
        session.tokenHash === tokenHash &&
        session.tokenId === decoded.jti &&
        !session.revokedAt &&
        new Date(session.expiresAt) > new Date()
    );

    if (!existingSession) {
      const knownSession = sessions.find((session) => session.tokenId === decoded.jti);
      if (knownSession?.revokedAt) {
        // Grace period: if this token was rotated very recently (within 30s),
        // return the replacement's tokens instead of revoking the whole family.
        // This handles the race condition when background + popup refresh simultaneously.
        const revokedAt = new Date(knownSession.revokedAt);
        const gracePeriodMs = 30_000; // 30 seconds
        if ((Date.now() - revokedAt.getTime()) < gracePeriodMs && knownSession.replacedByTokenId) {
          // Find the replacement session and return the current valid access token
          const replacementSession = sessions.find(
            (s) => s.tokenId === knownSession.replacedByTokenId && !s.revokedAt
          );
          if (replacementSession) {
            // Issue a new access token (reuse the same refresh family)
            const gracePair = await issueTokenPair(user, req, replacementSession.familyId);
            // Revoke the replacement and add the new one
            const graceSessions = getRefreshTokens(user).map((s) => {
              if (s.tokenId === replacementSession.tokenId) {
                return { ...s, revokedAt: new Date().toISOString(), replacedByTokenId: gracePair.tokenId };
              }
              return s;
            });
            setRefreshTokens(user, graceSessions);
            await saveUser(user);
            return res.json({
              accessToken: gracePair.accessToken,
              refreshToken: gracePair.refreshToken,
              expiresIn: gracePair.accessTokenExpiresIn,
            });
          }
        }
        // Outside grace period or no replacement found — real reuse attack
        revokeAllActiveRefreshTokens(user);
        await saveUser(user);
      }
      return res.status(401).json({ error: 'Refresh token is invalid or already rotated.' });
    }

    const replacement = await issueTokenPair(user, req, existingSession.familyId);

    const updatedSessions = getRefreshTokens(user).map((session) => {
      if (session.tokenId === existingSession.tokenId) {
        return {
          ...session,
          revokedAt: session.revokedAt || new Date().toISOString(),
          replacedByTokenId: replacement.tokenId,
        };
      }
      return session;
    });

    setRefreshTokens(user, updatedSessions);
    await saveUser(user);

    return res.json({
      accessToken: replacement.accessToken,
      refreshToken: replacement.refreshToken,
      expiresIn: replacement.accessTokenExpiresIn,
    });
  } catch {
    return res.status(401).json({ error: 'Invalid or expired refresh token.' });
  }
});

// POST /api/auth/logout
router.post('/logout', protect, async (req, res) => {
  try {
    const { refreshToken, allDevices } = req.body || {};

    if (allDevices) {
      revokeAllActiveRefreshTokens(req.user);
      await saveUser(req.user);
      return res.json({ message: 'Logged out from all devices.' });
    }

    if (refreshToken && typeof refreshToken === 'string') {
      const tokenHash = hashToken(refreshToken);
      const sessions = getRefreshTokens(req.user).map((existing) => {
        if (existing.tokenHash === tokenHash && !existing.revokedAt) {
          return {
            ...existing,
            revokedAt: new Date().toISOString(),
          };
        }
        return existing;
      });

      setRefreshTokens(req.user, sessions);
      await saveUser(req.user);
    }

    return res.json({ message: 'Logged out.' });
  } catch (error) {
    return res.status(500).json({ error: error.message });
  }
});

// GET /api/auth/me
router.get('/me', protect, async (req, res) => {
  const twoFactor = getTwoFactor(req.user);

  return res.json({
    user: {
      id: userIdAsString(req.user),
      email: req.user.email,
      name: req.user.name,
      lastSyncedAt: req.user.lastSyncedAt,
      twoFactorEnabled: twoFactor.enabled,
    },
  });
});

// POST /api/auth/verify-action — Verify identity before dangerous actions
router.post('/verify-action', protect, async (req, res) => {
  try {
    const { password, totpCode, backupCode } = req.body || {};
    const user = await findUserById(userIdAsString(req.user), { includePassword: true });
    if (!user) {
      return res.status(401).json({ error: 'User not found.' });
    }

    const twoFactor = getTwoFactor(user);

    if (twoFactor.enabled) {
      // 2FA enabled — require TOTP or backup code
      let verified = false;

      if (typeof totpCode === 'string' && totpCode.trim()) {
        const secret = decryptSecret(twoFactor.secretEncrypted);
        verified = authenticator.verify({ token: totpCode.trim(), secret });
      }

      if (!verified && typeof backupCode === 'string' && backupCode.trim()) {
        const consumeResult = consumeBackupCode(twoFactor, backupCode);
        if (consumeResult.consumed) {
          twoFactor.backupCodes = consumeResult.backupCodes;
          setTwoFactor(user, twoFactor);
          await saveUser(user);
          verified = true;
        }
      }

      if (!verified) {
        return res.status(401).json({ error: 'Invalid authenticator code.' });
      }
    } else {
      // No 2FA — require password
      if (!password || typeof password !== 'string') {
        return res.status(400).json({ error: 'Password is required for verification.' });
      }

      const valid = await verifyUserPassword(user, password);
      if (!valid) {
        return res.status(401).json({ error: 'Invalid password.' });
      }
    }

    // Issue a short-lived action token (5 min)
    const actionToken = jwt.sign(
      { id: userIdAsString(user), type: 'action_verify' },
      process.env.JWT_SECRET,
      { expiresIn: '5m' }
    );

    return res.json({ actionToken, twoFactorEnabled: twoFactor.enabled });
  } catch (error) {
    return res.status(500).json({ error: error.message });
  }
});

// GET /api/auth/2fa/status
router.get('/2fa/status', protect, async (req, res) => {
  const twoFactor = getTwoFactor(req.user);

  return res.json({
    twoFactor: {
      enabled: twoFactor.enabled,
      method: twoFactor.method || 'totp',
      hasSecret: Boolean(twoFactor.secretEncrypted),
      backupCodesCount: (twoFactor.backupCodes || []).filter((entry) => !entry.usedAt).length,
      pendingSetup: Boolean(twoFactor.pendingSecretEncrypted),
    },
  });
});

// POST /api/auth/2fa/totp/setup/start
router.post('/2fa/totp/setup/start', protect, async (req, res) => {
  try {
    const twoFactor = getTwoFactor(req.user);
    if (twoFactor.enabled) {
      return res.status(400).json({ error: '2FA is already enabled.' });
    }

    const secret = authenticator.generateSecret();
    const pendingSecretEncrypted = encryptSecret(secret);
    twoFactor.pendingSecretEncrypted = pendingSecretEncrypted;
    twoFactor.pendingCreatedAt = new Date().toISOString();

    setTwoFactor(req.user, twoFactor);
    await saveUser(req.user);

    const otpauthUrl = authenticator.keyuri(req.user.email, 'LinkNest', secret);

    // Generate QR code as data URL
    let qrDataUrl = null;
    try {
      qrDataUrl = await QRCode.toDataURL(otpauthUrl, {
        width: 200,
        margin: 2,
        color: { dark: '#1a1a2e', light: '#ffffff' },
      });
    } catch {
      // QR generation failed — client will fall back to manual entry
    }

    return res.json({
      method: 'totp',
      otpauthUrl,
      qrDataUrl,
      secret,
      message: 'Scan the QR code or enter the secret manually, then verify with a current code.',
    });
  } catch (error) {
    return res.status(500).json({ error: error.message });
  }
});

// POST /api/auth/2fa/totp/setup/verify
router.post('/2fa/totp/setup/verify', protect, async (req, res) => {
  try {
    const { code } = req.body || {};
    if (!code || typeof code !== 'string') {
      return res.status(400).json({ error: 'code is required.' });
    }

    const twoFactor = getTwoFactor(req.user);
    if (!twoFactor.pendingSecretEncrypted) {
      return res.status(400).json({ error: 'No pending 2FA setup found.' });
    }

    const pendingSecret = decryptSecret(twoFactor.pendingSecretEncrypted);
    const valid = authenticator.verify({ token: code.trim(), secret: pendingSecret });

    if (!valid) {
      return res.status(401).json({ error: 'Invalid authenticator code.' });
    }

    const backupCodes = generateBackupCodes(10);

    twoFactor.enabled = true;
    twoFactor.method = 'totp';
    twoFactor.secretEncrypted = encryptSecret(pendingSecret);
    twoFactor.enabledAt = new Date().toISOString();
    twoFactor.pendingSecretEncrypted = '';
    twoFactor.pendingCreatedAt = null;
    twoFactor.backupCodes = backupCodes.map((backupCode) => ({
      codeHash: hashBackupCode(backupCode),
      usedAt: null,
    }));

    setTwoFactor(req.user, twoFactor);
    revokeAllActiveRefreshTokens(req.user);
    await saveUser(req.user);

    return res.json({
      message: '2FA enabled successfully.',
      twoFactor: {
        enabled: true,
        method: 'totp',
      },
      backupCodes,
    });
  } catch (error) {
    return res.status(500).json({ error: error.message });
  }
});

// POST /api/auth/2fa/disable — requires TOTP or password verification
router.post('/2fa/disable', protect, async (req, res) => {
  try {
    const { totpCode, backupCode, password } = req.body || {};
    const user = await findUserById(userIdAsString(req.user), { includePassword: true });
    if (!user) {
      return res.status(401).json({ error: 'User not found.' });
    }

    const twoFactor = getTwoFactor(user);

    // Must verify identity before disabling
    if (twoFactor.enabled) {
      let verified = false;

      if (typeof totpCode === 'string' && totpCode.trim()) {
        const secret = decryptSecret(twoFactor.secretEncrypted);
        verified = authenticator.verify({ token: totpCode.trim(), secret });
      }

      if (!verified && typeof backupCode === 'string' && backupCode.trim()) {
        const consumeResult = consumeBackupCode(twoFactor, backupCode);
        if (consumeResult.consumed) {
          twoFactor.backupCodes = consumeResult.backupCodes;
          verified = true;
        }
      }

      if (!verified) {
        return res.status(401).json({ error: 'Invalid authenticator code. Verify your identity to disable 2FA.' });
      }
    } else {
      // 2FA not currently enabled — require password
      if (!password || typeof password !== 'string') {
        return res.status(400).json({ error: 'Password is required.' });
      }
      const valid = await verifyUserPassword(user, password);
      if (!valid) {
        return res.status(401).json({ error: 'Invalid password.' });
      }
    }

    const nextTwoFactor = {
      enabled: false,
      method: 'totp',
      secretEncrypted: '',
      enabledAt: null,
      backupCodes: [],
      pendingSecretEncrypted: '',
      pendingCreatedAt: null,
      webauthnCredentials: [],
    };

    setTwoFactor(user, nextTwoFactor);
    revokeAllActiveRefreshTokens(user);
    await saveUser(user);

    return res.json({ message: '2FA disabled.' });
  } catch (error) {
    return res.status(500).json({ error: error.message });
  }
});

// POST /api/auth/2fa/webauthn/register/options
router.post('/2fa/webauthn/register/options', protect, async (req, res) => {
  return res.status(501).json({
    error: 'WebAuthn is optional and not enabled in this build yet.',
  });
});

// POST /api/auth/2fa/webauthn/register/verify
router.post('/2fa/webauthn/register/verify', protect, async (req, res) => {
  return res.status(501).json({
    error: 'WebAuthn is optional and not enabled in this build yet.',
  });
});

module.exports = router;
