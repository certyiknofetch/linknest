require('dotenv').config();
const express = require('express');
const cors = require('cors');
const rateLimit = require('express-rate-limit');
const helmet = require('helmet');
const connectDB = require('./config/db');
const authRoutes = require('./routes/auth');
const bookmarkRoutes = require('./routes/bookmarks');

const app = express();
app.disable('x-powered-by');
app.set('trust proxy', 1);

const requireHttps = (process.env.REQUIRE_HTTPS || 'true').toLowerCase() === 'true';

const allowedOrigins = (process.env.CORS_ORIGINS || '')
  .split(',')
  .map((origin) => origin.trim())
  .filter(Boolean);

function isExtensionOrigin(origin = '') {
  return origin.startsWith('chrome-extension://') || origin.startsWith('moz-extension://');
}

function isLocalDevOrigin(origin = '') {
  return (
    origin.startsWith('http://localhost:') ||
    origin.startsWith('http://127.0.0.1:') ||
    origin.startsWith('https://localhost:') ||
    origin.startsWith('https://127.0.0.1:')
  );
}

// Connect to database
connectDB();

// Middleware
app.use(
  helmet({
    contentSecurityPolicy: false,
    crossOriginEmbedderPolicy: false,
  })
);

app.use(
  cors({
    origin: (origin, callback) => {
      if (!origin) return callback(null, true);

      if (allowedOrigins.includes(origin) || isExtensionOrigin(origin) || isLocalDevOrigin(origin)) {
        return callback(null, true);
      }

      return callback(new Error('CORS origin denied'));
    },
  })
);

app.use((req, res, next) => {
  if (!requireHttps) return next();

  const host = (req.headers.host || '').toLowerCase();
  const isLocalhost = host.startsWith('localhost') || host.startsWith('127.0.0.1');
  const forwardedProto = req.headers['x-forwarded-proto'];
  const isSecure = req.secure || forwardedProto === 'https';

  if (isLocalhost || isSecure) return next();

  return res.status(426).json({ error: 'HTTPS is required.' });
});

app.use(express.json({ limit: '10mb' })); // Large payload for bookmark sync

// Rate limiting
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 200,
  message: { error: 'Too many requests. Please try again later.' },
});
app.use('/api/', limiter);

const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 40,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'Too many authentication attempts. Please try again later.' },
});

// Strict rate limiter for dangerous action verification (5 per 15 min per IP)
const dangerousActionLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 5,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'Too many verification attempts. Please try again later.' },
});

// Routes
app.use('/api/auth/verify-action', dangerousActionLimiter);
app.use('/api/auth', authLimiter, authRoutes);
app.use('/api/bookmarks', bookmarkRoutes);

// Health check
app.get('/api/health', (req, res) => {
  res.json({ status: 'ok', timestamp: new Date().toISOString() });
});

// 404 handler
app.use((req, res) => {
  res.status(404).json({ error: 'Route not found.' });
});

// Error handler
app.use((err, req, res, next) => {
  console.error(err.stack);
  res.status(500).json({ error: 'Internal server error.' });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`LinkNest server running on port ${PORT}`);
});
