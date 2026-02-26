const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');

const userSchema = new mongoose.Schema(
  {
    email: {
      type: String,
      required: [true, 'Email is required'],
      unique: true,
      lowercase: true,
      trim: true,
      match: [/^\S+@\S+\.\S+$/, 'Please provide a valid email'],
    },
    password: {
      type: String,
      required: [true, 'Password is required'],
      minlength: [6, 'Password must be at least 6 characters'],
      select: false,
    },
    name: {
      type: String,
      trim: true,
      default: '',
    },
    lastSyncedAt: {
      type: Date,
      default: null,
    },
    refreshTokens: [
      {
        tokenId: {
          type: String,
          required: true,
        },
        familyId: {
          type: String,
          required: true,
        },
        tokenHash: {
          type: String,
          required: true,
        },
        issuedAt: {
          type: Date,
          default: Date.now,
        },
        expiresAt: {
          type: Date,
          required: true,
        },
        revokedAt: {
          type: Date,
          default: null,
        },
        replacedByTokenId: {
          type: String,
          default: null,
        },
        ip: {
          type: String,
          default: '',
        },
        userAgent: {
          type: String,
          default: '',
        },
      },
    ],
    twoFactor: {
      enabled: {
        type: Boolean,
        default: false,
      },
      method: {
        type: String,
        enum: ['totp', 'webauthn'],
        default: 'totp',
      },
      secretEncrypted: {
        type: String,
        default: '',
      },
      pendingSecretEncrypted: {
        type: String,
        default: '',
      },
      pendingCreatedAt: {
        type: Date,
        default: null,
      },
      enabledAt: {
        type: Date,
        default: null,
      },
      backupCodes: [
        {
          codeHash: {
            type: String,
            required: true,
          },
          usedAt: {
            type: Date,
            default: null,
          },
        },
      ],
      webauthnCredentials: [
        {
          credentialId: {
            type: String,
            required: true,
          },
          publicKey: {
            type: String,
            required: true,
          },
          counter: {
            type: Number,
            default: 0,
          },
          transports: [
            {
              type: String,
            },
          ],
        },
      ],
    },
  },
  { timestamps: true }
);

userSchema.index({ 'refreshTokens.tokenHash': 1 });

// Hash password before saving
userSchema.pre('save', async function (next) {
  if (!this.isModified('password')) return next();
  this.password = await bcrypt.hash(this.password, 12);
  next();
});

// Compare passwords
userSchema.methods.comparePassword = async function (candidatePassword) {
  return bcrypt.compare(candidatePassword, this.password);
};

module.exports = mongoose.model('User', userSchema);
