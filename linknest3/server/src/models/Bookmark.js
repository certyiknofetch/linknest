const mongoose = require('mongoose');

const bookmarkSchema = new mongoose.Schema(
  {
    user: {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'User',
      required: true,
      index: true,
    },
    // Unique identifier for this bookmark across browsers
    bookmarkHash: {
      type: String,
      required: true,
    },
    title: {
      type: String,
      required: true,
      trim: true,
    },
    url: {
      type: String,
      required: true,
      trim: true,
    },
    // Folder path like "Bookmarks Bar/Dev/JavaScript"
    folderPath: {
      type: String,
      default: '',
      trim: true,
    },
    // Favicon URL (optional)
    favicon: {
      type: String,
      default: '',
    },
    // Which browser added this bookmark
    sourceBrowser: {
      type: String,
      default: 'unknown',
    },
    // Position index within folder
    index: {
      type: Number,
      default: 0,
    },
    // Soft delete flag
    isDeleted: {
      type: Boolean,
      default: false,
    },
    deletedAt: {
      type: Date,
      default: null,
    },
  },
  { timestamps: true }
);

// Compound index for efficient querying
bookmarkSchema.index({ user: 1, bookmarkHash: 1 }, { unique: true });
bookmarkSchema.index({ user: 1, isDeleted: 1, updatedAt: 1 });

module.exports = mongoose.model('Bookmark', bookmarkSchema);
