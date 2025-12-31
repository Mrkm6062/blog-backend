const mongoose = require('mongoose');

const postSchema = new mongoose.Schema({
  title: {
    type: String,
    required: true,
    trim: true,
  },
  author: {
    type: String,
    required: true,
    trim: true,
  },
  content: {
    type: String, // Storing HTML content from ReactQuill
    required: true,
  },
  thumbnailUrl: { // New field for thumbnail image URL
    type: String,
    default: '',
  },
  category: { // New field for category
    type: String,
    default: 'Other',
  },
  date: {
    type: Date,
    default: Date.now,
  },
  comments: [ // Array of comments embedded in the post
    {
      author: {
        type: String,
        required: true,
      },
      content: {
        type: String,
        required: true,
      },
      date: {
        type: Date,
        default: Date.now,
      },
    },
  ],
});

// ✅ Prevent OverwriteModelError during hot reloads or multiple imports
module.exports = mongoose.models.Post || mongoose.model('Post', postSchema);
