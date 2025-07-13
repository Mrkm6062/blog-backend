// backend/routes/posts.js (or similar)

const express = require('express');
const router = express.Router();
const Post = require('../models/Post'); // Adjust path as needed

// GET all posts
router.get('/', async (req, res) => {
  try {
    const posts = await Post.find().sort({ date: -1 }); // Sort by newest first
    res.json(posts);
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

// GET a single post by ID
router.get('/:id', async (req, res) => {
  try {
    const post = await Post.findById(req.params.id);
    if (!post) {
      return res.status(404).json({ message: 'Post not found' });
    }
    res.json(post);
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

// POST a new post
router.post('/', async (req, res) => {
  const { title, author, content, thumbnailUrl, category } = req.body; // Destructure new fields

  // Basic validation
  if (!title || !author || !content) {
    return res.status(400).json({ message: 'Title, author, and content are required.' });
  }

  const post = new Post({
    title,
    author,
    content,
    thumbnailUrl: thumbnailUrl || '', // Use provided or default to empty string
    category: category || 'Other', // Use provided or default to 'Other'
  });

  try {
    const newPost = await post.save();
    res.status(201).json(newPost);
  } catch (err) {
    res.status(400).json({ message: err.message });
  }
});

// PUT (Update) an existing post
router.put('/:id', async (req, res) => {
  try {
    const { title, author, content, thumbnailUrl, category } = req.body; // Destructure new fields
    const updatedPost = await Post.findByIdAndUpdate(
      req.params.id,
      {
        title,
        author,
        content,
        thumbnailUrl, // Update thumbnail URL
        category,     // Update category
      },
      { new: true, runValidators: true } // Return the updated document and run schema validators
    );

    if (!updatedPost) {
      return res.status(404).json({ message: 'Post not found' });
    }
    res.json(updatedPost);
  } catch (err) {
    res.status(400).json({ message: err.message });
  }
});

// DELETE a post
router.delete('/:id', async (req, res) => {
  try {
    const deletedPost = await Post.findByIdAndDelete(req.params.id);
    if (!deletedPost) {
      return res.status(404).json({ message: 'Post not found' });
    }
    res.json({ message: 'Post deleted successfully' });
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

// POST a new comment to a post
router.post('/:id/comments', async (req, res) => {
  try {
    const post = await Post.findById(req.params.id);
    if (!post) {
      return res.status(404).json({ message: 'Post not found' });
    }

    const { author, content } = req.body;
    if (!author || !content) {
      return res.status(400).json({ message: 'Author and content are required for a comment.' });
    }

    const newComment = { author, content };
    post.comments.push(newComment);
    await post.save();
    res.status(201).json(post.comments[post.comments.length - 1]); // Return the newly added comment
  } catch (err) {
    res.status(400).json({ message: err.message });
  }
});

// GET comments for a post
router.get('/:id/comments', async (req, res) => {
  try {
    const post = await Post.findById(req.params.id);
    if (!post) {
      return res.status(404).json({ message: 'Post not found' });
    }
    res.json(post.comments);
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

module.exports = router;