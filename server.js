// server.js
const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const path = require('path');
const dotenv = require('dotenv');
const bcrypt = require('bcryptjs'); // For password hashing
const jwt = require('jsonwebtoken'); // For JSON Web Tokens

dotenv.config(); // Load environment variables from .env file

const app = express();
const PORT = process.env.PORT || 8000;

// Middleware
app.use(cors());
app.use(express.json());

// MongoDB Connection
const mongoURI = process.env.MONGO_URI || 'mongodb://localhost:27017/blogdb';

mongoose.connect(mongoURI)
  .then(() => console.log('MongoDB connected successfully!'))
  .catch(err => console.error('MongoDB connection error:', err));

// --- Mongoose Schemas and Models ---

// Define User Schema and Model
const userSchema = new mongoose.Schema({
  username: {
    type: String,
    required: true,
    unique: true,
    trim: true,
  },
  password: {
    type: String,
    required: true,
  },
  name: { // New field
    type: String,
    required: true,
    trim: true,
  },
  email: { // New field
    type: String,
    required: true,
    unique: true,
    trim: true,
    lowercase: true,
  },
  number: { // New field
    type: String,
    required: true,
    trim: true,
  },
}, {
  timestamps: true,
});

const User = mongoose.model('User', userSchema);

// Define Blog Post Schema and Model
const postSchema = new mongoose.Schema({
  title: {
    type: String,
    required: true,
    trim: true,
  },
  author: { // This will now typically be the username of the creator
    type: String,
    required: true,
    trim: true,
  },
  userId: { // New field to link post to the user who created it
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true,
  },
  date: {
    type: String,
    required: true,
  },
  content: {
    type: String, // Storing HTML content from ReactQuill
    required: true,
  },
  thumbnailUrl: {
    type: String,
    default: '',
  },
  category: {
    type: String,
    enum: ['Fitness', 'Health', 'Travel', 'Fashion', 'Other'],
    default: 'Other',
    required: true,
  },
}, {
  timestamps: true,
});

const Post = mongoose.model('Post', postSchema);

// Define Comment Schema and Model
const commentSchema = new mongoose.Schema({
  postId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'Post',
    required: true,
  },
  author: { // This will now typically be the username of the commenter
    type: String,
    required: true,
    trim: true,
  },
  userId: { // New field to link comment to the user who created it (optional, but good for moderation)
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
  },
  content: {
    type: String,
    required: true,
    trim: true,
  },
  date: {
    type: String,
    required: true,
  },
}, {
  timestamps: true,
});

const Comment = mongoose.model('Comment', commentSchema);

// --- Authentication Middleware ---
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1]; // Bearer TOKEN

  if (token == null) {
    return res.status(401).json({ message: 'Authentication token required' });
  }

  jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
    if (err) {
      console.error('JWT verification error:', err);
      return res.status(403).json({ message: 'Invalid or expired token' });
    }
    req.user = user; // Attach user payload (e.g., { id: 'userId', username: 'testuser' }) to request
    next();
  });
};

// --- API Routes ---

// User Registration
app.post('/api/register', async (req, res) => {
  const { username, password, name, email, number } = req.body; // Destructure new fields

  if (!username || !password || !name || !email || !number) { // Validate new fields
    return res.status(400).json({ message: 'Username, password, name, email, and number are all required.' });
  }

  try {
    const existingUserByUsername = await User.findOne({ username });
    if (existingUserByUsername) {
      return res.status(409).json({ message: 'Username already exists.' });
    }

    const existingUserByEmail = await User.findOne({ email });
    if (existingUserByEmail) {
      return res.status(409).json({ message: 'Email already exists.' });
    }

    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(password, salt);

    const newUser = new User({
      username,
      password: hashedPassword,
      name,   // Save new field
      email,  // Save new field
      number, // Save new field
    });

    await newUser.save();
    res.status(201).json({ message: 'User registered successfully!' });
  } catch (err) {
    console.error('Error during registration:', err);
    res.status(500).json({ message: 'Server error during registration.', details: err.message });
  }
});

// User Login
app.post('/api/login', async (req, res) => {
  const { username, password } = req.body;

  if (!username || !password) {
    return res.status(400).json({ message: 'Username and password are required.' });
  }

  try {
    const user = await User.findOne({ username });
    if (!user) {
      return res.status(401).json({ message: 'Invalid credentials.' });
    }

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return res.status(401).json({ message: 'Invalid credentials.' });
    }

    // Generate JWT
    const token = jwt.sign(
      { id: user._id, username: user.username },
      process.env.JWT_SECRET,
      { expiresIn: '1h' } // Token expires in 1 hour
    );

    res.json({ message: 'Logged in successfully!', token, username: user.username, userId: user._id });
  } catch (err) {
    console.error('Error during login:', err);
    res.status(500).json({ message: 'Server error during login.', details: err.message });
  }
});


// --- Blog Post Routes ---

// GET all posts (with optional category, search, and pagination)
app.get('/api/posts', async (req, res) => {
  try {
    const { category, search, page = 1, limit = 4, sortBy = 'createdAt', sortOrder = 'desc' } = req.query; // Added sortBy and sortOrder
    let filter = {};
    let sort = {};

    if (category && category !== 'All') {
      filter.category = category;
    }

    if (search) {
      const searchRegex = new RegExp(search, 'i');
      filter.$or = [
        { title: { $regex: searchRegex } },
        { author: { $regex: searchRegex } },
        { content: { $regex: searchRegex } }
      ];
    }

    // Dynamic Sorting
    if (sortBy) {
      sort[sortBy] = sortOrder === 'asc' ? 1 : -1;
    }

    const skip = (parseInt(page) - 1) * parseInt(limit);
    const postsQuery = Post.find(filter)
                            .sort(sort) // Apply dynamic sort
                            .skip(skip)
                            .limit(parseInt(limit));

    const [posts, totalPosts] = await Promise.all([
      postsQuery.exec(),
      Post.countDocuments(filter)
    ]);

    res.json({ posts, totalPosts });
  } catch (err) {
    console.error('Error fetching posts:', err);
    res.status(500).json({ message: 'Server error' });
  }
});

// GET a single post by ID
app.get('/api/posts/:id', async (req, res) => {
  try {
    const post = await Post.findById(req.params.id);
    if (!post) {
      return res.status(404).json({ message: 'Post not found' });
    }
    res.json(post);
  } catch (err) {
    console.error('Error fetching single post:', err);
    if (err.kind === 'ObjectId') {
        return res.status(400).json({ message: 'Invalid Post ID format' });
    }
    res.status(500).json({ message: 'Server error' });
  }
});

// CREATE a new post (PROTECTED)
app.post('/api/posts', authenticateToken, async (req, res) => {
  const { title, content, thumbnailUrl, category } = req.body;
  const author = req.user.username; // Author is now derived from authenticated user
  const userId = req.user.id; // Store userId of the creator

  if (!title || !content) {
    return res.status(400).json({ message: 'Please enter all fields: title and content.' });
  }

  try {
    const newPost = new Post({
      title,
      author,
      userId, // Save the userId
      date: new Date().toISOString().split('T')[0],
      content,
      thumbnailUrl: thumbnailUrl || '',
      category: category || 'Other',
    });

    const savedPost = await newPost.save();
    res.status(201).json(savedPost);
  } catch (err) {
    console.error('Error creating post:', err);
    res.status(500).json({ message: 'Server error', details: err.message });
  }
});

// UPDATE a post by ID (PROTECTED - only owner can update)
app.put('/api/posts/:id', authenticateToken, async (req, res) => {
  const { title, content, thumbnailUrl, category } = req.body; // Removed author as it's fixed by userId

  try {
    const post = await Post.findById(req.params.id);
    if (!post) {
      return res.status(404).json({ message: 'Post not found' });
    }

    // Authorization check: Only the owner can update the post
    if (post.userId.toString() !== req.user.id) {
      return res.status(403).json({ message: 'Unauthorized: You can only update your own posts.' });
    }

    const updatedPost = await Post.findByIdAndUpdate(
      req.params.id,
      { title, content, thumbnailUrl, category },
      { new: true, runValidators: true }
    );

    res.json(updatedPost);
  } catch (err) {
    console.error('Error updating post:', err);
    if (err.kind === 'ObjectId') {
        return res.status(400).json({ message: 'Invalid Post ID format' });
    }
    res.status(500).json({ message: 'Server error', details: err.message });
  }
});

// DELETE a post by ID (PROTECTED - only owner can delete)
app.delete('/api/posts/:id', authenticateToken, async (req, res) => {
  try {
    const post = await Post.findById(req.params.id);
    if (!post) {
      return res.status(404).json({ message: 'Post not found' });
    }

    // Authorization check: Only the owner can delete the post
    if (post.userId.toString() !== req.user.id) {
      return res.status(403).json({ message: 'Unauthorized: You can only delete your own posts.' });
    }

    await Post.findByIdAndDelete(req.params.id);
    // Optionally, delete associated comments when a post is deleted
    await Comment.deleteMany({ postId: req.params.id });
    res.json({ message: 'Post deleted successfully' });
  } catch (err) {
    console.error('Error deleting post:', err);
    if (err.kind === 'ObjectId') {
        return res.status(400).json({ message: 'Invalid Post ID format' });
    }
    res.status(500).json({ message: 'Server error' });
  }
});

// --- Comment Routes ---

// GET comments for a specific post
app.get('/api/posts/:postId/comments', async (req, res) => {
  try {
    const comments = await Comment.find({ postId: req.params.postId }).sort({ createdAt: 1 });
    res.json(comments);
  } catch (err) {
    console.error('Error fetching comments:', err);
    res.status(500).json({ message: 'Server error' });
  }
});

// CREATE a new comment for a specific post (PROTECTED)
app.post('/api/posts/:postId/comments', authenticateToken, async (req, res) => {
  const { content } = req.body;
  const { postId } = req.params;
  const author = req.user.username; // Author is now derived from authenticated user
  const userId = req.user.id; // Store userId of the commenter

  if (!content) {
    return res.status(400).json({ message: 'Content is required for the comment.' });
  }

  try {
    const post = await Post.findById(postId);
    if (!post) {
      return res.status(404).json({ message: 'Post not found' });
    }

    const newComment = new Comment({
      postId,
      author,
      userId, // Save the userId
      content,
      date: new Date().toISOString().split('T')[0],
    });

    const savedComment = await newComment.save();
    res.status(201).json(savedComment);
  } catch (err) {
    console.error('Error creating comment:', err);
    res.status(500).json({ message: 'Server error', details: err.message });
  }
});

// DELETE a comment by ID (PROTECTED - only owner can delete)
app.delete('/api/posts/:postId/comments/:commentId', authenticateToken, async (req, res) => {
  try {
    const { postId, commentId } = req.params;

    const comment = await Comment.findById(commentId);
    if (!comment) {
      return res.status(404).json({ message: 'Comment not found' });
    }

    // Authorization check: Only the owner of the comment can delete it
    if (comment.userId.toString() !== req.user.id) {
      return res.status(403).json({ message: 'Unauthorized: You can only delete your own comments.' });
    }

    await Comment.findByIdAndDelete(commentId);
    res.json({ message: 'Comment deleted successfully' });
  } catch (err) {
    console.error('Error deleting comment:', err);
    if (err.kind === 'ObjectId') {
      return res.status(400).json({ message: 'Invalid Comment ID format' });
    }
    res.status(500).json({ message: 'Server error' });
  }
});


// Serve static files from the React app in production
if (process.env.NODE_ENV === 'production') {
  app.use(express.static(path.join(__dirname, 'client/build')));

  app.get('*', (req, res) => {
    res.sendFile(path.resolve(__dirname, 'client', 'build', 'index.html'));
  });
}

// Start the server
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
