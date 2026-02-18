// server.js
const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const path = require('path');
const fs = require('fs');
const dotenv = require('dotenv');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const multer = require('multer');
const { Storage } = require('@google-cloud/storage');
const helmet = require('helmet'); // Import helmet
const nodemailer = require('nodemailer');

dotenv.config();

const app = express();
const PORT = process.env.PORT || 8000;

app.use(cors());
app.use(express.json());
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'", "'unsafe-inline'", "https://static.cloudflareinsights.com"],
      styleSrc: ["'self'", "'unsafe-inline'", "https://fonts.googleapis.com"],
      fontSrc: ["'self'", "https://fonts.gstatic.com"],
      imgSrc: ["'self'", "data:", "https://storage.googleapis.com"],
      connectSrc: ["'self'", "https://samriddhishop.info", "https://cloudflareinsights.com"],
    },
  },
})); // Use helmet middleware with custom CSP
app.use('/uploads', express.static(path.join(__dirname, 'uploads')));


// --- Google Cloud Storage Setup ---
let storageClient;
const bucketName = process.env.GCS_BUCKET_NAME;

console.log('Attempting to initialize Google Cloud Storage...');
if (process.env.GCP_SA_KEY) {
  try {
    const serviceAccountKey = JSON.parse(process.env.GCP_SA_KEY);
    storageClient = new Storage({
      credentials: {
        client_email: serviceAccountKey.client_email,
        private_key: serviceAccountKey.private_key.replace(/\\n/g, '\n'),
      },
      projectId: serviceAccountKey.project_id,
    });
    console.log('Google Cloud Storage initialized successfully using GCP_SA_KEY environment variable.');
  } catch (parseError) {
    console.error('Error parsing GCP_SA_KEY JSON:', parseError);
    console.error('Google Cloud Storage will not be available due to key parsing error. Check GCP_SA_KEY format.');
    storageClient = null;
  }
} else {
  try {
    storageClient = new Storage();
    console.log('Google Cloud Storage initialized using GOOGLE_APPLICATION_CREDENTIALS (or default ADC).');
  } catch (error) {
    console.error('GOOGLE_APPLICATION_CREDENTIALS environment variable not found or invalid, or other GCS initialization error:', error);
    console.error('Google Cloud Storage will not be available. Ensure GOOGLE_APPLICATION_CREDENTIALS points to a valid file or GCP_SA_KEY is set.');
    storageClient = null;
  }
}

if (!bucketName) {
  console.error('GCS_BUCKET_NAME environment variable is not set. GCS uploads will fail.');
} else {
  console.log(`GCS_BUCKET_NAME is set to: ${bucketName}`);
}

if (!storageClient) {
  console.error('Google Cloud Storage client is NOT initialized. Image uploads will fail.');
}

const upload = multer({
  storage: multer.memoryStorage(),
  limits: {
    fileSize: 5 * 1024 * 1024, // Limit file size to 5MB
  },
});

// MongoDB Connection
const mongoURI = process.env.MONGO_URI || 'mongodb+srv://akm222143:Z466GPPhEp5GlnuJ@marto.klqfj94.mongodb.net/samriddhiblogdb?retryWrites=true&w=majority';

mongoose.connect(mongoURI)
  .then(() => console.log('MongoDB connected successfully!'))
  .catch(err => console.error('MongoDB connection error:', err));

// --- Mongoose Schemas and Models ---
const slugify = (text) => {
  return text
    .toString()
    .normalize('NFD')
    .replace(/[\u0300-\u036f]/g, '')
    .toLowerCase()
    .trim()
    .replace(/\s+/g, '-')
    .replace(/[^\w-]+/g, '')
    .replace(/--+/g, '-');
};

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
  name: {
    type: String,
    required: true,
    trim: true,
  },
  email: {
    type: String,
    required: true,
    unique: true,
    trim: true,
    lowercase: true,
  },
  number: {
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
  seoTitle: {
  type: String,
  trim: true,
  maxlength: 60,
  },
  schemaType: {
  type: String,
  enum: ['Article', 'BlogPosting', 'NewsArticle'],
  default: 'BlogPosting',
  },
  slug: {
    type: String,
    unique: true,
    index: true,
  },
  author: {
    type: String,
    required: true,
    trim: true,
  },
  userId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true,
  },
  date: {
    type: String,
    required: true,
  },
  content: {
    type: String,
    required: true,
  },
  thumbnailUrl: {
    type: String,
    default: '',
  },
  thumbnailAltText: { // New field for thumbnail alt text
    type: String,
    default: '',
    trim: true,
  },
  metaDescription: { // New field for meta description
    type: String,
    default: '',
    trim: true,
    maxlength: 160, // Common max length for meta descriptions
  },
  focusKeyword: {
  type: String,
  trim: true,
  index: true,
  },
  category: {
    type: String,
    enum: ['Fitness', 'Health', 'Travel', 'Fashion', 'Other', 'Technology', 'Personal Finance', 'Lifestyle', 'Travels Blog', 'How-To-Guides', 'Software Tools', 'AI & Automation', 'Internet & Networking'],
    default: 'Other',
    required: true,
  },
  tags: [{
  type: String,
  trim: true,
  index: true,
  }],
  faqSchema: [{
  question: String,
  answer: String,
  }],
  excerpt: {
  type: String,
  trim: true,
  maxlength: 300,
  },
  readingTime: {
  type: Number, // in minutes
  },
  viewCount: {
  type: Number,
  default: 0,
  },
  likes: [{ // Array to store user IDs who liked the post (authenticated users)
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User'
  }],
  isIndexed: {
  type: Boolean,
  default: true,
  },
}, {
  timestamps: true,
});

// Pre-save hook to generate slug
postSchema.pre('save', function(next) {
  if (this.isModified('title') || this.isNew) {
    this.slug = slugify(this.title);
  }
  next();
});

// Pre-findOneAndUpdate hook to generate slug on update
postSchema.pre('findOneAndUpdate', function(next) {
  const update = this.getUpdate();
  if (update.title) {
    update.slug = slugify(update.title);
  }
  next();
});

const Post = mongoose.model('Post', postSchema);


// Define Comment Schema and Model
const commentSchema = new mongoose.Schema({
  postId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'Post',
    required: true,
  },
  author: {
    type: String,
    required: true,
    trim: true,
  },
  userId: {
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

const sitemapRoute = require('./routes/sitemap');
app.use('/', sitemapRoute);

// --- Authentication Middleware ---
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (token == null) {
    // If no token, proceed as unauthenticated (for routes that allow it)
    req.user = null;
    return next();
  }

  jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
    if (err) {
      console.error('JWT verification error:', err);
      // If token is invalid/expired, treat as unauthenticated for some routes
      req.user = null;
      // For protected routes, this would be a 403
      // For routes that allow optional auth, we just set req.user to null
      return next();
    }
    req.user = user;
    next();
  });
};

// --- API Routes ---

console.log('Defining /api/register route...');
// User Registration
app.post('/api/register', async (req, res) => {
  const { username, password, name, email, number } = req.body;

  if (!username || !password || !name || !email || !number) {
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
      name,
      email,
      number,
    });

    await newUser.save();
    res.status(201).json({ message: 'User registered successfully!' });
  } catch (err) {
    console.error('Error during registration:', err);
    res.status(500).json({ message: 'Server error during registration.', details: err.message });
  }
});

console.log('Defining /api/login route...');
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

    const token = jwt.sign(
      { id: user._id, username: user.username },
      process.env.JWT_SECRET,
      { expiresIn: '1h' }
    );

    res.json({ message: 'Logged in successfully!', token, username: user.username, userId: user._id });
  } catch (err) {
    console.error('Error during login:', err);
    res.status(500).json({ message: 'Server error during login.', details: err.message });
  }
});


// --- Blog Post Routes ---

console.log('Defining GET /api/posts route...');
// GET all posts (with optional category, search, and pagination)
app.get('/api/posts', async (req, res) => {
  try {
    const { category, search, page = 1, limit = 4, sortBy = 'createdAt', sortOrder = 'desc' } = req.query;
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

    if (sortBy) {
      sort[sortBy] = sortOrder === 'asc' ? 1 : -1;
    }

    const skip = (parseInt(page) - 1) * parseInt(limit);
    const postsQuery = Post.find(filter)
                            .sort(sort)
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

console.log('Defining GET /api/posts/my-posts route...');
app.get('/api/posts/my-posts', authenticateToken, async (req, res) => {
  try {
    // This route should strictly require authentication
    if (!req.user || !req.user.id) {
      return res.status(401).json({ message: 'Authentication required to view your posts.' });
    }
    const userId = req.user.id;
    const userPosts = await Post.find({ userId: userId }).sort({ createdAt: -1 });
    res.json({ posts: userPosts, totalPosts: userPosts.length });
  } catch (err) {
    console.error('Error fetching user-specific posts:', err);
    res.status(500).json({ message: 'Server error fetching your posts.' });
  }
});


// GET a single post by ID or SLUG
console.log('Defining GET /api/posts/detail/:identifier route...');
app.get('/api/posts/detail/:identifier', async (req, res) => {
  try {
    const identifier = req.params.identifier;
    let post;

    // Check if the identifier is a valid MongoDB ObjectId
    if (mongoose.Types.ObjectId.isValid(identifier)) {
      post = await Post.findById(identifier);
    }

    // If not found by ID or not a valid ID, try to find by slug
    if (!post) {
      post = await Post.findOne({ slug: identifier });
    }

    if (!post) {
      return res.status(404).json({ message: 'Post not found' });
    }
    res.json(post);
  } catch (err) {
    console.error('Error fetching single post by identifier:', err);
    res.status(500).json({ message: 'Server error' });
  }
});


// Helper function to upload file (GCS Only)
const uploadFile = async (file) => {
  if (!storageClient || !bucketName) {
    console.error('GCS not configured. Image uploads are disabled.');
    throw new Error('Google Cloud Storage is not configured. Cannot upload file.');
  }

  const bucket = storageClient.bucket(bucketName);
  const uniqueFilename = `${Date.now()}-${file.originalname}`;
  const blob = bucket.file(uniqueFilename);

  const blobStream = blob.createWriteStream({
    resumable: false,
    metadata: {
      contentType: file.mimetype,
    },
  });

  return new Promise((resolve, reject) => {
    blobStream.on('error', (err) => {
      console.error('GCS upload stream error:', err);
      reject(new Error('Failed to upload file to Google Cloud Storage.'));
    });

    blobStream.on('finish', () => {
      blob.makePublic().then(() => {
        const publicUrl = `https://storage.googleapis.com/${bucket.name}/${blob.name}`;
        console.log(`File uploaded to GCS: ${publicUrl}`);
        resolve(publicUrl);
      }).catch(err => {
        console.error('Error making GCS file public:', err);
        reject(new Error('Failed to make GCS file public. Check bucket permissions.'));
      });
    });

    blobStream.end(file.buffer);
  });
};

// Helper function to delete file (GCS or Local)
const deleteFile = async (fileUrl) => {
  if (!fileUrl) return;

  if (fileUrl.startsWith('/uploads/')) {
    const filename = fileUrl.split('/uploads/')[1];
    const filePath = path.join(__dirname, 'uploads', filename);
    try {
      await fs.promises.unlink(filePath);
      console.log(`Local file deleted: ${filePath}`);
    } catch (err) {
      console.warn(`Failed to delete local file: ${filePath}`, err);
    }
    return;
  }

  if (!fileUrl.includes('storage.googleapis.com')) return;

  if (!storageClient || !bucketName) {
    console.warn('Google Cloud Storage not configured. Skipping GCS file deletion.');
    return;
  }

  const filename = fileUrl.substring(fileUrl.lastIndexOf('/') + 1);
  if (!filename) {
    console.warn('Could not extract filename from URL for GCS deletion:', fileUrl);
    return;
  }

  const bucket = storageClient.bucket(bucketName);
  const blob = bucket.file(filename);

  try {
    await blob.delete();
    console.log(`File ${filename} deleted from GCS bucket ${bucketName}.`);
  } catch (err) {
    if (err.code === 404) {
      console.warn(`File ${filename} not found in GCS bucket ${bucketName}.`);
    } else {
      console.error(`Error deleting file ${filename} from GCS:`, err);
      throw new Error('Failed to delete file from Google Cloud Storage.');
    }
  }
};


console.log('Defining POST /api/posts route...');
// CREATE a new post (PROTECTED)
app.post('/api/posts', authenticateToken, upload.single('thumbnail'), async (req, res) => {
  const { title, content, category, thumbnailUrl: externalThumbnailUrl, metaDescription, thumbnailAltText, seoTitle, focusKeyword, tags, schemaType, faqSchema, excerpt, isIndexed } = req.body;
  const author = req.user.username;
  const userId = req.user.id;

  if (!title || !content) {
    return res.status(400).json({ message: 'Please enter all fields: title and content.' });
  }

  let finalThumbnailUrl = externalThumbnailUrl || '';

  if (req.file) {
    try {
      finalThumbnailUrl = await uploadFile(req.file);
    } catch (gcsErr) {
      console.error('Failed to upload thumbnail during post creation:', gcsErr);
      return res.status(500).json({ message: 'Failed to upload thumbnail.', details: gcsErr.message });
    }
  }

  // Calculate reading time
  const wpm = 200;
  const words = content ? content.trim().split(/\s+/).length : 0;
  const readingTime = Math.ceil(words / wpm);

  // Parse complex fields if they come as strings (FormData)
  let parsedTags = tags;
  if (typeof tags === 'string') {
    try {
      parsedTags = JSON.parse(tags);
    } catch (e) {
      parsedTags = tags.split(',').map(t => t.trim());
    }
  }

  let parsedFaqSchema = faqSchema;
  if (typeof faqSchema === 'string') {
    try {
      parsedFaqSchema = JSON.parse(faqSchema);
    } catch (e) {
      parsedFaqSchema = [];
    }
  }

  try {
    const newPost = new Post({
      title,
      author,
      userId,
      date: new Date().toISOString().split('T')[0],
      content,
      thumbnailUrl: finalThumbnailUrl,
      thumbnailAltText: thumbnailAltText || '', // Save new field
      metaDescription: metaDescription || '', // Save new field
      category: category || 'Other',
      seoTitle: seoTitle || '',
      focusKeyword: focusKeyword || '',
      tags: parsedTags || [],
      schemaType: schemaType || 'BlogPosting',
      faqSchema: parsedFaqSchema || [],
      excerpt: excerpt || '',
      readingTime,
      isIndexed: isIndexed === undefined ? true : (isIndexed === 'true' || isIndexed === true),
    });

    const savedPost = await newPost.save();
    res.status(201).json(savedPost);
  } catch (err) {
    console.error('Error creating post:', err);
    if (err.code === 11000 && err.keyPattern && err.keyPattern.slug) {
      return res.status(409).json({ message: 'A post with a similar title already exists. Please choose a more unique title.' });
    }
    res.status(500).json({ message: 'Server error', details: err.message });
  }
});

console.log('Defining PUT /api/posts/:id route...');
// UPDATE a post by ID (PROTECTED - only owner can update)
app.put('/api/posts/:id', authenticateToken, upload.single('thumbnail'), async (req, res) => {
  const { title, content, category, thumbnailUrl: externalThumbnailUrl, metaDescription, thumbnailAltText, seoTitle, focusKeyword, tags, schemaType, faqSchema, excerpt, isIndexed } = req.body;

  try {
    const post = await Post.findById(req.params.id);
    if (!post) {
      return res.status(404).json({ message: 'Post not found' });
    }

    if (post.userId.toString() !== req.user.id) {
      return res.status(403).json({ message: 'Unauthorized: You can only update your own posts.' });
    }

    let finalThumbnailUrl = post.thumbnailUrl;

    if (req.file) {
      try {
        if (post.thumbnailUrl) {
          await deleteFile(post.thumbnailUrl);
        }
        finalThumbnailUrl = await uploadFile(req.file);
      } catch (gcsErr) {
        console.error('Failed to upload new thumbnail during post update:', gcsErr);
        return res.status(500).json({ message: 'Failed to upload new thumbnail.', details: gcsErr.message });
      }
    } else if (externalThumbnailUrl !== undefined) {
      if (post.thumbnailUrl && externalThumbnailUrl === '') {
        await deleteFile(post.thumbnailUrl);
      }
      finalThumbnailUrl = externalThumbnailUrl;
    }

    // Calculate reading time if content is present
    let readingTime;
    if (content) {
      const wpm = 200;
      const words = content.trim().split(/\s+/).length;
      readingTime = Math.ceil(words / wpm);
    }

    // Parse complex fields
    let parsedTags = tags;
    if (typeof tags === 'string') {
      try {
        parsedTags = JSON.parse(tags);
      } catch (e) {
        parsedTags = tags.split(',').map(t => t.trim());
      }
    }

    let parsedFaqSchema = faqSchema;
    if (typeof faqSchema === 'string') {
      try {
        parsedFaqSchema = JSON.parse(faqSchema);
      } catch (e) {
        parsedFaqSchema = [];
      }
    }

    const updatedPost = await Post.findByIdAndUpdate(
      req.params.id,
      {
        title,
        content,
        thumbnailUrl: finalThumbnailUrl,
        thumbnailAltText: thumbnailAltText, // Update new field
        metaDescription: metaDescription, // Update new field
        category,
        seoTitle,
        focusKeyword,
        tags: parsedTags,
        schemaType,
        faqSchema: parsedFaqSchema,
        excerpt,
        readingTime,
        isIndexed: isIndexed === undefined ? undefined : (isIndexed === 'true' || isIndexed === true),
      },
      { new: true, runValidators: true }
    );

    res.json(updatedPost);
  } catch (err) {
    console.error('Error updating post:', err);
    if (err.kind === 'ObjectId') {
        return res.status(400).json({ message: 'Invalid Post ID format' });
    }
    if (err.code === 11000 && err.keyPattern && err.keyPattern.slug) {
      return res.status(409).json({ message: 'A post with a similar title already exists. Please choose a more unique title.' });
    }
    res.status(500).json({ message: 'Server error', details: err.message });
  }
});

console.log('Defining DELETE /api/posts/:id route...');
// DELETE a post by ID (PROTECTED - only owner can delete)
app.delete('/api/posts/:id', authenticateToken, async (req, res) => {
  try {
    const post = await Post.findById(req.params.id);
    if (!post) {
      return res.status(404).json({ message: 'Post not found' });
    }

    if (post.userId.toString() !== req.user.id) {
      return res.status(403).json({ message: 'Unauthorized: You can only delete your own posts.' });
    }

    if (post.thumbnailUrl) {
      await deleteFile(post.thumbnailUrl);
    }

    await Post.findByIdAndDelete(req.params.id);
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

console.log('Defining GET /api/posts/:postId/comments route...');
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

console.log('Defining POST /api/posts/:postId/comments route...');
// CREATE a new comment for a specific post (PROTECTED)
app.post('/api/posts/:postId/comments', authenticateToken, async (req, res) => {
  const { content } = req.body;
  const { postId } = req.params;
  const author = req.user.username;
  const userId = req.user.id;

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
      userId,
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

console.log('Defining DELETE /api/posts/:postId/comments/:commentId route...');
// DELETE a comment by ID (PROTECTED - only owner can delete)
app.delete('/api/posts/:postId/comments/:commentId', authenticateToken, async (req, res) => {
  try {
    const { postId, commentId } = req.params;

    const comment = await Comment.findById(commentId);
    if (!comment) {
      return res.status(404).json({ message: 'Comment not found' });
    }

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

// --- Likes Routes ---
console.log('Defining POST /api/posts/:postId/like route...');
// Allow unauthenticated users to like a post
app.post('/api/posts/:postId/like', authenticateToken, async (req, res) => {
  try {
    const { postId } = req.params;
    const userId = req.user ? req.user.id : null; // Get userId if authenticated, else null

    const post = await Post.findById(postId);
    if (!post) {
      return res.status(404).json({ message: 'Post not found.' });
    }

    if (userId) { // Authenticated user
      if (post.likes.includes(userId)) {
        return res.status(400).json({ message: 'You have already liked this post.' });
      }
      post.likes.push(userId);
    } else { // Unauthenticated user
      // For simplicity, we just increment anonymousLikeCount for unauthenticated users.
      // This means an anonymous user can like multiple times if they clear local storage.
      // To prevent this, a client-side UUID would need to be sent and stored in a separate array,
      // which is more complex and out of scope for this immediate request.
      post.anonymousLikeCount += 1;
    }

    await post.save();

    const totalLikes = post.likes.length + post.anonymousLikeCount;
    res.status(200).json({ message: 'Post liked successfully!', likesCount: totalLikes });
  } catch (err) {
    console.error('Error liking post:', err);
    res.status(500).json({ message: 'Server error liking post.', details: err.message });
  }
});

console.log('Defining DELETE /api/posts/:postId/like route...');
// Only authenticated users can unlike a post
app.delete('/api/posts/:postId/like', authenticateToken, async (req, res) => {
  try {
    // This route strictly requires authentication to unlike
    if (!req.user || !req.user.id) {
      return res.status(401).json({ message: 'Authentication required to unlike a post.' });
    }
    const { postId } = req.params;
    const userId = req.user.id;

    const post = await Post.findById(postId);
    if (!post) {
      return res.status(404).json({ message: 'Post not found.' });
    }

    if (!post.likes.includes(userId)) {
      return res.status(400).json({ message: 'You have not liked this post.' });
    }

    post.likes = post.likes.filter(id => id.toString() !== userId);
    await post.save();

    const totalLikes = post.likes.length + post.anonymousLikeCount;
    res.status(200).json({ message: 'Post unliked successfully!', likesCount: totalLikes });
  } catch (err) {
    console.error('Error unliking post:', err);
    res.status(500).json({ message: 'Server error unliking post.', details: err.message });
  }
});

console.log('Defining POST /api/support route...');
// Support Message Route
app.post('/api/support', async (req, res) => {
  const { name, email, subject, message } = req.body;

  if (!name || !email || !message) {
    return res.status(400).json({ message: 'Name, email, and message are required.' });
  }

  try {
    const transporter = nodemailer.createTransport({
      service: 'gmail',
      auth: {
        user: process.env.EMAIL_USER,
        pass: process.env.EMAIL_PASS,
      },
    });

    const mailOptions = {
      from: process.env.EMAIL_USER,
      to: 'info.theskyfacts@gmail.com',
      subject: subject || `New Support Message from ${name}`,
      text: `Name: ${name}\nEmail: ${email}\n\nMessage:\n${message}`,
      html: `<p><strong>Name:</strong> ${name}</p><p><strong>Email:</strong> ${email}</p><p><strong>Message:</strong><br/>${message}</p>`,
      replyTo: email,
    };

    await transporter.sendMail(mailOptions);
    res.status(200).json({ message: 'Message sent successfully!' });
  } catch (error) {
    console.error('Error sending support email:', error);
    res.status(500).json({ message: 'Failed to send message.', details: error.message });
  }
});


// Start the server
console.log(`Starting server on port ${PORT}...`);
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
