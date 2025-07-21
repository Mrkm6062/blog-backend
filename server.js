// server.js
const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const path = require('path');
const dotenv = require('dotenv');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const multer = require('multer'); // Still needed for parsing multipart/form-data
const { Storage } = require('@google-cloud/storage'); // Google Cloud Storage client library
// const fs = require('fs'); // No longer needed for local uploads directory

dotenv.config(); // Load environment variables from .env file

const app = express();
const PORT = process.env.PORT || 8000;

// Middleware
app.use(cors());
app.use(express.json());

// --- Google Cloud Storage Setup ---
// Initialize Google Cloud Storage
let storageClient;
const bucketName = process.env.GCS_BUCKET_NAME; // Your GCS bucket name

console.log('Attempting to initialize Google Cloud Storage...');
// Prioritize GCP_SA_KEY environment variable for service account credentials
if (process.env.GCP_SA_KEY) {
  try {
    const serviceAccountKey = JSON.parse(process.env.GCP_SA_KEY);
    storageClient = new Storage({
      credentials: {
        client_email: serviceAccountKey.client_email,
        // Replace escaped newlines if the key was pasted as a single line string
        private_key: serviceAccountKey.private_key.replace(/\\n/g, '\n'),
      },
      projectId: serviceAccountKey.project_id,
    });
    console.log('Google Cloud Storage initialized successfully using GCP_SA_KEY environment variable.');
  } catch (parseError) {
    console.error('Error parsing GCP_SA_KEY JSON:', parseError);
    console.error('Google Cloud Storage will not be available due to key parsing error. Check GCP_SA_KEY format.');
    storageClient = null; // Mark as not initialized
  }
} else {
  // Fallback to GOOGLE_APPLICATION_CREDENTIALS if GCP_SA_KEY is not set
  // This expects a file path to a service account key JSON file.
  // Note: Render might not easily support GOOGLE_APPLICATION_CREDENTIALS pointing to a file path directly.
  try {
    storageClient = new Storage();
    console.log('Google Cloud Storage initialized using GOOGLE_APPLICATION_CREDENTIALS (or default ADC).');
  } catch (error) {
    console.error('GOOGLE_APPLICATION_CREDENTIALS environment variable not found or invalid, or other GCS initialization error:', error);
    console.error('Google Cloud Storage will not be available. Ensure GOOGLE_APPLICATION_CREDENTIALS points to a valid file or GCP_SA_KEY is set.');
    storageClient = null; // Mark as not initialized
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


// Configure multer for memory storage (files will be held in RAM)
// This is necessary because GCS client expects a buffer or stream, not a file path.
const upload = multer({
  storage: multer.memoryStorage(),
  limits: {
    fileSize: 5 * 1024 * 1024, // Limit file size to 5MB (adjust as needed)
  },
});

// Removed local 'uploads' directory setup and static serving
// const uploadsDir = path.join(__dirname, 'uploads');
// if (!fs.existsSync(uploadsDir)) {
//   fs.mkdirSync(uploadsDir);
// }
// app.use('/uploads', express.static(uploadsDir));


// MongoDB Connection
const mongoURI = process.env.MONGO_URI || 'mongodb+srv://akm222143:Z466GPPhEp5GlnuJ@marto.klqfj94.mongodb.net/samriddhiblogdb?retryWrites=true&w=majority';

mongoose.connect(mongoURI)
  .then(() => console.log('MongoDB connected successfully!'))
  .catch(err => console.error('MongoDB connection error:', err));

// --- Mongoose Schemas and Models ---

// Utility function to create a URL-friendly slug
const slugify = (text) => {
  return text
    .toString()
    .normalize('NFD') // Normalize diacritics
    .replace(/[\u0300-\u036f]/g, '') // Remove diacritics
    .toLowerCase()
    .trim()
    .replace(/\s+/g, '-') // Replace spaces with -
    .replace(/[^\w-]+/g, '') // Remove all non-word chars
    .replace(/--+/g, '-'); // Replace multiple - with single -
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
  slug: { // New slug field
    type: String,
    unique: true,
    index: true, // Index for faster lookup
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
  thumbnailUrl: { // This will now store the GCS public URL
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

// --- Authentication Middleware ---
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (token == null) {
    return res.status(401).json({ message: 'Authentication token required' });
  }

  jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
    if (err) {
      console.error('JWT verification error:', err);
      return res.status(403).json({ message: 'Invalid or expired token' });
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
    const userId = req.user.id; // Get user ID from the authenticated token
    const userPosts = await Post.find({ userId: userId }).sort({ createdAt: -1 });
    res.json({ posts: userPosts, totalPosts: userPosts.length }); // Return totalPosts for pagination
  } catch (err) {
    console.error('Error fetching user-specific posts:', err);
    res.status(500).json({ message: 'Server error fetching your posts.' });
  }
});


// NEW ROUTE: GET a single post by ID or SLUG
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
      // Extract slug from the identifier (e.g., "my-post-title-654321abcdef...")
      // The slug is everything before the last 24 characters (the ID) if it exists.
      const slugMatch = identifier.match(/^(.*)-([a-f0-9]{24})$/);
      let slugToSearch = identifier; // Default to full identifier if no slug-ID format

      if (slugMatch && slugMatch[1]) {
        slugToSearch = slugMatch[1]; // Use the slug part
      }

      post = await Post.findOne({ slug: slugToSearch });
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


// Helper function to upload file to GCS
const uploadFileToGCS = async (file) => {
  if (!storageClient || !bucketName) {
    console.error('GCS upload attempt failed: storageClient or bucketName not configured.');
    throw new Error('Google Cloud Storage not configured. Check server logs for details.');
  }

  const bucket = storageClient.bucket(bucketName);
  const uniqueFilename = `${Date.now()}-${file.originalname}`;
  const blob = bucket.file(uniqueFilename);

  const blobStream = blob.createWriteStream({
    resumable: false, // For smaller files, resumable can be false
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
      // Make the uploaded file publicly accessible
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

// Helper function to delete file from GCS
const deleteFileFromGCS = async (fileUrl) => {
  if (!storageClient || !bucketName) {
    console.warn('Google Cloud Storage not configured. Skipping GCS file deletion.');
    return;
  }

  // Extract filename from the GCS public URL
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
    // If the file doesn't exist, GCS will return a 404, which is fine.
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
// Use upload.single('thumbnail') to handle file upload from frontend
app.post('/api/posts', authenticateToken, upload.single('thumbnail'), async (req, res) => {
  const { title, content, category, thumbnailUrl: externalThumbnailUrl } = req.body;
  const author = req.user.username;
  const userId = req.user.id;

  if (!title || !content) {
    return res.status(400).json({ message: 'Please enter all fields: title and content.' });
  }

  let finalThumbnailUrl = externalThumbnailUrl || '';

  if (req.file) {
    // If a file was uploaded, upload it to GCS
    try {
      finalThumbnailUrl = await uploadFileToGCS(req.file);
    } catch (gcsErr) {
      console.error('Failed to upload thumbnail to GCS during post creation:', gcsErr);
      return res.status(500).json({ message: 'Failed to upload thumbnail.', details: gcsErr.message });
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
      category: category || 'Other',
      // slug will be generated by the pre-save hook
    });

    const savedPost = await newPost.save();
    res.status(201).json(savedPost);
  } catch (err) {
    console.error('Error creating post:', err);
    // Handle duplicate slug error specifically
    if (err.code === 11000 && err.keyPattern && err.keyPattern.slug) {
      return res.status(409).json({ message: 'A post with a similar title already exists. Please choose a more unique title.' });
    }
    res.status(500).json({ message: 'Server error', details: err.message });
  }
});

console.log('Defining PUT /api/posts/:id route...');
// UPDATE a post by ID (PROTECTED - only owner can update)
app.put('/api/posts/:id', authenticateToken, upload.single('thumbnail'), async (req, res) => {
  const { title, content, category, thumbnailUrl: externalThumbnailUrl } = req.body;

  try {
    const post = await Post.findById(req.params.id);
    if (!post) {
      return res.status(404).json({ message: 'Post not found' });
    }

    if (post.userId.toString() !== req.user.id) {
      return res.status(403).json({ message: 'Unauthorized: You can only update your own posts.' });
    }

    let finalThumbnailUrl = post.thumbnailUrl; // Default to existing URL

    if (req.file) {
      // New file uploaded to GCS
      try {
        // Delete old GCS file if it exists and was a GCS URL
        if (post.thumbnailUrl && post.thumbnailUrl.includes('storage.googleapis.com')) {
          await deleteFileFromGCS(post.thumbnailUrl);
        }
        finalThumbnailUrl = await uploadFileToGCS(req.file);
      } catch (gcsErr) {
        console.error('Failed to upload new thumbnail to GCS during post update:', gcsErr);
        return res.status(500).json({ message: 'Failed to upload new thumbnail.', details: gcsErr.message });
      }
    } else if (externalThumbnailUrl !== undefined) {
      // If externalThumbnailUrl is explicitly provided (even if empty string), use it
      // This handles cases where user clears the URL or provides a new one
      if (post.thumbnailUrl && post.thumbnailUrl.includes('storage.googleapis.com') && externalThumbnailUrl === '') {
        // If old was GCS and new is empty, delete from GCS
        await deleteFileFromGCS(post.thumbnailUrl);
      }
      finalThumbnailUrl = externalThumbnailUrl;
    }
    // If neither req.file nor externalThumbnailUrl is provided, finalThumbnailUrl remains the old one.


    const updatedPost = await Post.findByIdAndUpdate(
      req.params.id,
      {
        title,
        content,
        thumbnailUrl: finalThumbnailUrl,
        category,
        // slug will be generated by the pre-findOneAndUpdate hook if title is modified
      },
      { new: true, runValidators: true }
    );

    res.json(updatedPost);
  } catch (err) {
    console.error('Error updating post:', err);
    if (err.kind === 'ObjectId') {
        return res.status(400).json({ message: 'Invalid Post ID format' });
    }
    // Handle duplicate slug error specifically
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

    // Delete associated thumbnail file from GCS if it's a GCS URL
    if (post.thumbnailUrl && post.thumbnailUrl.includes('storage.googleapis.com')) {
      await deleteFileFromGCS(post.thumbnailUrl);
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


// Serve static files from the React app in production
// console.log('Defining static file serving for production...');
// if (process.env.NODE_ENV === 'production') {
//   app.use(express.static(path.join(__dirname, 'client/build')));

//   app.get('*', (req, res) => {
//     res.sendFile(path.resolve(__dirname, 'client', 'build', 'index.html'));
//   });
// }

// Start the server
console.log(`Starting server on port ${PORT}...`);
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
