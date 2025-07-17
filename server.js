// server.js
const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const path = require('path');
const nodemailer = require('nodemailer');
const multer = require('multer');
// const fs = require('fs'); // No longer needed for local file system management with GCS
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const dotenv = require('dotenv'); // Ensure dotenv is imported

dotenv.config(); // Load environment variables from .env file

const app = express();
const PORT = process.env.PORT || 8000;

// Middleware
app.use(cors());
app.use(express.json());

// --- Google Cloud Storage Setup ---
const { Storage } = require('@google-cloud/storage'); // Google Cloud Storage client library
let storageClient;
const bucketName = process.env.GCS_BUCKET_NAME; // Your GCS bucket name

// Prioritize GCP_SA_KEY environment variable for service account credentials
if (process.env.GCP_SA_KEY) {
  try {
    const serviceAccountKey = JSON.parse(process.env.GCP_SA_KEY);
    storageClient = new Storage({
      credentials: {
        client_email: serviceAccountKey.client_email,
        private_key: serviceAccountKey.private_key.replace(/\\n/g, '\n'), // Handle escaped newlines
      },
      projectId: serviceAccountKey.project_id,
    });
    console.log('Google Cloud Storage initialized using GCP_SA_KEY environment variable.');
  } catch (parseError) {
    console.error('Error parsing GCP_SA_KEY JSON:', parseError);
    console.error('Google Cloud Storage will not be available due to key parsing error.');
    storageClient = null; // Mark as not initialized
  }
} else {
  // Fallback to GOOGLE_APPLICATION_CREDENTIALS if GCP_SA_KEY is not set
  // This expects a file path to a service account key JSON file.
  try {
    storageClient = new Storage();
    console.log('Google Cloud Storage initialized using GOOGLE_APPLICATION_CREDENTIALS.');
  } catch (error) {
    console.error('GOOGLE_APPLICATION_CREDENTIALS environment variable not found or invalid.');
    console.error('Google Cloud Storage will not be available.');
    storageClient = null; // Mark as not initialized
  }
}

if (!bucketName && storageClient) {
  console.error('GCS_BUCKET_NAME environment variable is not set. GCS uploads will fail.');
}

// Helper function to upload file to GCS
const uploadFileToGCS = async (file) => {
  if (!storageClient || !bucketName) {
    throw new Error('Google Cloud Storage not configured.');
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
      console.error('GCS upload error:', err);
      reject(new Error('Failed to upload file to Google Cloud Storage.'));
    });

    blobStream.on('finish', () => {
      // Make the uploaded file publicly accessible
      blob.makePublic().then(() => {
        const publicUrl = `https://storage.googleapis.com/${bucket.name}/${blob.name}`;
        resolve(publicUrl);
      }).catch(err => {
        console.error('Error making GCS file public:', err);
        reject(new Error('Failed to make GCS file public.'));
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

// Configure multer for memory storage (files will be held in RAM)
// This is necessary because GCS client expects a buffer or stream, not a file path.
const upload = multer({
  storage: multer.memoryStorage(),
  limits: {
    fileSize: 5 * 1024 * 1024, // Limit file size to 5MB (adjust as needed)
  },
});

// Removed local 'uploads' directory setup and static serving
// app.use('/uploads', express.static(path.join(__dirname, 'uploads')));
// const uploadsDir = path.join(__dirname, 'uploads');
// if (!fs.existsSync(uploadsDir)) { fs.mkdirSync(uploadsDir); }


// MongoDB Connection
const mongoURI = process.env.MONGODB_URI || 'mongodb://localhost:27017/blogdb';

mongoose.connect(mongoURI)
  .then(() => console.log('MongoDB connected successfully!'))
  .catch(err => console.error('MongoDB connection error:', err));

// Nodemailer Transporter Setup (kept as it's part of the support route)
const transporter = nodemailer.createTransport({
  service: 'gmail',
  auth: {
    user: process.env.EMAIL_USER, // Use environment variables
    pass: process.env.EMAIL_PASS, // Use environment variables
  },
});

const JWT_SECRET = process.env.JWT_SECRET || 'your_jwt_secret_key'; // CHANGE THIS IN PRODUCTION!
const SUPPORT_EMAIL = process.env.SUPPORT_EMAIL || 'your_support_email@example.com'; // Recipient for support emails


// JWT Authentication Middleware
const authMiddleware = (req, res, next) => {
  const token = req.header('Authorization');

  if (!token) {
    console.log('Auth Middleware: No token provided.');
    return res.status(401).json({ message: 'No token, authorization denied' });
  }

  try {
    const tokenString = token.split(' ')[1];
    const decoded = jwt.verify(tokenString, JWT_SECRET);
    req.user = decoded.user;
    console.log('Auth Middleware: Token decoded. User ID:', req.user.id, 'Username:', req.user.username);
    next();
  } catch (err) {
    console.error('Auth Middleware: Token verification failed:', err.message);
    res.status(401).json({ message: 'Token is not valid' });
  }
};

// Define User Schema and Model
const userSchema = new mongoose.Schema({
  username: { type: String, required: true, unique: true, trim: true },
  password: { type: String, required: true },
  name: { type: String, required: true, trim: true },
  email: { type: String, required: true, unique: true, trim: true, lowercase: true },
  number: { type: String, required: true, trim: true },
}, { timestamps: true });

const User = mongoose.model('User', userSchema);

// Define Blog Post Schema and Model
const postSchema = new mongoose.Schema({
  title: { type: String, required: true, trim: true },
  author: { type: String, required: true, trim: true }, // Author name
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true }, // Link to User model
  date: { type: String, required: true },
  content: { type: String, required: true },
  thumbnailUrl: { type: String, default: '' },
  category: { type: String, enum: ['Fitness', 'Health', 'Travel', 'Fashion', 'Other'], default: 'Other', required: true },
}, { timestamps: true });

const Post = mongoose.model('Post', postSchema);

// Define Comment Schema and Model
const commentSchema = new mongoose.Schema({
  postId: { type: mongoose.Schema.Types.ObjectId, ref: 'Post', required: true },
  author: { type: String, required: true, trim: true }, // Author name of the comment
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true }, // User ID of the comment author
  content: { type: String, required: true, trim: true },
  date: { type: String, required: true },
}, { timestamps: true });

const Comment = mongoose.model('Comment', commentSchema);

// Define Support Request Schema and Model
const supportRequestSchema = new mongoose.Schema({
  name: { type: String, required: true, trim: true },
  email: { type: String, required: true, trim: true, lowercase: true },
  message: { type: String, required: true },
}, { timestamps: true });

const SupportRequest = mongoose.model('SupportRequest', supportRequestSchema);

// User Authentication Routes
app.post('/api/register', async (req, res) => {
  const { username, password, name, email, number } = req.body;
  try {
    let user = await User.findOne({ $or: [{ username }, { email }] });
    if (user) {
      return res.status(400).json({ message: 'User with that username or email already exists' });
    }

    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(password, salt);

    user = new User({ username, password: hashedPassword, name, email, number });
    await user.save();

    res.status(201).json({ message: 'User registered successfully' });
  } catch (err) {
    console.error('Registration error:', err);
    res.status(500).json({ message: 'Server error', details: err.message });
  }
});

app.post('/api/login', async (req, res) => {
  const { username, password } = req.body;
  try {
    const user = await User.findOne({ username });
    if (!user) {
      return res.status(400).json({ message: 'Invalid credentials' });
    }

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return res.status(400).json({ message: 'Invalid credentials' });
    }

    const payload = {
      user: {
        id: user.id,
        username: user.username,
      },
    };

    jwt.sign(payload, JWT_SECRET, { expiresIn: '1h' }, (err, token) => {
      if (err) throw err;
      res.json({ token, username: user.username, userId: user.id });
    });
  } catch (err) {
    console.error('Login error:', err);
    res.status(500).json({ message: 'Server error', details: err.message });
  }
});


// API Routes for Blog Posts

// GET all posts (with optional category, search, and pagination)
app.get('/api/posts', async (req, res) => {
  try {
    const { category, search, page = 1, limit = 4, sortBy = 'createdAt', sortOrder = 'desc' } = req.query;
    let filter = {};

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

    const sortOptions = {};
    sortOptions[sortBy] = sortOrder === 'asc' ? 1 : -1;

    const skip = (parseInt(page) - 1) * parseInt(limit);
    const postsQuery = Post.find(filter)
                           .sort(sortOptions)
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

// CREATE a new post with optional image upload (protected by authMiddleware)
app.post('/api/posts', authMiddleware, upload.single('thumbnail'), async (req, res) => {
  const { title, content, category } = req.body;
  const thumbnailUrlFromForm = req.body.thumbnailUrl; // This is for external URLs
  const uploadedFile = req.file; // This is for files uploaded via input type="file"

  // Get author and userId from the authenticated user
  const author = req.user.username;
  const userId = req.user.id;

  let finalThumbnailUrl = thumbnailUrlFromForm; // Default to external URL if provided

  if (uploadedFile) {
    // If a file was uploaded, upload it to GCS
    try {
      finalThumbnailUrl = await uploadFileToGCS(uploadedFile);
    } catch (gcsErr) {
      console.error('Failed to upload thumbnail to GCS:', gcsErr);
      return res.status(500).json({ message: 'Failed to upload thumbnail.', details: gcsErr.message });
    }
  }

  if (!title || !author || !content) {
    return res.status(400).json({ message: 'Please enter all fields: title, author, and content.' });
  }

  try {
    const newPost = new Post({
      title,
      author,
      userId, // Save the userId of the creator
      date: new Date().toISOString().split('T')[0],
      content,
      thumbnailUrl: finalThumbnailUrl,
      category: category || 'Other',
    });

    const savedPost = await newPost.save();
    console.log('POST /api/posts: Saved Post:', savedPost);
    res.status(201).json(savedPost);
  } catch (err) {
    console.error('Error creating post:', err);
    res.status(500).json({ message: 'Server error', details: err.message });
  }
});

// UPDATE a post by ID with optional image upload (protected by authMiddleware)
app.put('/api/posts/:id', authMiddleware, upload.single('thumbnail'), async (req, res) => {
  const { title, content, category } = req.body;
  const thumbnailUrlFromForm = req.body.thumbnailUrl; // This is for external URLs or clearing
  const uploadedFile = req.file; // This is for files uploaded via input type="file"

  try {
    let post = await Post.findById(req.params.id);
    if (!post) {
      return res.status(404).json({ message: 'Post not found' });
    }

    // Authorization check: Only the post owner can update
    if (post.userId.toString() !== req.user.id) {
      return res.status(403).json({ message: 'Forbidden: You can only update your own posts.' });
    }

    let finalThumbnailUrl = post.thumbnailUrl; // Start with the existing URL

    if (uploadedFile) {
      // If a new file is uploaded, delete the old one from GCS if it exists and was a GCS URL
      if (post.thumbnailUrl && post.thumbnailUrl.includes('storage.googleapis.com')) {
        await deleteFileFromGCS(post.thumbnailUrl);
      }
      finalThumbnailUrl = await uploadFileToGCS(uploadedFile); // Upload new file
    } else if (thumbnailUrlFromForm !== undefined) { // Check if the field was sent, even if empty
      // If the old thumbnail was a GCS URL and the new one is empty (cleared by user)
      if (post.thumbnailUrl && post.thumbnailUrl.includes('storage.googleapis.com') && thumbnailUrlFromForm === '') {
        await deleteFileFromGCS(post.thumbnailUrl);
      }
      finalThumbnailUrl = thumbnailUrlFromForm; // Use the provided external URL (could be empty)
    }
    // If neither uploadedFile nor thumbnailUrlFromForm is provided, finalThumbnailUrl remains the old one.


    const updatedPost = await Post.findByIdAndUpdate(
      req.params.id,
      { title, content, thumbnailUrl: finalThumbnailUrl, category }, // Author and userId are not updated here
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

// DELETE a post by ID (protected by authMiddleware)
app.delete('/api/posts/:id', authMiddleware, async (req, res) => {
  try {
    const post = await Post.findById(req.params.id);
    if (!post) {
      return res.status(404).json({ message: 'Post not found' });
    }

    // Authorization check: Only the post owner can delete
    if (post.userId.toString() !== req.user.id) {
      return res.status(403).json({ message: 'Forbidden: You can only delete your own posts.' });
    }

    // Delete associated thumbnail file from GCS if it's a GCS URL
    if (post.thumbnailUrl && post.thumbnailUrl.includes('storage.googleapis.com')) {
      await deleteFileFromGCS(post.thumbnailUrl);
    }

    await Post.findByIdAndDelete(req.params.id);
    // Also delete associated comments when a post is deleted
    await Comment.deleteMany({ postId: req.params.id });
    res.json({ message: 'Post and associated comments deleted successfully' });
  } catch (err) {
    console.error('Error deleting post:', err);
    if (err.kind === 'ObjectId') {
        return res.status(400).json({ message: 'Invalid Post ID format' });
    }
    res.status(500).json({ message: 'Server error' });
  }
});

// API Routes for Comments

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

// CREATE a new comment for a specific post (protected by authMiddleware)
app.post('/api/posts/:postId/comments', authMiddleware, async (req, res) => {
  const { content } = req.body;
  const { postId } = req.params;

  // Get author and userId from the authenticated user
  const author = req.user.username;
  const userId = req.user.id;

  if (!content) {
    return res.status(400).json({ message: 'Comment content cannot be empty.' });
  }

  try {
    const newComment = new Comment({
      postId,
      author,
      userId, // Save the userId of the comment author
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

// DELETE a comment by ID (protected by authMiddleware)
app.delete('/api/posts/:postId/comments/:commentId', authMiddleware, async (req, res) => {
  try {
    const comment = await Comment.findById(req.params.commentId);
    if (!comment) {
      return res.status(404).json({ message: 'Comment not found' });
    }

    // Authorization check: Only the comment owner can delete
    if (comment.userId.toString() !== req.user.id) {
      return res.status(403).json({ message: 'Forbidden: You can only delete your own comments.' });
    }

    await Comment.findByIdAndDelete(req.params.commentId);
    res.json({ message: 'Comment deleted successfully' });
  } catch (err) {
    console.error('Error deleting comment:', err);
    if (err.kind === 'ObjectId') {
        return res.status(400).json({ message: 'Invalid Comment ID format' });
    }
    res.status(500).json({ message: 'Server error' });
  }
});

// API Route for Support Requests
app.post('/api/support', async (req, res) => {
  const { name, email, message } = req.body;

  if (!name || !email || !message) {
    return res.status(400).json({ message: 'Please fill in all fields (name, email, message).' });
  }

  try {
    const newSupportRequest = new SupportRequest({ name, email, message });
    await newSupportRequest.save();

    const mailOptions = {
      from: process.env.EMAIL_USER,
      to: process.env.SUPPORT_EMAIL,
      subject: `New Support Request from ${name} (${email})`,
      html: `
        <p>You have received a new support request:</p>
        <ul>
          <li><strong>Name:</strong> ${name}</li>
          <li><strong>Email:</strong> ${email}</li>
          <li><strong>Message:</strong></li>
        </ul>
        <p>${message}</p>
        <p>Sent at: ${new Date().toLocaleString()}</p>
      `,
    };

    transporter.sendMail(mailOptions, (error, info) => {
      if (error) {
        console.error('Error sending email:', error);
        return res.status(200).json({ message: 'Support request received, but email notification failed.', details: error.message });
      }
      console.log('Email sent: ' + info.response);
      res.status(201).json({ message: 'Support request sent successfully!' });
    });

  } catch (err) {
    console.error('Error handling support request:', err);
    res.status(500).json({ message: 'Server error', details: err.message });
  }
});


// Serve static files from the React app in production
// This part is for deployment. In development, the React dev server handles this.
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
