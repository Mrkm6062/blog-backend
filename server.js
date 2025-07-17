const dotenv = require('dotenv');
dotenv.config();

console.log('--- Loaded Environment Variables ---');
Object.keys(process.env).forEach(key => {
  console.log(`${key} = ${process.env[key]}`);
});
console.log('------------------------------------');

// Rest of your server.js below...
const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const path = require('path');
const nodemailer = require('nodemailer');
const multer = require('multer');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const postRoutes = require('./routes/posts'); // ✅ Externalized post routes

const app = express();
const PORT = process.env.PORT || 8000;

app.use(cors());
app.use(express.json());

// Google Cloud Storage Setup
const { Storage } = require('@google-cloud/storage');
let storageClient;
const bucketName = process.env.GCS_BUCKET_NAME;

if (process.env.GCP_SA_KEY) {
  try {
    const key = JSON.parse(process.env.GCP_SA_KEY);
    storageClient = new Storage({
      credentials: {
        client_email: key.client_email,
        private_key: key.private_key.replace(/\\n/g, '\n'),
      },
      projectId: key.project_id,
    });
    console.log('GCS initialized using GCP_SA_KEY.');
  } catch (e) {
    console.error('Error parsing GCP_SA_KEY:', e.message);
    storageClient = null;
  }
} else {
  try {
    storageClient = new Storage();
    console.log('GCS initialized using GOOGLE_APPLICATION_CREDENTIALS.');
  } catch (e) {
    console.error('GCS not configured:', e.message);
    storageClient = null;
  }
}

if (!bucketName && storageClient) {
  console.error('GCS_BUCKET_NAME missing.');
}

const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 5 * 1024 * 1024 },
});

const mongoURI = process.env.MONGODB_URI || 'mongodb://localhost:27017/blogdb';
mongoose.connect(mongoURI)
  .then(() => console.log('MongoDB connected.'))
  .catch(err => console.error('MongoDB error:', err.message));

const transporter = nodemailer.createTransport({
  service: 'gmail',
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASS,
  },
});

const JWT_SECRET = process.env.JWT_SECRET || 'your_jwt_secret_key';
const SUPPORT_EMAIL = process.env.SUPPORT_EMAIL || 'support@example.com';

const authMiddleware = (req, res, next) => {
  const token = req.header('Authorization');
  if (!token) return res.status(401).json({ message: 'No token provided.' });

  try {
    const decoded = jwt.verify(token.split(' ')[1], JWT_SECRET);
    req.user = decoded.user;
    next();
  } catch (err) {
    return res.status(401).json({ message: 'Invalid token.' });
  }
};

// User Model
const userSchema = new mongoose.Schema({
  username: { type: String, required: true, unique: true, trim: true },
  password: { type: String, required: true },
  name: { type: String, required: true, trim: true },
  email: { type: String, required: true, unique: true, lowercase: true, trim: true },
  number: { type: String, required: true, trim: true },
}, { timestamps: true });

const User = mongoose.model('User', userSchema);

// Comment Model
const commentSchema = new mongoose.Schema({
  postId: { type: mongoose.Schema.Types.ObjectId, ref: 'Post', required: true },
  author: { type: String, required: true },
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  content: { type: String, required: true },
  date: { type: String, required: true },
}, { timestamps: true });

const Comment = mongoose.model('Comment', commentSchema);

// Support Request Model
const supportSchema = new mongoose.Schema({
  name: String,
  email: String,
  message: String,
}, { timestamps: true });

const SupportRequest = mongoose.model('SupportRequest', supportSchema);

// Auth Routes
app.post('/api/register', async (req, res) => {
  const { username, password, name, email, number } = req.body;
  try {
    let user = await User.findOne({ $or: [{ username }, { email }] });
    if (user) return res.status(400).json({ message: 'User exists.' });

    const hashed = await bcrypt.hash(password, 10);
    user = new User({ username, password: hashed, name, email, number });
    await user.save();
    res.status(201).json({ message: 'Registered.' });
  } catch (err) {
    res.status(500).json({ message: 'Server error', details: err.message });
  }
});

app.post('/api/login', async (req, res) => {
  const { username, password } = req.body;
  try {
    const user = await User.findOne({ username });
    if (!user || !(await bcrypt.compare(password, user.password))) {
      return res.status(400).json({ message: 'Invalid credentials' });
    }

    const token = jwt.sign({ user: { id: user.id, username: user.username } }, JWT_SECRET, { expiresIn: '1h' });
    res.json({ token, username: user.username, userId: user.id });
  } catch (err) {
    res.status(500).json({ message: 'Server error', details: err.message });
  }
});

// Use external postRoutes
app.use('/api/posts', postRoutes);

// Support Request Route
app.post('/api/support', async (req, res) => {
  const { name, email, message } = req.body;
  if (!name || !email || !message) {
    return res.status(400).json({ message: 'All fields required.' });
  }

  try {
    await new SupportRequest({ name, email, message }).save();

    await transporter.sendMail({
      from: process.env.EMAIL_USER,
      to: SUPPORT_EMAIL,
      subject: `Support Request from ${name}`,
      html: `<p>${message}</p><p>From: ${name} (${email})</p>`,
    });

    res.status(201).json({ message: 'Support request sent.' });
  } catch (err) {
    res.status(500).json({ message: 'Error sending support request.', details: err.message });
  }
});

// Function to log all routes safely
function logRoutes(app) {
  if (!app._router) {
    console.log('⚠️ No routes registered yet (app._router is undefined)');
    return;
  }

  const routes = [];
  app._router.stack.forEach((middleware) => {
    if (middleware.route) {
      // Direct route on app
      routes.push(`${Object.keys(middleware.route.methods).join(', ').toUpperCase()} ${middleware.route.path}`);
    } else if (middleware.name === 'router' && middleware.handle.stack) {
      // Router middleware
      middleware.handle.stack.forEach((handler) => {
        if (handler.route) {
          const method = Object.keys(handler.route.methods).join(', ').toUpperCase();
          routes.push(`${method} ${handler.route.path}`);
        }
      });
    }
  });

  console.log('\n🔍 [DEBUG] All Registered Routes:');
  routes.forEach((r, i) => console.log(`  [${i}] ${r}`));
  console.log('--------------------------------------\n');
}

// Call route logger AFTER all routes are registered
logRoutes(app);

// Serve React frontend in production
if (process.env.NODE_ENV === 'production') {
  app.use(express.static(path.join(__dirname, 'client/build')));
  app.get('*', (req, res) =>
    res.sendFile(path.resolve(__dirname, 'client', 'build', 'index.html'))
  );
}

app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
