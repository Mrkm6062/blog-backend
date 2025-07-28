// routes/sitemap.js
const express = require('express');
const router = express.Router();
const Post = require('../models/Post'); // Correct path to the Post model

// Example sitemap route (adjust as per your actual sitemap logic)
router.get('/sitemap.xml', async (req, res) => {
  try {
    // Fetch _id and date from the Post model
    const posts = await Post.find({}, '_id date');
    let sitemap = `<?xml version="1.0" encoding="UTF-8"?>
<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
  <url>
    <loc>https://yourwebsite.com/</loc>
    <lastmod>${new Date().toISOString().split('T')[0]}</lastmod>
    <changefreq>daily</changefreq>
    <priority>1.0</priority>
  </url>
  <url>
    <loc>https://yourwebsite.com/blog</loc>
    <lastmod>${new Date().toISOString().split('T')[0]}</lastmod>
    <changefreq>daily</changefreq>
    <priority>0.8</priority>
  </url>`;

    posts.forEach(post => {
      sitemap += `
  <url>
    <loc>https://yourwebsite.com/blog/${post._id}</loc>
    <lastmod>${post.date ? post.date.toISOString().split('T')[0] : new Date().toISOString().split('T')[0]}</lastmod>
    <changefreq>weekly</changefreq>
    <priority>0.7</priority>
  </url>`;
    });

    sitemap += `
</urlset>`;

    res.header('Content-Type', 'application/xml');
    res.send(sitemap);
  } catch (error) {
    console.error('Error generating sitemap:', error);
    res.status(500).send('Error generating sitemap');
  }
});

module.exports = router;
