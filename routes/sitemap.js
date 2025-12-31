const express = require('express');
const router = express.Router();
const mongoose = require('mongoose');

router.get('/sitemap.xml', async (req, res) => {
  try {
    const baseUrl = 'http://localhost:3000'; // Your frontend base URL

    const Post = mongoose.model('Post');
    const posts = await Post.find({}, 'slug updatedAt date');

    let xml = `<?xml version="1.0" encoding="UTF-8"?>\n`;
    xml += `<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">\n`;

    // Static URLs
    const staticRoutes = ['/', '/about', '/contact'];
    staticRoutes.forEach(route => {
      xml += `  <url>\n`;
      xml += `    <loc>${baseUrl}${route}</loc>\n`;
      xml += `    <priority>1.0</priority>\n`;
      xml += `  </url>\n`;
    });

    // Dynamic blog posts with encoded slug
    posts.forEach(post => {
      if (!post.slug) return;
      const lastMod = post.updatedAt || post.date ? new Date(post.updatedAt || post.date).toISOString() : new Date().toISOString();
      xml += `  <url>\n`;
      xml += `    <loc>${baseUrl}/posts/${encodeURIComponent(post.slug)}</loc>\n`;
      xml += `    <lastmod>${lastMod}</lastmod>\n`;
      xml += `    <changefreq>weekly</changefreq>\n`;
      xml += `    <priority>0.8</priority>\n`;
      xml += `  </url>\n`;
    });

    xml += `</urlset>`;

    res.header('Content-Type', 'application/xml');
    res.status(200).send(xml);
  } catch (error) {
    console.error('❌ Sitemap generation failed:', error.message);
    res.status(500).send('Server error: ' + error.message);
  }
});

module.exports = router;
