// routes/sitemap.js

const express = require('express');
const router = express.Router();
const Post = require('../models/Post'); // Adjust path if needed

router.get('/sitemap.xml', async (req, res) => {
  try {
    const baseUrl = 'https://samriddhiblog.tech';
    const posts = await Post.find({}, 'slug updatedAt');

    let xml = `<?xml version="1.0" encoding="UTF-8"?>\n`;
    xml += `<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">\n`;

    const staticRoutes = ['/', '/about', '/contact'];
    staticRoutes.forEach(route => {
      xml += `  <url>\n`;
      xml += `    <loc>${baseUrl}${route}</loc>\n`;
      xml += `    <priority>1.0</priority>\n`;
      xml += `  </url>\n`;
    });

    posts.forEach(post => {
      xml += `  <url>\n`;
      xml += `    <loc>${baseUrl}/blog/${post.slug}</loc>\n`;
      xml += `    <lastmod>${new Date(post.updatedAt).toISOString()}</lastmod>\n`;
      xml += `    <changefreq>weekly</changefreq>\n`;
      xml += `    <priority>0.8</priority>\n`;
      xml += `  </url>\n`;
    });

    xml += `</urlset>`;

    res.header('Content-Type', 'application/xml');
    res.send(xml);
  } catch (err) {
    console.error('Sitemap generation failed:', err);
    res.status(500).send('Server error');
  }
});

module.exports = router;
