const express = require('express');
const app = express();

// HTTP endpoints — triggers ATTACK-001 and ATTACK-002.
app.get('/api/products', (req, res) => {
  res.json({ products: [] });
});

app.post('/api/checkout', (req, res) => {
  res.json({ status: 'ok' });
});

// Admin endpoint — triggers ATTACK-003.
app.get('/admin/settings', (req, res) => {
  res.json({ settings: {} });
});

// File upload — triggers ATTACK-004.
const multer = require('multer');
const upload = multer({ dest: 'uploads/' });
app.post('/api/upload', upload.single('file'), (req, res) => {
  res.json({ file: req.file });
});

// WebSocket endpoint — triggers ATTACK-005.
const WebSocket = require('ws');
const wss = new WebSocket.Server({ port: 8080 });
