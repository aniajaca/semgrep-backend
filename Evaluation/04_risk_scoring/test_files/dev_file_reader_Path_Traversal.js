// Development Testing Script - Local environment only
// Context: internet_facing=FALSE, production=FALSE, handles_pii=FALSE

const express = require('express');
const app = express();
const path = require('path');
const fs = require('fs');

/**
 * Development endpoint for testing file reading
 * Usage: GET /dev/read?file=filename
 */

app.get('/dev/read', (req, res) => {
  const filename = req.query.file || 'test.txt';
  
  console.log('Reading file:', filename);
  
  // VULNERABILITY: Path Traversal (CWE-22)
  const filepath = path.join(__dirname, 'test_data', filename);
  
  try {
    const content = fs.readFileSync(filepath, 'utf8');
    res.send(content);
  } catch (error) {
    res.status(500).send('Read failed: ' + error.message);
  }
});

module.exports = app;
