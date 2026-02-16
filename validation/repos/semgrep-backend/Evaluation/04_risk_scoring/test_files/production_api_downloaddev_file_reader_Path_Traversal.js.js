// Production API - Internet-facing file download endpoint
// Context: internet_facing=TRUE, production=TRUE, handles_pii=TRUE

const express = require('express');
const router = express.Router();
const path = require('path');
const fs = require('fs');

// Public API endpoint - no authentication required
router.get('/api/v1/download', async (req, res) => {
  const filename = req.query.file;
  
  // VULNERABILITY: Path Traversal (CWE-22)
  const filepath = path.join(__dirname, 'uploads', filename);
  
  try {
    const content = fs.readFileSync(filepath);
    res.send(content);
  } catch (error) {
    res.status(404).json({ error: 'File not found' });
  }
});

module.exports = router;
