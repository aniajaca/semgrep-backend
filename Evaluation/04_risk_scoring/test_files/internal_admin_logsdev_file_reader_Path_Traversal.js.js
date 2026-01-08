// Internal Admin Tool - VPN access only
// Context: internet_facing=FALSE, production=TRUE, handles_pii=FALSE

const express = require('express');
const router = express.Router();
const path = require('path');
const fs = require('fs');

// Requires admin authentication
router.use(requireAdmin);

router.get('/internal/admin/logs', async (req, res) => {
  const logFile = req.query.log;
  
  // VULNERABILITY: Path Traversal (CWE-22)
  const filepath = path.join(__dirname, 'logs', logFile);
  
  try {
    const content = fs.readFileSync(filepath, 'utf8');
    res.json({ content });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

function requireAdmin(req, res, next) {
  if (req.user && req.user.role === 'admin') {
    next();
  } else {
    res.status(403).json({ error: 'Admin required' });
  }
}

module.exports = router;
