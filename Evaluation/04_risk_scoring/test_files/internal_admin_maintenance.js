// Internal Admin Tool - VPN access only
// Context: internet_facing=FALSE, production=TRUE, handles_pii=FALSE

const express = require('express');
const router = express.Router();
const { exec } = require('child_process');

// Requires admin authentication
router.use(requireAdmin);

router.post('/internal/admin/cleanup', async (req, res) => {
  const directory = req.body.directory;
  
  // VULNERABILITY: Command Injection (CWE-78)
  // Admin input in system command - internal context, authenticated
  const command = 'find /tmp/' + directory + ' -type f -mtime +7 -delete';
  
  exec(command, (error, stdout, stderr) => {
    if (error) {
      res.status(500).json({ error: error.message });
    } else {
      res.json({ 
        success: true,
        cleaned: directory,
        output: stdout
      });
    }
  });
});

function requireAdmin(req, res, next) {
  if (req.user && req.user.role === 'admin') {
    next();
  } else {
    res.status(403).json({ error: 'Admin required' });
  }
}

module.exports = router;
