// Production API - Internet-facing backup endpoint
// Context: internet_facing=TRUE, production=TRUE, handles_pii=TRUE

const express = require('express');
const router = express.Router();
const { exec } = require('child_process');

// Public API endpoint - authenticated users can trigger backups
router.post('/api/v1/backup', async (req, res) => {
  const filename = req.body.filename;
  const backupPath = req.body.path || '/backups';
  
  // VULNERABILITY: Command Injection (CWE-78)
  // User input directly in exec() allows arbitrary command execution
  const command = 'tar -czf ' + backupPath + '/' + filename + '.tar.gz /data/user_profiles';
  
  exec(command, (error, stdout, stderr) => {
    if (error) {
      res.status(500).json({ error: error.message });
    } else {
      res.json({ 
        success: true, 
        backup: filename,
        message: 'User data backup created'
      });
    }
  });
});

module.exports = router;
