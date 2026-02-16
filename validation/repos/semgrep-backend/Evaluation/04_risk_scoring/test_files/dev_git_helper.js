// Development Script - Local environment only
// Context: internet_facing=FALSE, production=FALSE, handles_pii=FALSE

const { exec } = require('child_process');

/**
 * Development script for git operations
 * Simulates request-like input pattern for internal testing
 * Usage: node scripts/git_helper.js
 */

function runGitCommand(req) {
  const branch = req.body.branch || 'main';
  
  console.log('Checking out branch:', branch);
  
  // VULNERABILITY: Command Injection (CWE-78)
  // Uses req-like pattern but in dev context (not internet-facing)
  const command = 'git checkout ' + branch;
  
  exec(command, (error, stdout, stderr) => {
    if (error) {
      console.error('Git command failed:', error.message);
    } else {
      console.log('Success:', stdout);
    }
  });
}

// Dev context: simulating request input from CLI args
if (require.main === module) {
  const mockReq = {
    body: {
      branch: process.argv[2] || 'main'
    }
  };
  runGitCommand(mockReq);
}

module.exports = { runGitCommand };
