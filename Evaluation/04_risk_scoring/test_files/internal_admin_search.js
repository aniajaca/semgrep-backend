// Internal Admin Tool - Only accessible from internal network
// Context: internet_facing=FALSE, production=TRUE, handles_pii=FALSE

const express = require('express');
const router = express.Router();
const db = require('../database');

// Middleware ensures user is authenticated admin
router.use(requireAdmin);

router.post('/internal/admin/search-logs', async (req, res) => {
  const searchTerm = req.body.searchTerm;
  
  // VULNERABILITY: SQL Injection - same vulnerability, different context
  const query = `SELECT * FROM system_logs WHERE message LIKE '%${searchTerm}%'`;
  
  try {
    const result = await db.query(query);
    res.json({ logs: result.rows });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

function requireAdmin(req, res, next) {
  if (req.user && req.user.role === 'admin') {
    next();
  } else {
    res.status(403).json({ error: 'Admin access required' });
  }
}

module.exports = router;