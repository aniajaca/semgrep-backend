// Production API - Internet-facing login endpoint
// Context: internet_facing=TRUE, production=TRUE, handles_pii=TRUE

const express = require('express');
const router = express.Router();
const db = require('../database');

// Public API endpoint - no authentication required
router.post('/api/v1/login', async (req, res) => {
  const username = req.body.username;
  const password = req.body.password;
  
  // VULNERABILITY: SQL Injection
  const query = `SELECT * FROM users WHERE username='${username}' AND password='${password}'`;
  
  try {
    const result = await db.query(query);
    
    if (result.rows.length > 0) {
      const user = result.rows[0];
      res.json({
        success: true,
        user: {
          id: user.id,
          email: user.email,
          ssn: user.ssn,
          creditCard: user.credit_card
        }
      });
    } else {
      res.status(401).json({ success: false });
    }
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

module.exports = router;