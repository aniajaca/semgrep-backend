// test-vulnerable.js
const mysql = require('mysql');

function getUser(req, res) {
  const userId = req.params.id;
  // SQL Injection vulnerability
  const query = `SELECT * FROM users WHERE id = ${userId}`;
  connection.query(query, (err, results) => {
    res.json(results);
  });
}

// Hardcoded secret
const apiKey = "sk_live_abcd1234567890";

// Command injection
const exec = require('child_process').exec;
exec('ls -la ' + req.body.path);