// test-vulnerable.js
const mysql = require('mysql');
const express = require('express');
const app = express();

// SQL Injection - Semgrep WILL catch this
app.get('/user/:id', (req, res) => {
  const query = `SELECT * FROM users WHERE id = ${req.params.id}`;
  connection.query(query, (err, results) => {
    res.json(results);
  });
});

// Command Injection - Semgrep WILL catch this
const { exec } = require('child_process');
app.post('/run', (req, res) => {
  exec('ls -la ' + req.body.path, (err, stdout) => {
    res.send(stdout);
  });
});

// Hardcoded credentials - Semgrep WILL catch this
const AWS_SECRET_KEY = "AKIAIOSFODNN7EXAMPLE";
const password = "admin123";

// Path traversal - Semgrep WILL catch this
app.get('/file', (req, res) => {
  const fs = require('fs');
  fs.readFile(req.query.filename, (err, data) => {
    res.send(data);
  });
});