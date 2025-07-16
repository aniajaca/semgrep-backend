// Hardcoded secrets
const API_KEY = "sk-1234567890abcdef";
const DATABASE_URL = "postgres://admin:password123@localhost/db";

// XSS vulnerability
function renderUserData(userData) {
    document.getElementById('content').innerHTML = userData; // Direct HTML injection
}

// Command injection
const { exec } = require('child_process');
function processFile(filename) {
    exec(`cat ${filename}`, (error, stdout) => { // User input in command
        console.log(stdout);
    });
}

// Insecure random
function generateSessionId() {
    return Math.random().toString(36); // Weak randomness
}

// Path traversal
const fs = require('fs');
function readFile(userPath) {
    return fs.readFileSync(`/data/${userPath}`); // No path validation
}

// Prototype pollution
function merge(target, source) {
    for (let key in source) {
        target[key] = source[key]; // Dangerous assignment
    }
}