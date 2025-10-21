// Complex Enterprise Banking Application - Legacy Migration Example
// This code demonstrates multiple security vulnerabilities common in COBOL-to-JavaScript migrations

const express = require('express');
const mysql = require('mysql');
const crypto = require('crypto');
const fs = require('fs');
const { exec, spawn } = require('child_process');
const path = require('path');

// === HARDCODED CREDENTIALS (A07: Auth Failures) ===
const DB_CONFIG = {
    host: 'localhost',
    user: 'admin',
    password: 'BankingSystem2024!',  // Critical vulnerability
    database: 'customer_accounts'
};

const API_KEYS = {
    payment_gateway: 'pk_live_51H7wX2KuD9t4YzCxRpQm8vN',
    encryption_key: 'AES256-SECRET-KEY-12345',
    jwt_secret: 'super-secret-jwt-token-2024'
};

// === WEAK CRYPTOGRAPHY (A02: Crypto Failures) ===
function hashCustomerPassword(password) {
    // Using deprecated MD5 for password hashing
    return crypto.createHash('md5').update(password).digest('hex');
}

function generateSessionToken() {
    // Weak random generation for financial sessions
    return Math.random().toString(36).substring(2, 15);
}

// === SQL INJECTION (A03: Injection) ===
function getCustomerAccount(customerId, accountType) {
    const connection = mysql.createConnection(DB_CONFIG);
    
    // Direct string concatenation - major vulnerability
    const query = `SELECT account_number, balance, ssn, credit_score 
                   FROM customer_accounts 
                   WHERE customer_id = '${customerId}' 
                   AND account_type = '${accountType}'`;
    
    connection.query(query, (error, results) => {
        if (error) {
            // Information disclosure through error messages
            console.log('Database error details:', error.sqlMessage);
            return { error: error.sqlMessage };
        }
        return results;
    });
}

function searchTransactions(startDate, endDate, customerInput) {
    // Multiple injection points
    const searchQuery = `
        SELECT t.*, c.ssn, c.full_name 
        FROM transactions t 
        JOIN customers c ON t.customer_id = c.id 
        WHERE t.date BETWEEN '${startDate}' AND '${endDate}'
        AND (t.description LIKE '%${customerInput}%' 
        OR c.full_name LIKE '%${customerInput}%')
        ORDER BY ${customerInput}_date DESC
    `;
    
    return executeQuery(searchQuery);
}

// === COMMAND INJECTION (A03: Injection) ===
function generateCustomerReport(customerId, reportType, outputFormat) {
    // Command injection through user-controlled parameters
    const command = `python3 /reports/generator.py --customer=${customerId} --type=${reportType} --format=${outputFormat}`;
    
    exec(command, (error, stdout, stderr) => {
        if (error) {
            console.error(`Report generation failed: ${error}`);
            return;
        }
        console.log('Report generated:', stdout);
    });
}

function backupCustomerData(customerId, backupPath) {
    // Multiple command injection vectors
    const backupCommand = `tar -czf ${backupPath}/customer_${customerId}_backup.tar.gz /data/customers/${customerId}`;
    const compressionCommand = `gzip -9 ${backupPath}/*.sql && chmod 755 ${backupPath}`;
    
    exec(`${backupCommand} && ${compressionCommand}`, { shell: true });
}

// === PATH TRAVERSAL (A01: Broken Access Control) ===
function getCustomerDocument(customerId, documentName) {
    // Path traversal vulnerability
    const documentPath = `/secure/documents/${customerId}/${documentName}`;
    
    try {
        return fs.readFileSync(documentPath, 'utf8');
    } catch (error) {
        // Error message disclosure
        throw new Error(`Document access failed: ${error.message}`);
    }
}

function uploadCustomerFile(customerId, fileName, fileContent) {
    // No path validation - allows directory traversal
    const uploadPath = `/uploads/customer_${customerId}/${fileName}`;
    
    fs.writeFileSync(uploadPath, fileContent);
    
    // Unsafe file execution
    if (fileName.endsWith('.sh') || fileName.endsWith('.py')) {
        exec(`chmod +x ${uploadPath} && ${uploadPath}`);
    }
}

// === XSS VULNERABILITIES (A03: Injection) ===
function renderCustomerDashboard(customerData, userInput) {
    // Direct DOM manipulation without sanitization
    document.getElementById('customerName').innerHTML = customerData.fullName;
    document.getElementById('searchResults').innerHTML = `<h3>Search: ${userInput}</h3>`;
    
    // Reflected XSS through URL parameters
    const urlParams = new URLSearchParams(window.location.search);
    const message = urlParams.get('message');
    if (message) {
        document.getElementById('notifications').innerHTML = `<div class="alert">${message}</div>`;
    }
    
    // Stored XSS through database content
    const customerNotes = customerData.notes; // From database
    document.getElementById('customerNotes').innerHTML = customerNotes;
}

// === INSECURE DESERIALIZATION (A08: Software Integrity Failures) ===
function processCustomerSession(sessionData) {
    // Unsafe deserialization of user-controlled data
    const customerSession = JSON.parse(sessionData);
    
    // Dynamic code execution
    if (customerSession.callback) {
        eval(customerSession.callback); // Extremely dangerous
    }
    
    return customerSession;
}

// === SECURITY MISCONFIGURATION (A05: Security Misconfiguration) ===
const app = express();

// Disabled security headers
app.disable('x-powered-by');
app.use((req, res, next) => {
    // Permissive CORS
    res.header('Access-Control-Allow-Origin', '*');
    res.header('Access-Control-Allow-Headers', '*');
    res.header('Access-Control-Allow-Methods', '*');
    next();
});

// Debug mode in production
if (process.env.NODE_ENV !== 'production') {
    app.use('/debug', (req, res) => {
        res.json({
            environment: process.env,
            config: DB_CONFIG,
            secrets: API_KEYS
        });
    });
}

// === VULNERABLE AUTHENTICATION (A07: Auth Failures) ===
function authenticateCustomer(username, password, rememberMe) {
    // Weak password policy
    if (password.length < 6) {
        return { error: 'Password too short' };
    }
    
    // Timing attack vulnerability
    const storedPassword = getStoredPassword(username);
    if (hashCustomerPassword(password) === storedPassword) {
        const sessionToken = generateSessionToken();
        
        // Insecure session management
        if (rememberMe) {
            // Session never expires
            setSessionCookie(sessionToken, { maxAge: 365 * 24 * 60 * 60 * 1000 });
        }
        
        return { success: true, token: sessionToken };
    }
    
    return { error: 'Authentication failed' };
}

// === INSECURE LOGGING (A09: Security Logging Failures) ===
function logCustomerActivity(customerId, activity, sensitiveData) {
    // Logging sensitive information
    console.log(`Customer ${customerId} performed: ${activity}`);
    console.log(`Sensitive data: ${JSON.stringify(sensitiveData)}`);
    
    // Writing logs to insecure location
    const logEntry = `${new Date().toISOString()} - Customer: ${customerId}, SSN: ${sensitiveData.ssn}, Activity: ${activity}\n`;
    fs.appendFileSync('/tmp/customer_activity.log', logEntry);
}

// === SSRF VULNERABILITY (A10: SSRF) ===
function validateCustomerWithExternalAPI(customerId, apiEndpoint) {
    // Server-side request forgery
    const validationUrl = `${apiEndpoint}/validate?customer=${customerId}`;
    
    fetch(validationUrl)
        .then(response => response.json())
        .then(data => {
            console.log('External validation result:', data);
        })
        .catch(error => {
            console.error('Validation failed:', error.message);
        });
}

// === RACE CONDITION (A04: Insecure Design) ===
let accountBalance = 0;

function transferFunds(fromAccount, toAccount, amount) {
    // Race condition in financial transaction
    const currentBalance = getAccountBalance(fromAccount);
    
    // No atomic transaction - vulnerable to race conditions
    if (currentBalance >= amount) {
        setTimeout(() => {
            updateAccountBalance(fromAccount, currentBalance - amount);
            updateAccountBalance(toAccount, getAccountBalance(toAccount) + amount);
        }, Math.random() * 100);
        
        return { success: true, message: 'Transfer initiated' };
    }
    
    return { error: 'Insufficient funds' };
}

// === PROTOTYPE POLLUTION (A08: Software Integrity Failures) ===
function mergeCustomerPreferences(existingPrefs, newPrefs) {
    // Prototype pollution vulnerability
    for (let key in newPrefs) {
        existingPrefs[key] = newPrefs[key];
    }
    
    return existingPrefs;
}

// Export vulnerable functions for testing
module.exports = {
    getCustomerAccount,
    searchTransactions,
    generateCustomerReport,
    backupCustomerData,
    getCustomerDocument,
    uploadCustomerFile,
    renderCustomerDashboard,
    processCustomerSession,
    authenticateCustomer,
    logCustomerActivity,
    validateCustomerWithExternalAPI,
    transferFunds,
    mergeCustomerPreferences
};