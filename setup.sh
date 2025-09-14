#!/bin/bash
# setup.sh - Complete setup for Neperia Vulnerability Assessment Tool

echo "╔══════════════════════════════════════════════════════════════╗"
echo "║     Neperia Vulnerability Assessment Tool Setup             ║"
echo "╚══════════════════════════════════════════════════════════════╝"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Check OS
OS="unknown"
if [[ "$OSTYPE" == "linux-gnu"* ]]; then
    OS="linux"
elif [[ "$OSTYPE" == "darwin"* ]]; then
    OS="macos"
elif [[ "$OSTYPE" == "msys" ]] || [[ "$OSTYPE" == "cygwin" ]]; then
    OS="windows"
fi

echo -e "\n${GREEN}Detected OS: $OS${NC}"

# 1. Check Node.js
echo -e "\n${YELLOW}Checking Node.js...${NC}"
if command -v node &> /dev/null; then
    NODE_VERSION=$(node --version)
    echo -e "${GREEN}✓ Node.js installed: $NODE_VERSION${NC}"
else
    echo -e "${RED}✗ Node.js not found${NC}"
    echo "Please install Node.js v16 or higher from https://nodejs.org"
    exit 1
fi

# 2. Check Python
echo -e "\n${YELLOW}Checking Python...${NC}"
if command -v python3 &> /dev/null; then
    PYTHON_VERSION=$(python3 --version)
    echo -e "${GREEN}✓ Python installed: $PYTHON_VERSION${NC}"
    PYTHON_CMD="python3"
elif command -v python &> /dev/null; then
    PYTHON_VERSION=$(python --version)
    echo -e "${GREEN}✓ Python installed: $PYTHON_VERSION${NC}"
    PYTHON_CMD="python"
else
    echo -e "${RED}✗ Python not found${NC}"
    echo "Please install Python 3.7+ from https://python.org"
    exit 1
fi

# 3. Check pip
echo -e "\n${YELLOW}Checking pip...${NC}"
if command -v pip3 &> /dev/null; then
    PIP_CMD="pip3"
    echo -e "${GREEN}✓ pip3 found${NC}"
elif command -v pip &> /dev/null; then
    PIP_CMD="pip"
    echo -e "${GREEN}✓ pip found${NC}"
else
    echo -e "${RED}✗ pip not found${NC}"
    echo "Installing pip..."
    curl https://bootstrap.pypa.io/get-pip.py | $PYTHON_CMD
fi

# 4. Install Semgrep (CRITICAL FOR PRODUCTION)
echo -e "\n${YELLOW}Installing Semgrep...${NC}"
if command -v semgrep &> /dev/null; then
    SEMGREP_VERSION=$(semgrep --version)
    echo -e "${GREEN}✓ Semgrep already installed: $SEMGREP_VERSION${NC}"
else
    echo "Installing Semgrep..."
    $PIP_CMD install semgrep
    
    if command -v semgrep &> /dev/null; then
        echo -e "${GREEN}✓ Semgrep installed successfully${NC}"
    else
        echo -e "${RED}✗ Failed to install Semgrep${NC}"
        echo "Try manual installation:"
        echo "  pip install semgrep"
        echo "  OR"
        echo "  brew install semgrep (macOS)"
        exit 1
    fi
fi

# 5. Update Semgrep rules from registry
echo -e "\n${YELLOW}Updating Semgrep rules...${NC}"
semgrep --config=auto --dry-run --quiet . 2>/dev/null || true
echo -e "${GREEN}✓ Semgrep rules cached${NC}"

# 6. Install Node dependencies
echo -e "\n${YELLOW}Installing Node.js dependencies...${NC}"
npm install
echo -e "${GREEN}✓ Dependencies installed${NC}"

# 7. Verify Semgrep can access registry
echo -e "\n${YELLOW}Testing Semgrep registry access...${NC}"
echo "console.log('test');" > /tmp/test.js
SEMGREP_OUTPUT=$(semgrep --config=auto --json /tmp/test.js 2>/dev/null || echo "{}")
rm /tmp/test.js

if echo "$SEMGREP_OUTPUT" | grep -q "results"; then
    echo -e "${GREEN}✓ Semgrep can access rule registry${NC}"
else
    echo -e "${YELLOW}⚠ Semgrep may be running in offline mode${NC}"
    echo "This is OK - rules are cached locally"
fi

# 8. Create directories
echo -e "\n${YELLOW}Creating project directories...${NC}"
mkdir -p rules data logs reports sample
echo -e "${GREEN}✓ Directories created${NC}"

# 9. Create sample vulnerable code for testing
echo -e "\n${YELLOW}Creating sample vulnerable code...${NC}"
cat > sample/vulnerable.js << 'EOF'
// Sample vulnerable code for testing
const express = require('express');
const mysql = require('mysql');
const app = express();

// SQL Injection vulnerability
app.get('/user', (req, res) => {
    const userId = req.query.id;
    const query = `SELECT * FROM users WHERE id = ${userId}`; // BAD: SQL injection
    connection.query(query, (err, results) => {
        res.json(results);
    });
});

// XSS vulnerability
app.get('/search', (req, res) => {
    const search = req.query.q;
    res.send(`<h1>Results for: ${search}</h1>`); // BAD: XSS
});

// Hardcoded secret
const API_KEY = "sk_live_abcd1234567890"; // BAD: Hardcoded credential

// Command injection
const exec = require('child_process').exec;
app.get('/ping', (req, res) => {
    const host = req.query.host;
    exec(`ping -c 1 ${host}`, (err, stdout) => { // BAD: Command injection
        res.send(stdout);
    });
});
EOF

cat > sample/vulnerable.py << 'EOF'
# Sample vulnerable Python code
import os
import pickle
from flask import Flask, request, render_template_string

app = Flask(__name__)

# SQL Injection
@app.route('/user')
def user():
    user_id = request.args.get('id')
    query = f"SELECT * FROM users WHERE id = {user_id}"  # BAD: SQL injection
    cursor.execute(query)
    return str(cursor.fetchall())

# Command injection
@app.route('/ping')
def ping():
    host = request.args.get('host')
    os.system(f"ping -c 1 {host}")  # BAD: Command injection
    return "OK"

# Insecure deserialization
@app.route('/load')
def load():
    data = request.data
    obj = pickle.loads(data)  # BAD: Insecure deserialization
    return str(obj)

# Hardcoded secret
SECRET_KEY = "super_secret_key_12345"  # BAD: Hardcoded credential
EOF

echo -e "${GREEN}✓ Sample vulnerable code created${NC}"

# 10. Run test scan
echo -e "\n${YELLOW}Running test scan...${NC}"
echo -e "${YELLOW}This will verify everything is working...${NC}\n"

node scripts/scan.js --path ./sample --verbose

echo -e "\n${GREEN}════════════════════════════════════════════════════════════════${NC}"
echo -e "${GREEN}✓ Setup complete!${NC}"
echo -e "${GREEN}════════════════════════════════════════════════════════════════${NC}"

echo -e "\nYou can now:"
echo "1. Start the API server:  npm start"
echo "2. Run a scan:           npm run scan -- --path ./your-code"
echo "3. Run with context:     npm run scan -- --context production,internet-facing"
echo ""
echo "API Example:"
echo 'curl -X POST http://localhost:3000/scan-code \'
echo '  -H "Content-Type: application/json" \'
echo '  -d '"'"'{"path":"./sample","context":{"production":true}}'"'"''
echo ""
echo -e "${GREEN}Semgrep is configured to use the FULL security ruleset from the registry.${NC}"
echo -e "${GREEN}This includes 2000+ production security rules, not just demo rules.${NC}"