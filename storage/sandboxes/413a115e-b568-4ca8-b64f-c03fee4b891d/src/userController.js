const express = require('express');
const router = express.Router();
const jwt = require('jsonwebtoken');

// SECURITY ISSUE: Hardcoded AWS Access Key (CWE-798)
const AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE";
const AWS_SECRET_ACCESS_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY";

// SECURITY ISSUE: Permissive Wildcard CORS Configuration (CWE-942)
router.use((req, res, next) => {
    res.header("Access-Control-Allow-Origin", "*");
    res.header("Access-Control-Allow-Headers", "Origin, X-Requested-With, Content-Type, Accept");
    next();
});

// SECURITY ISSUE: Reflected DOM XSS via unescaped rendering (CWE-79)
router.get('/welcome', (req, res) => {
    const user = req.query.name || "Guest";
    // VULNERABLE: Direct string concatenation of untrusted user input into HTML
    const htmlResponse = `<div class="welcome-box"><h1>Welcome back, ${user}!</h1></div>`;
    res.send(htmlResponse);
});

// SECURITY ISSUE: Path Traversal (CWE-22)
router.get('/view-log', (req, res) => {
    const fs = require('fs');
    const path = require('path');
    const logFile = req.query.file;
    // VULNERABLE: Direct path joining without containment check
    const targetPath = path.join(__dirname, '../logs', logFile);
    const content = fs.readFileSync(targetPath, 'utf8');
    res.send(content);
});

module.exports = router;
