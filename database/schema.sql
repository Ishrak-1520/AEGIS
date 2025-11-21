-- CyberGuard Pro Database Schema
-- SQLite Database for local data storage

-- Users table for authentication
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    salt TEXT NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    last_login TIMESTAMP
);

-- Scan history table
CREATE TABLE IF NOT EXISTS scan_history (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_type TEXT NOT NULL,
    scan_path TEXT NOT NULL,
    threats_found INTEGER DEFAULT 0,
    files_scanned INTEGER DEFAULT 0,
    scan_duration REAL,
    scan_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    results TEXT
);

-- Password storage table (encrypted)
CREATE TABLE IF NOT EXISTS stored_passwords (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    website TEXT NOT NULL,
    username TEXT NOT NULL,
    encrypted_password TEXT NOT NULL,
    category TEXT,
    notes TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Threat logs table
CREATE TABLE IF NOT EXISTS threat_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    threat_type TEXT NOT NULL,
    threat_level TEXT NOT NULL,
    source TEXT,
    details TEXT,
    action_taken TEXT,
    confidence_score REAL,
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Quarantine table
CREATE TABLE IF NOT EXISTS quarantine (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    original_path TEXT NOT NULL,
    quarantine_path TEXT NOT NULL,
    file_hash TEXT NOT NULL,
    threat_type TEXT,
    quarantined_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    restored BOOLEAN DEFAULT 0,
    deleted BOOLEAN DEFAULT 0
);

-- System events log
CREATE TABLE IF NOT EXISTS system_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    event_type TEXT NOT NULL,
    severity TEXT NOT NULL,
    message TEXT NOT NULL,
    details TEXT,
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Malware signatures cache
CREATE TABLE IF NOT EXISTS malware_signatures (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    signature_hash TEXT UNIQUE NOT NULL,
    signature_name TEXT NOT NULL,
    threat_level TEXT NOT NULL,
    description TEXT,
    added_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Network connections log
CREATE TABLE IF NOT EXISTS network_connections (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    local_address TEXT,
    remote_address TEXT,
    remote_port INTEGER,
    protocol TEXT,
    status TEXT,
    process_name TEXT,
    is_suspicious BOOLEAN DEFAULT 0,
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Security reports metadata
CREATE TABLE IF NOT EXISTS security_reports (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    report_type TEXT NOT NULL,
    file_path TEXT,
    summary TEXT,
    generated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Application settings
CREATE TABLE IF NOT EXISTS settings (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Indexes for performance
CREATE INDEX IF NOT EXISTS idx_threat_logs_timestamp ON threat_logs(timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_scan_history_timestamp ON scan_history(scan_time DESC);
CREATE INDEX IF NOT EXISTS idx_system_events_timestamp ON system_events(timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_quarantine_restored ON quarantine(restored, deleted);
CREATE INDEX IF NOT EXISTS idx_network_connections_timestamp ON network_connections(timestamp DESC);
