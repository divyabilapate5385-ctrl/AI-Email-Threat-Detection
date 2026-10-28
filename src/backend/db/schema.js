/**
 * Aegis Cyber SOC - Database Schema Definitions
 * Supports persistent SQLite storage with relational integrity.
 */

const SCHEMA_SQL = `
CREATE TABLE IF NOT EXISTS scans (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  scan_uuid TEXT UNIQUE NOT NULL,
  created_at TEXT NOT NULL,
  scan_type TEXT NOT NULL DEFAULT 'email',
  sender TEXT,
  recipient TEXT,
  subject TEXT,
  raw_content TEXT,
  extracted_urls TEXT DEFAULT '[]',
  extracted_ips TEXT DEFAULT '[]',
  overall_score INTEGER NOT NULL DEFAULT 0,
  verdict TEXT NOT NULL DEFAULT 'Safe',
  phishing_score INTEGER DEFAULT 0,
  url_score INTEGER DEFAULT 0,
  spam_score INTEGER DEFAULT 0,
  domain_score INTEGER DEFAULT 0,
  ip_score INTEGER DEFAULT 0,
  ai_risk_score INTEGER DEFAULT 0,
  threat_indicators TEXT DEFAULT '[]',
  forensic_data TEXT DEFAULT '{}',
  explanation TEXT,
  recommendations TEXT DEFAULT '[]'
);

CREATE TABLE IF NOT EXISTS incidents (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  incident_id TEXT UNIQUE NOT NULL,
  scan_id INTEGER,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  title TEXT NOT NULL,
  severity TEXT NOT NULL DEFAULT 'Medium',
  status TEXT NOT NULL DEFAULT 'New',
  category TEXT NOT NULL DEFAULT 'Phishing',
  target_user TEXT,
  source_ip TEXT,
  source_domain TEXT,
  notes TEXT DEFAULT '',
  assigned_analyst TEXT DEFAULT 'SOC Analyst Alpha',
  FOREIGN KEY(scan_id) REFERENCES scans(id) ON DELETE SET NULL
);

CREATE TABLE IF NOT EXISTS blocklist (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  type TEXT NOT NULL,
  value TEXT UNIQUE NOT NULL,
  reason TEXT,
  added_at TEXT NOT NULL,
  added_by TEXT DEFAULT 'SOC Automation',
  enabled INTEGER DEFAULT 1
);

CREATE TABLE IF NOT EXISTS threat_intel (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  ioc_type TEXT NOT NULL,
  ioc_value TEXT UNIQUE NOT NULL,
  threat_type TEXT NOT NULL,
  confidence INTEGER DEFAULT 85,
  threat_actor TEXT DEFAULT 'Unknown',
  campaign TEXT DEFAULT 'Active Feed',
  first_seen TEXT NOT NULL,
  last_seen TEXT NOT NULL,
  tags TEXT DEFAULT '[]'
);

CREATE TABLE IF NOT EXISTS vpn_traffic (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  timestamp TEXT NOT NULL,
  tunnel_id TEXT NOT NULL,
  client_ip TEXT NOT NULL,
  exit_node TEXT NOT NULL,
  destination_ip TEXT NOT NULL,
  destination_domain TEXT,
  protocol TEXT DEFAULT 'HTTPS',
  port INTEGER DEFAULT 443,
  bytes_in INTEGER DEFAULT 0,
  bytes_out INTEGER DEFAULT 0,
  tunnel_status TEXT DEFAULT 'Healthy',
  threat_score INTEGER DEFAULT 0,
  anomaly_flag INTEGER DEFAULT 0,
  notes TEXT DEFAULT ''
);

CREATE TABLE IF NOT EXISTS system_settings (
  key TEXT PRIMARY KEY,
  value TEXT NOT NULL,
  updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS audit_logs (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  timestamp TEXT NOT NULL,
  actor TEXT NOT NULL DEFAULT 'analyst@aegis-soc.local',
  action TEXT NOT NULL,
  details TEXT
);

CREATE INDEX IF NOT EXISTS idx_scans_created_at ON scans(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_scans_verdict ON scans(verdict);
CREATE INDEX IF NOT EXISTS idx_scans_score ON scans(overall_score DESC);
CREATE INDEX IF NOT EXISTS idx_incidents_status ON incidents(status);
CREATE INDEX IF NOT EXISTS idx_incidents_severity ON incidents(severity);
CREATE INDEX IF NOT EXISTS idx_blocklist_value ON blocklist(value);
`;

module.exports = { SCHEMA_SQL };
