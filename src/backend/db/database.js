/**
 * Aegis Cyber SOC - Relational Database Manager
 * Uses Node 24 native SQLite (DatabaseSync) for high-performance persistent storage.
 */

const { DatabaseSync } = require('node:sqlite');
const path = require('node:path');
const fs = require('node:fs');
const crypto = require('node:crypto');
const { SCHEMA_SQL } = require('./schema');
const { SAMPLE_THREATS } = require('../samples/sampleThreats');
const { analyzeThreat } = require('../engine/threatScorer');

const DB_PATH = path.resolve(__dirname, '../../../aegis_soc.db');

let dbInstance = null;

function getDb() {
  if (!dbInstance) {
    dbInstance = new DatabaseSync(DB_PATH);
    dbInstance.exec('PRAGMA journal_mode = WAL;');
    dbInstance.exec('PRAGMA foreign_keys = ON;');
    dbInstance.exec(SCHEMA_SQL);
    seedInitialData(dbInstance);
  }
  return dbInstance;
}

function seedInitialData(db) {
  const scanCount = db.prepare('SELECT COUNT(*) as count FROM scans').get().count;
  if (scanCount > 0) return; // Already seeded

  console.log('[Aegis Database] First run detected. Seeding sample scans, incidents, blocklist, and threat intel...');

  // Seed Blocklist
  const insertBlocklist = db.prepare(`
    INSERT INTO blocklist (type, value, reason, added_at, added_by, enabled)
    VALUES (?, ?, ?, ?, ?, 1)
  `);

  const initialBlocks = [
    { type: 'domain', value: 'micros0ft-login-portal.xyz', reason: 'Confirmed M365 Credential Harvester' },
    { type: 'domain', value: 'consultant-group.top', reason: 'Active CEO Wire Transfer BEC Campaign' },
    { type: 'ip', value: '185.220.101.5', reason: 'Malicious Tor Exit Node (Known Spamhaus DROP)' },
    { type: 'ip', value: '91.240.118.172', reason: 'Bulletproof Phishing C2 Relay' },
    { type: 'domain', value: 'quick-prizes-reward.buzz', reason: 'Advance Fee Sweepstakes Spam' }
  ];

  initialBlocks.forEach(b => {
    insertBlocklist.run(b.type, b.value, b.reason, new Date(Date.now() - 86400000 * 3).toISOString(), 'SOC Automation');
  });

  // Seed Threat Intel
  const insertIntel = db.prepare(`
    INSERT INTO threat_intel (ioc_type, ioc_value, threat_type, confidence, threat_actor, campaign, first_seen, last_seen, tags)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
  `);

  const initialIntel = [
    { type: 'domain', value: 'micros0ft-login-portal.xyz', threat: 'Credential Harvesting', conf: 96, actor: 'Storm-0832', camp: 'M365 Phish Wave 4', tags: JSON.stringify(['homoglyph', 'm365', 'phishing']) },
    { type: 'ip', value: '185.220.101.5', threat: 'Tor Exit Node / Anonymizer', conf: 99, actor: 'Unknown', camp: 'Global Scanning', tags: JSON.stringify(['tor', 'proxy', 'scanner']) },
    { type: 'ip', value: '91.240.118.172', threat: 'C2 Server / Banking Trojan', conf: 92, actor: 'TA505 / Evil Corp', camp: 'Emotet Resurgence', tags: JSON.stringify(['c2', 'botnet', 'malware']) },
    { type: 'domain', value: 'paypaI.com', threat: 'Homoglyph Phish', conf: 94, actor: 'FinPhish Group', camp: 'Financial Credential Harvesting', tags: JSON.stringify(['homoglyph', 'paypal', 'banking']) },
    { type: 'url', value: 'http://45.154.255.89/docs/Invoice_Ref_98293.iso', threat: 'Malware Dropper (ISO)', conf: 98, actor: 'Qakbot Syndicate', camp: 'Invoice Lures Oct 2026', tags: JSON.stringify(['iso', 'trojan', 'dropper']) }
  ];

  initialIntel.forEach(i => {
    insertIntel.run(i.type, i.value, i.threat, i.conf, i.actor, i.camp, '2026-10-15T00:00:00Z', new Date().toISOString(), i.tags);
  });

  // Seed VPN / Traffic Sessions
  const insertVpn = db.prepare(`
    INSERT INTO vpn_traffic (timestamp, tunnel_id, client_ip, exit_node, destination_ip, destination_domain, protocol, port, bytes_in, bytes_out, tunnel_status, threat_score, anomaly_flag, notes)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
  `);

  const vpnSessions = [
    { tunnel: 'tun-sec-01', client: '10.200.4.15', exit: 'us-east-vpn.aegis.corp', destIp: '40.107.240.122', domain: 'outlook.office365.com', proto: 'HTTPS', port: 443, inB: 452900, outB: 124300, status: 'Healthy', threat: 5, anomaly: 0, notes: 'Routine corporate mail sync' },
    { tunnel: 'tun-sec-02', client: '10.200.4.88', exit: 'eu-west-vpn.aegis.corp', destIp: '185.220.101.5', domain: 'micros0ft-login-portal.xyz', proto: 'HTTPS', port: 443, inB: 18200, outB: 5400, status: 'Suspicious', threat: 88, anomaly: 1, notes: 'ALERT: Outbound connection to confirmed phishing lookalike!' },
    { tunnel: 'tun-sec-03', client: '10.200.4.102', exit: 'us-east-vpn.aegis.corp', destIp: '209.85.220.41', domain: 'mail.google.com', proto: 'HTTPS', port: 443, inB: 890120, outB: 341000, status: 'Healthy', threat: 2, anomaly: 0, notes: 'Google Workspace administrative session' },
    { tunnel: 'tun-sec-04', client: '10.200.4.45', exit: 'ap-south-vpn.aegis.corp', destIp: '91.240.118.172', domain: 'direct-c2-stream.ru', proto: 'TCP', port: 8888, inB: 4500, outB: 12040, status: 'Critical', threat: 92, anomaly: 1, notes: 'ALERT: Non-standard port outbound beacon to C2 IP' },
    { tunnel: 'tun-sec-05', client: '10.200.4.12', exit: 'us-west-vpn.aegis.corp', destIp: '142.250.190.46', domain: 'drive.google.com', proto: 'HTTPS', port: 443, inB: 2340000, outB: 140000, status: 'Healthy', threat: 4, anomaly: 0, notes: 'Normal cloud document sync' }
  ];

  vpnSessions.forEach(v => {
    insertVpn.run(new Date(Date.now() - Math.floor(Math.random() * 3600000)).toISOString(), v.tunnel, v.client, v.exit, v.destIp, v.domain, v.proto, v.port, v.inB, v.outB, v.status, v.threat, v.anomaly, v.notes);
  });

  // Seed Sample Scans and Incidents
  for (const sample of SAMPLE_THREATS) {
    const analysis = analyzeThreat(sample.data);
    const scanUuid = `scan-${crypto.randomUUID().slice(0, 8)}`;
    const createdAt = new Date(Date.now() - Math.floor(Math.random() * 86400000 * 2)).toISOString();

    const insertScan = db.prepare(`
      INSERT INTO scans (
        scan_uuid, created_at, scan_type, sender, recipient, subject, raw_content,
        extracted_urls, extracted_ips, overall_score, verdict,
        phishing_score, url_score, spam_score, domain_score, ip_score, ai_risk_score,
        threat_indicators, forensic_data, explanation, recommendations
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `);

    const result = insertScan.run(
      scanUuid,
      createdAt,
      'email',
      sample.data.sender,
      sample.data.recipient,
      sample.data.subject,
      sample.data.body,
      JSON.stringify(analysis.parsedEmail.urls || []),
      JSON.stringify(analysis.parsedEmail.ips || []),
      analysis.overallScore,
      analysis.verdict,
      analysis.modules.phishing.score,
      analysis.modules.url.score,
      analysis.modules.spam.score,
      analysis.modules.domain.score,
      analysis.modules.ip.score,
      analysis.modules.ai.score,
      JSON.stringify(analysis.threatIndicators || []),
      JSON.stringify(analysis.forensicData || {}),
      analysis.explanation,
      JSON.stringify(analysis.recommendations || [])
    );

    const scanId = Number(result.lastInsertRowid);

    // If Malicious or Suspicious, create an incident
    if (analysis.verdict === 'Malicious' || analysis.verdict === 'Suspicious') {
      const incId = `INC-${1000 + scanId}`;
      const severity = analysis.overallScore >= 80 ? 'Critical' : analysis.overallScore >= 60 ? 'High' : 'Medium';
      const status = analysis.overallScore >= 80 ? 'New' : 'Investigating';

      const insertInc = db.prepare(`
        INSERT INTO incidents (
          incident_id, scan_id, created_at, updated_at, title, severity, status,
          category, target_user, source_ip, source_domain, notes, assigned_analyst
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
      `);

      insertInc.run(
        incId,
        scanId,
        createdAt,
        createdAt,
        `Threat Alert: ${sample.name}`,
        severity,
        status,
        sample.category,
        sample.data.recipient,
        sample.data.ip || 'Unknown IP',
        analysis.parsedEmail.from.domain || 'Unknown Domain',
        `Automated triage created from scan ${scanUuid}. Risk score: ${analysis.overallScore}/100. Target recipient: ${sample.data.recipient}.`,
        'SOC Analyst Alpha'
      );
    }
  }

  // System Settings Defaults
  const insertSetting = db.prepare(`
    INSERT OR REPLACE INTO system_settings (key, value, updated_at)
    VALUES (?, ?, ?)
  `);

  insertSetting.run('soc_name', 'Aegis Cyber SOC Enterprise', new Date().toISOString());
  insertSetting.run('threat_threshold_malicious', '70', new Date().toISOString());
  insertSetting.run('threat_threshold_suspicious', '40', new Date().toISOString());
  insertSetting.run('auto_quarantine_enabled', 'true', new Date().toISOString());
  insertSetting.run('imap_sync_status', 'Connected (Stream Live)', new Date().toISOString());
  insertSetting.run('imap_host', 'imap.sec-enterprise.com:993', new Date().toISOString());

  console.log('[Aegis Database] Database seeded successfully.');
}

// Scans Repository
const ScansRepo = {
  create(data) {
    const db = getDb();
    const scanUuid = data.scanUuid || `scan-${crypto.randomUUID().slice(0, 8)}`;
    const createdAt = data.createdAt || new Date().toISOString();

    const stmt = db.prepare(`
      INSERT INTO scans (
        scan_uuid, created_at, scan_type, sender, recipient, subject, raw_content,
        extracted_urls, extracted_ips, overall_score, verdict,
        phishing_score, url_score, spam_score, domain_score, ip_score, ai_risk_score,
        threat_indicators, forensic_data, explanation, recommendations
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `);

    const result = stmt.run(
      scanUuid,
      createdAt,
      data.scanType || 'email',
      data.sender || '',
      data.recipient || '',
      data.subject || '',
      data.rawContent || '',
      JSON.stringify(data.extractedUrls || []),
      JSON.stringify(data.extractedIps || []),
      data.overallScore || 0,
      data.verdict || 'Safe',
      data.phishingScore || 0,
      data.urlScore || 0,
      data.spamScore || 0,
      data.domainScore || 0,
      data.ipScore || 0,
      data.aiRiskScore || 0,
      JSON.stringify(data.threatIndicators || []),
      JSON.stringify(data.forensicData || {}),
      data.explanation || '',
      JSON.stringify(data.recommendations || [])
    );

    return {
      id: Number(result.lastInsertRowid),
      scanUuid,
      ...data
    };
  },

  getById(id) {
    const db = getDb();
    let row;
    if (typeof id === 'number' || !isNaN(Number(id))) {
      row = db.prepare('SELECT * FROM scans WHERE id = ?').get(Number(id));
    } else {
      row = db.prepare('SELECT * FROM scans WHERE scan_uuid = ?').get(id);
    }
    if (!row) return null;

    return {
      ...row,
      extracted_urls: JSON.parse(row.extracted_urls || '[]'),
      extracted_ips: JSON.parse(row.extracted_ips || '[]'),
      threat_indicators: JSON.parse(row.threat_indicators || '[]'),
      forensic_data: JSON.parse(row.forensic_data || '{}'),
      recommendations: JSON.parse(row.recommendations || '[]')
    };
  },

  getAll(filters = {}) {
    const db = getDb();
    let query = 'SELECT * FROM scans WHERE 1=1';
    const params = [];

    if (filters.verdict) {
      query += ' AND verdict = ?';
      params.push(filters.verdict);
    }
    if (filters.search) {
      query += ' AND (subject LIKE ? OR sender LIKE ? OR recipient LIKE ? OR scan_uuid LIKE ?)';
      const s = `%${filters.search}%`;
      params.push(s, s, s, s);
    }

    query += ' ORDER BY id DESC LIMIT ? OFFSET ?';
    params.push(filters.limit || 50, filters.offset || 0);

    const rows = db.prepare(query).all(...params);
    return rows.map(r => ({
      ...r,
      extracted_urls: JSON.parse(r.extracted_urls || '[]'),
      extracted_ips: JSON.parse(r.extracted_ips || '[]'),
      threat_indicators: JSON.parse(r.threat_indicators || '[]'),
      forensic_data: JSON.parse(r.forensic_data || '{}'),
      recommendations: JSON.parse(r.recommendations || '[]')
    }));
  },

  getStats() {
    const db = getDb();
    const total = db.prepare('SELECT COUNT(*) as count FROM scans').get().count;
    const safe = db.prepare("SELECT COUNT(*) as count FROM scans WHERE verdict = 'Safe'").get().count;
    const suspicious = db.prepare("SELECT COUNT(*) as count FROM scans WHERE verdict = 'Suspicious'").get().count;
    const malicious = db.prepare("SELECT COUNT(*) as count FROM scans WHERE verdict = 'Malicious'").get().count;
    const avgScore = db.prepare('SELECT AVG(overall_score) as avg FROM scans').get().avg || 0;

    const recentTrends = db.prepare(`
      SELECT strftime('%Y-%m-%d', created_at) as day,
             COUNT(*) as count,
             SUM(CASE WHEN verdict = 'Malicious' THEN 1 ELSE 0 END) as malicious_count,
             SUM(CASE WHEN verdict = 'Suspicious' THEN 1 ELSE 0 END) as suspicious_count,
             SUM(CASE WHEN verdict = 'Safe' THEN 1 ELSE 0 END) as safe_count
      FROM scans
      GROUP BY day
      ORDER BY day DESC
      LIMIT 7
    `).all();

    return {
      total,
      safe,
      suspicious,
      malicious,
      avgScore: Math.round(avgScore),
      recentTrends
    };
  }
};

// Incidents Repository
const IncidentsRepo = {
  create(data) {
    const db = getDb();
    const count = db.prepare('SELECT COUNT(*) as count FROM incidents').get().count;
    const incidentId = data.incidentId || `INC-${1000 + count + 1}`;
    const now = new Date().toISOString();

    const stmt = db.prepare(`
      INSERT INTO incidents (
        incident_id, scan_id, created_at, updated_at, title, severity, status,
        category, target_user, source_ip, source_domain, notes, assigned_analyst
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `);

    const result = stmt.run(
      incidentId,
      data.scanId || null,
      now,
      now,
      data.title || 'Suspicious Threat Incident',
      data.severity || 'Medium',
      data.status || 'New',
      data.category || 'Phishing',
      data.targetUser || '',
      data.sourceIp || '',
      data.sourceDomain || '',
      data.notes || '',
      data.assignedAnalyst || 'SOC Analyst Alpha'
    );

    return {
      id: Number(result.lastInsertRowid),
      incidentId,
      ...data,
      created_at: now,
      updated_at: now
    };
  },

  getAll(filters = {}) {
    const db = getDb();
    let query = 'SELECT * FROM incidents WHERE 1=1';
    const params = [];

    if (filters.status) {
      query += ' AND status = ?';
      params.push(filters.status);
    }
    if (filters.severity) {
      query += ' AND severity = ?';
      params.push(filters.severity);
    }
    if (filters.search) {
      query += ' AND (title LIKE ? OR incident_id LIKE ? OR target_user LIKE ? OR source_domain LIKE ?)';
      const s = `%${filters.search}%`;
      params.push(s, s, s, s);
    }

    query += ' ORDER BY id DESC LIMIT ? OFFSET ?';
    params.push(filters.limit || 50, filters.offset || 0);

    return db.prepare(query).all(...params);
  },

  getById(id) {
    const db = getDb();
    if (typeof id === 'number' || !isNaN(Number(id))) {
      return db.prepare('SELECT * FROM incidents WHERE id = ?').get(Number(id));
    }
    return db.prepare('SELECT * FROM incidents WHERE incident_id = ?').get(id);
  },

  updateStatus(id, status, notes = null) {
    const db = getDb();
    const now = new Date().toISOString();
    if (notes !== null) {
      db.prepare('UPDATE incidents SET status = ?, notes = ?, updated_at = ? WHERE id = ? OR incident_id = ?')
        .run(status, notes, now, id, id);
    } else {
      db.prepare('UPDATE incidents SET status = ?, updated_at = ? WHERE id = ? OR incident_id = ?')
        .run(status, now, id, id);
    }
    return this.getById(id);
  },

  updateNotes(id, notes) {
    const db = getDb();
    const now = new Date().toISOString();
    db.prepare('UPDATE incidents SET notes = ?, updated_at = ? WHERE id = ? OR incident_id = ?')
      .run(notes, now, id, id);
    return this.getById(id);
  }
};

// Blocklist Repository
const BlocklistRepo = {
  getAll() {
    const db = getDb();
    return db.prepare('SELECT * FROM blocklist ORDER BY id DESC').all();
  },

  add(type, value, reason = '', addedBy = 'SOC Analyst') {
    const db = getDb();
    const now = new Date().toISOString();
    const cleanVal = (value || '').trim().toLowerCase();
    const stmt = db.prepare(`
      INSERT INTO blocklist (type, value, reason, added_at, added_by, enabled)
      VALUES (?, ?, ?, ?, ?, 1)
      ON CONFLICT(value) DO UPDATE SET reason = excluded.reason, enabled = 1
    `);
    const res = stmt.run(type, cleanVal, reason, now, addedBy);
    return { id: Number(res.lastInsertRowid), type, value: cleanVal, reason, added_at: now, enabled: 1 };
  },

  remove(id) {
    const db = getDb();
    db.prepare('DELETE FROM blocklist WHERE id = ? OR value = ?').run(id, id);
    return { success: true };
  },

  toggle(id) {
    const db = getDb();
    db.prepare('UPDATE blocklist SET enabled = CASE WHEN enabled = 1 THEN 0 ELSE 1 END WHERE id = ?').run(id);
    return db.prepare('SELECT * FROM blocklist WHERE id = ?').get(id);
  },

  isBlocked(value) {
    if (!value) return false;
    const db = getDb();
    const cleanVal = value.trim().toLowerCase();
    const row = db.prepare('SELECT id FROM blocklist WHERE value = ? AND enabled = 1').get(cleanVal);
    return !!row;
  }
};

// Threat Intel Repository
const ThreatIntelRepo = {
  getAll(limit = 100) {
    const db = getDb();
    const rows = db.prepare('SELECT * FROM threat_intel ORDER BY id DESC LIMIT ?').all(limit);
    return rows.map(r => ({ ...r, tags: JSON.parse(r.tags || '[]') }));
  },

  lookup(iocValue) {
    const db = getDb();
    const cleanVal = (iocValue || '').trim().toLowerCase();
    const row = db.prepare('SELECT * FROM threat_intel WHERE LOWER(ioc_value) = ?').get(cleanVal);
    if (!row) return null;
    return { ...row, tags: JSON.parse(row.tags || '[]') };
  }
};

// VPN Traffic Repository
const VpnRepo = {
  getAll(limit = 50) {
    const db = getDb();
    return db.prepare('SELECT * FROM vpn_traffic ORDER BY id DESC LIMIT ?').all(limit);
  },

  addEvent(event) {
    const db = getDb();
    const now = new Date().toISOString();
    const stmt = db.prepare(`
      INSERT INTO vpn_traffic (timestamp, tunnel_id, client_ip, exit_node, destination_ip, destination_domain, protocol, port, bytes_in, bytes_out, tunnel_status, threat_score, anomaly_flag, notes)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `);
    const res = stmt.run(
      now,
      event.tunnelId || 'tun-sec-auto',
      event.clientIp || '10.200.4.50',
      event.exitNode || 'us-east-vpn.aegis.corp',
      event.destinationIp || '0.0.0.0',
      event.destinationDomain || '',
      event.protocol || 'HTTPS',
      event.port || 443,
      event.bytesIn || 12000,
      event.bytesOut || 4500,
      event.tunnelStatus || 'Healthy',
      event.threatScore || 0,
      event.anomalyFlag || 0,
      event.notes || ''
    );
    return { id: Number(res.lastInsertRowid), ...event, timestamp: now };
  },

  getStats() {
    const db = getDb();
    const totalTunnels = db.prepare('SELECT COUNT(DISTINCT tunnel_id) as count FROM vpn_traffic').get().count;
    const activeEvents = db.prepare('SELECT COUNT(*) as count FROM vpn_traffic').get().count;
    const anomalies = db.prepare('SELECT COUNT(*) as count FROM vpn_traffic WHERE anomaly_flag = 1').get().count;
    const totalBytesIn = db.prepare('SELECT SUM(bytes_in) as sum FROM vpn_traffic').get().sum || 0;
    const totalBytesOut = db.prepare('SELECT SUM(bytes_out) as sum FROM vpn_traffic').get().sum || 0;

    return {
      totalTunnels: totalTunnels || 5,
      activeEvents,
      anomalies,
      totalBandwidthMb: Number(((totalBytesIn + totalBytesOut) / (1024 * 1024)).toFixed(2))
    };
  }
};

// System Settings Repository
const SettingsRepo = {
  getAll() {
    const db = getDb();
    const rows = db.prepare('SELECT * FROM system_settings').all();
    const settings = {};
    rows.forEach(r => { settings[r.key] = r.value; });
    return settings;
  },

  set(key, value) {
    const db = getDb();
    const now = new Date().toISOString();
    db.prepare('INSERT OR REPLACE INTO system_settings (key, value, updated_at) VALUES (?, ?, ?)')
      .run(key, String(value), now);
    return { key, value, updated_at: now };
  }
};

module.exports = {
  getDb,
  ScansRepo,
  IncidentsRepo,
  BlocklistRepo,
  ThreatIntelRepo,
  VpnRepo,
  SettingsRepo
};
