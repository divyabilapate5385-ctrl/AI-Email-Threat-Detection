# Aegis Cyber SOC
### AI-Powered Email Threat Detection, GeoLocation and Forensic Intelligence Platform

**Aegis Cyber SOC** is an enterprise-grade cybersecurity operations platform designed to analyze suspicious emails, embedded URLs, sender domains, and originating IP addresses in real time. It calculates an **explainable 0–100 threat risk score**, maps findings to the **MITRE ATT&CK framework**, renders **interactive geolocation radar visualizations**, and facilitates incident response workflows for phishing, spam, trojan droppers, and Business Email Compromise (BEC).

---

## 🛡️ Key Features & Capabilities

### 1. Six-Module Explainable Threat Detection Engine
The scoring engine generates a transparent **0–100 risk score** with granular evidence:
1. **Phishing Detection (25% Weight)**: Evaluates manufactured urgency, credential harvesting lures, document signing impersonations, and executive isolation tactics.
2. **Malicious URL Analysis (25% Weight)**: Inspects direct payload download extensions (`.iso`, `.exe`, `.scr`), raw IP addresses in hostnames, URL shorteners, credential parameters, non-standard ports, and entropy.
3. **Spam & Bulk Lures (15% Weight)**: Detects advance-fee / 419 lottery patterns, excessive uppercase character ratios, manipulative punctuation, and RFC 5322 header violations.
4. **Domain Reputation (20% Weight)**: Performs real-time **Levenshtein edit distance**, **homoglyph/visual substitution** (e.g. `paypaI.com` vs `paypal.com`), combo-squatting detection, disposable domain matching, domain age calculation (<60 days flagged as newly registered), and MX routability checks.
5. **IP Reputation & Geolocation (15% Weight)**: Maps originating and relay IP addresses to ASN, ISP, country, city, and coordinates. Detects **Tor exit relays**, anonymous VPN tunnels, and known botnet C2 nodes.
6. **AI Risk Synthesis & Correlation**: Identifies cross-vector synergy (e.g., lookalike domain + credential lure + Tor exit node = critical correlation) and generates human-readable natural language synthesis, remediation guidance, and MITRE ATT&CK technique mappings (`T1566.002`, `T1586.002`, `T1056.003`, `T1090.003`).

### 2. Forensic Investigation & Geolocation Radar
- **Hop-by-Hop MTA Tracer**: Reconstructs the complete email transit route from the originating client to the final MX recipient gateway.
- **Interactive World Geolocation Visualizer**: Plots originating IP coordinates on an SVG radar map with an animated pulse ring.
- **Cryptographic Authentication Matrix**: Real-time evaluation of SPF, DKIM, and DMARC alignment status.
- **WHOIS & DNS Intelligence**: Displays registrar, creation date, domain age in days, MX records, and DMARC enforcement policies (`reject`, `quarantine`, `none`).

### 3. Incident Response & Threat Containment
- **SOC Triage Kanban & Table**: Categorized by severity (`Critical`, `High`, `Medium`, `Low`) and status (`New`, `Investigating`, `Mitigated`, `False Positive`).
- **Analyst Triage Modal**: Edit investigation notes, update case status, and assign analysts.
- **1-Click Perimeter Blocklist**: Immediately blocks malicious sender domains or originating IPs from the UI.
- **Forensic Dossier Export**: Print or export complete forensic evidence summaries to JSON or printable dossier format.

### 4. VPN & Network Traffic Monitor
- Real-time monitoring of encrypted tunnel egress, bandwidth metrics, active endpoints, and protocol breakdown.
- Network anomaly detection for outbound beacons to phishing lookalikes or suspicious ports.
- **Synthetic Network Probe Simulator**: Test SOC network anomaly detection in real time.

---

## 🎨 Design System & Palette (Slate Blue & Steel Gray)

Designed for 24/7 Security Operations Center monitoring with readable high-contrast typography and subtle borders:
- **Main Background**: `#202B3C`
- **Sidebar**: `#26364A`
- **Cards & Panels**: `#304156`
- **Elevated Surfaces**: `#374B63`
- **Primary Blue**: `#5B9BEB`
- **Cyan Accent**: `#58D5D0`
- **Text Main**: `#E7EDF5`
- **Text Secondary**: `#AAB8CA`
- **Safe State**: `#4CC38A`
- **Suspicious State**: `#F0B75E`
- **Malicious State**: `#F07878`
- **Borders**: `#43556B`

---

## 🏗️ Architecture & Technology Stack

```
AI Powered Email Thread Detection_PROJECT/
├── src/
│   ├── backend/
│   │   ├── server.js               # Production HTTP/REST API with rate limiting & security headers
│   │   ├── db/
│   │   │   ├── schema.js           # Relational SQLite tables & indices
│   │   │   └── database.js         # Node 24 native SQLite (DatabaseSync) manager & seed data
│   │   ├── engine/
│   │   │   ├── threatScorer.js     # 6-Module explainable threat scoring engine
│   │   │   ├── lookalikeDetector.js# Levenshtein distance, homoglyph & combo-squatting detector
│   │   │   ├── urlAnalyzer.js      # URL forensics, shortener & payload inspection
│   │   │   ├── emailParser.js      # EML / RFC 822 MIME parser & SPF/DKIM/DMARC validator
│   │   │   └── geoIpLookup.js      # Forensic GeoIP, ASN, Tor/VPN & WHOIS intelligence
│   │   └── samples/
│   │       └── sampleThreats.js    # Preloaded attack scenarios (M365 Phish, BEC, Trojan, PayPal)
│   └── frontend/
│       └── public/
│           ├── index.html          # Responsive single-page SOC dashboard layout
│           ├── style.css           # Slate Blue & Steel Gray CSS design system
│           └── app.js              # Client state, SVG charts, radar visualizer & REST client
├── tests/
│   ├── testEngine.js               # Comprehensive unit & integration test suite (32 tests)
│   └── testServer.js               # Server endpoint verification
├── aegis_soc.db                    # Persistent relational SQLite database
├── package.json                    # Project configuration
├── run_server.bat                  # Windows batch launcher
├── run_server.ps1                  # PowerShell launcher
└── README.md                       # Complete documentation
```

---

## 🚀 Quick Start Instructions

### Running the Application

To start the Aegis Cyber SOC web server and REST API:

```powershell
# Using the PowerShell launcher
.\run_server.ps1

# Or using the Windows batch file
run_server.bat

# Or directly with agy-node
agy-node src/backend/server.js
```

Then open your web browser at:
👉 **`http://localhost:3000`**

### Running the Automated Test Suite

To verify the threat detection engine, lookalike algorithms, and database persistence:

```powershell
agy-node tests/testEngine.js
```

All 32 test cases will execute:
- Homoglyph detection (`micros0ft.com`, `paypaI.com`)
- Combo-squatting detection (`chase-security-verify.top`)
- URL forensics & payload identification (`.exe`, `.iso`, IP hosts)
- RFC header analysis (SPF, DKIM, DMARC, Display Name spoofing)
- 6-module threat scoring across all attack benchmarks
- Database CRUD and perimeter blocklist enforcement

---

## 📡 REST API Reference

| Method | Endpoint | Description |
|---|---|---|
| `GET` | `/api/stats` | Overview dashboard metrics, scan breakdown, active incidents |
| `GET` | `/api/samples` | Preloaded attack scenarios for 1-click testing |
| `POST` | `/api/scan` | Analyze email content/EML/URL and persist results |
| `GET` | `/api/scans` | Query scan history with filtering (`?verdict=&search=&limit=`) |
| `GET` | `/api/scans/:id` | Fetch full forensic audit dossier for a scan |
| `GET` | `/api/incidents` | Query incident response queue (`?status=&severity=`) |
| `PATCH` | `/api/incidents/:id` | Update incident status and triage notes |
| `GET` | `/api/intel/lookup` | Query domain, IP, or hash intelligence (`?query=`) |
| `GET` | `/api/intel/feed` | Active global IOC threat stream |
| `GET` | `/api/blocklist` | Retrieve perimeter domain and IP blocklist |
| `POST` | `/api/blocklist` | Add an entry to the perimeter blocklist |
| `DELETE` | `/api/blocklist/:id` | Remove an entry from the blocklist |
| `POST` | `/api/blocklist/toggle/:id` | Enable or disable a blocklist rule |
| `GET` | `/api/vpn/traffic` | Encrypted tunnel session logs and bandwidth stats |
| `POST` | `/api/vpn/simulate` | Inject a synthetic network anomaly probe |
| `GET` | `/api/settings` | Retrieve SOC thresholds and connector configuration |
| `POST` | `/api/settings` | Update SOC thresholds and settings |

---

## 🔒 Security & Hardening Features

- **Built-in Rate Limiting**: 200 requests per 60 seconds per IP with sliding window buckets.
- **Hardened HTTP Headers**: Automatic enforcement of `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, `X-XSS-Protection: 1; mode=block`, and `Referrer-Policy: strict-origin-when-cross-origin`.
- **SQL Injection Immune**: 100% prepared parameterized SQL queries using `DatabaseSync.prepare()`.
- **Safe Handling of Untrusted Inputs**: All client rendered outputs are HTML escaped to prevent Stored XSS.
- **Relational Integrity**: Foreign key constraints and transaction logging enabled via SQLite WAL mode.
