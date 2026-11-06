/**
 * Aegis Cyber SOC - Production REST API & Web Application Server
 * Built with native Node.js HTTP, secure routing, rate limiting, and persistent storage.
 */

const http = require('node:http');
const url = require('node:url');
const path = require('node:path');
const fs = require('node:fs');
const crypto = require('node:crypto');

const { ScansRepo, IncidentsRepo, BlocklistRepo, ThreatIntelRepo, VpnRepo, SettingsRepo } = require('./db/database');
const { analyzeThreat } = require('./engine/threatScorer');
const { checkLookalike } = require('./engine/lookalikeDetector');
const { resolveIpIntelligence, resolveDomainIntelligence, resolveSenderLocation } = require('./engine/geoIpLookup');
const { SAMPLE_THREATS } = require('./samples/sampleThreats');

const PORT = process.env.PORT || 3000;
const PUBLIC_DIR = fs.existsSync(path.resolve(__dirname, '../../../public'))
  ? path.resolve(__dirname, '../../../public')
  : path.resolve(__dirname, '../frontend/public');

// In-Memory Rate Limiting: 200 requests per 60 seconds per IP
const RATE_LIMIT_WINDOW_MS = 60000;
const RATE_LIMIT_MAX = 200;
const rateLimitBuckets = new Map();

function isRateLimited(clientIp) {
  const now = Date.now();
  let bucket = rateLimitBuckets.get(clientIp);
  if (!bucket || now - bucket.startTime > RATE_LIMIT_WINDOW_MS) {
    bucket = { startTime: now, count: 1 };
    rateLimitBuckets.set(clientIp, bucket);
    return false;
  }
  bucket.count++;
  return bucket.count > RATE_LIMIT_MAX;
}

// Helpers for JSON responses & static file serving
function sendJson(res, statusCode, data, headers = {}) {
  const payload = JSON.stringify(data);
  res.writeHead(statusCode, {
    'Content-Type': 'application/json; charset=utf-8',
    'Content-Length': Buffer.byteLength(payload),
    'Access-Control-Allow-Origin': '*',
    'Access-Control-Allow-Methods': 'GET, POST, PATCH, PUT, DELETE, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type, Authorization, X-Requested-With',
    'X-Content-Type-Options': 'nosniff',
    'X-Frame-Options': 'DENY',
    'X-XSS-Protection': '1; mode=block',
    'Referrer-Policy': 'strict-origin-when-cross-origin',
    ...headers
  });
  res.end(payload);
}

function parseBody(req) {
  if (req.body !== undefined && req.body !== null) {
    if (typeof req.body === 'object') {
      return Promise.resolve(req.body);
    }
    if (typeof req.body === 'string') {
      try {
        return Promise.resolve(JSON.parse(req.body));
      } catch (err) {
        return Promise.resolve({ rawText: req.body });
      }
    }
  }

  return new Promise((resolve, reject) => {
    let body = '';
    req.on('data', chunk => {
      body += chunk.toString();
      if (body.length > 10 * 1024 * 1024) { // 10MB limit
        reject(new Error('Request body exceeds maximum allowed size (10MB)'));
      }
    });
    req.on('end', () => {
      if (!body) return resolve({});
      try {
        resolve(JSON.parse(body));
      } catch (err) {
        resolve({ rawText: body });
      }
    });
    req.on('error', reject);
  });
}

function getMimeType(filePath) {
  const ext = path.extname(filePath).toLowerCase();
  switch (ext) {
    case '.html': return 'text/html; charset=utf-8';
    case '.css': return 'text/css; charset=utf-8';
    case '.js': return 'application/javascript; charset=utf-8';
    case '.json': return 'application/json; charset=utf-8';
    case '.png': return 'image/png';
    case '.jpg':
    case '.jpeg': return 'image/jpeg';
    case '.svg': return 'image/svg+xml';
    case '.ico': return 'image/x-icon';
    case '.woff2': return 'font/woff2';
    default: return 'application/octet-stream';
  }
}

function serveStatic(req, res, pathname) {
  let relativePath = pathname === '/' ? 'index.html' : pathname.replace(/^\/+/, '');
  let filePath = path.join(PUBLIC_DIR, relativePath);

  // Security: prevent directory traversal
  if (!filePath.startsWith(PUBLIC_DIR)) {
    sendJson(res, 403, { error: 'Forbidden' });
    return;
  }

  fs.stat(filePath, (err, stats) => {
    if (err || !stats.isFile()) {
      // Fallback to index.html for SPA client-side routing
      const indexPath = path.join(PUBLIC_DIR, 'index.html');
      fs.readFile(indexPath, (err2, indexContent) => {
        if (err2) {
          sendJson(res, 404, { error: 'Not Found' });
          return;
        }
        res.writeHead(200, {
          'Content-Type': 'text/html; charset=utf-8',
          'Content-Length': Buffer.byteLength(indexContent)
        });
        res.end(indexContent);
      });
      return;
    }

    const mime = getMimeType(filePath);
    res.writeHead(200, {
      'Content-Type': mime,
      'Content-Length': stats.size,
      'Cache-Control': 'no-cache'
    });
    fs.createReadStream(filePath).pipe(res);
  });
}

async function handleRequest(req, res) {
  const parsedUrl = url.parse(req.url, true);
  let { pathname, query } = parsedUrl;
  const method = req.method ? req.method.toUpperCase() : 'GET';
  const clientIp = (req.headers && req.headers['x-forwarded-for'])
    ? req.headers['x-forwarded-for'].split(',')[0].trim()
    : (req.socket ? req.socket.remoteAddress : '127.0.0.1');

  // Support Vercel catch-all rewrites or path query
  if (pathname === '/api/index.js' || pathname === '/api' || pathname === '/api/') {
    if (query && query.path) {
      const sub = Array.isArray(query.path) ? query.path.join('/') : query.path;
      pathname = '/api/' + sub;
    } else if (req.headers && req.headers['x-matched-path']) {
      pathname = req.headers['x-matched-path'];
    }
  }

  // Rate Limiting Check
  if (isRateLimited(clientIp)) {
    return sendJson(res, 429, { error: 'Rate limit exceeded. Please wait 60 seconds.' });
  }

  // CORS Preflight
  if (method === 'OPTIONS') {
    res.writeHead(204, {
      'Access-Control-Allow-Origin': '*',
      'Access-Control-Allow-Methods': 'GET, POST, PATCH, PUT, DELETE, OPTIONS',
      'Access-Control-Allow-Headers': 'Content-Type, Authorization, X-Requested-With',
      'Access-Control-Max-Age': '86400'
    });
    return res.end();
  }

  try {
    // REST API ROUTES
    if (pathname.startsWith('/api/')) {
      // 1. STATS: Overview dashboard metrics
      if (pathname === '/api/stats' && method === 'GET') {
        const stats = ScansRepo.getStats();
        const vpnStats = VpnRepo.getStats();
        const activeIncidents = IncidentsRepo.getAll({ status: 'New' }).length;
        return sendJson(res, 200, {
          success: true,
          stats: {
            ...stats,
            activeIncidents,
            vpnStats
          }
        });
      }

      // 2. SAMPLES: Preloaded cyber threat scenarios
      if (pathname === '/api/samples' && method === 'GET') {
        return sendJson(res, 200, { success: true, samples: SAMPLE_THREATS });
      }

      // 3. SCAN: Perform deep analysis
      if (pathname === '/api/scan' && method === 'POST') {
        const body = await parseBody(req);
        if (!body.content && !body.body && !body.rawEml && !body.url && !body.sender) {
          return sendJson(res, 400, { error: 'Missing required scan input (content, body, rawEml, or url)' });
        }

        // Run 6-module analysis
        const analysis = analyzeThreat(body);

        // Check local blocklist against sender and URLs
        const senderDomain = analysis.parsedEmail.from.domain;
        const senderAddress = analysis.parsedEmail.from.address;
        const originatingIp = analysis.forensicData.originatingIp;

        let blocklistHit = null;
        if (senderDomain && BlocklistRepo.isBlocked(senderDomain)) {
          blocklistHit = { type: 'domain', value: senderDomain, reason: 'Sender domain matches local perimeter blocklist' };
        } else if (senderAddress && BlocklistRepo.isBlocked(senderAddress)) {
          blocklistHit = { type: 'sender', value: senderAddress, reason: 'Sender address matches local perimeter blocklist' };
        } else if (originatingIp && BlocklistRepo.isBlocked(originatingIp)) {
          blocklistHit = { type: 'ip', value: originatingIp, reason: 'Originating IP matches local perimeter blocklist' };
        }

        if (blocklistHit) {
          analysis.threatIndicators.unshift({
            module: 'Blocklist Enforcement',
            severity: 'Critical',
            label: `Local Blocklist Match (${blocklistHit.value})`,
            weight: 50,
            detail: blocklistHit.reason
          });
          analysis.overallScore = Math.max(90, analysis.overallScore);
          analysis.verdict = 'Malicious';
        }

        // Save scan to database
        const scanRecord = ScansRepo.create({
          scanType: body.scanType || (body.rawEml ? 'eml' : body.url ? 'url' : 'email'),
          sender: analysis.parsedEmail.from.address ? `"${analysis.parsedEmail.from.name}" <${analysis.parsedEmail.from.address}>` : (body.sender || ''),
          recipient: analysis.parsedEmail.to.address || body.recipient || 'threat-quarantine@corp.local',
          subject: analysis.parsedEmail.subject || body.subject || 'Automated Threat Scan',
          rawContent: body.rawEml || body.body || body.content || body.url || '',
          extractedUrls: analysis.parsedEmail.urls || [],
          extractedIps: analysis.parsedEmail.ips || [],
          overallScore: analysis.overallScore,
          verdict: analysis.verdict,
          phishingScore: analysis.modules.phishing.score,
          urlScore: analysis.modules.url.score,
          spamScore: analysis.modules.spam.score,
          domainScore: analysis.modules.domain.score,
          ipScore: analysis.modules.ip.score,
          aiRiskScore: analysis.modules.ai.score,
          threatIndicators: analysis.threatIndicators,
          forensicData: analysis.forensicData,
          explanation: analysis.explanation,
          recommendations: analysis.recommendations
        });

        // Automatically create an Incident if suspicious or malicious
        let createdIncident = null;
        if (analysis.verdict === 'Malicious' || analysis.verdict === 'Suspicious') {
          const category = analysis.modules.url.score >= 70 ? 'Malicious URL / Dropper' :
                           analysis.modules.phishing.score >= 70 ? 'Credential Harvester' :
                           analysis.modules.spam.score >= 70 ? 'Spam Campaign' : 'Suspicious Email Anomaly';

          createdIncident = IncidentsRepo.create({
            scanId: scanRecord.id,
            title: `Alert: ${analysis.verdict} - ${analysis.parsedEmail.subject || 'Threat Inbound'}`,
            severity: analysis.overallScore >= 80 ? 'Critical' : analysis.overallScore >= 60 ? 'High' : 'Medium',
            status: 'New',
            category,
            targetUser: scanRecord.recipient,
            sourceIp: originatingIp || 'Unknown',
            sourceDomain: senderDomain || 'Unknown',
            notes: `Auto-generated incident from scan #${scanRecord.id}. Score: ${analysis.overallScore}/100. ${analysis.explanation.slice(0, 150)}...`,
            assignedAnalyst: 'SOC Tier 1 Analyst'
          });
        }

        return sendJson(res, 201, {
          success: true,
          scan: scanRecord,
          incident: createdIncident,
          analysis
        });
      }

      // 4. SCANS: Get all with filters
      if (pathname === '/api/scans' && method === 'GET') {
        const verdict = query.verdict || null;
        const search = query.search || null;
        const limit = parseInt(query.limit, 10) || 50;
        const offset = parseInt(query.offset, 10) || 0;

        const scans = ScansRepo.getAll({ verdict, search, limit, offset });
        return sendJson(res, 200, { success: true, count: scans.length, scans });
      }

      // 5. SCAN BY ID
      if (pathname.startsWith('/api/scans/') && method === 'GET') {
        const id = pathname.replace('/api/scans/', '');
        const scan = ScansRepo.getById(id);
        if (!scan) return sendJson(res, 404, { error: 'Scan record not found' });
        return sendJson(res, 200, { success: true, scan });
      }

      // 6. INCIDENTS: Get all
      if (pathname === '/api/incidents' && method === 'GET') {
        const status = query.status || null;
        const severity = query.severity || null;
        const search = query.search || null;

        const incidents = IncidentsRepo.getAll({ status, severity, search });
        return sendJson(res, 200, { success: true, count: incidents.length, incidents });
      }

      // 7. INCIDENT UPDATE: Status and Notes
      if (pathname.startsWith('/api/incidents/') && (method === 'PATCH' || method === 'POST')) {
        const id = pathname.replace('/api/incidents/', '');
        const body = await parseBody(req);

        let updated;
        if (body.status && body.notes !== undefined) {
          updated = IncidentsRepo.updateStatus(id, body.status, body.notes);
        } else if (body.status) {
          updated = IncidentsRepo.updateStatus(id, body.status);
        } else if (body.notes !== undefined) {
          updated = IncidentsRepo.updateNotes(id, body.notes);
        }

        if (!updated) return sendJson(res, 404, { error: 'Incident not found' });
        return sendJson(res, 200, { success: true, incident: updated });
      }

      // 8. THREAT INTEL: Lookup
      if (pathname === '/api/intel/lookup' && method === 'GET') {
        const q = (query.query || '').trim();
        if (!q) return sendJson(res, 400, { error: 'Missing query parameter' });

        const isIp = /^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$/.test(q);
        const intelHit = ThreatIntelRepo.lookup(q);
        const lookalike = checkLookalike(q);
        const senderLoc = resolveSenderLocation(q);
        const ipInfo = isIp ? resolveIpIntelligence(q) : senderLoc;
        const cleanDomain = q.includes('@') ? q.split('@')[1] : q;
        const domainInfo = !isIp && cleanDomain.includes('.') ? resolveDomainIntelligence(cleanDomain) : null;

        return sendJson(res, 200, {
          success: true,
          query: q,
          isIp,
          threatIntel: intelHit,
          lookalike,
          senderLocation: senderLoc,
          ipIntelligence: ipInfo,
          domainIntelligence: domainInfo
        });
      }

      // 8b. SENDER GEOLOCATION TRACKER
      if (pathname === '/api/track/sender' && method === 'GET') {
        const q = (query.query || query.sender || '').trim();
        if (!q) return sendJson(res, 400, { error: 'Missing query or sender parameter' });

        const senderLoc = resolveSenderLocation(q);
        return sendJson(res, 200, {
          success: true,
          query: q,
          senderLocation: senderLoc
        });
      }

      // 9. THREAT INTEL: Feed
      if (pathname === '/api/intel/feed' && method === 'GET') {
        const feed = ThreatIntelRepo.getAll(50);
        return sendJson(res, 200, { success: true, feed });
      }

      // 10. BLOCKLIST: Get all
      if (pathname === '/api/blocklist' && method === 'GET') {
        const list = BlocklistRepo.getAll();
        return sendJson(res, 200, { success: true, blocklist: list });
      }

      // 11. BLOCKLIST: Add entry
      if (pathname === '/api/blocklist' && method === 'POST') {
        const body = await parseBody(req);
        if (!body.value || !body.type) {
          return sendJson(res, 400, { error: 'Missing type or value for blocklist' });
        }
        const created = BlocklistRepo.add(body.type, body.value, body.reason || 'Added via SOC Interface');
        return sendJson(res, 201, { success: true, entry: created });
      }

      // 12. BLOCKLIST: Remove or toggle
      if (pathname.startsWith('/api/blocklist/') && method === 'DELETE') {
        const id = pathname.replace('/api/blocklist/', '');
        BlocklistRepo.remove(id);
        return sendJson(res, 200, { success: true, message: 'Blocklist entry deleted' });
      }

      if (pathname.startsWith('/api/blocklist/toggle/') && method === 'POST') {
        const id = pathname.replace('/api/blocklist/toggle/', '');
        const updated = BlocklistRepo.toggle(id);
        return sendJson(res, 200, { success: true, entry: updated });
      }

      // 13. VPN TRAFFIC: Logs & stats
      if (pathname === '/api/vpn/traffic' && method === 'GET') {
        const traffic = VpnRepo.getAll(50);
        const stats = VpnRepo.getStats();
        return sendJson(res, 200, { success: true, stats, traffic });
      }

      // 14. VPN SIMULATE: Inject synthetic traffic probe
      if (pathname === '/api/vpn/simulate' && method === 'POST') {
        const body = await parseBody(req);
        const event = VpnRepo.addEvent({
          tunnelId: body.tunnelId || 'tun-sec-probe',
          clientIp: body.clientIp || '10.200.4.77',
          exitNode: 'us-east-vpn.aegis.corp',
          destinationIp: body.destinationIp || '185.220.101.5',
          destinationDomain: body.destinationDomain || 'external-gateway.xyz',
          protocol: body.protocol || 'HTTPS',
          port: body.port || 443,
          bytesIn: body.bytesIn || 34000,
          bytesOut: body.bytesOut || 8500,
          tunnelStatus: body.threatScore > 50 ? 'Suspicious' : 'Healthy',
          threatScore: body.threatScore || 35,
          anomalyFlag: body.threatScore > 50 ? 1 : 0,
          notes: body.notes || 'Simulated network event via SOC dashboard'
        });
        return sendJson(res, 201, { success: true, event });
      }

      // 15. SETTINGS: Get and update
      if (pathname === '/api/settings' && method === 'GET') {
        const settings = SettingsRepo.getAll();
        return sendJson(res, 200, { success: true, settings });
      }

      if (pathname === '/api/settings' && method === 'POST') {
        const body = await parseBody(req);
        for (const [key, val] of Object.entries(body)) {
          SettingsRepo.set(key, val);
        }
        return sendJson(res, 200, { success: true, settings: SettingsRepo.getAll() });
      }

      // Unknown API route
      return sendJson(res, 404, { error: 'API Endpoint Not Found' });
    }

    // Static Frontend Assets
    serveStatic(req, res, pathname);
  } catch (error) {
    console.error('[Aegis Server Error]', error);
    sendJson(res, 500, { error: 'Internal Server Error', details: error.message });
  }
}

const server = http.createServer(handleRequest);
server.handleRequest = handleRequest;

server.on('error', (err) => {
  if (err.code === 'EADDRINUSE') {
    // Port already bound by another process or dev server, ignore in test/import mode
    return;
  }
  console.error('[Aegis Server Error]', err);
});

if (!process.env.VERCEL && !process.env.AWS_LAMBDA_FUNCTION_NAME && !process.env.LAMBDA_TASK_ROOT) {
  server.listen(PORT, '0.0.0.0', () => {
    console.log(`[Aegis Cyber SOC] Server listening at http://localhost:${PORT}`);
    console.log(`[Aegis Cyber SOC] REST API ready and persistent SQLite DB active`);
  });
}

module.exports = server;
