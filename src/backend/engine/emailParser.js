/**
 * Forensic Email Header & MIME/EML Stream Parser
 * Reconstructs relay hops, extracts authentication verdicts (SPF/DKIM/DMARC), and flags header spoofing.
 */

const { extractUrlsFromText } = require('./urlAnalyzer');

function parseEmailHeaders(headerBlock) {
  const headers = {};
  const receivedChain = [];

  if (!headerBlock) return { headers, receivedChain };

  // Handle multi-line header folding (lines starting with space or tab)
  const unfolded = headerBlock.replace(/\r\n([ \t]+)/g, ' ').replace(/\n([ \t]+)/g, ' ');
  const lines = unfolded.split(/\r?\n/);

  for (const line of lines) {
    const colonIdx = line.indexOf(':');
    if (colonIdx === -1) continue;
    const name = line.substring(0, colonIdx).trim().toLowerCase();
    const value = line.substring(colonIdx + 1).trim();

    if (name === 'received') {
      receivedChain.push(value);
    } else {
      headers[name] = value;
    }
  }

  return { headers, receivedChain };
}

function parseAddressField(str) {
  if (!str) return { name: '', address: '', domain: '' };
  const trimmed = str.trim();
  const match = trimmed.match(/^(?:(?:"?([^"]*)"?\s*)?<)?([^<>\s]+@[^<>\s]+)>?$/);
  if (match) {
    const name = (match[1] || '').trim();
    const address = (match[2] || '').trim().toLowerCase();
    const domain = address.split('@')[1] || '';
    return { name, address, domain };
  }
  const cleanAddr = trimmed.replace(/[<>]/g, '').toLowerCase();
  return { name: '', address: cleanAddr, domain: cleanAddr.split('@')[1] || '' };
}

function parseReceivedHop(hopString, hopIndex) {
  // Example: from mail-relay.evil.com (unknown [185.220.101.5]) by mx.google.com with ESMTPS id xyz; Mon, 26 Oct 2026 12:00:00 -0000
  const ipMatch = hopString.match(/\[([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})\]/);
  const byMatch = hopString.match(/by\s+([^\s;]+)/i);
  const fromMatch = hopString.match(/from\s+([^\s]+)/i);
  const dateMatch = hopString.match(/;\s*(.+)$/);

  return {
    hop: hopIndex + 1,
    raw: hopString,
    ip: ipMatch ? ipMatch[1] : null,
    fromHost: fromMatch ? fromMatch[1] : 'Unknown Host',
    byServer: byMatch ? byMatch[1] : 'Unknown Server',
    timestamp: dateMatch ? dateMatch[1].trim() : null
  };
}

function parseEmlContent(rawEml) {
  if (!rawEml) {
    return {
      subject: '',
      from: { name: '', address: '', domain: '' },
      to: { name: '', address: '', domain: '' },
      replyTo: null,
      headers: {},
      receivedHops: [],
      body: '',
      urls: [],
      ips: []
    };
  }

  // Split headers and body at the first double newline
  let headerPart = '';
  let bodyPart = '';
  const doubleBreak = rawEml.search(/\r?\n\r?\n/);

  if (doubleBreak !== -1) {
    headerPart = rawEml.substring(0, doubleBreak);
    bodyPart = rawEml.substring(doubleBreak).trim();
  } else {
    // If no explicit header break, treat as plain body
    bodyPart = rawEml;
  }

  const { headers, receivedChain } = parseEmailHeaders(headerPart);

  const from = parseAddressField(headers['from'] || '');
  const to = parseAddressField(headers['to'] || '');
  const replyTo = headers['reply-to'] ? parseAddressField(headers['reply-to']) : null;
  const subject = headers['subject'] || '';
  const messageId = headers['message-id'] || '';
  const date = headers['date'] || new Date().toUTCString();

  // Parse Received Chain (Reverse order so Hop 1 is the origin)
  const receivedHops = receivedChain.map((hop, idx) => parseReceivedHop(hop, idx));

  // Extract IPs
  const ips = [];
  receivedHops.forEach(h => {
    if (h.ip && !ips.includes(h.ip)) ips.push(h.ip);
  });

  const ipRegex = /\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b/g;
  const bodyIps = (bodyPart.match(ipRegex) || []);
  bodyIps.forEach(ip => {
    if (!ips.includes(ip) && !ip.startsWith('0.') && !ip.startsWith('255.')) {
      ips.push(ip);
    }
  });

  // Extract URLs
  const urls = extractUrlsFromText(bodyPart);

  // Parse SPF / DKIM / DMARC from Authentication-Results or specific headers
  const authResults = headers['authentication-results'] || '';
  const receivedSpf = headers['received-spf'] || '';

  let spfStatus = 'neutral';
  let dkimStatus = 'neutral';
  let dmarcStatus = 'neutral';

  if (receivedSpf.toLowerCase().includes('pass') || authResults.toLowerCase().includes('spf=pass')) {
    spfStatus = 'pass';
  } else if (receivedSpf.toLowerCase().includes('fail') || authResults.toLowerCase().includes('spf=fail')) {
    spfStatus = 'fail';
  } else if (receivedSpf.toLowerCase().includes('softfail') || authResults.toLowerCase().includes('spf=softfail')) {
    spfStatus = 'softfail';
  }

  if (authResults.toLowerCase().includes('dkim=pass')) {
    dkimStatus = 'pass';
  } else if (authResults.toLowerCase().includes('dkim=fail')) {
    dkimStatus = 'fail';
  }

  if (authResults.toLowerCase().includes('dmarc=pass')) {
    dmarcStatus = 'pass';
  } else if (authResults.toLowerCase().includes('dmarc=fail')) {
    dmarcStatus = 'fail';
  }

  // Header Anomaly & Spoofing Analysis
  const headerAnomalies = [];

  // 1. Display name spoofing (e.g. "CEO Tim Cook" <random@evil.com> or "PayPal Security" <info@phish.xyz>)
  const brandKeywords = ['microsoft', 'paypal', 'apple', 'google', 'chase', 'bank of america', 'support', 'it helpdesk', 'admin', 'security alert', 'docusign'];
  const displayNameLower = from.name.toLowerCase();
  for (const bk of brandKeywords) {
    if (displayNameLower.includes(bk) && !from.domain.includes(bk.replace(/\s+/g, ''))) {
      headerAnomalies.push({
        type: 'DISPLAY_NAME_SPOOFING',
        severity: 'Critical',
        detail: `Sender display name "${from.name}" impersonates known brand/authority, but email domain is "${from.domain}"`
      });
      break;
    }
  }

  // 2. Reply-To domain divergence
  if (replyTo && replyTo.domain && from.domain && replyTo.domain !== from.domain) {
    headerAnomalies.push({
      type: 'REPLY_TO_DIVERGENCE',
      severity: 'High',
      detail: `Reply-To destination "${replyTo.address}" differs from sender address "${from.address}", typical indicator of Business Email Compromise (BEC)`
    });
  }

  // 3. Authentication failures
  if (spfStatus === 'fail') {
    headerAnomalies.push({
      type: 'SPF_VALIDATION_FAILURE',
      severity: 'High',
      detail: 'Sender IP is not authorized in sending domain SPF TXT records'
    });
  }
  if (dkimStatus === 'fail') {
    headerAnomalies.push({
      type: 'DKIM_SIGNATURE_INVALID',
      severity: 'High',
      detail: 'Cryptographic DKIM email signature check failed or was altered in transit'
    });
  }
  if (dmarcStatus === 'fail') {
    headerAnomalies.push({
      type: 'DMARC_ALIGNMENT_FAILURE',
      severity: 'Critical',
      detail: 'DMARC policy failed: sender envelope domain does not align with authenticated identity'
    });
  }

  // 4. Missing Message-ID or Date
  if (!messageId) {
    headerAnomalies.push({
      type: 'MISSING_MESSAGE_ID',
      severity: 'Medium',
      detail: 'RFC 5322 violation: Message-ID header is missing, common in automated mass spam tools'
    });
  }

  return {
    subject,
    date,
    messageId,
    from,
    to,
    replyTo,
    headers,
    receivedHops,
    originatingIp: receivedHops.length > 0 && receivedHops[0].ip ? receivedHops[0].ip : (ips[0] || null),
    ips,
    urls,
    body: bodyPart,
    authSummary: {
      spf: spfStatus,
      dkim: dkimStatus,
      dmarc: dmarcStatus
    },
    headerAnomalies
  };
}

module.exports = {
  parseEmlContent,
  parseEmailHeaders,
  parseAddressField,
  parseReceivedHop
};
