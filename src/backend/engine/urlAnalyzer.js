/**
 * Deep URL Forensics & Malicious Link Analyzer
 * Analyzes embedded links, redirect obfuscations, IP targets, and credential lures.
 */

const { checkLookalike, normalizeDomain, SUSPICIOUS_TLDS } = require('./lookalikeDetector');

const KNOWN_SHORTENERS = new Set([
  'bit.ly', 'tinyurl.com', 't.co', 'is.gd', 'buff.ly', 'ow.ly', 'rebrand.ly',
  'cutt.ly', 'tiny.cc', 'bc.vc', 'goo.gl', 'shorte.st', 'adf.ly', 'bit.do'
]);

const DANGEROUS_EXTENSIONS = new Set([
  '.exe', '.scr', '.vbs', '.bat', '.ps1', '.iso', '.img', '.apk', '.jar',
  '.hta', '.cmd', '.pif', '.dll', '.msi', '.wsf', '.cpl', '.dmg'
]);

const CREDENTIAL_KEYWORDS = [
  'login', 'signin', 'sign-in', 'log-in', 'verify', 'verification', 'authenticate',
  'secure', 'banking', 'account', 'recovery', 'password', 'credential', 'unlock',
  'billing', 'invoice', 'payment', 'wallet', 'confirm', 'security-checkpoint'
];

function calculateEntropy(str) {
  if (!str || str.length === 0) return 0;
  const freq = {};
  for (const ch of str) {
    freq[ch] = (freq[ch] || 0) + 1;
  }
  let entropy = 0;
  const len = str.length;
  for (const ch in freq) {
    const p = freq[ch] / len;
    entropy -= p * Math.log2(p);
  }
  return Number(entropy.toFixed(2));
}

function analyzeUrl(rawUrl) {
  let cleanUrl = (rawUrl || '').trim();
  if (!cleanUrl) return null;

  if (!cleanUrl.startsWith('http://') && !cleanUrl.startsWith('https://')) {
    cleanUrl = 'https://' + cleanUrl;
  }

  let parsed;
  try {
    parsed = new URL(cleanUrl);
  } catch (err) {
    return {
      rawUrl,
      valid: false,
      riskScore: 65,
      threatIndicators: ['Malformed or Obfuscated URL Syntax'],
      verdict: 'Suspicious'
    };
  }

  const hostname = parsed.hostname.toLowerCase();
  const pathname = parsed.pathname.toLowerCase();
  const search = parsed.search.toLowerCase();
  const fullHref = parsed.href;

  const indicators = [];
  let riskScore = 0;

  // 1. IP address in hostname (e.g. http://192.168.1.1/...)
  const isIpv4 = /^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$/.test(hostname);
  if (isIpv4) {
    indicators.push({
      type: 'IP_AS_HOSTNAME',
      severity: 'Critical',
      weight: 35,
      detail: `URL uses raw IP host (${hostname}) rather than a registered domain name, common in malware command & control`
    });
    riskScore += 35;
  }

  // 2. URL Shortener detection
  if (KNOWN_SHORTENERS.has(hostname)) {
    indicators.push({
      type: 'URL_SHORTENER',
      severity: 'Medium',
      weight: 20,
      detail: `URL shortener detected (${hostname}), frequently utilized to evade email gateway filters and mask final destination`
    });
    riskScore += 20;
  }

  // 3. Lookalike & Brand Spoofing Check
  const lookalike = checkLookalike(hostname);
  if (lookalike.isLookalike) {
    indicators.push({
      type: 'LOOKALIKE_DOMAIN',
      severity: 'Critical',
      weight: lookalike.riskScoreBonus || 30,
      detail: `${lookalike.technique}: targeting ${lookalike.impersonatedBrand} (confidence ${lookalike.confidence}%) - ${lookalike.reason}`
    });
    riskScore += (lookalike.riskScoreBonus || 30);
  } else if (lookalike.isSuspiciousTLD) {
    indicators.push({
      type: 'SUSPICIOUS_TLD',
      severity: 'High',
      weight: 20,
      detail: lookalike.reason
    });
    riskScore += 20;
  }

  // 4. Executable / Dangerous payload attachment in URL path
  for (const ext of DANGEROUS_EXTENSIONS) {
    if (pathname.endsWith(ext) || search.includes(ext)) {
      indicators.push({
        type: 'EXECUTABLE_PAYLOAD',
        severity: 'Critical',
        weight: 45,
        detail: `Direct download link to potentially executable/malicious file extension: ${ext}`
      });
      riskScore += 45;
      break;
    }
  }

  // 5. Credential phishing keywords in path or query
  const matchedKeywords = CREDENTIAL_KEYWORDS.filter(kw => pathname.includes(kw) || search.includes(kw));
  if (matchedKeywords.length > 0 && !lookalike.isLegitimateBrand) {
    const kwWeight = Math.min(25, matchedKeywords.length * 8);
    indicators.push({
      type: 'CREDENTIAL_LURE_PARAMS',
      severity: 'High',
      weight: kwWeight,
      detail: `Detected sensitive authentication lure parameters: [${matchedKeywords.slice(0, 4).join(', ')}]`
    });
    riskScore += kwWeight;
  }

  // 6. Suspicious Open Redirect patterns
  if (search.includes('redirect=') || search.includes('url=') || search.includes('next=') || search.includes('goto=') || search.includes('dest=')) {
    indicators.push({
      type: 'OPEN_REDIRECT_PARAMETER',
      severity: 'Medium',
      weight: 15,
      detail: 'Detected potential open-redirect query parameter capable of routing victim to secondary attack infrastructure'
    });
    riskScore += 15;
  }

  // 7. Non-standard ports
  if (parsed.port && parsed.port !== '80' && parsed.port !== '443') {
    indicators.push({
      type: 'NON_STANDARD_PORT',
      severity: 'Medium',
      weight: 15,
      detail: `URL uses non-standard web port: :${parsed.port}`
    });
    riskScore += 15;
  }

  // 8. High entropy path / obfuscated strings
  const pathEntropy = calculateEntropy(pathname + search);
  if (pathEntropy > 4.6 && (pathname + search).length > 30) {
    indicators.push({
      type: 'HIGH_ENTROPY_PATH',
      severity: 'Low',
      weight: 10,
      detail: `Path randomness score (${pathEntropy}) indicates possible encoded payload, tracking hash, or polymorphic target token`
    });
    riskScore += 10;
  }

  // 9. Plain HTTP protocol
  if (parsed.protocol === 'http:') {
    indicators.push({
      type: 'UNENCRYPTED_HTTP',
      severity: 'Low',
      weight: 10,
      detail: 'Cleartext HTTP communication without TLS encryption'
    });
    riskScore += 10;
  }

  const finalScore = Math.min(100, riskScore);
  const verdict = finalScore >= 70 ? 'Malicious' : finalScore >= 40 ? 'Suspicious' : 'Safe';

  return {
    rawUrl,
    cleanUrl,
    domain: hostname,
    protocol: parsed.protocol.replace(':', ''),
    port: parsed.port || (parsed.protocol === 'https:' ? '443' : '80'),
    path: parsed.pathname,
    query: parsed.search,
    entropy: pathEntropy,
    riskScore: finalScore,
    verdict,
    indicators,
    isLookalike: lookalike.isLookalike || false,
    impersonatedBrand: lookalike.impersonatedBrand || null
  };
}

function extractUrlsFromText(text) {
  if (!text) return [];
  const urlRegex = /(?:https?:\/\/|www\.)[^\s<>"'{}|\\^`\[\]]+/gi;
  const matches = text.match(urlRegex) || [];
  return Array.from(new Set(matches));
}

module.exports = {
  analyzeUrl,
  extractUrlsFromText,
  calculateEntropy,
  KNOWN_SHORTENERS,
  DANGEROUS_EXTENSIONS
};
