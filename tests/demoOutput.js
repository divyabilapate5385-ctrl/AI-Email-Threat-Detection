/**
 * Aegis Cyber SOC - Comprehensive Live Demonstration Script
 * Executes each core module and outputs the exact forensic threat analysis results.
 */

const { analyzeThreat } = require('../src/backend/engine/threatScorer');
const { checkLookalike } = require('../src/backend/engine/lookalikeDetector');
const { analyzeUrl } = require('../src/backend/engine/urlAnalyzer');
const { parseEmlContent } = require('../src/backend/engine/emailParser');
const { resolveIpIntelligence, resolveDomainIntelligence } = require('../src/backend/engine/geoIpLookup');
const { SAMPLE_THREATS } = require('../src/backend/samples/sampleThreats');
const { ScansRepo, IncidentsRepo, BlocklistRepo } = require('../src/backend/db/database');

console.log('======================================================================');
console.log('        AEGIS CYBER SOC - LIVE ENGINE DEMONSTRATION & OUTPUT');
console.log('======================================================================\n');

// 1. Lookalike & Homoglyph Detection Output
console.log('>>> [1] LOOKALIKE & HOMOGLYPH DETECTION ENGINE');
console.log('----------------------------------------------------------------------');
const testDomains = [
  'micros0ft.com',
  'paypaI.com',
  'chase-security-verify.top',
  'google.com',
  'login.microsoft.com.attacker-portal.xyz'
];

testDomains.forEach(domain => {
  const res = checkLookalike(domain);
  console.log(`Domain: ${domain.padEnd(40)} | Lookalike: ${String(res.isLookalike).padEnd(5)} | Target: ${(res.impersonatedBrand || res.matchedBrand || 'None').padEnd(12)} | Technique: ${res.technique || res.reason}`);
});

// 2. URL Forensics Output
console.log('\n>>> [2] DEEP URL FORENSICS & PAYLOAD INSPECTOR');
console.log('----------------------------------------------------------------------');
const testUrls = [
  'http://185.220.101.5/login/office365_verify.exe',
  'https://bit.ly/3x8Zb9',
  'https://paypaI.com/cgi-bin/webscr?cmd=_login-run&dispatch=verify-checkpoint',
  'https://admin.google.com/ac/security'
];

testUrls.forEach(url => {
  const u = analyzeUrl(url);
  console.log(`URL: ${url}`);
  console.log(`  -> Risk Score: ${u.riskScore}/100 | Verdict: ${u.verdict} | Entropy: ${u.entropy}`);
  console.log(`  -> Indicators Flagged: ${u.indicators.map(i => i.type).join(', ') || 'None (Clean)'}\n`);
});

// 3. RFC Header & EML Parser Output
console.log('>>> [3] FORENSIC EMAIL HEADER & AUTHENTICATION PARSER (EML)');
console.log('----------------------------------------------------------------------');
const rawEml = `Received: from mail-relay.evil-server.xyz ([185.220.101.5])
    by mx.enterprise-target.corp with ESMTPS id 4Kz92xL;
    Mon, 26 Oct 2026 14:22:01 -0400
From: "Microsoft Security Center" <support@micros0ft-portal.xyz>
Reply-To: "Executive Recovery" <attacker-inbox@gmail.com>
To: cfo.corporate@victim-corp.com
Subject: URGENT: Microsoft 365 Password Expiring in 24 Hours
Date: Mon, 26 Oct 2026 18:22:01 +0000
Message-ID: <89102-urgent-sec@micros0ft-portal.xyz>
Authentication-Results: spf=fail; dkim=fail; dmarc=fail

Dear Executive,
Your Microsoft 365 enterprise account access is scheduled for immediate suspension.
Immediate action required within 24 hours to prevent permanent account deactivation.
Verify your credentials now:
https://micros0ft-portal.xyz/auth/login.exe`;

const parsed = parseEmlContent(rawEml);
console.log(`From:         "${parsed.from.name}" <${parsed.from.address}>`);
console.log(`Reply-To:     "${parsed.replyTo.name}" <${parsed.replyTo.address}>`);
console.log(`Subject:      ${parsed.subject}`);
console.log(`Relay Origin: ${parsed.originatingIp} (via ${parsed.receivedHops.length} hops)`);
console.log(`Auth Matrix:  SPF=[${parsed.authSummary.spf}] DKIM=[${parsed.authSummary.dkim}] DMARC=[${parsed.authSummary.dmarc}]`);
console.log(`Anomalies:    ${parsed.headerAnomalies.map(a => a.type).join(', ')}`);

// 4. Full 6-Module Threat Assessment Output
console.log('\n>>> [4] 6-MODULE EXPLAINABLE THREAT ENGINE OUTPUT (SAMPLE ATTACK)');
console.log('----------------------------------------------------------------------');
const scanAnalysis = analyzeThreat(rawEml);
console.log(`OVERALL THREAT RISK SCORE: ${scanAnalysis.overallScore}/100`);
console.log(`FINAL SOC VERDICT:         ${scanAnalysis.verdict.toUpperCase()}`);
console.log('\nMODULE BREAKDOWN EVIDENCE:');
console.log(`  1. Phishing Detection:    ${scanAnalysis.modules.phishing.score}/100 (Weight: 25%)`);
console.log(`  2. Malicious URL:         ${scanAnalysis.modules.url.score}/100 (Weight: 25%)`);
console.log(`  3. Spam & Lures:          ${scanAnalysis.modules.spam.score}/100 (Weight: 15%)`);
console.log(`  4. Domain Reputation:     ${scanAnalysis.modules.domain.score}/100 (Weight: 20%)`);
console.log(`  5. IP Reputation & Geo:   ${scanAnalysis.modules.ip.score}/100 (Weight: 15%)`);
console.log(`  6. AI Risk Synthesis:     ${scanAnalysis.modules.ai.score}/100 (Confidence: ${scanAnalysis.modules.ai.confidence}%)`);

console.log('\nMITRE ATT&CK MAPPINGS:');
scanAnalysis.modules.ai.mitreTactics.forEach(t => {
  console.log(`  - [${t.id}] ${t.name} (Tactic: ${t.tactic})`);
});

console.log('\nEXPLAINABLE AI SYNTHESIS:');
console.log(`"${scanAnalysis.explanation}"`);

console.log('\nRECOMMENDED INCIDENT ACTIONS:');
scanAnalysis.recommendations.forEach((r, idx) => {
  console.log(`  ${idx + 1}. ${r}`);
});

// 5. Geolocation Intelligence
console.log('\n>>> [5] FORENSIC GEOLOCATION & ASN RESOLVER');
console.log('----------------------------------------------------------------------');
const geo = resolveIpIntelligence('185.220.101.5');
console.log(`IP Address:   ${geo.ip}`);
console.log(`Location:     ${geo.city}, ${geo.region}, ${geo.country} (${geo.countryCode})`);
console.log(`Coordinates:  Lat ${geo.latitude}, Lng ${geo.longitude}`);
console.log(`ISP:          ${geo.isp}`);
console.log(`ASN:          ${geo.asn} (${geo.asName})`);
console.log(`Tor Relay:    ${geo.isTor ? 'TRUE (Malicious Anonymizer)' : 'FALSE'}`);
console.log(`VPN / Proxy:  ${geo.isVpn || geo.isProxy ? 'TRUE' : 'FALSE'}`);
console.log(`Threat Feed:  ${geo.threatFeed}`);

console.log('\n======================================================================');
console.log('        LIVE DEMONSTRATION COMPLETE - ALL SYSTEMS FUNCTIONAL');
console.log('======================================================================');
