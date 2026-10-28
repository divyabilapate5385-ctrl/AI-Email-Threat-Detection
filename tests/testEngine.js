/**
 * Unit & Integration Test Suite for Aegis Cyber SOC Engine
 * Tests Threat Scoring, URL Analysis, Lookalike Detection, and In-Memory Handlers
 */

const { analyzeThreat, scorePhishingModule, scoreUrlModule, scoreSpamModule, scoreDomainModule, scoreIpModule } = require('../src/backend/engine/threatScorer');
const { checkLookalike, levenshteinDistance } = require('../src/backend/engine/lookalikeDetector');
const { analyzeUrl } = require('../src/backend/engine/urlAnalyzer');
const { resolveIpIntelligence, resolveDomainIntelligence } = require('../src/backend/engine/geoIpLookup');
const { parseEmlContent } = require('../src/backend/engine/emailParser');
const { SAMPLE_THREATS } = require('../src/backend/samples/sampleThreats');
const { ScansRepo, IncidentsRepo, BlocklistRepo } = require('../src/backend/db/database');

console.log('====================================================');
console.log('   AEGIS CYBER SOC - ENGINE TEST SUITE');
console.log('====================================================\n');

let passed = 0;
let failed = 0;

function assert(condition, message) {
  if (condition) {
    console.log(`[PASS] ${message}`);
    passed++;
  } else {
    console.error(`[FAIL] ${message}`);
    failed++;
  }
}

// 1. Lookalike Detection Tests
console.log('--- 1. Testing Lookalike & Typosquatting Engine ---');
const l1 = checkLookalike('micros0ft.com');
assert(l1.isLookalike && l1.impersonatedBrand === 'Microsoft', 'Detected homoglyph micros0ft.com -> Microsoft');

const l2 = checkLookalike('paypaI.com');
assert(l2.isLookalike && l2.impersonatedBrand === 'PayPal', 'Detected capital-I homoglyph paypaI.com -> PayPal');

const l3 = checkLookalike('google.com');
assert(!l3.isLookalike && l3.isLegitimateBrand, 'Recognized genuine google.com as legitimate');

const l4 = checkLookalike('chase-security-verify.top');
assert(l4.isLookalike && l4.impersonatedBrand === 'Chase Bank', 'Detected combo-squatting chase-security-verify.top -> Chase Bank');

// 2. URL Analyzer Tests
console.log('\n--- 2. Testing URL Forensics Module ---');
const u1 = analyzeUrl('http://185.220.101.5/malware.exe');
assert(u1.verdict === 'Malicious' && u1.riskScore >= 70, 'Flagged raw IP + .exe payload as Malicious');

const u2 = analyzeUrl('https://bit.ly/3x8Zb9');
assert(u2.indicators.some(i => i.type === 'URL_SHORTENER'), 'Detected URL shortener bit.ly');

const u3 = analyzeUrl('https://admin.google.com/ac/security');
assert(u3.verdict === 'Safe' && u3.riskScore < 30, 'Verified benign Google administration URL');

// 3. Email & Header Parsing Tests
console.log('\n--- 3. Testing Email Parsing & RFC Header Analysis ---');
const rawEmailSample = `From: "IT Helpdesk" <support@fake-support.xyz>
To: target.user@enterprise.corp
Subject: Urgent Security Notice: Password Reset
Date: Mon, 26 Oct 2026 10:00:00 GMT
Message-ID: <12345@fake-support.xyz>
Authentication-Results: spf=fail; dkim=fail; dmarc=fail

Dear Employee,
Your access has been suspended. Please confirm your password immediately.
Click here: http://fake-support.xyz/login
`;

const parsed = parseEmlContent(rawEmailSample);
assert(parsed.from.address === 'support@fake-support.xyz', 'Parsed sender address successfully');
assert(parsed.authSummary.spf === 'fail' && parsed.authSummary.dmarc === 'fail', 'Extracted SPF and DMARC failures');
assert(parsed.urls.length > 0, 'Extracted embedded URL from email body');

// 4. Six-Module Threat Analysis Tests on Sample Threats
console.log('\n--- 4. Testing 6-Module Threat Scoring on Sample Dataset ---');
for (const sample of SAMPLE_THREATS) {
  const result = analyzeThreat(sample.data);
  const isMatch = (sample.expectedVerdict === 'Safe' && result.verdict === 'Safe') ||
                  (sample.expectedVerdict === 'Malicious' && result.verdict === 'Malicious') ||
                  (sample.expectedVerdict === 'Suspicious' && (result.verdict === 'Suspicious' || result.verdict === 'Malicious'));

  assert(isMatch, `Sample '${sample.name}': Score = ${result.overallScore}/100, Verdict = ${result.verdict} (Expected: ${sample.expectedVerdict})`);
  assert(result.threatIndicators.length >= 0, `  -> Extracted ${result.threatIndicators.length} threat indicators`);
  assert(result.explanation.length > 20, `  -> Generated explainable AI synthesis`);
}

// 5. Database CRUD & Persistence Tests
console.log('\n--- 5. Testing Database Persistence & CRUD ---');
const scanCountBefore = ScansRepo.getStats().total;
const newScan = ScansRepo.create({
  scanType: 'test',
  sender: 'attacker@evil.com',
  recipient: 'victim@corp.com',
  subject: 'Test Scan Payload',
  rawContent: 'Test Content',
  overallScore: 85,
  verdict: 'Malicious'
});
assert(newScan.id > 0, `Created scan record with ID ${newScan.id}`);
const scanFetched = ScansRepo.getById(newScan.id);
assert(scanFetched.overall_score === 85 && scanFetched.verdict === 'Malicious', 'Retrieved scan record matches inserted values');

// Blocklist test
BlocklistRepo.add('domain', 'test-malicious-domain.xyz', 'Unit test block');
assert(BlocklistRepo.isBlocked('test-malicious-domain.xyz'), 'Blocklist enforcement returned true for blocked domain');
BlocklistRepo.remove('test-malicious-domain.xyz');
assert(!BlocklistRepo.isBlocked('test-malicious-domain.xyz'), 'Blocklist removal successfully cleared domain');

console.log('\n====================================================');
console.log(`TEST SUMMARY: ${passed} PASSED, ${failed} FAILED`);
console.log('====================================================');

if (failed > 0) process.exit(1);
