/**
 * Test File Upload and Forensic Extraction Engine
 */
const assert = require('assert');
const { parseUploadedEmailFile, classifyAttachmentRisk } = require('../src/backend/engine/fileThreatParser');
const { analyzeThreat } = require('../src/backend/engine/threatScorer');

console.log('--- 1. Testing Attachment Risk Classifier ---');
assert(classifyAttachmentRisk('malware.exe').severity === 'Malicious', 'Executable classified as Malicious');
assert(classifyAttachmentRisk('script.bat').severity === 'Malicious', 'Batch file classified as Malicious');
assert(classifyAttachmentRisk('invoice.docm').severity === 'Suspicious', 'Macro doc classified as Suspicious');
assert(classifyAttachmentRisk('report.pdf').severity === 'Safe', 'PDF classified as Safe');
console.log('[PASS] Attachment risk classification verified.');

console.log('\n--- 2. Testing EML File Parsing with Attachments ---');
const sampleEml = `Received: from mail-relay.evil.com (unknown [185.220.101.5]) by mx.corp.com; Fri, 06 Nov 2026 12:00:00 -0000
From: "Executive Board" <ceo-alerts@company.ru>
To: cfo@target-corp.com
Subject: URGENT: Wire Transfer Authorization Required
Authentication-Results: spf=fail; dkim=fail; dmarc=fail;
Content-Type: multipart/mixed; boundary="BOUNDARY123"

--BOUNDARY123
Content-Type: text/plain; charset=utf-8

Please execute the attached urgent financial request immediately: http://phish-login.xyz/auth.php

--BOUNDARY123
Content-Type: application/octet-stream; name="Urgent_Transfer_Form.exe"
Content-Disposition: attachment; filename="Urgent_Transfer_Form.exe"

[BINARY DATA]
--BOUNDARY123--`;

const parsedEml = parseUploadedEmailFile(sampleEml, 'Urgent_Transfer.eml', 'message/rfc822');
assert(parsedEml.from.address === 'ceo-alerts@company.ru', 'Parsed sender email address');
assert(parsedEml.attachments.length > 0, 'Extracted MIME attachment');
assert(parsedEml.attachments[0].filename === 'Urgent_Transfer_Form.exe', 'Extracted attachment filename');
assert(parsedEml.attachments[0].severity === 'Malicious', 'Flagged executable attachment as Malicious');
console.log('[PASS] EML parsing with attachment verified.');

console.log('\n--- 3. Testing 6-Module Threat Scoring with Uploaded File ---');
const threatResult = analyzeThreat({
  isParsedFile: true,
  parsedEmail: parsedEml,
  attachments: parsedEml.attachments
});

assert(threatResult.overallScore >= 80, `Expected Critical score for malicious executable, got ${threatResult.overallScore}`);
assert(threatResult.verdict === 'Malicious', `Expected Malicious verdict, got ${threatResult.verdict}`);
assert(threatResult.forensicData.senderLocation !== null, 'Sender location resolved');
assert(threatResult.forensicData.attachments.length > 0, 'Forensic data contains attachments');
console.log(`[PASS] Threat scoring on file upload: Score = ${threatResult.overallScore}/100, Verdict = ${threatResult.verdict}`);

console.log('\n====================================================');
console.log('ALL FILE UPLOAD & FORENSIC TESTS PASSED SUCCESSFULLY');
console.log('====================================================');
