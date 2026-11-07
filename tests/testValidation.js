/**
 * Aegis Cyber SOC - Email File Validation Test Suite
 * Verifies strict validation: prevents phishing score generation for non-email files,
 * corrupted files, and documents lacking email headers.
 */

const assert = require('assert');
const { validateEmailFile, detectBinaryMagic } = require('../src/backend/engine/fileThreatParser');

console.log('====================================================');
console.log('   EMAIL FILE VALIDATION & INTEGRITY TEST SUITE');
console.log('====================================================');

// --- CASE 1: Valid .EML File ---
console.log('\n--- Case 1: Valid .EML Email File ---');
const validEml = Buffer.from(`From: "Security Team" <security@company.com>
To: user@target.org
Subject: Urgent Security Notice
Date: Sat, 07 Nov 2026 12:00:00 +0000
Message-ID: <123456@company.com>
Content-Type: text/plain; charset=utf-8

Please review your login activity: https://company.com/verify`);

const res1 = validateEmailFile(validEml, 'security_alert.eml', 'message/rfc822');
assert(res1.valid === true, 'Valid .eml was rejected!');
assert(res1.format === 'EML', 'Expected format EML');
console.log('[PASS] Valid .eml accepted successfully.');

// --- CASE 2: Valid .MSG File ---
console.log('\n--- Case 2: Valid .MSG Outlook File ---');
// OLE Compound Header: D0 CF 11 E0 A1 B1 1A E1 + IPM.Note + From/Subject
const oleHeader = Buffer.from([0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1]);
const msgBody = Buffer.from('From: boss@corp.com\nTo: finance@corp.com\nSubject: Invoice Payment\nIPM.Note\n__substg1.0_0037001E');
const validMsg = Buffer.concat([oleHeader, msgBody]);

const res2 = validateEmailFile(validMsg, 'invoice.msg', 'application/vnd.ms-outlook');
assert(res2.valid === true, 'Valid .msg was rejected!');
assert(res2.format === 'MSG', 'Expected format MSG');
console.log('[PASS] Valid .msg accepted successfully.');

// --- CASE 3: Unrelated Image Files (JPG / PNG) ---
console.log('\n--- Case 3: Image Files (JPG / PNG) ---');
// JPEG Magic bytes: FF D8 FF E0
const fakeJpg = Buffer.from([0xFF, 0xD8, 0xFF, 0xE0, 0x00, 0x10, 0x4A, 0x46, 0x49, 0x46, 0x00, 0x01, 0x01, 0x00, 0x00]);
const resJpg = validateEmailFile(fakeJpg, 'photo.jpg', 'image/jpeg');
assert(resJpg.valid === false, 'JPEG was incorrectly accepted!');
assert(resJpg.errorType === 'UNSUPPORTED_FORMAT', 'Expected errorType UNSUPPORTED_FORMAT');
assert(resJpg.message.includes('not a supported email file'), 'Expected error message for unsupported file');

// Even if renamed to .eml:
const renamedJpg = validateEmailFile(fakeJpg, 'malicious_picture.eml', 'message/rfc822');
assert(renamedJpg.valid === false, 'Renamed JPEG was incorrectly accepted as .eml!');
assert(renamedJpg.errorType === 'UNSUPPORTED_FORMAT', 'Expected magic byte detection for renamed JPEG');
console.log('[PASS] JPG correctly blocked by extension and binary magic bytes.');

// PNG Magic bytes: 89 50 4E 47 0D 0A 1A 0A
const fakePng = Buffer.from([0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A, 0x00, 0x00, 0x00, 0x0D, 0x49, 0x48, 0x44, 0x52]);
const resPng = validateEmailFile(fakePng, 'screenshot.png', 'image/png');
assert(resPng.valid === false, 'PNG was incorrectly accepted!');
console.log('[PASS] PNG correctly blocked by extension and binary magic bytes.');

// --- CASE 4: Media Audio / Video Files (MP3 / MP4) ---
console.log('\n--- Case 4: Audio & Video Files (MP3 / MP4) ---');
// MP3 with ID3 tag
const fakeMp3 = Buffer.from([0x49, 0x44, 0x33, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x20, 0x54, 0x49, 0x54, 0x32, 0x00]);
const resMp3 = validateEmailFile(fakeMp3, 'song.mp3', 'audio/mpeg');
assert(resMp3.valid === false, 'MP3 was incorrectly accepted!');
assert(resMp3.errorType === 'UNSUPPORTED_FORMAT');

// MP4 with ftyp
const fakeMp4 = Buffer.from([0x00, 0x00, 0x00, 0x18, 0x66, 0x74, 0x79, 0x70, 0x69, 0x73, 0x6F, 0x6D, 0x00, 0x00, 0x02, 0x00]);
const resMp4 = validateEmailFile(fakeMp4, 'video.mp4', 'video/mp4');
assert(resMp4.valid === false, 'MP4 was incorrectly accepted!');
assert(resMp4.errorType === 'UNSUPPORTED_FORMAT');
console.log('[PASS] MP3 and MP4 correctly blocked by extension and binary magic bytes.');

// --- CASE 5: Corrupted .EML File ---
console.log('\n--- Case 5: Corrupted / Empty .EML File ---');
// Corrupted: random garbage without email headers
const corruptedEml = Buffer.from('aslkdfjalskdfj alskdfjalksjdf laksjdf lkasjdf lkasjdflkasjdf lkasjfd laksjdf');
const resCorrupt = validateEmailFile(corruptedEml, 'corrupted.eml', 'message/rfc822');
assert(resCorrupt.valid === false, 'Corrupted .eml without headers was accepted!');
assert(resCorrupt.errorType === 'CORRUPTED_EMAIL', `Expected CORRUPTED_EMAIL, got ${resCorrupt.errorType}`);
assert(resCorrupt.message.includes('Unable to analyze'), 'Expected "Unable to analyze" message');

// Empty file
const emptyEml = Buffer.from('');
const resEmpty = validateEmailFile(emptyEml, 'empty.eml', 'message/rfc822');
assert(resEmpty.valid === false, 'Empty file was accepted!');
assert(resEmpty.message.includes('Unable to analyze'), 'Expected "Unable to analyze" message');
console.log('[PASS] Corrupted and empty .eml files correctly rejected.');

// --- CASE 6: PDF / TXT Without Email Content ---
console.log('\n--- Case 6: PDF / TXT Without Email Content ---');
// Plain TXT without email headers
const randomTxt = Buffer.from('Shopping List:\n1. Apples\n2. Milk\n3. Bread\n4. Coffee beans');
const resTxt = validateEmailFile(randomTxt, 'notes.txt', 'text/plain');
assert(resTxt.valid === false, 'Plain text without email content was accepted!');
assert(resTxt.errorType === 'NO_EMAIL_CONTENT', `Expected NO_EMAIL_CONTENT, got ${resTxt.errorType}`);
assert(resTxt.message.includes('No valid email content found'), 'Expected "No valid email content found" message');

// Valid TXT with email content
const emailTxt = Buffer.from('From: boss@corp.com\nTo: team@corp.com\nSubject: Meeting Tomorrow\nDate: Mon, 02 Nov 2026\n\nPlease find agenda attached.');
const resValidTxt = validateEmailFile(emailTxt, 'email_dump.txt', 'text/plain');
assert(resValidTxt.valid === true, 'Valid text email was rejected!');

// PDF without email content
const plainPdf = Buffer.from('%PDF-1.4\n1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n%%EOF');
const resPlainPdf = validateEmailFile(plainPdf, 'brochure.pdf', 'application/pdf');
assert(resPlainPdf.valid === false, 'Plain PDF without email headers was accepted!');
assert(resPlainPdf.errorType === 'NO_EMAIL_CONTENT', `Expected NO_EMAIL_CONTENT, got ${resPlainPdf.errorType}`);

// PDF with email content
const emailPdf = Buffer.from('%PDF-1.4\nFrom: billing@vendor.com\nTo: accounts@corp.com\nSubject: Invoice #9921\nSent: Nov 5 2026\nPlease pay via link http://pay.com\n%%EOF');
const resEmailPdf = validateEmailFile(emailPdf, 'scanned_invoice.pdf', 'application/pdf');
assert(resEmailPdf.valid === true, 'PDF with email content was rejected!');
console.log('[PASS] PDF/TXT content filtering verified: only email documents accepted.');

console.log('\n====================================================');
console.log('ALL VALIDATION TEST CASES PASSED SUCCESSFULLY!');
console.log('====================================================');
