/**
 * Test Endpoint File Validation
 */
const server = require('../src/backend/server');
const { EventEmitter } = require('events');

async function testEndpoint(name, payload, expectedCode, expectSuccess, expectedSnippet) {
  return new Promise((resolve) => {
    const req = new EventEmitter();
    req.method = 'POST';
    req.url = '/api/file/analyze';
    req.headers = { host: 'localhost', 'content-type': 'application/json' };
    req.body = payload;

    const res = {
      statusCode: 200,
      headers: {},
      writeHead: function(c, h) { this.statusCode = c; Object.assign(this.headers, h); },
      setHeader: function(k, v) { this.headers[k] = v; },
      end: function(body) {
        const json = JSON.parse(body);
        console.log(`[${name}] Status: ${this.statusCode}, Success: ${json.success}, Valid: ${json.valid}`);
        if (expectSuccess) {
          if (this.statusCode === 201 && json.success === true && json.analysis) {
            console.log(`  -> [PASS] Generated Threat Score: ${json.analysis.overallScore}/100, Verdict: ${json.analysis.verdict}`);
          } else {
            console.error('  -> [FAIL] Expected success, got error:', json);
            process.exit(1);
          }
        } else {
          if (this.statusCode === expectedCode && json.success === false && json.valid === false && !json.analysis) {
            if (expectedSnippet && !json.error.includes(expectedSnippet)) {
              console.error(`  -> [FAIL] Expected snippet "${expectedSnippet}" in error: "${json.error}"`);
              process.exit(1);
            }
            console.log(`  -> [PASS] Safely blocked without score generation. Error: "${json.error}"`);
          } else {
            console.error('  -> [FAIL] Expected blocked without analysis, but got:', json);
            process.exit(1);
          }
        }
        resolve();
      }
    };

    server.emit('request', req, res);
  });
}

async function run() {
  console.log('Testing /api/file/analyze endpoint directly:');

  // Case 1: Valid EML
  await testEndpoint('Case 1: Valid EML', {
    filename: 'alert.eml',
    content: 'From: alert@phish.com\nTo: user@target.com\nSubject: Account Locked\nDate: Fri, 06 Nov 2026\n\nClick: http://phish.com/login.exe'
  }, 201, true);

  // Case 2: Valid MSG (Outlook)
  const oleHeader = Buffer.from([0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1]);
  const msgBody = Buffer.from('From: boss@corp.com\nTo: finance@corp.com\nSubject: Wire Transfer\nIPM.Note\n__substg1.0_0037001E');
  await testEndpoint('Case 2: Valid MSG', {
    filename: 'wire.msg',
    content: Buffer.concat([oleHeader, msgBody]).toString('base64'),
    isBase64: true
  }, 201, true);

  // Case 3: Invalid JPG
  await testEndpoint('Case 3: Invalid JPG', {
    filename: 'photo.jpg',
    content: Buffer.from([0xFF, 0xD8, 0xFF, 0xE0, 0x00, 0x10, 0x4A, 0x46, 0x49, 0x46, 0x00, 0x01, 0x01, 0x00, 0x00]).toString('base64'),
    isBase64: true
  }, 422, false, 'Invalid File: This is not a supported email file');

  // Case 4: Invalid MP3
  await testEndpoint('Case 4: Invalid MP3', {
    filename: 'song.mp3',
    content: Buffer.from([0x49, 0x44, 0x33, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x20, 0x54, 0x49, 0x54, 0x32, 0x00]).toString('base64'),
    isBase64: true
  }, 422, false, 'Invalid File: This is not a supported email file');

  // Case 5: Corrupted EML
  await testEndpoint('Case 5: Corrupted EML', {
    filename: 'broken.eml',
    content: 'random characters and text that have no email headers or addresses at all'
  }, 422, false, 'Unable to analyze: The uploaded file does not contain valid readable email content');

  // Case 6: Plain TXT without email content
  await testEndpoint('Case 6: Plain TXT (No Email Content)', {
    filename: 'notes.txt',
    content: '1. Buy groceries\n2. Walk the dog\n3. Do laundry'
  }, 422, false, 'No valid email content found');

  console.log('\n====================================================');
  console.log('ALL 6 ENDPOINT VALIDATION CASES PASSED PERFECTLY!');
  console.log('====================================================');
  process.exit(0);
}

run();
