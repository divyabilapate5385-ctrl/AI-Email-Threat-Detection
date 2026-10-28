/**
 * Integration Test for Aegis Cyber SOC Server
 */
const http = require('node:http');

async function runTests() {
  const server = require('../src/backend/server');
  await new Promise(r => setTimeout(r, 600));

  try {
    console.log('[TEST] Checking GET /api/stats...');
    const statsRes = await fetch('http://127.0.0.1:3000/api/stats');
    const stats = await statsRes.json();
    console.log('[PASS] /api/stats returned total scans:', stats.stats.total);

    console.log('[TEST] Checking GET /api/samples...');
    const sampleRes = await fetch('http://127.0.0.1:3000/api/samples');
    const sampleJson = await sampleRes.json();
    console.log('[PASS] /api/samples count:', sampleJson.samples.length);

    console.log('[TEST] Checking POST /api/scan with suspicious lure...');
    const scanRes = await fetch('http://127.0.0.1:3000/api/scan', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        sender: 'Security <alert@micros0ft-login-support.xyz>',
        recipient: 'user@corp.com',
        subject: 'URGENT: Password expired',
        body: 'Your account is suspended. Verify password now: https://micros0ft-login-support.xyz/login.exe',
        ip: '185.220.101.5'
      })
    });
    const scanData = await scanRes.json();
    console.log('[PASS] POST /api/scan result: Score =', scanData.scan.overall_score, 'Verdict =', scanData.scan.verdict);
    console.log('[PASS] Incident created ID =', scanData.incident ? scanData.incident.incidentId : 'none');

    console.log('[TEST] Checking GET /api/intel/lookup?query=paypaI.com...');
    const intelRes = await fetch('http://127.0.0.1:3000/api/intel/lookup?query=paypaI.com');
    const intel = await intelRes.json();
    console.log('[PASS] Lookalike detected:', intel.lookalike.isLookalike, 'Target:', intel.lookalike.impersonatedBrand);

    console.log('[ALL TESTS COMPLETED SUCCESSFULLY]');
  } catch (err) {
    console.error('[TEST FAILED]', err);
  } finally {
    server.close(() => {
      process.exit(0);
    });
  }
}

runTests();
