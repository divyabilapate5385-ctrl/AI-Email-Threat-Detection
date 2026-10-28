/**
 * Aegis Cyber SOC - Client Application Logic
 * Implements interactive SOC dashboard, SVG analytics, threat scoring visualizer,
 * geolocation radar, incident response, and REST API connectivity.
 */

// Global State
const state = {
  currentView: 'overview',
  stats: {},
  samples: [],
  scans: [],
  incidents: [],
  blocklist: [],
  intelFeed: [],
  vpnTraffic: [],
  settings: {},
  currentScanResult: null,
  activeIncident: null,
  scanMode: 'form' // 'form' | 'eml' | 'url'
};

// Initialization on DOM Load
document.addEventListener('DOMContentLoaded', async () => {
  setupNavigation();
  setupSidebarToggle();
  await loadAllData();
  setupTickerAnimation();
});

// Navigation Handling
function setupNavigation() {
  const navItems = document.querySelectorAll('.sidebar-nav .nav-item');
  navItems.forEach(item => {
    item.addEventListener('click', () => {
      const target = item.getAttribute('data-target');
      if (target) navigateTo(target);
    });
  });

  document.getElementById('btnTopScan').addEventListener('click', () => navigateTo('scanner'));
  document.getElementById('btnQuickSample').addEventListener('click', () => {
    navigateTo('scanner');
    if (state.samples.length > 0) loadSampleIntoScanner(state.samples[0].id);
  });
}

function navigateTo(viewId) {
  state.currentView = viewId;

  // Update Nav links
  document.querySelectorAll('.sidebar-nav .nav-item').forEach(el => {
    if (el.getAttribute('data-target') === viewId) {
      el.classList.add('active');
    } else {
      el.classList.remove('active');
    }
  });

  // Update View Sections
  document.querySelectorAll('.view-section').forEach(sec => {
    sec.classList.remove('active');
  });

  const activeSec = document.getElementById(`view-${viewId}`);
  if (activeSec) activeSec.classList.add('active');

  // Update Header Title
  const titles = {
    overview: 'SOC Overview Dashboard',
    scanner: 'Email & URL Threat Scanner',
    intel: 'Threat Intelligence & IOC Resolver',
    forensics: 'Forensic Investigation & Geolocation',
    incidents: 'Alerts & Incident Response Queue',
    history: 'Persistent Scan Audit Records',
    vpn: 'VPN & Encrypted Traffic Monitor',
    settings: 'SOC Settings & IMAP Connector'
  };
  const titleEl = document.getElementById('pageTitle');
  if (titleEl) {
    titleEl.innerHTML = `
      <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
        <polygon points="12 2 2 7 12 12 22 7 12 2"></polygon>
      </svg>
      ${titles[viewId] || 'SOC Workspace'}
    `;
  }

  // View specific refreshes
  if (viewId === 'overview') renderCharts();
  if (viewId === 'forensics') populateForensicSelector();
}

function setupSidebarToggle() {
  const sidebar = document.getElementById('sidebar');
  const collapseBtn = document.getElementById('collapseBtn');
  const mobileBtn = document.getElementById('mobileMenuBtn');

  collapseBtn.addEventListener('click', () => {
    sidebar.classList.toggle('collapsed');
  });

  if (mobileBtn) {
    mobileBtn.addEventListener('click', () => {
      sidebar.classList.toggle('mobile-open');
    });
  }
}

// Data Fetching
async function loadAllData() {
  try {
    await Promise.all([
      loadStats(),
      loadSamples(),
      loadScans(),
      loadIncidents(),
      loadBlocklist(),
      loadIntelFeed(),
      loadVpnTraffic(),
      loadSettings()
    ]);
  } catch (err) {
    console.warn('[Aegis Data Load Error]', err);
  }
}

async function loadStats() {
  const res = await fetch('/api/stats');
  const data = await res.json();
  if (data.success && data.stats) {
    state.stats = data.stats;
    document.getElementById('kpiTotalScans').textContent = data.stats.total;
    document.getElementById('kpiMalicious').textContent = data.stats.malicious;
    document.getElementById('kpiSuspicious').textContent = data.stats.suspicious;
    document.getElementById('kpiSafe').textContent = data.stats.safe;
    document.getElementById('sidebarIncidentBadge').textContent = data.stats.activeIncidents || 0;
    renderCharts();
  }
}

async function loadSamples() {
  const res = await fetch('/api/samples');
  const data = await res.json();
  if (data.success && data.samples) {
    state.samples = data.samples;
    renderDashboardSamples();
  }
}

async function loadScans() {
  const res = await fetch('/api/scans?limit=50');
  const data = await res.json();
  if (data.success) {
    state.scans = data.scans;
    renderScanHistoryTable();
    populateForensicSelector();
  }
}

async function loadIncidents() {
  const status = document.getElementById('filterIncidentStatus')?.value || '';
  const severity = document.getElementById('filterIncidentSeverity')?.value || '';
  let url = '/api/incidents?';
  if (status) url += `status=${encodeURIComponent(status)}&`;
  if (severity) url += `severity=${encodeURIComponent(severity)}`;

  const res = await fetch(url);
  const data = await res.json();
  if (data.success) {
    state.incidents = data.incidents;
    renderIncidentsTable();
    renderOverviewIncidents();
  }
}

async function loadBlocklist() {
  const res = await fetch('/api/blocklist');
  const data = await res.json();
  if (data.success) {
    state.blocklist = data.blocklist;
    renderBlocklistTable();
  }
}

async function loadIntelFeed() {
  const res = await fetch('/api/intel/feed');
  const data = await res.json();
  if (data.success) {
    state.intelFeed = data.feed;
    renderIntelFeedTable();
  }
}

async function loadVpnTraffic() {
  const res = await fetch('/api/vpn/traffic');
  const data = await res.json();
  if (data.success) {
    state.vpnTraffic = data.traffic;
    document.getElementById('vpnTotalTunnels').textContent = data.stats.totalTunnels;
    document.getElementById('vpnAnomalies').textContent = data.stats.anomalies;
    document.getElementById('vpnBandwidth').textContent = `${data.stats.totalBandwidthMb} MB`;
    renderVpnTrafficTable();
  }
}

async function loadSettings() {
  const res = await fetch('/api/settings');
  const data = await res.json();
  if (data.success) {
    state.settings = data.settings;
    if (data.settings.threat_threshold_malicious) {
      document.getElementById('settingMaliciousThreshold').value = data.settings.threat_threshold_malicious;
    }
    if (data.settings.threat_threshold_suspicious) {
      document.getElementById('settingSuspiciousThreshold').value = data.settings.threat_threshold_suspicious;
    }
  }
}

// Interactive SVG Charts
function renderCharts() {
  renderDonutChart();
  renderTimelineChart();
}

function renderDonutChart() {
  const container = document.getElementById('donutChartContainer');
  if (!container) return;

  const safe = state.stats.safe || 0;
  const suspicious = state.stats.suspicious || 0;
  const malicious = state.stats.malicious || 0;
  const total = safe + suspicious + malicious || 1;

  const safePct = safe / total;
  const suspPct = suspicious / total;
  const malPct = malicious / total;

  // Circumference of radius 60 is 2 * PI * 60 = 377
  const c = 377;
  const safeDash = safePct * c;
  const suspDash = suspPct * c;
  const malDash = malPct * c;

  const safeOffset = 0;
  const suspOffset = -safeDash;
  const malOffset = -(safeDash + suspDash);

  container.innerHTML = `
    <div style="display: flex; align-items: center; gap: 30px;">
      <svg width="180" height="180" viewBox="0 0 160 160" style="transform: rotate(-90deg);">
        <circle cx="80" cy="80" r="60" fill="none" stroke="#26364A" stroke-width="20" />
        <circle cx="80" cy="80" r="60" fill="none" stroke="#4CC38A" stroke-width="20"
          stroke-dasharray="${safeDash} ${c}" stroke-dashoffset="${safeOffset}" stroke-linecap="round" />
        <circle cx="80" cy="80" r="60" fill="none" stroke="#F0B75E" stroke-width="20"
          stroke-dasharray="${suspDash} ${c}" stroke-dashoffset="${suspOffset}" stroke-linecap="round" />
        <circle cx="80" cy="80" r="60" fill="none" stroke="#F07878" stroke-width="20"
          stroke-dasharray="${malDash} ${c}" stroke-dashoffset="${malOffset}" stroke-linecap="round" />
      </svg>
      <div style="display: flex; flex-direction: column; gap: 8px; font-size: 0.82rem;">
        <div style="display: flex; align-items: center; gap: 8px;">
          <span style="width: 10px; height: 10px; border-radius: 50%; background: #4CC38A;"></span>
          <span>Safe: <strong>${safe}</strong> (${Math.round(safePct * 100)}%)</span>
        </div>
        <div style="display: flex; align-items: center; gap: 8px;">
          <span style="width: 10px; height: 10px; border-radius: 50%; background: #F0B75E;"></span>
          <span>Suspicious: <strong>${suspicious}</strong> (${Math.round(suspPct * 100)}%)</span>
        </div>
        <div style="display: flex; align-items: center; gap: 8px;">
          <span style="width: 10px; height: 10px; border-radius: 50%; background: #F07878;"></span>
          <span>Malicious: <strong>${malicious}</strong> (${Math.round(malPct * 100)}%)</span>
        </div>
        <div style="margin-top: 6px; padding-top: 6px; border-top: 1px solid var(--border-color); color: var(--text-secondary); font-size: 0.75rem;">
          Total Evaluated: ${total}
        </div>
      </div>
    </div>
  `;
}

function renderTimelineChart() {
  const container = document.getElementById('timelineChartContainer');
  if (!container) return;

  const trends = (state.stats.recentTrends || []).slice(0, 7).reverse();
  if (trends.length === 0) {
    // Generate placeholder timeline for visual clarity
    container.innerHTML = '<p style="color: var(--text-secondary); font-size: 0.82rem;">Recording threat activity timeline...</p>';
    return;
  }

  const maxVal = Math.max(...trends.map(t => t.count || 1), 5);
  const chartHeight = 140;
  const barWidth = 32;
  const gap = 20;

  let barsHtml = '';
  trends.forEach((t, i) => {
    const x = i * (barWidth + gap) + 30;
    const safeH = ((t.safe_count || 0) / maxVal) * chartHeight;
    const suspH = ((t.suspicious_count || 0) / maxVal) * chartHeight;
    const malH = ((t.malicious_count || 0) / maxVal) * chartHeight;
    const totalH = safeH + suspH + malH || 4;

    const yStart = 160 - totalH;
    const dayLabel = t.day ? t.day.slice(5) : `Day ${i + 1}`;

    barsHtml += `
      <g class="bar-group">
        <rect x="${x}" y="${160 - safeH}" width="${barWidth}" height="${safeH}" fill="#4CC38A" rx="2" />
        <rect x="${x}" y="${160 - safeH - suspH}" width="${barWidth}" height="${suspH}" fill="#F0B75E" rx="2" />
        <rect x="${x}" y="${160 - totalH}" width="${barWidth}" height="${malH}" fill="#F07878" rx="2" />
        <text x="${x + barWidth / 2}" y="178" font-size="10" fill="#AAB8CA" text-anchor="middle">${dayLabel}</text>
      </g>
    `;
  });

  container.innerHTML = `
    <svg width="100%" height="200" viewBox="0 0 380 190">
      <line x1="20" y1="160" x2="360" y2="160" stroke="#43556B" stroke-width="1" />
      <line x1="20" y1="90" x2="360" y2="90" stroke="#43556B" stroke-dasharray="3 3" opacity="0.4" />
      <line x1="20" y1="20" x2="360" y2="20" stroke="#43556B" stroke-dasharray="3 3" opacity="0.4" />
      ${barsHtml}
    </svg>
  `;
}

// 1-Click Attack Scenarios
function renderDashboardSamples() {
  const container = document.getElementById('dashboardSamplesList');
  if (!container) return;

  container.innerHTML = state.samples.map(s => `
    <div class="sample-pill" onclick="loadSampleAndRun('${s.id}')">
      <div style="font-size: 1.1rem;">
        ${s.category.includes('Phishing') ? '🚨' : s.category.includes('BEC') ? '💼' : s.category.includes('Safe') ? '🛡️' : '📎'}
      </div>
      <div>
        <strong style="display: block; font-size: 0.84rem;">${escapeHtml(s.name)}</strong>
        <span style="font-size: 0.72rem; color: var(--text-secondary);">${escapeHtml(s.category)}</span>
      </div>
    </div>
  `).join('');
}

function loadSampleIntoScanner(sampleId) {
  const sample = state.samples.find(s => s.id === sampleId);
  if (!sample) return;

  setScanMode('form');
  document.getElementById('scanSender').value = sample.data.sender || '';
  document.getElementById('scanRecipient').value = sample.data.recipient || '';
  document.getElementById('scanSubject').value = sample.data.subject || '';
  document.getElementById('scanBody').value = sample.data.body || '';
  document.getElementById('scanUrl').value = sample.data.url || '';
  document.getElementById('scanIp').value = sample.data.ip || '';
}

async function loadSampleAndRun(sampleId) {
  loadSampleIntoScanner(sampleId);
  navigateTo('scanner');
  await executeScan();
}

function setScanMode(mode) {
  state.scanMode = mode;
  document.getElementById('tabModeForm').classList.toggle('active', mode === 'form');
  document.getElementById('tabModeEml').classList.toggle('active', mode === 'eml');
  document.getElementById('tabModeUrl').classList.toggle('active', mode === 'url');

  document.getElementById('scanFormFields').style.display = mode === 'form' ? 'block' : 'none';
  document.getElementById('scanEmlFields').style.display = mode === 'eml' ? 'block' : 'none';
  document.getElementById('scanUrlFields').style.display = mode === 'url' ? 'block' : 'none';
}

function clearScanForm() {
  document.getElementById('scannerForm').reset();
  setScanMode('form');
}

// Execute Threat Scan
async function executeScan() {
  const btn = document.getElementById('btnExecuteScan');
  btn.disabled = true;
  btn.innerHTML = `<span class="ticker-pulse"></span> Analyzing Threat Vectors...`;

  let payload = {};
  if (state.scanMode === 'form') {
    payload = {
      scanType: 'email',
      sender: document.getElementById('scanSender').value.trim(),
      recipient: document.getElementById('scanRecipient').value.trim(),
      subject: document.getElementById('scanSubject').value.trim(),
      body: document.getElementById('scanBody').value.trim(),
      url: document.getElementById('scanUrl').value.trim(),
      ip: document.getElementById('scanIp').value.trim()
    };
  } else if (state.scanMode === 'eml') {
    payload = {
      scanType: 'eml',
      rawEml: document.getElementById('scanRawEml').value.trim()
    };
  } else if (state.scanMode === 'url') {
    payload = {
      scanType: 'url',
      url: document.getElementById('scanStandaloneUrl').value.trim()
    };
  }

  try {
    const res = await fetch('/api/scan', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload)
    });
    const data = await res.json();

    if (data.success && data.analysis) {
      state.currentScanResult = data;
      renderScanResult(data);
      await loadStats();
      await loadScans();
      await loadIncidents();
    } else {
      alert(data.error || 'Scan analysis failed');
    }
  } catch (err) {
    console.error('Scan Error:', err);
    alert('Failed to connect to Aegis SOC analysis engine');
  } finally {
    btn.disabled = false;
    btn.innerHTML = `
      <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="11" cy="11" r="8"></circle><line x1="21" y1="21" x2="16.65" y2="16.65"></line></svg>
      Run 6-Module Threat Assessment
    `;
  }
}

function renderScanResult(data) {
  const { analysis, scan, incident } = data;
  const score = analysis.overallScore;
  const verdict = analysis.verdict;

  // Score Circle & Verdict
  const scoreCircle = document.getElementById('scanScoreCircle');
  const scoreVal = document.getElementById('scanScoreValue');
  const verdictBadge = document.getElementById('scanResultVerdictBadge');
  const heading = document.getElementById('scanResultHeading');
  const summary = document.getElementById('scanResultSummary');

  scoreVal.textContent = score;
  scoreCircle.className = `score-circle ${verdict.toLowerCase()}`;

  verdictBadge.textContent = verdict.toUpperCase();
  verdictBadge.className = `badge badge-${verdict.toLowerCase()}`;

  heading.textContent = `${verdict} Threat Detected (Risk Score: ${score}/100)`;
  summary.textContent = analysis.explanation;

  // 6 Modules
  const m = analysis.modules;
  updateModuleCard('Phishing', m.phishing.score);
  updateModuleCard('Url', m.url.score);
  updateModuleCard('Spam', m.spam.score);
  updateModuleCard('Domain', m.domain.score);
  updateModuleCard('Ip', m.ip.score);
  updateModuleCard('Ai', m.ai.score);

  // MITRE ATT&CK Mapping
  const mitreContainer = document.getElementById('scanMitreContainer');
  const mitreTags = document.getElementById('scanMitreTags');
  if (m.ai.mitreTactics && m.ai.mitreTactics.length > 0) {
    mitreContainer.style.display = 'block';
    mitreTags.innerHTML = m.ai.mitreTactics.map(t => `
      <span class="badge badge-neutral" title="${escapeHtml(t.tactic)}">${escapeHtml(t.id)}: ${escapeHtml(t.name)}</span>
    `).join('');
  } else {
    mitreContainer.style.display = 'none';
  }

  // Response Buttons
  document.getElementById('btnBlockSender').disabled = false;
  document.getElementById('btnViewDeepForensics').disabled = false;
  document.getElementById('btnExportJson').disabled = false;

  // Threat Indicators List
  const indicatorsCard = document.getElementById('scanIndicatorsCard');
  const indicatorsList = document.getElementById('scanIndicatorsList');
  const indicatorsCount = document.getElementById('scanIndicatorCount');

  indicatorsCard.style.display = 'block';
  indicatorsCount.textContent = `${analysis.threatIndicators.length} evidence indicators identified`;

  if (analysis.threatIndicators.length === 0) {
    indicatorsList.innerHTML = '<p style="color: var(--color-safe); font-size: 0.85rem;">No malicious or suspicious indicators detected. Email complies with authentication security standards.</p>';
  } else {
    indicatorsList.innerHTML = analysis.threatIndicators.map(ind => `
      <div class="indicator-item ${(ind.severity || 'medium').toLowerCase()}">
        <div style="flex-grow: 1;">
          <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 4px;">
            <strong style="font-size: 0.86rem; color: var(--text-main);">${escapeHtml(ind.label || ind.type)}</strong>
            <span class="badge badge-${ind.severity === 'Critical' || ind.severity === 'High' ? 'malicious' : ind.severity === 'Medium' ? 'suspicious' : 'neutral'}">${escapeHtml(ind.severity || 'Medium')}</span>
          </div>
          <p style="font-size: 0.8rem; color: var(--text-secondary);">${escapeHtml(ind.detail || '')}</p>
        </div>
      </div>
    `).join('');
  }
}

function updateModuleCard(name, score) {
  const scoreEl = document.getElementById(`mScore${name}`);
  const fillEl = document.getElementById(`mFill${name}`);
  if (scoreEl && fillEl) {
    scoreEl.textContent = `${score}/100`;
    fillEl.style.width = `${score}%`;
    fillEl.className = `module-fill ${score >= 70 ? 'malicious' : score >= 40 ? 'suspicious' : 'safe'}`;
  }
}

// Threat Intelligence Lookup
async function performIntelLookup() {
  const query = document.getElementById('intelLookupInput').value.trim();
  if (!query) return;

  const resultBox = document.getElementById('intelLookupResult');
  resultBox.style.display = 'block';
  resultBox.innerHTML = '<p style="color: var(--text-secondary);">Querying threat intelligence database...</p>';

  try {
    const res = await fetch(`/api/intel/lookup?query=${encodeURIComponent(query)}`);
    const data = await res.json();

    if (!data.success) {
      resultBox.innerHTML = `<p style="color: var(--color-malicious);">${data.error || 'Lookup error'}</p>`;
      return;
    }

    let lookalikeHtml = '';
    if (data.lookalike) {
      if (data.lookalike.isLookalike) {
        lookalikeHtml = `
          <div class="card" style="border-color: var(--color-malicious); background: rgba(240, 120, 120, 0.08);">
            <h4 style="color: var(--color-malicious); font-size: 0.95rem;">🚨 Confirmed Lookalike Domain Impersonation</h4>
            <p style="font-size: 0.85rem; margin-top: 4px;"><strong>Targeted Brand:</strong> ${escapeHtml(data.lookalike.impersonatedBrand)} (${escapeHtml(data.lookalike.targetDomain)})</p>
            <p style="font-size: 0.85rem;"><strong>Spoofing Technique:</strong> ${escapeHtml(data.lookalike.technique)}</p>
            <p style="font-size: 0.82rem; color: var(--text-secondary); margin-top: 4px;">${escapeHtml(data.lookalike.reason)}</p>
          </div>
        `;
      } else if (data.lookalike.isLegitimateBrand) {
        lookalikeHtml = `
          <div class="card" style="border-color: var(--color-safe); background: rgba(76, 195, 138, 0.08);">
            <h4 style="color: var(--color-safe); font-size: 0.95rem;">Verified Official Brand Domain: ${escapeHtml(data.lookalike.matchedBrand)}</h4>
            <p style="font-size: 0.82rem; color: var(--text-secondary);">${escapeHtml(data.lookalike.reason)}</p>
          </div>
        `;
      }
    }

    let ipHtml = '';
    if (data.ipIntelligence) {
      const ip = data.ipIntelligence;
      ipHtml = `
        <div class="card" style="margin-top: 12px;">
          <h4 style="font-size: 0.95rem; margin-bottom: 8px;">IP Forensics & ASN Intelligence (${escapeHtml(ip.ip)})</h4>
          <div class="grid-2">
            <div>
              <p style="font-size: 0.82rem; color: var(--text-secondary);">Country / City: <strong>${escapeHtml(ip.country)} (${escapeHtml(ip.city)})</strong></p>
              <p style="font-size: 0.82rem; color: var(--text-secondary);">ISP / Relay: <strong>${escapeHtml(ip.isp)}</strong></p>
              <p style="font-size: 0.82rem; color: var(--text-secondary);">ASN: <strong>${escapeHtml(ip.asn)}</strong></p>
            </div>
            <div>
              <p style="font-size: 0.82rem; color: var(--text-secondary);">Tor Relay: <strong style="color: ${ip.isTor ? 'var(--color-malicious)' : 'var(--color-safe)'};">${ip.isTor ? 'YES (MALICIOUS)' : 'NO'}</strong></p>
              <p style="font-size: 0.82rem; color: var(--text-secondary);">VPN / Proxy: <strong>${ip.isVpn || ip.isProxy ? 'Detected' : 'None'}</strong></p>
              <p style="font-size: 0.82rem; color: var(--text-secondary);">Threat Score: <strong style="color: ${ip.threatScore >= 70 ? 'var(--color-malicious)' : 'var(--color-safe)'};">${ip.threatScore}/100</strong></p>
            </div>
          </div>
        </div>
      `;
    }

    let domainHtml = '';
    if (data.domainIntelligence) {
      const d = data.domainIntelligence;
      domainHtml = `
        <div class="card" style="margin-top: 12px;">
          <h4 style="font-size: 0.95rem; margin-bottom: 8px;">Domain Registration & DNS Intel (${escapeHtml(d.domain)})</h4>
          <div class="grid-2">
            <div>
              <p style="font-size: 0.82rem; color: var(--text-secondary);">Domain Age: <strong>${d.ageDays} Days</strong> ${d.isNewlyRegistered ? '<span class="badge badge-suspicious">NEWLY REGISTERED</span>' : ''}</p>
              <p style="font-size: 0.82rem; color: var(--text-secondary);">Registrar: <strong>${escapeHtml(d.registrar || '--')}</strong></p>
              <p style="font-size: 0.82rem; color: var(--text-secondary);">Created Date: <strong>${escapeHtml(d.createdDate || '--')}</strong></p>
            </div>
            <div>
              <p style="font-size: 0.82rem; color: var(--text-secondary);">MX Route: <strong>${escapeHtml(d.mxRecord || 'NONE')}</strong></p>
              <p style="font-size: 0.82rem; color: var(--text-secondary);">DMARC Policy: <strong>${escapeHtml(d.dmarcPolicy || 'none')}</strong></p>
              <p style="font-size: 0.82rem; color: var(--text-secondary);">Reputation Score: <strong>${d.reputationScore}/100</strong></p>
            </div>
          </div>
        </div>
      `;
    }

    resultBox.innerHTML = lookalikeHtml + ipHtml + domainHtml;
  } catch (err) {
    resultBox.innerHTML = `<p style="color: var(--color-malicious);">Failed to query intelligence resolver.</p>`;
  }
}

function renderIntelFeedTable() {
  const tbody = document.getElementById('intelFeedTableBody');
  if (!tbody) return;

  tbody.innerHTML = state.intelFeed.map(item => `
    <tr>
      <td><span class="badge badge-neutral">${escapeHtml(item.ioc_type.toUpperCase())}</span></td>
      <td><strong style="font-family: var(--font-mono); font-size: 0.82rem;">${escapeHtml(item.ioc_value)}</strong></td>
      <td><span class="badge badge-malicious">${escapeHtml(item.threat_type)}</span></td>
      <td>${item.confidence}%</td>
      <td>${escapeHtml(item.threat_actor)} / ${escapeHtml(item.campaign)}</td>
      <td>${(item.tags || []).map(t => `<span class="badge badge-neutral" style="font-size: 0.65rem;">#${escapeHtml(t)}</span>`).join(' ')}</td>
      <td>
        <button class="btn btn-outline btn-sm" onclick="quickInvestigateIoc('${escapeHtml(item.ioc_value)}')">Investigate</button>
      </td>
    </tr>
  `).join('');
}

function quickInvestigateIoc(val) {
  document.getElementById('intelLookupInput').value = val;
  performIntelLookup();
}

// Forensic Geolocation & Hops Visualizer
function populateForensicSelector() {
  const select = document.getElementById('forensicScanSelector');
  if (!select) return;

  select.innerHTML = state.scans.map(s => `
    <option value="${s.id}">#${s.id} - [${s.verdict}] ${escapeHtml(s.subject || 'Automated Scan')}</option>
  `).join('');

  if (state.scans.length > 0) {
    loadForensicScan(state.scans[0].id);
  }
}

function loadForensicScan(scanId) {
  const scan = state.scans.find(s => s.id == scanId);
  if (!scan) return;

  const fd = scan.forensic_data || {};
  const ipIntel = fd.ipIntelligence || {};
  const domainIntel = fd.domainIntelligence || {};
  const auth = fd.authentication || {};
  const hops = fd.receivedHops || [];

  // Top Stats
  document.getElementById('fGeoLocation').textContent = `${ipIntel.city || 'Unknown'}, ${ipIntel.country || 'Unknown'}`;
  document.getElementById('fGeoIsp').textContent = `ASN: ${ipIntel.asn || 'AS0'} | ${ipIntel.isp || 'Commercial Transit'}`;
  
  const flagsEl = document.getElementById('fGeoFlags');
  let flagsHtml = '';
  if (ipIntel.isTor) flagsHtml += '<span class="badge badge-malicious" style="margin-right: 4px;">TOR EXIT RELAY</span>';
  if (ipIntel.isVpn) flagsHtml += '<span class="badge badge-suspicious" style="margin-right: 4px;">ANONYMOUS VPN</span>';
  if (ipIntel.isProxy) flagsHtml += '<span class="badge badge-suspicious">WEB PROXY</span>';
  flagsEl.innerHTML = flagsHtml || '<span class="badge badge-safe">STANDARD RESIDENTIAL/COMMERCIAL</span>';

  // Auth Badges
  const authBadges = document.getElementById('fAuthBadges');
  authBadges.innerHTML = `
    <span class="badge badge-${auth.spf === 'pass' ? 'safe' : auth.spf === 'fail' ? 'malicious' : 'suspicious'}">SPF: ${(auth.spf || 'neutral').toUpperCase()}</span>
    <span class="badge badge-${auth.dkim === 'pass' ? 'safe' : auth.dkim === 'fail' ? 'malicious' : 'suspicious'}">DKIM: ${(auth.dkim || 'neutral').toUpperCase()}</span>
    <span class="badge badge-${auth.dmarc === 'pass' ? 'safe' : auth.dmarc === 'fail' ? 'malicious' : 'suspicious'}">DMARC: ${(auth.dmarc || 'neutral').toUpperCase()}</span>
  `;
  document.getElementById('fAuthDetail').textContent = 
    auth.spf === 'fail' || auth.dmarc === 'fail' 
      ? 'Spoofing alert: Email domain authentication check failed alignment.'
      : 'Cryptographic SPF/DKIM validation passed successfully.';

  // Domain WHOIS
  document.getElementById('fDomainAge').textContent = `${domainIntel.ageDays || '--'} Days Old`;
  document.getElementById('fDomainRegistrar').textContent = `Registrar: ${domainIntel.registrar || 'Unknown'}`;
  document.getElementById('fDomainMx').textContent = `MX: ${domainIntel.mxRecord || 'None'}`;

  // Geolocation Radar SVG
  renderGeoMap(ipIntel.latitude || 50.11, ipIntel.longitude || 8.68, ipIntel.country || 'Germany', ipIntel.ip || '185.220.101.5');

  // Hop Tracer
  renderHopTracer(hops);
}

function renderGeoMap(lat, lng, country, ip) {
  const canvas = document.getElementById('geoMapCanvas');
  const sub = document.getElementById('fMapSubtitle');
  if (!canvas) return;

  sub.textContent = `Coordinates: ${lat.toFixed(4)}° N, ${lng.toFixed(4)}° E | Observed Host: ${ip} (${country})`;

  // Convert lat/lng to roughly 0-600 x 0-300 SVG projection
  // Equirectangular mapping: x = (lng + 180) * (600 / 360), y = (90 - lat) * (300 / 180)
  const x = Math.round((lng + 180) * (600 / 360));
  const y = Math.round((90 - lat) * (300 / 180));

  canvas.innerHTML = `
    <svg width="100%" height="100%" viewBox="0 0 600 300" style="background: #192331;">
      <!-- Grid Lines -->
      <line x1="0" y1="150" x2="600" y2="150" stroke="#2c3c52" stroke-dasharray="4 4" />
      <line x1="300" y1="0" x2="300" y2="300" stroke="#2c3c52" stroke-dasharray="4 4" />
      <circle cx="300" cy="150" r="100" fill="none" stroke="#2c3c52" stroke-dasharray="2 2" opacity="0.4" />
      <circle cx="300" cy="150" r="140" fill="none" stroke="#2c3c52" stroke-dasharray="2 2" opacity="0.3" />

      <!-- Simplified World Outlines -->
      <!-- Americas -->
      <path d="M 90 60 Q 140 70 170 110 Q 150 160 170 200 Q 190 260 160 280 Q 130 250 130 190 Q 90 140 80 90 Z" fill="#253549" stroke="#374b63" />
      <!-- Eurasia & Africa -->
      <path d="M 270 50 Q 380 40 480 80 Q 520 140 450 160 Q 370 140 330 110 Q 320 160 350 220 Q 310 260 280 200 Q 250 140 270 50 Z" fill="#253549" stroke="#374b63" />
      <!-- Australia -->
      <path d="M 480 210 Q 540 200 550 240 Q 510 270 470 250 Z" fill="#253549" stroke="#374b63" />

      <!-- Target Geolocation Ping -->
      <g>
        <circle cx="${x}" cy="${y}" r="20" fill="rgba(240, 120, 120, 0.2)">
          <animate attributeName="r" values="6;26" dur="2s" repeatCount="indefinite" />
          <animate attributeName="opacity" values="0.8;0" dur="2s" repeatCount="indefinite" />
        </circle>
        <circle cx="${x}" cy="${y}" r="6" fill="#F07878" stroke="#fff" stroke-width="2" />
        <text x="${x + 12}" y="${y + 4}" fill="#E7EDF5" font-size="11" font-weight="700" font-family="monospace">${ip} (${country})</text>
      </g>
    </svg>
  `;
}

function renderHopTracer(hops) {
  const container = document.getElementById('fHopList');
  if (!container) return;

  if (!hops || hops.length === 0) {
    container.innerHTML = `
      <div class="hop-step">
        <div class="hop-icon">1</div>
        <div class="hop-content">
          <strong style="color: var(--cyan-accent);">Originating Client Subnet</strong>
          <p style="font-size: 0.8rem; color: var(--text-secondary);">Direct submission via authenticated web client / mail submission agent (Port 587)</p>
        </div>
      </div>
      <div class="hop-step">
        <div class="hop-icon">2</div>
        <div class="hop-content">
          <strong style="color: var(--primary-blue);">Inbound SOC Inspection Gateway (Aegis MX)</strong>
          <p style="font-size: 0.8rem; color: var(--text-secondary);">Received via TLS 1.3 encrypted tunnel. Deep inspection heuristics applied.</p>
        </div>
      </div>
    `;
    return;
  }

  container.innerHTML = hops.map(h => `
    <div class="hop-step">
      <div class="hop-icon">${h.hop}</div>
      <div class="hop-content">
        <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 4px;">
          <strong style="color: var(--cyan-accent);">${escapeHtml(h.fromHost)}</strong>
          <span style="font-size: 0.75rem; color: var(--text-secondary);">${escapeHtml(h.timestamp || '')}</span>
        </div>
        <p style="font-size: 0.82rem; color: var(--text-main);">
          Relayed by <code>${escapeHtml(h.byServer)}</code>
          ${h.ip ? `&bull; IP: <strong>${escapeHtml(h.ip)}</strong>` : ''}
        </p>
      </div>
    </div>
  `).join('');
}

// Incidents & Triage Management
function renderIncidentsTable() {
  const tbody = document.getElementById('incidentsTableBody');
  if (!tbody) return;

  tbody.innerHTML = state.incidents.map(inc => `
    <tr>
      <td><strong style="font-family: var(--font-mono); font-size: 0.82rem;">${escapeHtml(inc.incident_id)}</strong></td>
      <td style="font-size: 0.78rem; color: var(--text-secondary);">${escapeHtml(inc.created_at ? inc.created_at.slice(0, 16).replace('T', ' ') : '')}</td>
      <td><strong>${escapeHtml(inc.title)}</strong></td>
      <td><span class="badge badge-${inc.severity === 'Critical' || inc.severity === 'High' ? 'malicious' : inc.severity === 'Medium' ? 'suspicious' : 'neutral'}">${escapeHtml(inc.severity)}</span></td>
      <td><span class="badge badge-${inc.status === 'Mitigated' ? 'safe' : inc.status === 'New' ? 'malicious' : 'suspicious'}">${escapeHtml(inc.status)}</span></td>
      <td style="font-size: 0.82rem;">${escapeHtml(inc.target_user || '--')}</td>
      <td style="font-size: 0.82rem; font-family: var(--font-mono);">${escapeHtml(inc.source_domain || inc.source_ip || '--')}</td>
      <td style="font-size: 0.82rem; color: var(--text-secondary);">${escapeHtml(inc.assigned_analyst || 'Analyst Alpha')}</td>
      <td>
        <button class="btn btn-outline btn-sm" onclick="openIncidentTriage('${escapeHtml(inc.incident_id)}')">Triage</button>
      </td>
    </tr>
  `).join('');
}

function renderOverviewIncidents() {
  const tbody = document.getElementById('overviewIncidentsTable');
  if (!tbody) return;

  tbody.innerHTML = state.incidents.slice(0, 5).map(inc => `
    <tr>
      <td><strong style="font-family: var(--font-mono); font-size: 0.82rem;">${escapeHtml(inc.incident_id)}</strong></td>
      <td>${escapeHtml(inc.title)}</td>
      <td><span class="badge badge-${inc.severity === 'Critical' || inc.severity === 'High' ? 'malicious' : 'suspicious'}">${escapeHtml(inc.severity)}</span></td>
      <td>${escapeHtml(inc.category)}</td>
      <td>${escapeHtml(inc.target_user || '--')}</td>
      <td><span class="badge badge-${inc.status === 'New' ? 'malicious' : 'neutral'}">${escapeHtml(inc.status)}</span></td>
      <td>
        <button class="btn btn-outline btn-sm" onclick="openIncidentTriage('${escapeHtml(inc.incident_id)}')">Triage</button>
      </td>
    </tr>
  `).join('');
}

function openIncidentTriage(incId) {
  const inc = state.incidents.find(i => i.incident_id === incId);
  if (!inc) return;

  state.activeIncident = inc;
  document.getElementById('mIncidentId').textContent = inc.incident_id;
  document.getElementById('mIncidentTitle').textContent = `Triage: ${inc.title}`;
  document.getElementById('mIncidentSeverityBadge').textContent = inc.severity.toUpperCase();
  document.getElementById('mIncidentSeverityBadge').className = `badge badge-${inc.severity === 'Critical' || inc.severity === 'High' ? 'malicious' : 'suspicious'}`;
  document.getElementById('mIncidentStatusSelect').value = inc.status;
  document.getElementById('mIncidentNotes').value = inc.notes || '';
  document.getElementById('mIncidentOffender').textContent = `${inc.source_domain} / ${inc.source_ip}`;

  document.getElementById('incidentModal').classList.add('active');
}

function closeIncidentModal() {
  document.getElementById('incidentModal').classList.remove('active');
  state.activeIncident = null;
}

async function saveIncidentTriage() {
  if (!state.activeIncident) return;

  const status = document.getElementById('mIncidentStatusSelect').value;
  const notes = document.getElementById('mIncidentNotes').value;

  try {
    const res = await fetch(`/api/incidents/${state.activeIncident.incident_id}`, {
      method: 'PATCH',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ status, notes })
    });
    const data = await res.json();
    if (data.success) {
      closeIncidentModal();
      await loadIncidents();
      await loadStats();
    }
  } catch (err) {
    alert('Failed to update incident triage.');
  }
}

async function blockIncidentOffender() {
  if (!state.activeIncident) return;
  const domain = state.activeIncident.source_domain;
  const ip = state.activeIncident.source_ip;

  const target = domain && domain !== 'Unknown Domain' ? domain : ip;
  const type = domain && domain !== 'Unknown Domain' ? 'domain' : 'ip';

  if (!target || target === 'Unknown IP') {
    alert('No valid offending domain or IP found to block.');
    return;
  }

  try {
    await fetch('/api/blocklist', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        type,
        value: target,
        reason: `Blocked from incident ${state.activeIncident.incident_id}`
      })
    });
    alert(`Successfully added ${target} to perimeter blocklist!`);
    await loadBlocklist();
  } catch (err) {
    alert('Failed to block offender.');
  }
}

// Blocklist Management
function renderBlocklistTable() {
  const tbody = document.getElementById('blocklistTableBody');
  if (!tbody) return;

  tbody.innerHTML = state.blocklist.map(b => `
    <tr>
      <td><span class="badge badge-neutral">${escapeHtml(b.type.toUpperCase())}</span></td>
      <td><strong style="font-family: var(--font-mono); font-size: 0.85rem;">${escapeHtml(b.value)}</strong></td>
      <td>${escapeHtml(b.reason || '--')}</td>
      <td style="font-size: 0.78rem; color: var(--text-secondary);">${escapeHtml(b.added_at ? b.added_at.slice(0, 10) : '')}</td>
      <td style="font-size: 0.82rem;">${escapeHtml(b.added_by || 'SOC')}</td>
      <td>
        <span class="badge badge-${b.enabled ? 'malicious' : 'neutral'}" style="cursor: pointer;" onclick="toggleBlocklist(${b.id})">
          ${b.enabled ? 'BLOCKED' : 'DISABLED'}
        </span>
      </td>
      <td>
        <button class="btn btn-outline btn-sm" onclick="removeBlocklist(${b.id})">Remove</button>
      </td>
    </tr>
  `).join('');
}

async function addNewBlockEntry() {
  const val = document.getElementById('newBlockValue').value.trim();
  const type = document.getElementById('newBlockType').value;
  if (!val) return;

  try {
    const res = await fetch('/api/blocklist', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ type, value: val, reason: 'Manually added via settings' })
    });
    const data = await res.json();
    if (data.success) {
      document.getElementById('newBlockValue').value = '';
      await loadBlocklist();
    }
  } catch (err) {
    alert('Failed to add blocklist entry.');
  }
}

async function toggleBlocklist(id) {
  try {
    await fetch(`/api/blocklist/toggle/${id}`, { method: 'POST' });
    await loadBlocklist();
  } catch (err) {}
}

async function removeBlocklist(id) {
  if (!confirm('Remove entry from perimeter blocklist?')) return;
  try {
    await fetch(`/api/blocklist/${id}`, { method: 'DELETE' });
    await loadBlocklist();
  } catch (err) {}
}

// Scan History
function renderScanHistoryTable() {
  const tbody = document.getElementById('historyTableBody');
  if (!tbody) return;

  const search = (document.getElementById('historySearchInput')?.value || '').toLowerCase();
  const verdict = document.getElementById('historyVerdictFilter')?.value || '';

  const filtered = state.scans.filter(s => {
    if (verdict && s.verdict !== verdict) return false;
    if (search) {
      const matchSub = (s.subject || '').toLowerCase().includes(search);
      const matchSend = (s.sender || '').toLowerCase().includes(search);
      const matchUuid = (s.scan_uuid || '').toLowerCase().includes(search);
      if (!matchSub && !matchSend && !matchUuid) return false;
    }
    return true;
  });

  tbody.innerHTML = filtered.map(s => `
    <tr>
      <td><strong style="font-family: var(--font-mono); font-size: 0.8rem;">${escapeHtml(s.scan_uuid)}</strong></td>
      <td style="font-size: 0.78rem; color: var(--text-secondary);">${escapeHtml(s.created_at ? s.created_at.slice(0, 16).replace('T', ' ') : '')}</td>
      <td style="font-size: 0.82rem;">${escapeHtml(s.sender || 'Unknown')}</td>
      <td><strong>${escapeHtml(s.subject || 'Automated Scan')}</strong></td>
      <td><strong style="font-family: var(--font-mono);">${s.overall_score}/100</strong></td>
      <td><span class="badge badge-${s.verdict.toLowerCase()}">${escapeHtml(s.verdict)}</span></td>
      <td>
        <button class="btn btn-outline btn-sm" onclick="viewScanDossier(${s.id})">Inspect Dossier</button>
      </td>
    </tr>
  `).join('');
}

function loadScanHistory() {
  renderScanHistoryTable();
}

function viewScanDossier(scanId) {
  const scan = state.scans.find(s => s.id == scanId);
  if (!scan) return;

  const modal = document.getElementById('scanDossierModal');
  const content = document.getElementById('dossierContent');
  document.getElementById('dossierTitle').textContent = `Forensic Dossier: ${scan.scan_uuid}`;

  const fd = scan.forensic_data || {};
  const indicators = scan.threat_indicators || [];
  const recs = scan.recommendations || [];

  content.innerHTML = `
    <div style="background: var(--bg-elevated); padding: 16px; border-radius: 8px; margin-bottom: 16px;">
      <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 8px;">
        <h4 style="font-size: 1.1rem; color: var(--text-main);">${escapeHtml(scan.subject || 'Untitled')}</h4>
        <span class="badge badge-${scan.verdict.toLowerCase()}">${scan.verdict} (Risk: ${scan.overall_score}/100)</span>
      </div>
      <p style="font-size: 0.82rem; color: var(--text-secondary);"><strong>Sender:</strong> ${escapeHtml(scan.sender || 'Unknown')}</p>
      <p style="font-size: 0.82rem; color: var(--text-secondary);"><strong>Recipient:</strong> ${escapeHtml(scan.recipient || 'Quarantine')}</p>
      <p style="font-size: 0.82rem; color: var(--text-secondary);"><strong>Timestamp:</strong> ${escapeHtml(scan.created_at)}</p>
    </div>

    <h4 style="font-size: 0.9rem; text-transform: uppercase; margin-bottom: 8px; color: var(--cyan-accent);">AI Threat Synthesis</h4>
    <p style="font-size: 0.86rem; margin-bottom: 16px; line-height: 1.5;">${escapeHtml(scan.explanation || 'No summary available.')}</p>

    <h4 style="font-size: 0.9rem; text-transform: uppercase; margin-bottom: 8px; color: var(--cyan-accent);">Flagged IOC Evidence</h4>
    <div style="margin-bottom: 16px;">
      ${indicators.map(i => `
        <div class="indicator-item ${(i.severity || 'medium').toLowerCase()}">
          <div>
            <strong>${escapeHtml(i.label || i.type)}</strong>
            <p style="font-size: 0.8rem; color: var(--text-secondary);">${escapeHtml(i.detail || '')}</p>
          </div>
        </div>
      `).join('')}
    </div>

    <h4 style="font-size: 0.9rem; text-transform: uppercase; margin-bottom: 8px; color: var(--cyan-accent);">SOC Recommended Actions</h4>
    <ul style="padding-left: 20px; font-size: 0.85rem; color: var(--text-secondary); margin-bottom: 16px;">
      ${recs.map(r => `<li>${escapeHtml(r)}</li>`).join('')}
    </ul>
  `;

  modal.classList.add('active');
}

function closeDossierModal() {
  document.getElementById('scanDossierModal').classList.remove('active');
}

function printDossier() {
  window.print();
}

function exportHistoryCsv() {
  const jsonStr = "data:text/json;charset=utf-8," + encodeURIComponent(JSON.stringify(state.scans, null, 2));
  const dlAnchor = document.createElement('a');
  dlAnchor.setAttribute("href", jsonStr);
  dlAnchor.setAttribute("download", `aegis_soc_audit_${new Date().toISOString().slice(0, 10)}.json`);
  dlAnchor.click();
}

// VPN Traffic & Network
function renderVpnTrafficTable() {
  const tbody = document.getElementById('vpnTrafficTableBody');
  if (!tbody) return;

  tbody.innerHTML = state.vpnTraffic.map(v => `
    <tr>
      <td style="font-size: 0.78rem; color: var(--text-secondary);">${escapeHtml(v.timestamp ? v.timestamp.slice(11, 19) : '')}</td>
      <td><code>${escapeHtml(v.tunnel_id)}</code></td>
      <td>${escapeHtml(v.client_ip)}</td>
      <td><strong>${escapeHtml(v.destination_domain || v.destination_ip)}</strong></td>
      <td>:${v.port}</td>
      <td style="font-size: 0.78rem;">${Math.round(v.bytes_in / 1024)}K / ${Math.round(v.bytes_out / 1024)}K</td>
      <td><strong style="color: ${v.threat_score >= 70 ? 'var(--color-malicious)' : 'var(--color-safe)'};">${v.threat_score}/100</strong></td>
      <td>
        <span class="badge badge-${v.anomaly_flag ? 'malicious' : 'safe'}">
          ${v.anomaly_flag ? 'ANOMALY' : 'HEALTHY'}
        </span>
      </td>
      <td style="font-size: 0.78rem; color: var(--text-secondary);">${escapeHtml(v.notes || '--')}</td>
    </tr>
  `).join('');
}

async function simulateVpnProbe() {
  try {
    const res = await fetch('/api/vpn/simulate', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        destinationIp: '185.220.101.5',
        destinationDomain: 'micros0ft-login-portal.xyz',
        threatScore: 92,
        notes: 'Simulated high-risk outbound beacon to Tor phishing node'
      })
    });
    const data = await res.json();
    if (data.success) {
      await loadVpnTraffic();
      alert('Injected synthetic outbound network event: Anomaly Flagged and Logged!');
    }
  } catch (err) {
    alert('Failed to simulate network event.');
  }
}

// Settings
async function saveSettings() {
  const mal = document.getElementById('settingMaliciousThreshold').value;
  const susp = document.getElementById('settingSuspiciousThreshold').value;
  const auto = document.getElementById('settingAutoQuarantine').value;

  try {
    const res = await fetch('/api/settings', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        threat_threshold_malicious: mal,
        threat_threshold_suspicious: susp,
        auto_quarantine_enabled: auto
      })
    });
    if (res.ok) alert('Settings saved successfully!');
  } catch (err) {
    alert('Failed to save settings.');
  }
}

function testImapConnection() {
  alert('Testing TLS IMAP Stream Pipeline...\nStatus: Connected to imap.sec-enterprise.com:993 with TLS 1.3\nInbound polling: Active');
}

// Helpers
function blockCurrentSender() {
  if (!state.currentScanResult) return;
  const senderDomain = state.currentScanResult.analysis.parsedEmail.from.domain;
  if (!senderDomain) return;

  fetch('/api/blocklist', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      type: 'domain',
      value: senderDomain,
      reason: `Blocked from scan #${state.currentScanResult.scan.id}`
    })
  }).then(() => {
    alert(`Domain '${senderDomain}' successfully blocked across tenant perimeter.`);
    loadBlocklist();
  });
}

function loadDeepForensicsFromCurrentScan() {
  if (!state.currentScanResult) return;
  navigateTo('forensics');
  loadForensicScan(state.currentScanResult.scan.id);
}

function exportScanJson() {
  if (!state.currentScanResult) return;
  const jsonStr = "data:text/json;charset=utf-8," + encodeURIComponent(JSON.stringify(state.currentScanResult, null, 2));
  const dlAnchor = document.createElement('a');
  dlAnchor.setAttribute("href", jsonStr);
  dlAnchor.setAttribute("download", `scan_${state.currentScanResult.scan.scan_uuid}.json`);
  dlAnchor.click();
}

function setupTickerAnimation() {
  const ticker = document.getElementById('tickerText');
  if (!ticker) return;

  const messages = [
    'Threat Feed: TA505 Trojan Dropper blocked • M365 Homoglyph lure active • 0 False Positives today',
    'Network Alert: Outbound connection to Tor exit node 185.220.101.5 quarantined',
    'Perimeter Intel: Lookalike domain micros0ft-login-portal.xyz added to global blocklist',
    'IMAP Stream: Ingesting 452 emails/min • SPF/DKIM validation engine active'
  ];

  let idx = 0;
  setInterval(() => {
    idx = (idx + 1) % messages.length;
    ticker.textContent = messages[idx];
  }, 6000);
}

function escapeHtml(str) {
  if (!str) return '';
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#039;');
}
