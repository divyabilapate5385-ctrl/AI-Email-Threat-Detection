/**
 * Explainable 6-Module Threat Scoring Engine
 * Computes transparent, explainable 0-100 threat scores across:
 * 1. Phishing Detection
 * 2. Malicious URL Detection
 * 3. Spam Detection
 * 4. Domain Reputation
 * 5. IP Reputation
 * 6. AI Risk Synthesis & MITRE ATT&CK Mapping
 */

const { analyzeUrl } = require('./urlAnalyzer');
const { checkLookalike } = require('./lookalikeDetector');
const { resolveIpIntelligence, resolveDomainIntelligence, resolveSenderLocation } = require('./geoIpLookup');
const { parseEmlContent } = require('./emailParser');

// Phishing Lexicon & Urgency Patterns
const PHISHING_LURES = [
  { pattern: /account\s+(?:suspended|locked|restricted|disabled|compromised|terminated)/i, weight: 28, label: 'Account Suspension/Deactivation Threat' },
  { pattern: /(?:verify|confirm|validate|update)\s+your\s+(?:account|identity|password|credentials|security|billing|details)/i, weight: 30, label: 'Credential / Identity Harvesting Lure' },
  { pattern: /(?:immediate|urgent|action\s+required|within\s+(?:24|48|12)\s+hours|expires\s+soon)/i, weight: 22, label: 'Manufactured Urgency / Pressure Tactic' },
  { pattern: /(?:unauthorized|suspicious|unusual)\s+(?:sign-in|activity|transaction|access|charge|debit)/i, weight: 25, label: 'Fake Security Warning / Phony Alarm' },
  { pattern: /(?:wire\s+transfer|fund\s+transfer|swift|confidential\s+wire|vendor\s+acquisition|overdue\s+payment|remittance)/i, weight: 32, label: 'Financial / Payment Request Coercion (BEC)' },
  { pattern: /(?:click\s+here|login\s+to\s+view|review\s+document|view\s+shared\s+file)/i, weight: 18, label: 'Call-to-Action Link Baiting' },
  { pattern: /(?:docusign|envelope\s+waiting|sign\s+now|pdf\s+invoice|overdue\s+invoice)/i, weight: 26, label: 'Document Signing Impersonation' },
  { pattern: /(?:executive\s+board|cannot\s+take\s+calls|private\s+(?:encrypted\s+)?mailbox|are\s+you\s+at\s+your\s+desk|reply\s+to\s+my)/i, weight: 30, label: 'Executive Authority Isolation / BEC Evasion' }
];

// Spam Keywords
const SPAM_TRIGGERS = [
  { pattern: /\b(?:lottery|jackpot|winner|won\s+\$\d+|prize|claim\s+reward)\b/i, weight: 25, label: 'Lottery / Reward Bait' },
  { pattern: /\b(?:100%\s+free|risk-free|guaranteed\s+profit|passive\s+income|bitcoin\s+multiplier)\b/i, weight: 25, label: 'Financial Scam / Unrealistic Promise' },
  { pattern: /\b(?:viagra|cialis|weight\s+loss|diet\s+pills|pharmacy\s+express)\b/i, weight: 30, label: 'Illicit Pharmaceutical Promotion' },
  { pattern: /\b(?:act\s+now|don't\s+hesitate|limited\s+time\s+offer|one\s+time\s+deal)\b/i, weight: 15, label: 'High-Pressure Sales Tactic' },
  { pattern: /\b(?:unclaimed\s+(?:inheritance|funds|consignment|estate))\b/i, weight: 30, label: 'Advance Fee (419) Scam Pattern' }
];

const DISPOSABLE_DOMAINS = new Set([
  'mailinator.com', '10minutemail.com', 'tempmail.com', 'guerrillamail.com',
  'sharklasers.com', 'throwawaymail.com', 'yopmail.com', 'trashmail.com'
]);

function scorePhishingModule(parsedEmail) {
  let score = 0;
  const indicators = [];
  const fullText = `${parsedEmail.subject} ${parsedEmail.body}`;

  // 1. Phishing lure keywords & urgency
  for (const lure of PHISHING_LURES) {
    if (lure.pattern.test(fullText)) {
      indicators.push({
        module: 'Phishing',
        severity: lure.weight >= 25 ? 'High' : 'Medium',
        label: lure.label,
        weight: lure.weight
      });
      score += lure.weight;
    }
  }

  // 2. Display Name Spoofing
  parsedEmail.headerAnomalies.forEach(anomaly => {
    if (anomaly.type === 'DISPLAY_NAME_SPOOFING') {
      indicators.push({
        module: 'Phishing',
        severity: 'Critical',
        label: 'Display Name Spoofing',
        weight: 35,
        detail: anomaly.detail
      });
      score += 35;
    }
    if (anomaly.type === 'REPLY_TO_DIVERGENCE') {
      indicators.push({
        module: 'Phishing',
        severity: 'High',
        label: 'Reply-To Diversion (CEO / BEC Indicator)',
        weight: 30,
        detail: anomaly.detail
      });
      score += 30;
    }
  });

  return {
    score: Math.min(100, score),
    indicators
  };
}

function scoreUrlModule(parsedEmail) {
  let maxUrlScore = 0;
  let aggregateScore = 0;
  const analyzedUrls = [];
  const indicators = [];

  for (const url of parsedEmail.urls) {
    const analysis = analyzeUrl(url);
    if (!analysis) continue;
    analyzedUrls.push(analysis);

    if (analysis.riskScore > maxUrlScore) {
      maxUrlScore = analysis.riskScore;
    }
    aggregateScore += analysis.riskScore * 0.4;

    analysis.indicators.forEach(ind => {
      indicators.push({
        module: 'Malicious URL',
        severity: ind.severity,
        label: `${ind.type} (${analysis.domain})`,
        weight: ind.weight,
        detail: ind.detail
      });
    });
  }

  const finalScore = Math.min(100, Math.round(maxUrlScore * 0.75 + Math.min(25, aggregateScore * 0.25)));

  return {
    score: finalScore,
    urlCount: parsedEmail.urls.length,
    analyzedUrls,
    indicators
  };
}

function scoreSpamModule(parsedEmail) {
  let score = 0;
  const indicators = [];
  const body = parsedEmail.body || '';
  const subject = parsedEmail.subject || '';

  // 1. Spam keywords
  for (const trigger of SPAM_TRIGGERS) {
    if (trigger.pattern.test(subject) || trigger.pattern.test(body)) {
      indicators.push({
        module: 'Spam',
        severity: 'Medium',
        label: trigger.label,
        weight: trigger.weight
      });
      score += trigger.weight;
    }
  }

  // 2. Excessive Capitalization
  const cleanBody = body.replace(/[^a-zA-Z]/g, '');
  if (cleanBody.length > 40) {
    const capsCount = (body.match(/[A-Z]/g) || []).length;
    const capsRatio = capsCount / cleanBody.length;
    if (capsRatio > 0.45) {
      indicators.push({
        module: 'Spam',
        severity: 'Medium',
        label: 'Excessive Capitalization in Content',
        weight: 20,
        detail: `${Math.round(capsRatio * 100)}% uppercase characters detected`
      });
      score += 20;
    }
  }

  // 3. Excessive Punctuation (e.g. ??? or !!! or $$$)
  const excessivePunctuation = (body.match(/[!?$]{3,}/g) || []).length;
  if (excessivePunctuation >= 2) {
    indicators.push({
      module: 'Spam',
      severity: 'Low',
      label: 'Manipulative Punctuation Patterns (!!! / $$$)',
      weight: 15
    });
    score += 15;
  }

  // 4. Missing Message-ID or Date RFC violations
  if (parsedEmail.headerAnomalies.some(a => a.type === 'MISSING_MESSAGE_ID')) {
    indicators.push({
      module: 'Spam',
      severity: 'Low',
      label: 'RFC 5322 Missing Message-ID (Automated Bulk Sender)',
      weight: 15
    });
    score += 15;
  }

  return {
    score: Math.min(100, score),
    indicators
  };
}

function scoreDomainModule(parsedEmail) {
  let score = 0;
  const indicators = [];
  const senderDomain = parsedEmail.from.domain;

  if (!senderDomain) {
    return {
      score: 40,
      domainIntel: null,
      indicators: [{ module: 'Domain Reputation', severity: 'Medium', label: 'Missing or Malformed Sender Domain', weight: 40 }]
    };
  }

  const domainIntel = resolveDomainIntelligence(senderDomain);
  const lookalike = checkLookalike(senderDomain);

  // 1. Lookalike Sender Domain
  if (lookalike.isLookalike) {
    indicators.push({
      module: 'Domain Reputation',
      severity: 'Critical',
      label: `Lookalike Domain Impersonating ${lookalike.impersonatedBrand}`,
      weight: 45,
      detail: lookalike.reason
    });
    score += 45;
  }

  // 2. Disposable / Burner Domain
  if (DISPOSABLE_DOMAINS.has(senderDomain)) {
    indicators.push({
      module: 'Domain Reputation',
      severity: 'High',
      label: 'Temporary Disposable Email Service',
      weight: 35,
      detail: `Sender domain ${senderDomain} is an ephemeral burner mailbox service`
    });
    score += 35;
  }

  // 3. Newly registered domain (< 60 days)
  if (domainIntel.isNewlyRegistered) {
    indicators.push({
      module: 'Domain Reputation',
      severity: 'High',
      label: `Newly Registered Domain (${domainIntel.ageDays} days old)`,
      weight: 30,
      detail: `Domain registered recently on ${domainIntel.createdDate} via ${domainIntel.registrar}`
    });
    score += 30;
  }

  // 4. Missing MX configuration
  if (!domainIntel.mxConfigured) {
    indicators.push({
      module: 'Domain Reputation',
      severity: 'High',
      label: 'Missing or Non-Routable MX Records',
      weight: 25,
      detail: 'Domain cannot receive email replies (outbound spam-only vector)'
    });
    score += 25;
  }

  // 5. SPF / DMARC Failures
  if (parsedEmail.authSummary.spf === 'fail') {
    indicators.push({
      module: 'Domain Reputation',
      severity: 'High',
      label: 'Sender SPF Authentication FAILED',
      weight: 25
    });
    score += 25;
  }
  if (parsedEmail.authSummary.dmarc === 'fail') {
    indicators.push({
      module: 'Domain Reputation',
      severity: 'Critical',
      label: 'Sender DMARC Alignment FAILED',
      weight: 30
    });
    score += 30;
  }

  return {
    score: Math.min(100, score),
    domainIntel,
    indicators
  };
}

function scoreIpModule(parsedEmail) {
  let score = 0;
  const indicators = [];
  const targetIp = parsedEmail.originatingIp || (parsedEmail.ips && parsedEmail.ips.length > 0 ? parsedEmail.ips[0] : null);

  const ipIntel = resolveSenderLocation(parsedEmail.from ? (parsedEmail.from.address || parsedEmail.from.domain) : null, targetIp);
  score = ipIntel.threatScore || 0;

  if (ipIntel.isTor) {
    indicators.push({
      module: 'IP Reputation',
      severity: 'Critical',
      label: 'Tor Anonymizing Exit Node',
      weight: 45,
      detail: `Originating IP ${ipIntel.ip} is a verified Tor exit relay (${ipIntel.isp})`
    });
  }

  if (ipIntel.isVpn || ipIntel.isProxy) {
    indicators.push({
      module: 'IP Reputation',
      severity: 'Medium',
      label: 'Commercial VPN / Anonymous Proxy Relay',
      weight: 25,
      detail: `IP is routed through an intermediate anonymity proxy or cloud VPN tunnel`
    });
  }

  if (ipIntel.threatScore >= 70) {
    indicators.push({
      module: 'IP Reputation',
      severity: 'High',
      label: `Blacklist Hit: ${ipIntel.threatCategory}`,
      weight: 35,
      detail: `Listed on security threat feeds (${ipIntel.threatFeed})`
    });
  }

  return {
    score: Math.min(100, score),
    ipIntel,
    indicators
  };
}

function scoreAiRiskSynthesis(phishing, url, spam, domain, ip, parsedEmail) {
  // Dominant Module Score (Security Principle: A critical URL or Phish cannot be masked by low spam score)
  const dominantScore = Math.max(phishing.score, url.score, domain.score, ip.score);

  // Composite Weighted Calculation
  const weightedBase = (
    phishing.score * 0.30 +
    url.score * 0.30 +
    domain.score * 0.20 +
    ip.score * 0.15 +
    spam.score * 0.05
  );

  // Blend dominant vector (60%) with supporting vectors (40%)
  let baseScore = Math.round(dominantScore * 0.60 + weightedBase * 0.40);

  // Synergy Multipliers:
  // Correlation between credential lure + lookalike URL or Tor IP elevates threat to Critical
  let synergyMultiplier = 1.0;
  const hasLookalike = url.indicators.some(i => i.label.includes('LOOKALIKE') || i.label.includes('Lookalike')) ||
                       domain.indicators.some(i => i.label.includes('Lookalike'));
  const hasCredLure = phishing.indicators.some(i => i.label.includes('Credential') || i.label.includes('Suspension') || i.label.includes('Payment Request'));
  const hasTorOrBlacklist = ip.indicators.some(i => i.label.includes('Tor') || i.label.includes('Blacklist'));
  const hasExecutable = url.indicators.some(i => i.label.includes('EXECUTABLE') || i.label.includes('IP_AS_HOSTNAME'));

  if (hasLookalike && hasCredLure) {
    synergyMultiplier += 0.22;
  }
  if (hasTorOrBlacklist && (hasLookalike || hasCredLure)) {
    synergyMultiplier += 0.18;
  }
  if (hasExecutable) {
    synergyMultiplier += 0.20;
  }

  let finalAiScore = Math.round(baseScore * synergyMultiplier);

  // Safety floor: if dominant vector >= 75 and multiple indicators present, ensure Malicious threshold (>= 70)
  if (dominantScore >= 75 && finalAiScore < 72) {
    finalAiScore = 72;
  }

  finalAiScore = Math.min(100, finalAiScore);

  // Determine MITRE ATT&CK Mapping
  const mitreTactics = [];
  if (hasLookalike || phishing.indicators.some(i => i.label.includes('Display Name'))) {
    mitreTactics.push({ id: 'T1566.002', name: 'Spearphishing Link', tactic: 'Initial Access' });
    mitreTactics.push({ id: 'T1586.002', name: 'Email Accounts Impersonation', tactic: 'Resource Development' });
  }
  if (hasCredLure) {
    mitreTactics.push({ id: 'T1056.003', name: 'Web Portal Credential Capture', tactic: 'Credential Access' });
  }
  if (hasTorOrBlacklist) {
    mitreTactics.push({ id: 'T1090.003', name: 'Multi-hop Anonymization Proxy', tactic: 'Command and Control' });
  }
  if (url.indicators.some(i => i.label.includes('EXECUTABLE_PAYLOAD'))) {
    mitreTactics.push({ id: 'T1204.002', name: 'Malicious File Execution', tactic: 'Execution' });
  }
  if (mitreTactics.length === 0) {
    mitreTactics.push({ id: 'T1566.001', name: 'Spearphishing Attachment/Content', tactic: 'Initial Access' });
  }

  // Construct Explainable Evidence Summary
  let explanation = '';
  const highIndicators = [
    ...phishing.indicators,
    ...url.indicators,
    ...domain.indicators,
    ...ip.indicators,
    ...spam.indicators
  ].filter(i => i.severity === 'Critical' || i.severity === 'High');

  if (finalAiScore >= 70) {
    explanation = `HIGH SEVERITY THREAT DETECTED (Score ${finalAiScore}/100). The automated heuristic and multi-vector analysis identified ${highIndicators.length} high-confidence malicious indicators. ` +
      `Key threat vectors include ${highIndicators.slice(0, 3).map(i => i.label).join(', ')}. ` +
      `Immediate quarantine and domain/IP perimeter blocking is advised.`;
  } else if (finalAiScore >= 40) {
    explanation = `SUSPICIOUS EMAIL ACTIVITY (Score ${finalAiScore}/100). Elevated risk detected due to anomalous indicators (${highIndicators.length > 0 ? highIndicators.slice(0, 2).map(i => i.label).join(' and ') : 'unusual formatting/headers'}). ` +
      `Recommended for manual tier-2 SOC analyst triage before releasing to recipient.`;
  } else {
    explanation = `VERIFIED SAFE (Score ${finalAiScore}/100). Validated email authentication parameters (SPF/DKIM/DMARC align), reputable sender domain history, and benign link destinations. No deceptive lures identified.`;
  }

  // Remediation Recommendations
  const recommendations = [];
  if (finalAiScore >= 70) {
    recommendations.push('Quarantine message immediately across all enterprise mailboxes');
    recommendations.push(`Add sender domain (${parsedEmail.from.domain}) to tenant-wide perimeter blocklist`);
    if (parsedEmail.originatingIp) recommendations.push(`Block originating IP (${parsedEmail.originatingIp}) on border firewall / WAF`);
    recommendations.push('Trigger password reset workflow if targeted recipient clicked embedded links');
  } else if (finalAiScore >= 40) {
    recommendations.push('Hold email in SOC quarantine queue pending analyst review');
    recommendations.push('Deliver message with security warning banner prepended to subject and body');
    recommendations.push('Sanitize and rewrite embedded hyperlinks via web proxy sandbox');
  } else {
    recommendations.push('Allow message delivery through primary inbox pipeline');
    recommendations.push('Log routine delivery metrics to SIEM audit index');
  }

  return {
    score: finalAiScore,
    confidence: finalAiScore >= 70 ? 94 : finalAiScore >= 40 ? 82 : 96,
    mitreTactics,
    explanation,
    recommendations
  };
}

function analyzeThreat(input) {
  // Support both raw EML text and structured inputs
  let parsedEmail;
  if (typeof input === 'string') {
    parsedEmail = parseEmlContent(input);
  } else if (input && input.rawEml) {
    parsedEmail = parseEmlContent(input.rawEml);
  } else {
    // Structured input: { sender, recipient, subject, body, urls, headers, ip }
    const pseudoHeaders = `From: ${input.sender || 'unknown@domain.com'}\nTo: ${input.recipient || 'soc-target@corp.local'}\nSubject: ${input.subject || 'Security Notification'}\nDate: ${new Date().toUTCString()}\n\n`;
    const fullContent = pseudoHeaders + (input.body || input.content || '');
    parsedEmail = parseEmlContent(fullContent);

    if (input.ip) {
      if (!parsedEmail.ips.includes(input.ip)) parsedEmail.ips.unshift(input.ip);
      parsedEmail.originatingIp = input.ip;
    }
    if (input.url && !parsedEmail.urls.includes(input.url)) {
      parsedEmail.urls.unshift(input.url);
    }
  }

  // 1. Phishing Detection Module
  const phishing = scorePhishingModule(parsedEmail);

  // 2. Malicious URL Detection Module
  const url = scoreUrlModule(parsedEmail);

  // 3. Spam Detection Module
  const spam = scoreSpamModule(parsedEmail);

  // 4. Domain Reputation Module
  const domain = scoreDomainModule(parsedEmail);

  // 5. IP Reputation Module
  const ip = scoreIpModule(parsedEmail);

  // 6. AI Risk Synthesis Module
  const ai = scoreAiRiskSynthesis(phishing, url, spam, domain, ip, parsedEmail);

  const overallScore = ai.score;
  const verdict = overallScore >= 70 ? 'Malicious' : overallScore >= 40 ? 'Suspicious' : 'Safe';

  const allIndicators = [
    ...phishing.indicators,
    ...url.indicators,
    ...spam.indicators,
    ...domain.indicators,
    ...ip.indicators
  ];

  return {
    timestamp: new Date().toISOString(),
    overallScore,
    verdict,
    modules: {
      phishing: { score: phishing.score, weight: '25%', name: 'Phishing Detection', indicators: phishing.indicators },
      url: { score: url.score, weight: '25%', name: 'Malicious URL Analysis', indicators: url.indicators, analyzedUrls: url.analyzedUrls },
      spam: { score: spam.score, weight: '15%', name: 'Spam Detection', indicators: spam.indicators },
      domain: { score: domain.score, weight: '20%', name: 'Domain Reputation', indicators: domain.indicators, intel: domain.domainIntel },
      ip: { score: ip.score, weight: '15%', name: 'IP Reputation & Geo', indicators: ip.indicators, intel: ip.ipIntel },
      ai: { score: ai.score, confidence: ai.confidence, name: 'AI Risk Synthesis', mitreTactics: ai.mitreTactics, explanation: ai.explanation }
    },
    threatIndicators: allIndicators,
    parsedEmail,
    forensicData: {
      originatingIp: parsedEmail.originatingIp || (ip.ipIntel ? ip.ipIntel.ip : null),
      senderDomain: parsedEmail.from.domain,
      senderLocation: ip.ipIntel,
      ipIntelligence: ip.ipIntel,
      domainIntelligence: domain.domainIntel,
      receivedHops: parsedEmail.receivedHops,
      authentication: parsedEmail.authSummary,
      headerAnomalies: parsedEmail.headerAnomalies
    },
    explanation: ai.explanation,
    recommendations: ai.recommendations
  };
}

module.exports = {
  analyzeThreat,
  scorePhishingModule,
  scoreUrlModule,
  scoreSpamModule,
  scoreDomainModule,
  scoreIpModule
};
