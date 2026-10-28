/**
 * Lookalike, Typosquatting, and Homoglyph Detection Engine
 * Identifies targeted brand impersonation, deceptive unicode, and combo-squatting.
 */

const TARGETED_BRANDS = [
  { name: 'Microsoft', domain: 'microsoft.com', variants: ['office365', 'outlook', 'azure', 'sharepoint', 'onedrive'] },
  { name: 'PayPal', domain: 'paypal.com', variants: ['paypal-security', 'paypal-service'] },
  { name: 'Google', domain: 'google.com', variants: ['gmail', 'google-drive', 'google-workspace'] },
  { name: 'Apple', domain: 'apple.com', variants: ['appleid', 'icloud', 'apple-support'] },
  { name: 'Amazon', domain: 'amazon.com', variants: ['amazon-pay', 'aws-security'] },
  { name: 'Netflix', domain: 'netflix.com', variants: ['netflix-billing'] },
  { name: 'Chase Bank', domain: 'chase.com', variants: ['chase-online', 'chase-security'] },
  { name: 'Bank of America', domain: 'bankofamerica.com', variants: ['bofa-login', 'bankofamerica-alert'] },
  { name: 'Wells Fargo', domain: 'wellsfargo.com', variants: ['wellsfargo-verify'] },
  { name: 'DocuSign', domain: 'docusign.com', variants: ['docusign-envelope', 'docusign-net'] },
  { name: 'Dropbox', domain: 'dropbox.com', variants: ['dropbox-share'] },
  { name: 'FedEx', domain: 'fedex.com', variants: ['fedex-tracking', 'fedex-delivery'] },
  { name: 'DHL', domain: 'dhl.com', variants: ['dhl-express', 'dhl-shipment'] }
];

const HOMOGLYPH_MAP = {
  '0': 'o', '1': 'l', 'l': 'i', 'i': 'l', 'I': 'l',
  '5': 's', '8': 'b', 'v': 'u', 'vv': 'w', 'rn': 'm'
};

const SUSPICIOUS_TLDS = new Set([
  'xyz', 'top', 'click', 'buzz', 'cam', 'work', 'rest', 'gq', 'ml', 'cf', 'tk',
  'ga', 'support', 'live', 'club', 'monster', 'vip', 'quest', 'sbs', 'bond'
]);

function levenshteinDistance(s1, s2) {
  const m = s1.length;
  const n = s2.length;
  const dp = Array.from({ length: m + 1 }, () => new Array(n + 1).fill(0));

  for (let i = 0; i <= m; i++) dp[i][0] = i;
  for (let j = 0; j <= n; j++) dp[0][j] = j;

  for (let i = 1; i <= m; i++) {
    for (let j = 1; j <= n; j++) {
      const cost = s1[i - 1].toLowerCase() === s2[j - 1].toLowerCase() ? 0 : 1;
      dp[i][j] = Math.min(
        dp[i - 1][j] + 1,      // deletion
        dp[i][j - 1] + 1,      // insertion
        dp[i - 1][j - 1] + cost // substitution
      );
    }
  }
  return dp[m][n];
}

function normalizeDomain(inputDomain) {
  if (!inputDomain) return '';
  let d = inputDomain.trim().toLowerCase();
  d = d.replace(/^(?:https?:\/\/)?(?:www\.)?/i, '');
  d = d.split('/')[0].split(':')[0].split('?')[0];
  return d;
}

function checkLookalike(rawDomain) {
  const domain = normalizeDomain(rawDomain);
  if (!domain) {
    return { isLookalike: false, confidence: 0, matchedBrand: null, reason: 'Invalid or empty domain' };
  }

  const parts = domain.split('.');
  const tld = parts.length > 1 ? parts[parts.length - 1] : '';
  const domainBase = parts.slice(0, -1).join('.');
  const isSuspiciousTLD = SUSPICIOUS_TLDS.has(tld);

  for (const brand of TARGETED_BRANDS) {
    const brandBase = brand.domain.split('.')[0];

    // Exact match is legitimate (unless weird subdomain spoofing)
    if (domain === brand.domain) {
      return {
        isLookalike: false,
        isLegitimateBrand: true,
        matchedBrand: brand.name,
        confidence: 0,
        reason: `Official domain for ${brand.name}`
      };
    }

    // 1. Subdomain impersonation check (e.g. login.microsoft.com.evil-portal.net)
    if (domain.includes(brand.domain) && !domain.endsWith(`.${brand.domain}`)) {
      return {
        isLookalike: true,
        impersonatedBrand: brand.name,
        targetDomain: brand.domain,
        technique: 'Subdomain Prefix Hijack / Multi-Level Spoof',
        confidence: 95,
        riskScoreBonus: 35,
        reason: `Domain embeds official brand '${brand.domain}' as an untrusted subdomain prefix`
      };
    }

    // 2. Combo-squatting (brand + security/login/verify/update)
    const comboRegex = new RegExp(`(^|-|_)${brandBase}(-|_|login|verify|auth|support|portal|account|sec|secure|update|alert)`, 'i');
    if (comboRegex.test(domain) && !domain.endsWith(brand.domain)) {
      return {
        isLookalike: true,
        impersonatedBrand: brand.name,
        targetDomain: brand.domain,
        technique: 'Combo-Squatting / Phishing Portal Prefix',
        confidence: 90,
        riskScoreBonus: 30,
        reason: `Domain pairs '${brand.name}' brand keywords with auth/security lures`
      };
    }

    // 3. Homoglyph and character substitution
    let deobfuscated = domainBase;
    for (const [suspect, target] of Object.entries(HOMOGLYPH_MAP)) {
      deobfuscated = deobfuscated.replaceAll(suspect, target);
    }
    if (deobfuscated === brandBase && domainBase !== brandBase) {
      return {
        isLookalike: true,
        impersonatedBrand: brand.name,
        targetDomain: brand.domain,
        technique: 'Homoglyph Character Substitution',
        confidence: 92,
        riskScoreBonus: 35,
        reason: `Visual glyph spoofing targeting ${brand.name} (visually mirrors '${brand.domain}')`
      };
    }

    // 4. Levenshtein edit distance check (1 or 2 typos)
    const dist = levenshteinDistance(domainBase, brandBase);
    if (dist > 0 && dist <= 2 && domainBase.length >= 4) {
      return {
        isLookalike: true,
        impersonatedBrand: brand.name,
        targetDomain: brand.domain,
        technique: 'Typosquatting (Levenshtein Distance ' + dist + ')',
        confidence: dist === 1 ? 88 : 75,
        riskScoreBonus: dist === 1 ? 28 : 20,
        reason: `Domain base '${domainBase}' is ${dist} edit(s) away from '${brandBase}'`
      };
    }
  }

  // TLD check standalone
  if (isSuspiciousTLD) {
    return {
      isLookalike: false,
      isSuspiciousTLD: true,
      technique: 'Abused Top-Level Domain (TLD)',
      confidence: 60,
      riskScoreBonus: 15,
      reason: `TLD .${tld} is frequently associated with disposable bulletproof phishing campaigns`
    };
  }

  return { isLookalike: false, confidence: 0, reason: 'No lookalike markers detected' };
}

module.exports = {
  checkLookalike,
  normalizeDomain,
  levenshteinDistance,
  TARGETED_BRANDS,
  SUSPICIOUS_TLDS
};
