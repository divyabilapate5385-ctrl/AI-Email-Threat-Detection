/**
 * Forensic GeoIP, ASN, and Threat Intelligence Resolver
 * Maps IP addresses to geographical coordinates, ISP, autonomous systems, and threat indicators.
 */

const KNOWN_IP_INTEL = {
  // Malicious / Bulletproof / Tor / Scanner nodes
  '185.220.101.5': {
    ip: '185.220.101.5',
    country: 'Germany',
    countryCode: 'DE',
    city: 'Frankfurt',
    region: 'Hesse',
    latitude: 50.1109,
    longitude: 8.6821,
    asn: 'AS208294',
    asName: 'Zwiebelfreunde e.V.',
    isp: 'Tor Exit Relay Network',
    isTor: true,
    isVpn: true,
    isProxy: true,
    isDatacenter: true,
    threatScore: 92,
    threatCategory: 'Tor Exit Node / Anonymizer',
    threatFeed: 'EmergingThreats / TorBlock'
  },
  '91.240.118.172': {
    ip: '91.240.118.172',
    country: 'Russia',
    countryCode: 'RU',
    city: 'Moscow',
    region: 'Moscow',
    latitude: 55.7558,
    longitude: 37.6173,
    asn: 'AS48282',
    asName: 'Scalaxy Host Network',
    isp: 'Bulletproof Dedicated Hosting',
    isTor: false,
    isVpn: false,
    isProxy: true,
    isDatacenter: true,
    threatScore: 88,
    threatCategory: 'Phishing Campaign C2 / Emotet Relay',
    threatFeed: 'Spamhaus DROP / Feodo Tracker'
  },
  '45.154.255.89': {
    ip: '45.154.255.89',
    country: 'Netherlands',
    countryCode: 'NL',
    city: 'Amsterdam',
    region: 'North Holland',
    latitude: 52.3676,
    longitude: 4.9041,
    asn: 'AS210644',
    asName: 'Biterika LLC',
    isp: 'High-Risk Anonymous Hosting',
    isTor: false,
    isVpn: true,
    isProxy: true,
    isDatacenter: true,
    threatScore: 82,
    threatCategory: 'Credential Harvester Host / Fast Flux',
    threatFeed: 'URLhaus / PhishTank'
  },
  '194.26.29.112': {
    ip: '194.26.29.112',
    country: 'Seychelles',
    countryCode: 'SC',
    city: 'Victoria',
    region: 'Mahe',
    latitude: -4.6191,
    longitude: 55.4513,
    asn: 'AS59796',
    asName: 'Offshore Cyber VPS Ltd',
    isp: 'Offshore Privacy Cloud',
    isTor: false,
    isVpn: true,
    isProxy: true,
    isDatacenter: true,
    threatScore: 78,
    threatCategory: 'Banking Trojan Distribution',
    threatFeed: 'AbuseIPDB Verified Malicious'
  },
  '103.145.13.44': {
    ip: '103.145.13.44',
    country: 'Vietnam',
    countryCode: 'VN',
    city: 'Hanoi',
    region: 'Hanoi',
    latitude: 21.0285,
    longitude: 105.8542,
    asn: 'AS135905',
    asName: 'Viettel Telecom Corp',
    isp: 'Compromised Residential Botnet',
    isTor: false,
    isVpn: false,
    isProxy: false,
    isDatacenter: false,
    threatScore: 75,
    threatCategory: 'Mirai / Necurs Spam Botnet Member',
    threatFeed: 'Spamhaus SBL'
  },
  // Reputable / Major Tech Nodes
  '40.107.240.122': {
    ip: '40.107.240.122',
    country: 'United States',
    countryCode: 'US',
    city: 'Quincy',
    region: 'Washington',
    latitude: 47.2343,
    longitude: -119.8526,
    asn: 'AS8075',
    asName: 'Microsoft Corporation',
    isp: 'Microsoft Office 365 Exchange Online',
    isTor: false,
    isVpn: false,
    isProxy: false,
    isDatacenter: true,
    threatScore: 5,
    threatCategory: 'Verified Enterprise Mail Gateway',
    threatFeed: 'Clean / Reputable'
  },
  '209.85.220.41': {
    ip: '209.85.220.41',
    country: 'United States',
    countryCode: 'US',
    city: 'Mountain View',
    region: 'California',
    latitude: 37.3861,
    longitude: -122.0839,
    asn: 'AS15169',
    asName: 'Google LLC',
    isp: 'Google Workspace Mail Relays',
    isTor: false,
    isVpn: false,
    isProxy: false,
    isDatacenter: true,
    threatScore: 2,
    threatCategory: 'Verified Enterprise Mail Gateway',
    threatFeed: 'Clean / Reputable'
  },
  '17.58.63.1': {
    ip: '17.58.63.1',
    country: 'United States',
    countryCode: 'US',
    city: 'Cupertino',
    region: 'California',
    latitude: 37.3230,
    longitude: -122.0322,
    asn: 'AS714',
    asName: 'Apple Inc.',
    isp: 'Apple iCloud Inbound Relay',
    isTor: false,
    isVpn: false,
    isProxy: false,
    isDatacenter: true,
    threatScore: 3,
    threatCategory: 'Verified Enterprise Mail Gateway',
    threatFeed: 'Clean / Reputable'
  }
};

const COUNTRY_COORDINATES = [
  { country: 'United States', code: 'US', lat: 37.0902, lng: -95.7129, city: 'Dallas', isp: 'DigitalOcean Cloud' },
  { country: 'Germany', code: 'DE', lat: 51.1657, lng: 10.4515, city: 'Berlin', isp: 'Hetzner Online GmbH' },
  { country: 'Netherlands', code: 'NL', lat: 52.1326, lng: 5.2913, city: 'Haarlem', isp: 'Leaseweb Global' },
  { country: 'United Kingdom', code: 'GB', lat: 55.3781, lng: -3.4360, city: 'London', isp: 'BT Global Services' },
  { country: 'Russia', code: 'RU', lat: 61.5240, lng: 105.3188, city: 'Saint Petersburg', isp: 'Rostelecom Data' },
  { country: 'China', code: 'CN', lat: 35.8617, lng: 104.1954, city: 'Shanghai', isp: 'China Telecom Backbone' },
  { country: 'India', code: 'IN', lat: 20.5937, lng: 78.9629, city: 'Bengaluru', isp: 'Tata Communications' },
  { country: 'Brazil', code: 'BR', lat: -14.2350, lng: -51.9253, city: 'Sao Paulo', isp: 'Claro Brasil' },
  { country: 'Japan', code: 'JP', lat: 36.2048, lng: 138.2529, city: 'Tokyo', isp: 'NTT Communications' },
  { country: 'Australia', code: 'AU', lat: -25.2744, lng: 133.7751, city: 'Sydney', isp: 'Telstra Corp' },
  { country: 'Singapore', code: 'SG', lat: 1.3521, lng: 103.8198, city: 'Singapore', isp: 'Singtel Backbone' },
  { country: 'Romania', code: 'RO', lat: 45.9432, lng: 24.9668, city: 'Bucharest', isp: 'Voxility S.R.L.' }
];

function isPrivateIp(ip) {
  if (!ip) return false;
  const parts = ip.split('.').map(Number);
  if (parts.length !== 4) return false;
  // 10.0.0.0/8
  if (parts[0] === 10) return true;
  // 172.16.0.0/12
  if (parts[0] === 172 && parts[1] >= 16 && parts[1] <= 31) return true;
  // 192.168.0.0/16
  if (parts[0] === 192 && parts[1] === 168) return true;
  // 127.0.0.0/8
  if (parts[0] === 127) return true;
  return false;
}

function resolveIpIntelligence(ip) {
  if (!ip) {
    return {
      ip: '0.0.0.0',
      valid: false,
      country: 'Unknown',
      city: 'Unknown',
      isp: 'Unknown',
      asn: 'AS0',
      threatScore: 0
    };
  }

  const cleanIp = ip.trim();

  if (isPrivateIp(cleanIp)) {
    return {
      ip: cleanIp,
      valid: true,
      isPrivate: true,
      country: 'Local Network',
      countryCode: 'LAN',
      city: 'Internal Subnet',
      region: 'Intranet',
      latitude: 0,
      longitude: 0,
      asn: 'RFC-1918',
      asName: 'Private Address Space',
      isp: 'Internal Enterprise Network',
      isTor: false,
      isVpn: false,
      isProxy: false,
      isDatacenter: false,
      threatScore: 0,
      threatCategory: 'Private RFC 1918 Address'
    };
  }

  // Known catalog
  if (KNOWN_IP_INTEL[cleanIp]) {
    return { ...KNOWN_IP_INTEL[cleanIp], valid: true };
  }

  // Deterministic hash lookup for uncataloged public IPs
  let hash = 0;
  for (let i = 0; i < cleanIp.length; i++) {
    hash = (hash << 5) - hash + cleanIp.charCodeAt(i);
    hash |= 0;
  }
  const absHash = Math.abs(hash);
  const countryEntry = COUNTRY_COORDINATES[absHash % COUNTRY_COORDINATES.length];
  const asnNumber = 10000 + (absHash % 55000);

  // Deterministic threat flags
  const isTor = (absHash % 17) === 0;
  const isVpn = (absHash % 7) === 0;
  const isProxy = (absHash % 9) === 0;
  const isDatacenter = (absHash % 3) === 0;

  let baseThreat = (absHash % 45);
  if (isTor) baseThreat += 40;
  if (isVpn) baseThreat += 20;
  if (isProxy) baseThreat += 15;
  const threatScore = Math.min(95, baseThreat);

  return {
    ip: cleanIp,
    valid: true,
    isPrivate: false,
    country: countryEntry.country,
    countryCode: countryEntry.code,
    city: countryEntry.city,
    region: countryEntry.country,
    latitude: countryEntry.lat + ((absHash % 20) - 10) * 0.05,
    longitude: countryEntry.lng + ((absHash % 20) - 10) * 0.05,
    asn: `AS${asnNumber}`,
    asName: countryEntry.isp,
    isp: countryEntry.isp,
    isTor,
    isVpn,
    isProxy,
    isDatacenter,
    threatScore,
    threatCategory: threatScore >= 70 ? 'High-Risk Anonymous Gateway' : threatScore >= 40 ? 'Suspicious Cloud Instance' : 'Standard Commercial Transit',
    threatFeed: threatScore >= 70 ? 'Aegis Threat Stream' : 'Clean'
  };
}

function resolveDomainIntelligence(domain) {
  if (!domain) return null;
  const cleanDomain = domain.toLowerCase().trim();

  // Well known top brands
  const reputableDomains = {
    'microsoft.com': { ageYears: 33, registrar: 'MarkMonitor Inc.', dnssec: true, mx: 'microsoft-com.mail.protection.outlook.com', spf: 'v=spf1 include:_netblocks.microsoft.com ~all', dmarc: 'v=DMARC1; p=reject; rua=mailto:d@rua.agari.com' },
    'google.com': { ageYears: 28, registrar: 'MarkMonitor Inc.', dnssec: true, mx: 'aspmx.l.google.com', spf: 'v=spf1 include:_spf.google.com ~all', dmarc: 'v=DMARC1; p=reject; rua=mailto:mailauth-reports@google.com' },
    'paypal.com': { ageYears: 26, registrar: 'MarkMonitor Inc.', dnssec: true, mx: 'mx1.paypal.com', spf: 'v=spf1 include:paypal.com ~all', dmarc: 'v=DMARC1; p=reject; rua=mailto:d@rua.agari.com' },
    'apple.com': { ageYears: 37, registrar: 'CSC Corporate Domains', dnssec: true, mx: 'mx-apple.mail.icloud.com', spf: 'v=spf1 include:_spf.apple.com ~all', dmarc: 'v=DMARC1; p=reject;' }
  };

  if (reputableDomains[cleanDomain]) {
    return {
      domain: cleanDomain,
      ageDays: reputableDomains[cleanDomain].ageYears * 365,
      registrar: reputableDomains[cleanDomain].registrar,
      createdDate: new Date(Date.now() - reputableDomains[cleanDomain].ageYears * 365 * 86400000).toISOString().split('T')[0],
      mxConfigured: true,
      mxRecord: reputableDomains[cleanDomain].mx,
      dnssecEnabled: reputableDomains[cleanDomain].dnssec,
      spfRecord: reputableDomains[cleanDomain].spf,
      dmarcPolicy: 'reject',
      dmarcRecord: reputableDomains[cleanDomain].dmarc,
      reputationScore: 98,
      isNewlyRegistered: false,
      riskLevel: 'Safe'
    };
  }

  // Hash calculation for realistic simulated WHOIS & DNS
  let hash = 0;
  for (let i = 0; i < cleanDomain.length; i++) {
    hash = (hash << 5) - hash + cleanDomain.charCodeAt(i);
    hash |= 0;
  }
  const absHash = Math.abs(hash);

  // If domain has suspicious TLD or lookalike words, make it newly registered
  const parts = cleanDomain.split('.');
  const tld = parts[parts.length - 1];
  const isSuspiciousTLD = ['xyz', 'top', 'click', 'buzz', 'cam', 'work', 'quest', 'sbs'].includes(tld);
  const isPhishyName = /security|verify|login|update|account|billing|support|auth|portal/i.test(cleanDomain);

  let ageDays = (absHash % 1200) + 10;
  if (isSuspiciousTLD || isPhishyName) {
    ageDays = (absHash % 45) + 2; // Under 45 days old!
  }

  const createdDate = new Date(Date.now() - ageDays * 86400000).toISOString().split('T')[0];
  const registrars = ['NameCheap, Inc.', 'GoDaddy.com, LLC', 'NameSilo, LLC', 'Tucows Domains Inc.', 'REG.RU LLC', 'Porkbun LLC', 'Dynadot Inc.'];
  const registrar = registrars[absHash % registrars.length];

  const mxConfigured = !isSuspiciousTLD || (absHash % 3 !== 0);
  const mxRecord = mxConfigured ? `mail.${cleanDomain}` : 'NO_MX_CONFIGURED';
  const hasSpf = (absHash % 2 === 0);
  const spfRecord = hasSpf ? 'v=spf1 +a +mx ~all' : 'NONE';
  const dmarcPolicies = ['none', 'none', 'quarantine', 'reject', 'none'];
  const dmarcPolicy = dmarcPolicies[absHash % dmarcPolicies.length];

  const isNewlyRegistered = ageDays < 60;
  let riskLevel = 'Safe';
  let reputationScore = 80;

  if (isNewlyRegistered) {
    riskLevel = 'Suspicious';
    reputationScore -= 30;
  }
  if (!mxConfigured) {
    riskLevel = 'Suspicious';
    reputationScore -= 20;
  }
  if (isSuspiciousTLD) {
    riskLevel = 'High';
    reputationScore -= 25;
  }
  if (isNewlyRegistered && (isSuspiciousTLD || isPhishyName)) {
    riskLevel = 'Malicious';
    reputationScore = Math.max(10, reputationScore - 30);
  }

  return {
    domain: cleanDomain,
    ageDays,
    isNewlyRegistered,
    registrar,
    createdDate,
    mxConfigured,
    mxRecord,
    dnssecEnabled: (absHash % 5 === 0),
    spfRecord,
    dmarcPolicy,
    dmarcRecord: dmarcPolicy !== 'none' ? `v=DMARC1; p=${dmarcPolicy};` : 'NONE',
    reputationScore: Math.max(5, Math.min(100, reputationScore)),
    riskLevel
  };
}

const KNOWN_DOMAIN_MAIL_SERVERS = {
  'google.com': '209.85.220.41',
  'gmail.com': '209.85.220.41',
  'microsoft.com': '40.107.240.122',
  'office365.com': '40.107.240.122',
  'outlook.com': '40.107.240.122',
  'apple.com': '17.58.63.1',
  'icloud.com': '17.58.63.1',
  'paypal.com': '194.26.29.112',
  'micros0ft-login-portal.xyz': '185.220.101.5',
  'micros0ft-portal.xyz': '185.220.101.5',
  'micros0ft.com': '185.220.101.5',
  'consultant-group.top': '91.240.118.172',
  'express-notifications-billing.com': '45.154.255.89',
  'paypaI.com': '194.26.29.112',
  'quick-prizes-reward.buzz': '103.145.13.44'
};

function getCountryFlag(countryCode) {
  if (!countryCode || countryCode.length !== 2) return '🌐';
  const codePoints = countryCode
    .toUpperCase()
    .split('')
    .map(char => 127397 + char.charCodeAt(0));
  return String.fromCodePoint(...codePoints);
}

function resolveSenderLocation(input, explicitIp = null) {
  let targetIp = explicitIp;
  let senderEmail = '';
  let senderDomain = '';

  if (input) {
    const clean = String(input).trim();
    if (/^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$/.test(clean)) {
      targetIp = clean;
    } else {
      const emailMatch = clean.match(/<?([a-zA-Z0-9._%+-]+@([a-zA-Z0-9.-]+\.[a-zA-Z]{2,}))>?/);
      if (emailMatch) {
        senderEmail = emailMatch[1].toLowerCase();
        senderDomain = emailMatch[2].toLowerCase();
      } else {
        senderDomain = clean.replace(/^(?:https?:\/\/)?(?:www\.)?/, '').split('/')[0].split(':')[0].toLowerCase();
      }

      if (!targetIp) {
        if (KNOWN_DOMAIN_MAIL_SERVERS[senderDomain]) {
          targetIp = KNOWN_DOMAIN_MAIL_SERVERS[senderDomain];
        } else {
          let hash = 0;
          for (let i = 0; i < senderDomain.length; i++) {
            hash = (hash << 5) - hash + senderDomain.charCodeAt(i);
            hash |= 0;
          }
          const absHash = Math.abs(hash);
          const octet1 = 45 + (absHash % 140);
          const octet2 = (absHash >> 3) % 250;
          const octet3 = (absHash >> 6) % 250;
          const octet4 = 10 + (absHash % 240);
          targetIp = `${octet1}.${octet2}.${octet3}.${octet4}`;
        }
      }
    }
  }

  if (!targetIp) {
    targetIp = '185.220.101.5';
  }

  const ipIntel = resolveIpIntelligence(targetIp);
  const countryFlag = getCountryFlag(ipIntel.countryCode);
  const utcOffsetHours = Math.round(ipIntel.longitude / 15);
  const offsetSign = utcOffsetHours >= 0 ? '+' : '';
  const timezoneStr = `UTC${offsetSign}${utcOffsetHours}:00`;

  const nowUtc = new Date();
  const senderTime = new Date(nowUtc.getTime() + utcOffsetHours * 3600000);
  const hours = String(senderTime.getUTCHours()).padStart(2, '0');
  const mins = String(senderTime.getUTCMinutes()).padStart(2, '0');
  const localTimeStr = `${hours}:${mins} (${timezoneStr})`;

  return {
    ...ipIntel,
    senderEmail,
    senderDomain: senderDomain || ipIntel.asName,
    countryFlag,
    timezone: timezoneStr,
    localTime: localTimeStr,
    reverseDns: `mail-gw-${targetIp.replace(/\./g, '-')}.${(ipIntel.countryCode || 'net').toLowerCase()}.net`
  };
}

module.exports = {
  resolveIpIntelligence,
  resolveDomainIntelligence,
  resolveSenderLocation,
  getCountryFlag,
  isPrivateIp,
  KNOWN_IP_INTEL,
  KNOWN_DOMAIN_MAIL_SERVERS
};
