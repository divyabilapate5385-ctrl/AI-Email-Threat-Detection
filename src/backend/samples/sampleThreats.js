/**
 * Sample Threat Scenarios & Real-World Cyber Attack Datasets
 * Includes credential harvesting, lookalike domains, BEC CEO fraud, and clean benchmark emails.
 */

const SAMPLE_THREATS = [
  {
    id: 'sample-m365-phish',
    name: 'Microsoft 365 Credential Harvester (Homoglyph & Tor)',
    category: 'Phishing',
    expectedVerdict: 'Malicious',
    description: 'Targeted spearphishing campaign impersonating Microsoft Security with typosquatted login portal hosted on a Tor exit relay.',
    data: {
      sender: '"Microsoft Security Center" <support@micros0ft-login-portal.xyz>',
      recipient: 'cfo.corporate@victim-corp.com',
      subject: 'URGENT: Microsoft 365 Password Expiring in 24 Hours - Identity Verification Required',
      body: `Dear User,

Your Microsoft 365 enterprise account access is scheduled for immediate suspension due to unverified directory security credentials.

Immediate action required within 24 hours to prevent permanent account deactivation and loss of mailbox data.

Please verify your credentials and retain your access now:
https://micros0ft-login-portal.xyz/auth/login?redirect=https%3A%2F%2Flogin.microsoftonline.com&user=cfo.corporate

Microsoft Security Response Team
One Microsoft Way, Redmond, WA`,
      ip: '185.220.101.5',
      url: 'https://micros0ft-login-portal.xyz/auth/login?redirect=https%3A%2F%2Flogin.microsoftonline.com&user=cfo.corporate'
    }
  },
  {
    id: 'sample-bec-ceo',
    name: 'CEO Urgent Wire Transfer (BEC & Reply-To Hijack)',
    category: 'Impersonation / BEC',
    expectedVerdict: 'Malicious',
    description: 'Business Email Compromise (BEC) masquerading as the CEO demanding an urgent confidential acquisition wire transfer.',
    data: {
      sender: '"Satya Nadella (CEO)" <satya.nadella@global-cloud-corp.com>',
      recipient: 'treasury@victim-corp.com',
      subject: 'Strictly Confidential: Immediate Wire Transfer - Project Titan Acquisition',
      body: `Hi,

Are you at your desk right now? I need you to execute a confidential wire transfer of $84,500 immediately for our international vendor acquisition under Project Titan.

I am currently in an executive board meeting and cannot take calls. Please reply to my private encrypted mailbox (satya-executive-wire@consultant-group.top) with the SWIFT confirmation as soon as initiated.

Do not discuss this with the rest of the finance team until the transaction is confirmed.

Best regards,
Satya Nadella
Chief Executive Officer`,
      ip: '91.240.118.172',
      url: 'http://wire-portal.consultant-group.top/invoice-download.exe'
    }
  },
  {
    id: 'sample-docusign-malware',
    name: 'DocuSign Invoice Lure (Executable Trojan Dropper)',
    category: 'Malware Link',
    expectedVerdict: 'Malicious',
    description: 'Impersonates DocuSign with a direct payload link serving an ISO/EXE malware dropper.',
    data: {
      sender: '"DocuSign Secure Envelope" <docusign@express-notifications-billing.com>',
      recipient: 'accounting@victim-corp.com',
      subject: 'DocuSign: Please review and sign overdue invoice #INV-94021',
      body: `All parties have completed review. Your signature is required on overdue payment invoice #INV-94021.

Click below to access your secure document envelope:
http://45.154.255.89/docs/Invoice_Ref_98293.iso

Document will expire in 48 hours.

DocuSign Electronic Signature Service`,
      ip: '45.154.255.89',
      url: 'http://45.154.255.89/docs/Invoice_Ref_98293.iso'
    }
  },
  {
    id: 'sample-paypal-homoglyph',
    name: 'PayPal Account Alert (Homoglyph paypaI.com)',
    category: 'Phishing',
    expectedVerdict: 'Malicious',
    description: 'Uses capital letter I instead of lowercase l (paypaI.com) with unauthorized activity threat.',
    data: {
      sender: '"PayPal Security Shield" <service-alert@paypaI.com>',
      recipient: 'merchant@victim-corp.com',
      subject: 'Security Alert: Unauthorized sign-in detected on your PayPal Account',
      body: `Hello Member,

We detected an unusual sign-in attempt to your PayPal account from a device in Russia (IP: 91.240.118.172).

To secure your account and cancel any pending fraudulent transfers, verify your identity immediately:
https://paypaI.com/cgi-bin/webscr?cmd=_login-run&dispatch=verify-checkpoint

Failure to confirm within 12 hours will result in permanent account locking.

Thank you for helping us keep PayPal safe.`,
      ip: '194.26.29.112',
      url: 'https://paypaI.com/cgi-bin/webscr?cmd=_login-run&dispatch=verify-checkpoint'
    }
  },
  {
    id: 'sample-clean-google',
    name: 'Clean Google Workspace Security Digest',
    category: 'Safe Benchmark',
    expectedVerdict: 'Safe',
    description: 'Legitimate Google Workspace administrative email with valid cryptographic authentication and clean domain reputation.',
    data: {
      sender: '"Google Workspace Team" <workspace-noreply@google.com>',
      recipient: 'admin@victim-corp.com',
      subject: 'Google Workspace monthly security and administration summary',
      body: `Hello Administrator,

Here is your monthly Google Workspace security audit report.
During the past 30 days:
- 0 suspicious logins detected
- Two-step verification compliance: 100%
- All tenant services operating normally

You can review your full admin console settings at:
https://admin.google.com/ac/security

Google LLC, 1600 Amphitheatre Parkway, Mountain View, CA 94043`,
      ip: '209.85.220.41',
      url: 'https://admin.google.com/ac/security'
    }
  },
  {
    id: 'sample-spam-lottery',
    name: 'Advance Fee Sweepstakes Spam (Excessive Caps & Punctuation)',
    category: 'Spam',
    expectedVerdict: 'Suspicious',
    description: 'Classic bulk spam featuring multi-million dollar lottery promises, high-pressure punctuation and missing message headers.',
    data: {
      sender: '"International Sweepstakes Board" <winner-draw@quick-prizes-reward.buzz>',
      recipient: 'lucky.recipient@corp.local',
      subject: 'CONGRATULATIONS!!! YOU HAVE BEEN SELECTED AS THE LUCKY $5,000,000 WINNER!!!',
      body: `DEAR BENEFICIARY,

WE ARE PLEASED TO INFORM YOU THAT YOUR EMAIL WON THE 1ST PRIZE CATEGORY OF $5,000,000.00 USD IN THE ANNUAL INTERNATIONAL LOTTERY SWEEPSTAKES PROGRAM!!!

TO CLAIM YOUR RISK-FREE UNCLAIMED FUNDS, CONTACT THE AUDIT AGENT IMMEDIATELY WITH YOUR FULL NAME, BANKING DETAILS AND PASSPORT COPY.

ACT NOW OR YOUR UNCLAIMED FUNDS WILL BE TRANSFERRED TO GOVERNMENT TREASURY WITHIN 48 HOURS!

REGARDS,
BARRISTER DONALD STERLING`,
      ip: '103.145.13.44',
      url: 'http://quick-prizes-reward.buzz/claim-reward-now?id=99281'
    }
  }
];

module.exports = { SAMPLE_THREATS };
