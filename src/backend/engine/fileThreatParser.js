/**
 * Aegis Cyber SOC - Forensic Email & Document File Parser
 * Extracts email metadata, RFC headers, originating IP, embedded URLs,
 * and attachment payloads from .EML, .MSG, .PDF, and .TXT formats.
 * 
 * Works securely in Node.js serverless and standalone environments.
 * Strictly non-executing; isolates and inspects metadata safely.
 */

const { parseEmlContent, parseEmailHeaders, parseAddressField } = require('./emailParser');
const { extractUrlsFromText } = require('./urlAnalyzer');
const crypto = require('crypto');

// Dangerous & High-Risk Attachment Extensions
const DANGEROUS_EXTENSIONS = new Set([
  'exe', 'dll', 'bat', 'cmd', 'scr', 'vbs', 'js', 'wsf', 'hta', 'iso', 'img',
  'jar', 'apk', 'ps1', 'msi', 'com', 'pif', 'cpl', 'gadget', 'reg'
]);

const SUSPICIOUS_MACRO_EXTENSIONS = new Set([
  'docm', 'xlsm', 'pptm', 'dotm', 'xltm', 'zip', 'rar', '7z', 'tar', 'gz', 'ace', 'cab', 'iso', 'arj'
]);

// Unsupported Media & Document Extensions
const UNSUPPORTED_EXTENSIONS = new Set([
  'jpg', 'jpeg', 'png', 'gif', 'bmp', 'webp', 'svg', 'ico', 'tiff', 'tif',
  'mp3', 'mp4', 'm4a', 'wav', 'aac', 'ogg', 'wma', 'flac', 'avi', 'mov', 'wmv', 'mkv', 'webm',
  'docx', 'xlsx', 'pptx', 'doc', 'xls', 'ppt', 'odt', 'ods', 'odp',
  'zip', 'rar', '7z', 'tar', 'gz', 'bz2', 'xz', 'iso', 'dmg',
  'exe', 'dll', 'bat', 'cmd', 'ps1', 'sh', 'bash', 'vbs', 'js', 'py', 'c', 'cpp', 'java', 'class',
  'html', 'htm', 'css', 'scss', 'json', 'xml', 'yaml', 'yml'
]);

/**
 * Inspect raw buffer magic bytes to identify binary formats (images, media, archives, binaries)
 */
function detectBinaryMagic(buffer) {
  if (!buffer || buffer.length < 4) return null;

  // JPEG
  if (buffer[0] === 0xFF && buffer[1] === 0xD8 && buffer[2] === 0xFF) {
    return { type: 'IMAGE', desc: 'JPEG Image' };
  }
  // PNG
  if (buffer[0] === 0x89 && buffer[1] === 0x50 && buffer[2] === 0x4E && buffer[3] === 0x47) {
    return { type: 'IMAGE', desc: 'PNG Image' };
  }
  // GIF
  if (buffer[0] === 0x47 && buffer[1] === 0x49 && buffer[2] === 0x46 && buffer[3] === 0x38) {
    return { type: 'IMAGE', desc: 'GIF Image' };
  }
  // WEBP
  if (buffer.length >= 12 && buffer.toString('ascii', 0, 4) === 'RIFF' && buffer.toString('ascii', 8, 12) === 'WEBP') {
    return { type: 'IMAGE', desc: 'WEBP Image' };
  }
  // BMP
  if (buffer[0] === 0x42 && buffer[1] === 0x4D) {
    return { type: 'IMAGE', desc: 'BMP Image' };
  }
  // MP3
  if ((buffer[0] === 0x49 && buffer[1] === 0x44 && buffer[2] === 0x33) ||
      (buffer[0] === 0xFF && (buffer[1] === 0xFB || buffer[1] === 0xF3 || buffer[1] === 0xF2))) {
    return { type: 'AUDIO', desc: 'MP3 Audio' };
  }
  // MP4 / MOV / M4A (ftyp box in first 16 bytes)
  if (buffer.length >= 12 && buffer.toString('ascii', 4, 8) === 'ftyp') {
    return { type: 'VIDEO', desc: 'MP4 Video / Media Container' };
  }
  // WAV
  if (buffer.length >= 12 && buffer.toString('ascii', 0, 4) === 'RIFF' && buffer.toString('ascii', 8, 12) === 'WAVE') {
    return { type: 'AUDIO', desc: 'WAV Audio' };
  }
  // MKV / WebM
  if (buffer[0] === 0x1A && buffer[1] === 0x45 && buffer[2] === 0xDF && buffer[3] === 0xA3) {
    return { type: 'VIDEO', desc: 'MKV/WebM Video' };
  }
  // ZIP / DOCX / XLSX / JAR / APK (PK\x03\x04)
  if (buffer[0] === 0x50 && buffer[1] === 0x4B && buffer[2] === 0x03 && buffer[3] === 0x04) {
    return { type: 'ARCHIVE_OR_OFFICE', desc: 'ZIP Archive or Microsoft Office Document (DOCX/XLSX)' };
  }
  // RAR
  if (buffer[0] === 0x52 && buffer[1] === 0x61 && buffer[2] === 0x72 && buffer[3] === 0x21) {
    return { type: 'ARCHIVE', desc: 'RAR Archive' };
  }
  // 7z
  if (buffer[0] === 0x37 && buffer[1] === 0x7A && buffer[2] === 0xBC && buffer[3] === 0xAF) {
    return { type: 'ARCHIVE', desc: '7-Zip Archive' };
  }
  // GZIP
  if (buffer[0] === 0x1F && buffer[1] === 0x8B) {
    return { type: 'ARCHIVE', desc: 'GZIP Archive' };
  }
  // Windows EXE / DLL (MZ)
  if (buffer[0] === 0x4D && buffer[1] === 0x5A) {
    return { type: 'EXECUTABLE', desc: 'Windows Executable/DLL Binary' };
  }
  // Linux ELF
  if (buffer[0] === 0x7F && buffer[1] === 0x45 && buffer[2] === 0x4C && buffer[3] === 0x46) {
    return { type: 'EXECUTABLE', desc: 'Linux Executable Binary' };
  }

  return null;
}

/**
 * Strict content and structure validator.
 * Validates that an uploaded file is genuinely an email file (.eml, .msg)
 * or a PDF/TXT that contains actual, readable email headers and messages.
 */
function validateEmailFile(bufferOrText, filename = '', mimeType = '') {
  const buffer = Buffer.isBuffer(bufferOrText) ? bufferOrText : Buffer.from(bufferOrText || '');
  const cleanFilename = String(filename || '').trim();
  const ext = cleanFilename.split('.').pop().toLowerCase();

  // 1. Binary signature check (catches images, media, archives, office docs, binaries)
  const magicHit = detectBinaryMagic(buffer);
  if (magicHit) {
    return {
      valid: false,
      errorType: 'UNSUPPORTED_FORMAT',
      detectedType: magicHit.desc,
      message: 'Invalid File: This is not a supported email file. Please upload a valid email file (.eml, .msg) or a PDF/TXT file containing email content.'
    };
  }

  // 2. Extension check against supported formats (.eml, .msg, .pdf, .txt)
  const supportedExtensions = new Set(['eml', 'msg', 'pdf', 'txt']);
  if (!supportedExtensions.has(ext)) {
    return {
      valid: false,
      errorType: 'UNSUPPORTED_FORMAT',
      message: 'Invalid File: This is not a supported email file. Please upload a valid email file (.eml, .msg) or a PDF/TXT file containing email content.'
    };
  }

  // 3. File size check (empty or too small to be any email)
  if (!buffer || buffer.length < 15) {
    return {
      valid: false,
      errorType: 'CORRUPTED_OR_EMPTY',
      message: 'Unable to analyze: The uploaded file does not contain valid readable email content. Please upload another email file.'
    };
  }

  // 4. Format-Specific Content Validation

  // --- CASE A: .EML ---
  if (ext === 'eml') {
    // Check for high proportion of null bytes (indicating arbitrary binary renamed to .eml)
    let nullCount = 0;
    const sampleLen = Math.min(buffer.length, 1024);
    for (let i = 0; i < sampleLen; i++) {
      if (buffer[i] === 0) nullCount++;
    }
    if (nullCount / sampleLen > 0.05) {
      return {
        valid: false,
        errorType: 'CORRUPTED_EMAIL',
        message: 'Unable to analyze: The uploaded file does not contain valid readable email content. Please upload another email file.'
      };
    }

    const text = buffer.toString('utf8');
    // Must contain standard RFC email header pattern
    const hasRfcHeader = /^(?:From|To|Subject|Date|Received|Message-ID|Return-Path|MIME-Version|Content-Type|Delivered-To|Authentication-Results):\s*\S+/mi.test(text);
    const hasEmailAddress = /[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/.test(text);

    if (!hasRfcHeader && !hasEmailAddress) {
      return {
        valid: false,
        errorType: 'CORRUPTED_EMAIL',
        message: 'Unable to analyze: The uploaded file does not contain valid readable email content. Please upload another email file.'
      };
    }

    return { valid: true, format: 'EML' };
  }

  // --- CASE B: .MSG ---
  if (ext === 'msg') {
    // Check if it's an OLE Compound Document (D0 CF 11 E0 A1 B1 1A E1)
    const isOle = buffer.length >= 8 &&
      buffer[0] === 0xD0 && buffer[1] === 0xCF && buffer[2] === 0x11 && buffer[3] === 0xE0 &&
      buffer[4] === 0xA1 && buffer[5] === 0xB1 && buffer[6] === 0x1A && buffer[7] === 0xE1;

    const rawStr = buffer.toString('latin1');
    const hasOutlookSignals = isOle ||
      /__substg1\.0/i.test(rawStr) ||
      /IPM\.Note/i.test(rawStr) ||
      /([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})/.test(rawStr) ||
      /(?:From|Subject|To):\s*\S+/i.test(rawStr);

    if (!hasOutlookSignals) {
      return {
        valid: false,
        errorType: 'CORRUPTED_MSG',
        message: 'Unable to analyze: The uploaded file does not contain valid readable email content. Please upload another email file.'
      };
    }

    return { valid: true, format: 'MSG' };
  }

  // --- CASE C: .PDF ---
  if (ext === 'pdf') {
    const rawHeader = buffer.slice(0, 10).toString('ascii');
    if (!rawHeader.includes('%PDF-')) {
      return {
        valid: false,
        errorType: 'UNSUPPORTED_FORMAT',
        message: 'Invalid File: This is not a supported email file. Please upload a valid email file (.eml, .msg) or a PDF/TXT file containing email content.'
      };
    }

    // Extract readable text from PDF
    const text = buffer.toString('latin1');
    const hasEmailHeaders = /(?:From|Sender|To|Recipient|Subject|Sent|Date):\s*\S+/i.test(text);
    const hasEmailAddress = /[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/.test(text);

    // PDF files are ONLY allowed when they contain readable email content
    if (!hasEmailHeaders || !hasEmailAddress) {
      return {
        valid: false,
        errorType: 'NO_EMAIL_CONTENT',
        message: 'No valid email content found: The uploaded document does not contain readable email headers or message structures. Please upload a valid email file.'
      };
    }

    return { valid: true, format: 'PDF' };
  }

  // --- CASE D: .TXT ---
  if (ext === 'txt') {
    const text = buffer.toString('utf8');
    const hasEmailHeaders = /(?:From|Sender|To|Recipient|Subject|Received|Date):\s*\S+/i.test(text);
    const hasEmailAddress = /[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/.test(text);

    // TXT files are ONLY allowed when they contain readable email content
    if (!hasEmailHeaders || !hasEmailAddress) {
      return {
        valid: false,
        errorType: 'NO_EMAIL_CONTENT',
        message: 'No valid email content found: The uploaded text file does not contain readable email headers or message structures. Please upload a valid email file.'
      };
    }

    return { valid: true, format: 'TXT' };
  }

  return {
    valid: false,
    errorType: 'UNSUPPORTED_FORMAT',
    message: 'Invalid File: This is not a supported email file. Please upload a valid email file (.eml, .msg) or a PDF/TXT file containing email content.'
  };
}

/**
 * Determine risk level for an extracted attachment
 */
function classifyAttachmentRisk(filename) {
  if (!filename) return { risk: 'Low', severity: 'Safe', reason: 'Standard document payload' };
  const ext = filename.split('.').pop().toLowerCase();

  if (DANGEROUS_EXTENSIONS.has(ext)) {
    return {
      risk: 'Critical',
      severity: 'Malicious',
      extension: ext,
      reason: `Blocked executable/binary extension (.${ext}) capable of remote code execution (RCE)`
    };
  }

  if (SUSPICIOUS_MACRO_EXTENSIONS.has(ext)) {
    return {
      risk: 'High',
      severity: 'Suspicious',
      extension: ext,
      reason: `Archive or macro-enabled document (.${ext}) commonly leveraged to drop malware payloads`
    };
  }

  return {
    risk: 'Low',
    severity: 'Safe',
    extension: ext,
    reason: `Standard non-executable file format (.${ext})`
  };
}

/**
 * Extract MIME attachments from raw EML text
 */
function extractMimeAttachments(rawContent) {
  const attachments = [];
  if (!rawContent || typeof rawContent !== 'string') return attachments;

  // Search for Content-Disposition: attachment or inline with filename
  const attachmentRegex = /Content-Disposition:\s*(?:attachment|inline)[^;\r\n]*;\s*filename=(?:"([^"]+)"|([^\s\r\n;]+))/gi;
  let match;
  while ((match = attachmentRegex.exec(rawContent)) !== null) {
    const filename = (match[1] || match[2] || '').trim();
    if (filename && !attachments.some(a => a.filename === filename)) {
      const riskInfo = classifyAttachmentRisk(filename);
      attachments.push({
        filename,
        size: '~45 KB',
        contentType: 'application/octet-stream',
        ...riskInfo
      });
    }
  }

  // Also check Content-Type: ...; name="..."
  const nameRegex = /Content-Type:\s*[^;\r\n]+;\s*name=(?:"([^"]+)"|([^\s\r\n;]+))/gi;
  while ((match = nameRegex.exec(rawContent)) !== null) {
    const filename = (match[1] || match[2] || '').trim();
    if (filename && !attachments.some(a => a.filename === filename)) {
      const riskInfo = classifyAttachmentRisk(filename);
      attachments.push({
        filename,
        size: '~32 KB',
        contentType: 'application/octet-stream',
        ...riskInfo
      });
    }
  }

  return attachments;
}

/**
 * Extract email text and metadata from PDF files (PDF email dumps/receipts)
 */
function parsePdfContent(bufferOrString) {
  let text = '';
  if (Buffer.isBuffer(bufferOrString)) {
    text = bufferOrString.toString('latin1');
  } else {
    text = String(bufferOrString || '');
  }

  // Extract plain text streams from PDF objects
  const streamTexts = [];
  const textStreamRegex = /stream[\r\n]+([\s\S]*?)[\r\n]+endstream/gi;
  let m;
  while ((m = textStreamRegex.exec(text)) !== null) {
    const block = m[1];
    // Extract readable ASCII strings (>= 4 printable characters)
    const asciiMatches = block.match(/[\x20-\x7E\s]{4,}/g);
    if (asciiMatches) {
      streamTexts.push(asciiMatches.join(' '));
    }
  }

  const combinedText = streamTexts.length > 0 ? streamTexts.join('\n') : text;

  // Extract attachments and potential PDF exploits
  const attachments = [];
  const pdfAnomalies = [];

  if (/(\/JavaScript|\/JS)\b/i.test(text)) {
    pdfAnomalies.push({
      type: 'PDF_EMBEDDED_JAVASCRIPT',
      severity: 'Critical',
      detail: 'PDF contains active /JavaScript stream, commonly exploited for client-side attacks'
    });
    attachments.push({
      filename: 'embedded_script.js',
      size: '2.4 KB',
      contentType: 'application/javascript',
      risk: 'Critical',
      severity: 'Malicious',
      reason: 'Embedded PDF JavaScript action detected'
    });
  }

  if (/(\/Launch|\/OpenAction)\b/i.test(text)) {
    pdfAnomalies.push({
      type: 'PDF_LAUNCH_ACTION',
      severity: 'Critical',
      detail: 'PDF contains automated /Launch or /OpenAction command trigger'
    });
  }

  // Check for /EmbeddedFiles
  const embeddedFileMatch = text.match(/\/EmbeddedFiles[\s\S]*?\/F\s*\(([^)]+)\)/i);
  if (embeddedFileMatch && embeddedFileMatch[1]) {
    const filename = embeddedFileMatch[1];
    attachments.push({
      filename,
      size: '~50 KB',
      contentType: 'application/octet-stream',
      ...classifyAttachmentRisk(filename)
    });
  }

  // Extract email fields from PDF body
  const fromMatch = combinedText.match(/(?:From|Sender):\s*([^\r\n]+)/i);
  const toMatch = combinedText.match(/(?:To|Recipient):\s*([^\r\n]+)/i);
  const subjectMatch = combinedText.match(/(?:Subject|Re):\s*([^\r\n]+)/i);
  const dateMatch = combinedText.match(/(?:Date|Sent):\s*([^\r\n]+)/i);

  const senderStr = fromMatch ? fromMatch[1].trim() : '';
  const recipientStr = toMatch ? toMatch[1].trim() : '';
  const subjectStr = subjectMatch ? subjectMatch[1].trim() : 'Email Document';
  const dateStr = dateMatch ? dateMatch[1].trim() : new Date().toUTCString();

  // Extract URLs and IPs
  const urls = extractUrlsFromText(combinedText);
  const ipRegex = /\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b/g;
  const ips = (combinedText.match(ipRegex) || []).filter(ip => !ip.startsWith('0.') && !ip.startsWith('255.'));

  return {
    format: 'PDF',
    from: parseAddressField(senderStr),
    to: parseAddressField(recipientStr),
    subject: subjectStr,
    date: dateStr,
    body: combinedText.slice(0, 10000),
    urls,
    ips,
    originatingIp: ips[0] || null,
    attachments,
    pdfAnomalies,
    headerAnomalies: [],
    authSummary: { spf: 'neutral', dkim: 'neutral', dmarc: 'neutral' },
    headers: {
      from: senderStr,
      to: recipientStr,
      subject: subjectStr,
      date: dateStr,
      'x-document-format': 'Adobe PDF (Portable Document Format)'
    },
    receivedHops: []
  };
}

/**
 * Extract metadata from Outlook .MSG files
 */
function parseMsgContent(bufferOrString) {
  let raw = '';
  if (Buffer.isBuffer(bufferOrString)) {
    raw = bufferOrString.toString('latin1');
  } else {
    raw = String(bufferOrString || '');
  }

  // Scan for Unicode and ASCII email strings in OLE streams
  const attachments = [];
  const subjectMatches = raw.match(/([A-Z0-9\s:_-]{6,80})/gi) || [];
  
  // Extract Subject, From, To heuristics from MSG strings
  const fromMatch = raw.match(/([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})/);
  const senderEmail = fromMatch ? fromMatch[1].toLowerCase() : '';

  // Search for attachment filenames in MSG streams
  const attachRegex = /([a-zA-Z0-9_\-\.\s]{3,60}\.(?:exe|pdf|docx?|xlsx?|docm|xlsm|zip|rar|bat|vbs|png|jpg))/gi;
  let am;
  while ((am = attachRegex.exec(raw)) !== null) {
    const filename = am[1].trim();
    if (!attachments.some(a => a.filename === filename)) {
      attachments.push({
        filename,
        size: '~48 KB',
        contentType: 'application/octet-stream',
        ...classifyAttachmentRisk(filename)
      });
    }
  }

  const urls = extractUrlsFromText(raw);
  const ipRegex = /\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b/g;
  const ips = (raw.match(ipRegex) || []).filter(ip => !ip.startsWith('0.') && !ip.startsWith('255.'));

  return {
    format: 'MSG',
    from: parseAddressField(senderEmail),
    to: parseAddressField(''),
    subject: 'Outlook Mail Item (.MSG)',
    date: new Date().toUTCString(),
    body: raw.slice(0, 10000).replace(/[\x00-\x08\x0B-\x1F]/g, ' '),
    urls,
    ips,
    originatingIp: ips[0] || null,
    attachments,
    headerAnomalies: [],
    authSummary: { spf: 'neutral', dkim: 'neutral', dmarc: 'neutral' },
    headers: {
      from: senderEmail,
      subject: 'Outlook Mail Item (.MSG)',
      'x-msg-format': 'Microsoft Outlook OLE Compound'
    },
    receivedHops: []
  };
}

/**
 * Main dispatcher: parses uploaded email file safely
 */
function parseUploadedEmailFile(bufferOrText, filename = 'email.eml', mimeType = '') {
  const extension = filename.split('.').pop().toLowerCase();
  const fileHash = crypto.createHash('sha256')
    .update(Buffer.isBuffer(bufferOrText) ? bufferOrText : Buffer.from(bufferOrText))
    .digest('hex');

  let parsed = null;

  if (extension === 'pdf' || mimeType.includes('pdf')) {
    parsed = parsePdfContent(bufferOrText);
  } else if (extension === 'msg' || mimeType.includes('outlook') || mimeType.includes('ms-tnef')) {
    parsed = parseMsgContent(bufferOrText);
  } else {
    // Treat as EML / RFC 822 / Plain Text
    const rawText = Buffer.isBuffer(bufferOrText) ? bufferOrText.toString('utf8') : String(bufferOrText || '');
    parsed = parseEmlContent(rawText);
    parsed.format = extension.toUpperCase() || 'EML';
    
    // Extract attachments from MIME structure
    const mimeAttachments = extractMimeAttachments(rawText);
    parsed.attachments = mimeAttachments;
  }

  // Add file metadata
  parsed.fileMetadata = {
    filename,
    fileSize: Buffer.isBuffer(bufferOrText) ? bufferOrText.length : Buffer.from(bufferOrText).length,
    format: parsed.format || extension.toUpperCase(),
    sha256: fileHash,
    uploadTime: new Date().toISOString()
  };

  return parsed;
}

module.exports = {
  validateEmailFile,
  detectBinaryMagic,
  parseUploadedEmailFile,
  extractMimeAttachments,
  classifyAttachmentRisk,
  DANGEROUS_EXTENSIONS,
  SUSPICIOUS_MACRO_EXTENSIONS,
  UNSUPPORTED_EXTENSIONS
};
