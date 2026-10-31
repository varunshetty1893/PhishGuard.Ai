const APP_PORTS = new Set([5173, 3000, 8000, 8080]);
const LOCAL_DOMAIN_SUFFIXES = [
  '.localhost',
  '.local',
  '.internal',
  '.lan',
  '.home',
  '.test',
  '.example',
  '.invalid'
];

const FORBIDDEN_SCHEMES = [
  'javascript:',
  'data:',
  'file:',
  'vbscript:',
  'about:',
  'blob:',
  'ws:',
  'wss:',
  'ftp:',
  'ftps:',
  'gopher:',
  'mailto:',
  'tel:'
];

const EMAIL_PATTERN = /^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$/;

export interface ValidationResult {
  isValid: boolean;
  error?: string;
  sanitizedUrl?: string;
}

function isPrivateIpv4(ipStr: string): boolean {
  const parts = ipStr.split('.').map((p) => parseInt(p, 10));
  if (parts.length !== 4 || parts.some((p) => isNaN(p) || p < 0 || p > 255)) {
    return false;
  }

  const [p0, p1] = parts;

  // 127.0.0.0/8 (Loopback)
  if (p0 === 127) return true;
  // 10.0.0.0/8 (RFC 1918)
  if (p0 === 10) return true;
  // 172.16.0.0/12 (RFC 1918)
  if (p0 === 172 && p1 >= 16 && p1 <= 31) return true;
  // 192.168.0.0/16 (RFC 1918)
  if (p0 === 192 && p1 === 168) return true;
  // 169.254.0.0/16 (Link Local)
  if (p0 === 169 && p1 === 254) return true;
  // 0.0.0.0/8 (Current network)
  if (p0 === 0) return true;
  // 224.0.0.0/4 (Multicast)
  if (p0 >= 224 && p0 <= 239) return true;
  // 240.0.0.0/4 (Reserved)
  if (p0 >= 240) return true;

  return false;
}

function isPrivateIpv6(host: string): boolean {
  const clean = host.toLowerCase().replace(/^\[|\]$/g, '');
  if (clean === '::1' || clean === '::' || clean.startsWith('fc') || clean.startsWith('fd') || clean.startsWith('fe80')) {
    return true;
  }
  return false;
}

export function validateScanUrl(rawInput: string): ValidationResult {
  const trimmed = rawInput.trim();

  if (!trimmed) {
    return { isValid: false, error: 'URL cannot be empty or pure whitespace.' };
  }

  if (trimmed.length > 2048) {
    return { isValid: false, error: 'URL length exceeds maximum permitted threshold of 2,048 characters.' };
  }

  if (/\s/.test(trimmed)) {
    return { isValid: false, error: 'Web addresses cannot contain spaces or whitespace characters.' };
  }

  // 1. Reject email addresses (e.g. shettybvarun@gmail.com)
  if (EMAIL_PATTERN.test(trimmed)) {
    return {
      isValid: false,
      error: `'${trimmed}' is an email address, not a website URL. PhishGuard AI analyzes website destinations (e.g., https://gmail.com).`
    };
  }

  // 2. Reject social handles (e.g. @username)
  if (trimmed.startsWith('@')) {
    return {
      isValid: false,
      error: `'${trimmed}' is a social username/handle, not a website URL. Please provide a full web address.`
    };
  }

  // 3. Reject internal application routes
  if (trimmed.startsWith('/')) {
    return {
      isValid: false,
      error: "Cannot scan internal application routes (e.g. '/scanner'). Please provide a full external URL."
    };
  }

  const lower = trimmed.toLowerCase();

  // 4. Reject non-HTTP/HTTPS schemes
  for (const forbidden of FORBIDDEN_SCHEMES) {
    if (lower.startsWith(forbidden)) {
      return {
        isValid: false,
        error: 'Only external HTTP and HTTPS web addresses are supported for security scanning.'
      };
    }
  }

  // Prefix https:// for modern web standards if scheme is omitted
  let testUrl = trimmed;
  if (!/^[a-zA-Z][a-zA-Z0-9+.-]*:\/\//.test(testUrl)) {
    testUrl = 'https://' + testUrl;
  }

  let parsed: URL;
  try {
    parsed = new URL(testUrl);
  } catch (e) {
    return { isValid: false, error: `Malformed URL structure: ${(e as Error).message}` };
  }

  const scheme = parsed.protocol.replace(':', '').toLowerCase();
  if (scheme !== 'http' && scheme !== 'https') {
    return {
      isValid: false,
      error: `Unsupported URL scheme '${scheme}://'. Only 'http://' and 'https://' are supported.`
    };
  }

  let hostname = parsed.hostname;
  if (!hostname) {
    return {
      isValid: false,
      error: `'${trimmed}' is not a valid web address (no destination hostname detected).`
    };
  }

  const cleanHost = hostname.toLowerCase().replace(/\.+$/, '');

  // 5. Reject localhost and local dev domains
  if (cleanHost === 'localhost' || LOCAL_DOMAIN_SUFFIXES.some((s) => cleanHost.endsWith(s))) {
    return {
      isValid: false,
      error: `Scanning local development destinations ('${cleanHost}') is prohibited for security isolation.`
    };
  }

  // 6. Reject loopback and internal addresses
  if (['localhost', '127.0.0.1', '0.0.0.0', '::1', '[::1]'].includes(cleanHost)) {
    return {
      isValid: false,
      error: 'Scanning localhost, loopback, or internal host addresses is disallowed.'
    };
  }

  // 7. Check if host is a private or internal IP address
  const isIpv4Pattern = /^(\d{1,3}\.){3}\d{1,3}$/.test(cleanHost);
  const isIpv6Pattern = cleanHost.includes(':');

  if (isIpv4Pattern && isPrivateIpv4(cleanHost)) {
    return {
      isValid: false,
      error: `Scanning private or internal network IP addresses ('${cleanHost}') is prohibited to protect internal networks.`
    };
  }

  if (isIpv6Pattern && isPrivateIpv6(cleanHost)) {
    return {
      isValid: false,
      error: `Scanning private or internal IPv6 addresses ('${cleanHost}') is prohibited to protect internal networks.`
    };
  }

  // 8. Reject our own active application ports on loopback/localhost
  const portNum = parsed.port ? parseInt(parsed.port, 10) : null;
  if (portNum && APP_PORTS.has(portNum) && ['localhost', '127.0.0.1', '0.0.0.0'].includes(cleanHost)) {
    return {
      isValid: false,
      error: `Scanning PhishGuard's own active application port (${portNum}) is prohibited.`
    };
  }

  // 9. Validate domain structure if not an IP address
  if (!isIpv4Pattern && !isIpv6Pattern) {
    const parts = cleanHost.split('.').filter(Boolean);
    if (parts.length < 2) {
      return {
        isValid: false,
        error: `'${trimmed}' is not a valid web address. A valid external URL must include a registered domain extension (e.g., .com, .org, or .net).`
      };
    }

    const tld = parts[parts.length - 1];
    if (!/^[a-zA-Z]{2,}$/.test(tld)) {
      return {
        isValid: false,
        error: `'${trimmed}' contains an invalid domain extension ('.${tld}').`
      };
    }

    for (const part of parts) {
      if (!/^[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?$/.test(part)) {
        return {
          isValid: false,
          error: `'${trimmed}' contains an invalid domain component ('${part}').`
        };
      }
    }
  }

  return { isValid: true, sanitizedUrl: testUrl };
}
