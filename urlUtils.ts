// Security Pattern Detection
const SQL_INJECTION_PATTERNS = [
  /(\bOR\b|\bAND\b)\s+[\w\d]+\s*=\s*[\w\d]+/i,
  /'\s*(OR|AND)\s*'?\d+/i,
  /--/,
  /;.*?(DROP|DELETE|INSERT|UPDATE|ALTER|CREATE|EXEC)/i,
  /UNION\s+SELECT/i,
  /SELECT\s+.*?\s+FROM/i,
  /INSERT\s+INTO/i,
  /UPDATE\s+.*?\s+SET/i,
  /DELETE\s+FROM/i,
  /DROP\s+(TABLE|DATABASE)/i,
  /EXEC(UTE)?\s*\(/i,
  /CAST\s*\(/i,
  /CONCAT\s*\(/i,
  /CHAR\s*\(/i,
  /\/\*.*?\*\//,
  /xp_cmdshell/i,
  /sp_executesql/i,
  /WAITFOR\s+DELAY/i,
  /BENCHMARK\s*\(/i,
  /SLEEP\s*\(/i,
  /pg_sleep/i,
];

const DANGEROUS_JS_PATTERNS = [
  /eval\s*\(/i,
  /Function\s*\(/i,
  /setTimeout\s*\(/i,
  /setInterval\s*\(/i,
  /innerHTML/i,
  /outerHTML/i,
  /document\.write/i,
  /\.insertAdjacentHTML/i,
];

const NOSQL_INJECTION_PATTERNS = [
  /\$where/i,
  /\$ne/i,
  /\$gt/i,
  /\$lt/i,
  /\$regex/i,
  /\$or/i,
  /\$and/i,
  /mapReduce/i,
  /\$function/i,
];

const XSS_PATTERNS = [
  /<script/i,
  /javascript:/i,
  /<embed/i,
  /<iframe/i,
  /<object/i,
  /eval\(/i,
  /expression\(/i,
];

const DANGEROUS_PROTOCOLS = new Set([
  'javascript:',
  'data:',
  'vbscript:',
  'file:',
  'about:',
  'blob:',
]);

const SAFE_PROTOCOLS = new Set(['http:', 'https:']);

// Combine all security checks
function hasDangerousPattern(value: string): boolean {
  const allPatterns = [
    ...SQL_INJECTION_PATTERNS,
    ...NOSQL_INJECTION_PATTERNS,
    ...DANGEROUS_JS_PATTERNS,
    ...XSS_PATTERNS,
  ];
  
  return allPatterns.some(pattern => pattern.test(value));
}

function hasDangerousProtocol(value: string): boolean {
  const normalized = value.trim().toLowerCase();
  
  // Check direct protocol match
  for (const protocol of DANGEROUS_PROTOCOLS) {
    if (normalized.startsWith(protocol)) {
      return true;
    }
  }
  
  // Check URL protocol
  try {
    const parsed = new URL(value);
    return DANGEROUS_PROTOCOLS.has(parsed.protocol.toLowerCase());
  } catch {
    return false;
  }
}

// Main sanitization functions
export function sanitizeAbsoluteUrl(input?: string | null): string | null {
  if (!input?.trim()) {
    return null;
  }
  
  const trimmed = input.trim();
  
  // Check for dangerous patterns or protocols
  if (hasDangerousPattern(trimmed) || hasDangerousProtocol(trimmed)) {
    return null;
  }
  
  // Try parsing as-is
  try {
    const url = new URL(trimmed);
    if (SAFE_PROTOCOLS.has(url.protocol)) {
      return url.toString();
    }
  } catch {
    // Try with https prefix
    try {
      const url = new URL(`https://${trimmed.replace(/^\/+/, '')}`);
      if (SAFE_PROTOCOLS.has(url.protocol)) {
        return url.toString();
      }
    } catch {
      return null;
    }
  }
  
  return null;
}

export function sanitizeUrlOrigin(input?: string | null): string | null {
  const sanitized = sanitizeAbsoluteUrl(input);
  return sanitized ? new URL(sanitized).origin : null;
}
