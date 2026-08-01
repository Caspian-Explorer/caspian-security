import { SecurityRule, SecuritySeverity, SecurityCategory, RuleType } from '../types';

export const securityHeadersRules: SecurityRule[] = [
  {
    code: 'HDR001',
    message: 'Missing X-Frame-Options header — clickjacking risk',
    severity: SecuritySeverity.Warning,
    patterns: [
      /res\.(?:set|setHeader|header)\s*\(/i,
      /response\.(?:set|setHeader|header)\s*\(/i,
    ],
    suppressIfNearby: [/X-Frame-Options/i, /frameguard/i, /helmet\s*\(/i],
    suppressNearbyWindow: 200,
    suggestion:
      'Set the X-Frame-Options header to DENY or SAMEORIGIN to prevent clickjacking attacks where your page is embedded in a malicious iframe.',
    category: SecurityCategory.InfrastructureDeployment,
    ruleType: RuleType.Informational,
  },
  {
    code: 'HDR002',
    message: 'Missing X-Content-Type-Options header — MIME sniffing risk',
    severity: SecuritySeverity.Warning,
    patterns: [
      /res\.(?:set|setHeader|header)\s*\(/i,
      /response\.(?:set|setHeader|header)\s*\(/i,
    ],
    suppressIfNearby: [/X-Content-Type-Options/i, /noSniff/i, /helmet\s*\(/i],
    suppressNearbyWindow: 200,
    suggestion:
      'Set X-Content-Type-Options: nosniff to prevent browsers from MIME-sniffing the response content type, which can lead to XSS via content type confusion.',
    category: SecurityCategory.InfrastructureDeployment,
    ruleType: RuleType.Informational,
  },
  {
    code: 'HDR003',
    message: 'Missing Referrer-Policy header — referrer leakage risk',
    severity: SecuritySeverity.Info,
    patterns: [
      /res\.(?:set|setHeader|header)\s*\(/i,
      /response\.(?:set|setHeader|header)\s*\(/i,
    ],
    suppressIfNearby: [/Referrer-Policy/i, /referrerPolicy/i, /helmet\s*\(/i],
    suppressNearbyWindow: 200,
    suggestion:
      'Set the Referrer-Policy header (e.g., strict-origin-when-cross-origin or no-referrer) to control how much referrer information is sent with requests, preventing URL leakage of sensitive paths or tokens.',
    category: SecurityCategory.InfrastructureDeployment,
    ruleType: RuleType.Informational,
  },
  {
    code: 'HDR004',
    message: 'Missing Permissions-Policy header — unrestricted browser features',
    severity: SecuritySeverity.Info,
    patterns: [
      /app\.listen\s*\(/i,
      /createServer\s*\(/i,
    ],
    suppressIfNearby: [/Permissions-Policy/i, /Feature-Policy/i, /permittedCrossDomainPolicies/i, /helmet\s*\(/i],
    suppressNearbyWindow: 200,
    suggestion:
      'Set the Permissions-Policy header to restrict browser features (camera, microphone, geolocation, payment) your app does not use, reducing the attack surface if your site is compromised.',
    category: SecurityCategory.InfrastructureDeployment,
    ruleType: RuleType.Informational,
    filePatterns: { include: [/\.(?:js|ts|mjs|cjs)$/i] },
  },
  {
    code: 'HDR005',
    message: 'Sensitive response without Cache-Control: no-store',
    severity: SecuritySeverity.Warning,
    patterns: [
      /res\.(?:json|send)\s*\(.*(?:token|password|secret|ssn|creditCard)/i,
      /response\.(?:json|send)\s*\(.*(?:token|password|secret|ssn|creditCard)/i,
    ],
    negativePatterns: [/Cache-Control/i, /no-store/i],
    suppressIfNearby: [/Cache-Control/i, /no-store/i, /no-cache/i],
    suggestion:
      'Responses containing sensitive data (tokens, passwords, PII) should include Cache-Control: no-store to prevent browsers and proxies from caching them.',
    category: SecurityCategory.InfrastructureDeployment,
    ruleType: RuleType.CodeDetectable,
  },
];
