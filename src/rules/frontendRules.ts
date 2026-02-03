import { SecurityRule, SecuritySeverity, SecurityCategory, RuleType } from '../types';

export const frontendRules: SecurityRule[] = [
  {
    code: 'FE001',
    message: 'Unsafe eval() usage allows arbitrary code execution',
    severity: SecuritySeverity.Error,
    patterns: [
      /\beval\s*\(/,
      /new\s+Function\s*\(/,
      /setTimeout\s*\(\s*['"`]/,
      /setInterval\s*\(\s*['"`]/,
    ],
    suggestion: 'Avoid eval(), new Function(), and string arguments to setTimeout/setInterval',
    category: SecurityCategory.FrontendSecurity,
    ruleType: RuleType.CodeDetectable,
    contextAware: true,
  },
  {
    code: 'FE002',
    message: 'postMessage without origin validation',
    severity: SecuritySeverity.Warning,
    patterns: [
      /postMessage\s*\([^,]+,\s*['"]\*['"]\s*\)/,
    ],
    suggestion: 'Always specify target origin in postMessage and verify event.origin in message handlers',
    category: SecurityCategory.FrontendSecurity,
    ruleType: RuleType.CodeDetectable,
  },
  {
    code: 'FE003',
    message: 'Opening links without rel="noopener noreferrer"',
    severity: SecuritySeverity.Warning,
    patterns: [
      /target\s*=\s*['"]_blank['"]/i,
    ],
    suppressIfNearby: [/rel\s*=\s*['"][^'"]*noopener[^'"]*noreferrer[^'"]*['"]/i, /rel\s*=\s*['"][^'"]*noreferrer[^'"]*noopener[^'"]*['"]/i],
    suggestion: 'Add rel="noopener noreferrer" to links with target="_blank" to prevent tab-nabbing',
    category: SecurityCategory.FrontendSecurity,
    ruleType: RuleType.Informational,
  },
  {
    code: 'FE004',
    message: 'Insecure use of iframe without sandbox',
    severity: SecuritySeverity.Warning,
    patterns: [
      /<iframe(?![^>]*sandbox)[^>]*>/i,
    ],
    suggestion: 'Add sandbox attribute to iframes to restrict embedded content capabilities',
    category: SecurityCategory.FrontendSecurity,
    ruleType: RuleType.CodeDetectable,
  },
  {
    code: 'FE005',
    message: 'Script loaded from external CDN without integrity check',
    severity: SecuritySeverity.Warning,
    patterns: [
      /<script\s+src\s*=\s*['"]https?:\/\/(?![^'"]*localhost)[^'"]*['"](?![^>]*integrity)[^>]*>/i,
    ],
    suggestion: 'Add Subresource Integrity (SRI) hash attributes to external script tags',
    category: SecurityCategory.FrontendSecurity,
    ruleType: RuleType.CodeDetectable,
  },
  {
    code: 'FE006',
    message: 'Sensitive data stored via document.cookie',
    severity: SecuritySeverity.Warning,
    patterns: [
      /document\.cookie\s*=/i,
    ],
    suggestion: 'Use Secure, HttpOnly, and SameSite flags on cookies; prefer server-side cookie setting',
    category: SecurityCategory.FrontendSecurity,
    ruleType: RuleType.CodeDetectable,
  },
  {
    code: 'FE007',
    message: 'Prototype pollution: unsafe __proto__ or constructor access',
    severity: SecuritySeverity.Warning,
    patterns: [
      /__proto__/,
      /\bconstructor\s*\[/,
    ],
    suggestion: 'Use Object.create(null) for dictionaries; validate keys to prevent __proto__ and constructor pollution',
    category: SecurityCategory.FrontendSecurity,
    ruleType: RuleType.CodeDetectable,
  },
  {
    code: 'FE008',
    message: 'Reminder: Add Subresource Integrity for third-party CDN resources',
    severity: SecuritySeverity.Info,
    patterns: [
      /cdn\.|unpkg\.com|cdnjs|jsdelivr/i,
    ],
    suggestion: 'Add integrity and crossorigin attributes to all third-party script and link tags',
    category: SecurityCategory.FrontendSecurity,
    ruleType: RuleType.Informational,
  },
  {
    code: 'FE009',
    message: 'Reminder: Client-side validation is for UX only — server-side validation is required for security',
    severity: SecuritySeverity.Info,
    patterns: [
      /checkValidity\s*\(/,
      /setCustomValidity\s*\(/,
      /\.validity\./,
      /reportValidity\s*\(/,
    ],
    suggestion: 'Client-side validation improves user experience but can be bypassed. Always validate and sanitize all inputs on the server side as the authoritative security boundary',
    category: SecurityCategory.FrontendSecurity,
    ruleType: RuleType.Informational,
  },
];
