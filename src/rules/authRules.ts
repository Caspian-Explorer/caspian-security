import { SecurityRule, SecuritySeverity, SecurityCategory, RuleType } from '../types';

export const authRules: SecurityRule[] = [
  {
    code: 'AUTH001',
    message: 'Hardcoded JWT secret detected',
    severity: SecuritySeverity.Error,
    patterns: [
      /jwt\.sign\s*\([^,]+,\s*['"][^'"]{1,}['"]/i,
      /jsonwebtoken.*secret\s*[:=]\s*['"][^'"]+['"]/i,
    ],
    suggestion: 'Store JWT secrets in environment variables, never hardcode them',
    category: SecurityCategory.AuthAccessControl,
    ruleType: RuleType.CodeDetectable,
  },
  {
    code: 'AUTH002',
    message: 'Session configured without secure flags',
    severity: SecuritySeverity.Warning,
    patterns: [
      /httpOnly\s*:\s*false/i,
      /secure\s*:\s*false/i,
    ],
    suggestion: 'Set httpOnly: true, secure: true, and sameSite on session cookies',
    category: SecurityCategory.AuthAccessControl,
    ruleType: RuleType.CodeDetectable,
  },
  {
    code: 'AUTH003',
    message: 'Comparing passwords with equality operator instead of constant-time comparison',
    severity: SecuritySeverity.Error,
    patterns: [
      /password\s*===?\s*(?:req\.|request\.|body\.|params\.|input)/i,
      /(?:req\.|request\.|body\.)password\s*===?\s*/i,
    ],
    suggestion: 'Use crypto.timingSafeEqual() or bcrypt.compare() to prevent timing attacks',
    category: SecurityCategory.AuthAccessControl,
    ruleType: RuleType.CodeDetectable,
  },
  {
    code: 'AUTH004',
    message: 'Authentication bypass: permissive access control',
    severity: SecuritySeverity.Warning,
    patterns: [
      /isAdmin\s*[:=]\s*true/i,
      /skipAuth\s*[:=]\s*true/i,
    ],
    suggestion: 'Avoid hardcoding administrative privileges; use proper RBAC mechanisms',
    category: SecurityCategory.AuthAccessControl,
    ruleType: RuleType.CodeDetectable,
  },
  {
    code: 'AUTH005',
    message: 'Weak password policy: minimum length too short',
    severity: SecuritySeverity.Warning,
    patterns: [
      /password\.length\s*>=?\s*[1-5]\b/i,
      /minlength\s*[:=]\s*[1-5]\b/i,
      /min_length\s*[:=]\s*[1-5]\b/i,
    ],
    suggestion: 'Enforce minimum 8-character passwords with complexity requirements',
    category: SecurityCategory.AuthAccessControl,
    ruleType: RuleType.CodeDetectable,
  },
  {
    code: 'AUTH006',
    message: 'Reminder: Apply rate limiting to authentication endpoints',
    severity: SecuritySeverity.Info,
    patterns: [
      /\/login|\/signin|\/authenticate|\/auth\//i,
    ],
    suggestion: 'Apply rate limiting (e.g., express-rate-limit) to prevent brute force attacks',
    category: SecurityCategory.AuthAccessControl,
    ruleType: RuleType.Informational,
  },
  {
    code: 'AUTH007',
    message: 'Token stored in localStorage is vulnerable to XSS',
    severity: SecuritySeverity.Warning,
    patterns: [
      /localStorage\.setItem\s*\(\s*['"](?:token|jwt|auth|session|access_token)['"]/i,
    ],
    suggestion: 'Use httpOnly cookies instead of localStorage for authentication tokens',
    category: SecurityCategory.AuthAccessControl,
    ruleType: RuleType.CodeDetectable,
  },
];
