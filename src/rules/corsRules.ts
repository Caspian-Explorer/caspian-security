import { SecurityRule, SecuritySeverity, SecurityCategory, RuleType } from '../types';

export const corsRules: SecurityRule[] = [
  {
    code: 'CORS001',
    message: 'CORS allows all origins (wildcard)',
    severity: SecuritySeverity.Error,
    patterns: [
      /Access-Control-Allow-Origin['":\s]*['"]\*['"]/i,
      /origin\s*:\s*['"]\*['"]/i,
      /cors\(\s*\)/,
    ],
    suggestion: 'Restrict CORS to specific trusted origins instead of using wildcard *',
    category: SecurityCategory.CORSConfiguration,
    ruleType: RuleType.CodeDetectable,
  },
  {
    code: 'CORS002',
    message: 'CORS credentials enabled with potentially permissive origin',
    severity: SecuritySeverity.Warning,
    patterns: [
      /credentials\s*:\s*true/i,
    ],
    suggestion: 'When credentials are enabled, ensure origin is explicitly whitelisted (not wildcard)',
    category: SecurityCategory.CORSConfiguration,
    ruleType: RuleType.Informational,
  },
  {
    code: 'CORS003',
    message: 'CORS origin reflected from request without validation',
    severity: SecuritySeverity.Error,
    patterns: [
      /Access-Control-Allow-Origin.*req\.header/i,
      /Access-Control-Allow-Origin.*request\.headers/i,
    ],
    suggestion: 'Validate the Origin header against a whitelist before reflecting it',
    category: SecurityCategory.CORSConfiguration,
    ruleType: RuleType.CodeDetectable,
  },
  {
    code: 'CORS004',
    message: 'Overly permissive CORS methods',
    severity: SecuritySeverity.Warning,
    patterns: [
      /Access-Control-Allow-Methods['":\s]*['"].*\*.*['"]/i,
    ],
    suggestion: 'Restrict allowed methods to only those required by the endpoint',
    category: SecurityCategory.CORSConfiguration,
    ruleType: RuleType.CodeDetectable,
  },
  {
    code: 'CORS005',
    message: 'Reminder: Review CORS headers configuration for least privilege',
    severity: SecuritySeverity.Info,
    patterns: [
      /Access-Control-Allow-Headers/i,
    ],
    suggestion: 'Only expose headers that consumers actually need; avoid exposing sensitive headers',
    category: SecurityCategory.CORSConfiguration,
    ruleType: RuleType.Informational,
  },
  {
    code: 'CORS006',
    message: 'CORS preflight cache set too long',
    severity: SecuritySeverity.Warning,
    patterns: [
      /maxAge\s*:\s*\d{6,}/,
      /Access-Control-Max-Age['":\s]*['"]?\d{6,}/i,
    ],
    suggestion: 'Keep CORS preflight cache (maxAge) to 86400 (24 hours) or less',
    category: SecurityCategory.CORSConfiguration,
    ruleType: RuleType.CodeDetectable,
  },
];
