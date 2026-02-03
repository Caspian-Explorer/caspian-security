import { SecurityRule, SecuritySeverity, SecurityCategory, RuleType } from '../types';

export const loggingRules: SecurityRule[] = [
  {
    code: 'LOG001',
    message: 'Reminder: Log all authentication attempts (success and failure)',
    severity: SecuritySeverity.Info,
    patterns: [
      /(?:login|signIn|authenticate)\s*(?:\(|=)/i,
    ],
    suggestion: 'Log all authentication attempts with timestamp, IP, user agent, and outcome (success/failure) for audit trails',
    category: SecurityCategory.LoggingMonitoring,
    ruleType: RuleType.Informational,
  },
  {
    code: 'LOG002',
    message: 'Reminder: Log all authorization failures',
    severity: SecuritySeverity.Info,
    patterns: [
      /(?:unauthorized|forbidden|403|accessDenied|access_denied)/i,
    ],
    suggestion: 'Log all authorization failures with user ID, requested resource, and timestamp to detect privilege escalation attempts',
    category: SecurityCategory.LoggingMonitoring,
    ruleType: RuleType.Informational,
  },
  {
    code: 'LOG003',
    message: 'Reminder: Log all admin and privileged operations',
    severity: SecuritySeverity.Info,
    patterns: [
      /(?:isAdmin|is_admin|role.*admin|adminAction|privileged)/i,
    ],
    suggestion: 'Log all admin/privileged operations including who performed them, what changed, and when',
    category: SecurityCategory.LoggingMonitoring,
    ruleType: RuleType.Informational,
  },
  {
    code: 'LOG004',
    message: 'Reminder: Log all role/permission changes and payment/API key modifications',
    severity: SecuritySeverity.Info,
    patterns: [
      /(?:updateRole|changeRole|setPermission|grantAccess|revokeAccess)/i,
      /(?:update|change|modify).*(?:role|permission|access)/i,
    ],
    suggestion: 'Log all role/permission changes, payment modifications, data exports, and API key operations with before/after values',
    category: SecurityCategory.LoggingMonitoring,
    ruleType: RuleType.Informational,
  },
  {
    code: 'LOG005',
    message: 'Password may be present in log output',
    severity: SecuritySeverity.Error,
    patterns: [
      /(?:console\.log|logger\.\w+|log\.\w+|print)\s*\(.*password/i,
      /(?:console\.log|logger\.\w+|log\.\w+|print)\s*\(.*passwd/i,
    ],
    suggestion: 'NEVER log passwords in any form; strip password fields before logging request bodies',
    category: SecurityCategory.LoggingMonitoring,
    ruleType: RuleType.CodeDetectable,
  },
  {
    code: 'LOG006',
    message: 'API key or secret may be present in log output',
    severity: SecuritySeverity.Error,
    patterns: [
      /(?:console\.log|logger\.\w+|log\.\w+|print)\s*\(.*(?:api[_-]?key|apiSecret|secret[_-]?key|access[_-]?key)/i,
    ],
    suggestion: 'NEVER log API keys or secrets; mask them (e.g., show only last 4 characters) if needed for debugging',
    category: SecurityCategory.LoggingMonitoring,
    ruleType: RuleType.CodeDetectable,
  },
  {
    code: 'LOG007',
    message: 'Reminder: Store logs securely with encryption',
    severity: SecuritySeverity.Info,
    patterns: [
      /(?:winston|bunyan|pino|log4js|morgan)\s*(?:\(|\.)/i,
      /createLogger/i,
    ],
    suggestion: 'Store logs in encrypted storage; use centralized logging (e.g., ELK, CloudWatch, Datadog) with encryption at rest',
    category: SecurityCategory.LoggingMonitoring,
    ruleType: RuleType.ProjectAdvisory,
  },
  {
    code: 'LOG008',
    message: 'Reminder: Restrict log access to admin/security personnel only',
    severity: SecuritySeverity.Info,
    patterns: [
      /logFile|log_file|logPath|log_path|logDir/i,
    ],
    suggestion: 'Restrict log file access to admin/security team only; use IAM policies for cloud log services; set file permissions to 0600',
    category: SecurityCategory.LoggingMonitoring,
    ruleType: RuleType.ProjectAdvisory,
  },
  {
    code: 'LOG009',
    message: 'Reminder: Log data export and API key change operations',
    severity: SecuritySeverity.Info,
    patterns: [
      /(?:export|download).*(?:data|report|csv|pdf)/i,
      /(?:rotate|regenerate|revoke).*(?:key|token|secret)/i,
    ],
    suggestion: 'Log all data export operations and API key lifecycle events (creation, rotation, revocation) for compliance auditing',
    category: SecurityCategory.LoggingMonitoring,
    ruleType: RuleType.Informational,
  },
];
