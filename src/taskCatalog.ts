import { SecurityCategory } from './types';
import {
  SecurityTaskDefinition,
  TaskInterval,
  AutoCompleteTrigger,
} from './taskTypes';

export const SECURITY_TASK_CATALOG: SecurityTaskDefinition[] = [
  // ── Dependencies & Supply Chain ──
  {
    id: 'TASK-DEP-001',
    title: 'Run dependency vulnerability audit',
    description: 'Run npm audit (or equivalent) to identify known vulnerabilities in direct and transitive dependencies. Subscribe to security advisories (GitHub Dependabot, Snyk).',
    category: SecurityCategory.DependenciesSupplyChain,
    defaultInterval: TaskInterval.Weekly,
    autoCompleteTrigger: AutoCompleteTrigger.DependencyCheck,
    relatedRuleCodes: ['DEP004', 'DEP005'],
    priority: 9,
  },
  {
    id: 'TASK-DEP-002',
    title: 'Review and apply security patches',
    description: 'Apply security patches to dependencies within 48 hours of disclosure. Review npm audit, GitHub Dependabot, or Snyk alerts. Define an SLA for patch response times.',
    category: SecurityCategory.DependenciesSupplyChain,
    defaultInterval: TaskInterval.Weekly,
    autoCompleteTrigger: AutoCompleteTrigger.Manual,
    relatedRuleCodes: ['DEP003'],
    priority: 10,
  },
  {
    id: 'TASK-DEP-003',
    title: 'Check for outdated dependencies',
    description: 'Review npm outdated or equivalent to identify stale packages that may have security fixes in newer versions.',
    category: SecurityCategory.DependenciesSupplyChain,
    defaultInterval: TaskInterval.Monthly,
    autoCompleteTrigger: AutoCompleteTrigger.DependencyCheck,
    relatedRuleCodes: ['DEP002'],
    priority: 7,
  },
  {
    id: 'TASK-DEP-004',
    title: 'Audit transitive dependency tree',
    description: 'Review lock files (package-lock.json, yarn.lock) for unexpected transitive packages. Use tools that scan the full dependency tree including indirect dependencies.',
    category: SecurityCategory.DependenciesSupplyChain,
    defaultInterval: TaskInterval.Monthly,
    autoCompleteTrigger: AutoCompleteTrigger.Manual,
    relatedRuleCodes: ['DEP006'],
    priority: 6,
  },

  // ── Secrets & Credentials ──
  {
    id: 'TASK-CRED-001',
    title: 'Rotate secrets and API keys',
    description: 'Review and rotate secrets, API keys, and access tokens on a regular schedule. Audit access permissions and revoke unused credentials.',
    category: SecurityCategory.SecretsCredentials,
    defaultInterval: TaskInterval.Quarterly,
    autoCompleteTrigger: AutoCompleteTrigger.Manual,
    relatedRuleCodes: ['CRED008'],
    priority: 8,
  },
  {
    id: 'TASK-CRED-002',
    title: 'Scan git history for leaked secrets',
    description: 'Run git-secrets, truffleHog, or gitleaks to check commit history for accidentally committed credentials.',
    category: SecurityCategory.SecretsCredentials,
    defaultInterval: TaskInterval.Monthly,
    autoCompleteTrigger: AutoCompleteTrigger.Manual,
    relatedRuleCodes: ['CRED009'],
    priority: 8,
  },

  // ── Encryption & Data Protection ──
  {
    id: 'TASK-ENC-001',
    title: 'Verify database backups are encrypted',
    description: 'Confirm all database backups are encrypted at rest using appropriate encryption standards (AES-256 or equivalent).',
    category: SecurityCategory.EncryptionDataProtection,
    defaultInterval: TaskInterval.Monthly,
    autoCompleteTrigger: AutoCompleteTrigger.Manual,
    relatedRuleCodes: ['ENC011'],
    priority: 7,
  },
  {
    id: 'TASK-ENC-002',
    title: 'Review data protection compliance',
    description: 'Verify user data export (GDPR Art. 20) and right-to-erasure (Art. 17) processes are functional. Ensure data retention policies are enforced.',
    category: SecurityCategory.EncryptionDataProtection,
    defaultInterval: TaskInterval.Quarterly,
    autoCompleteTrigger: AutoCompleteTrigger.Manual,
    relatedRuleCodes: ['ENC012'],
    priority: 6,
  },

  // ── Logging & Monitoring ──
  {
    id: 'TASK-LOG-001',
    title: 'Verify log storage encryption and access',
    description: 'Confirm logs are stored in encrypted storage, centralized logging has encryption at rest, and log file access is restricted to admin/security team.',
    category: SecurityCategory.LoggingMonitoring,
    defaultInterval: TaskInterval.Monthly,
    autoCompleteTrigger: AutoCompleteTrigger.Manual,
    relatedRuleCodes: ['LOG007', 'LOG008'],
    priority: 6,
  },
  {
    id: 'TASK-LOG-002',
    title: 'Review security event monitoring',
    description: 'Verify authentication events, access control failures, and anomalous patterns are being logged and alerted on.',
    category: SecurityCategory.LoggingMonitoring,
    defaultInterval: TaskInterval.Monthly,
    autoCompleteTrigger: AutoCompleteTrigger.Manual,
    relatedRuleCodes: ['LOG001', 'LOG009'],
    priority: 7,
  },

  // ── Infrastructure & Deployment ──
  {
    id: 'TASK-INFRA-001',
    title: 'Audit CI/CD pipeline for secret exposure',
    description: 'Review build logs and CI/CD configuration for accidental secret exposure. Verify secret masking is enabled and debug mode is disabled in production.',
    category: SecurityCategory.InfrastructureDeployment,
    defaultInterval: TaskInterval.Monthly,
    autoCompleteTrigger: AutoCompleteTrigger.Manual,
    relatedRuleCodes: ['INFRA006', 'INFRA002'],
    priority: 7,
  },
  {
    id: 'TASK-INFRA-002',
    title: 'Review environment separation',
    description: 'Verify production, staging, and development environments are properly separated with independent credentials and configurations.',
    category: SecurityCategory.InfrastructureDeployment,
    defaultInterval: TaskInterval.Quarterly,
    autoCompleteTrigger: AutoCompleteTrigger.Manual,
    relatedRuleCodes: ['INFRA001'],
    priority: 6,
  },

  // ── Authentication & Access Control ──
  {
    id: 'TASK-AUTH-001',
    title: 'Review authentication and rate limiting',
    description: 'Verify rate limiting is active on all login, signup, and password reset endpoints. Review session management and token expiry policies.',
    category: SecurityCategory.AuthAccessControl,
    defaultInterval: TaskInterval.Monthly,
    autoCompleteTrigger: AutoCompleteTrigger.Manual,
    relatedRuleCodes: ['AUTH006', 'AUTH003'],
    priority: 8,
  },

  // ── CORS Configuration ──
  {
    id: 'TASK-CORS-001',
    title: 'Review CORS configuration',
    description: 'Audit CORS headers to ensure only required origins, methods, and headers are allowed. Verify no wildcard origins are used with credentials.',
    category: SecurityCategory.CORSConfiguration,
    defaultInterval: TaskInterval.Monthly,
    autoCompleteTrigger: AutoCompleteTrigger.Manual,
    relatedRuleCodes: ['CORS001', 'CORS005'],
    priority: 7,
  },

  // ── Input Validation & XSS ──
  {
    id: 'TASK-INPUT-001',
    title: 'Review input validation coverage',
    description: 'Verify all user-facing endpoints have proper input validation, output encoding, and sanitization. Check for innerHTML, document.write, and template injection patterns.',
    category: SecurityCategory.InputValidationXSS,
    defaultInterval: TaskInterval.Monthly,
    autoCompleteTrigger: AutoCompleteTrigger.WorkspaceScan,
    relatedRuleCodes: ['XSS001', 'XSS002'],
    priority: 8,
  },

  // ── CSRF Protection ──
  {
    id: 'TASK-CSRF-001',
    title: 'Verify CSRF protection on state-changing endpoints',
    description: 'Confirm all POST/PUT/DELETE endpoints have proper CSRF token validation. Verify SameSite cookie attributes are set appropriately.',
    category: SecurityCategory.CSRFProtection,
    defaultInterval: TaskInterval.Monthly,
    autoCompleteTrigger: AutoCompleteTrigger.Manual,
    relatedRuleCodes: ['CSRF001', 'CSRF004'],
    priority: 7,
  },

  // ── API Security ──
  {
    id: 'TASK-API-001',
    title: 'Review API authentication and rate limiting',
    description: 'Verify all API endpoints require authentication, have appropriate rate limiting, and enforce authorization checks to prevent IDOR vulnerabilities.',
    category: SecurityCategory.APISecurity,
    defaultInterval: TaskInterval.Monthly,
    autoCompleteTrigger: AutoCompleteTrigger.Manual,
    relatedRuleCodes: ['API001', 'API003', 'API006'],
    priority: 8,
  },

  // ── Database Security ──
  {
    id: 'TASK-DB-001',
    title: 'Review database security controls',
    description: 'Verify parameterized queries are used everywhere, database credentials are properly secured, and least-privilege access is enforced.',
    category: SecurityCategory.DatabaseSecurity,
    defaultInterval: TaskInterval.Monthly,
    autoCompleteTrigger: AutoCompleteTrigger.Manual,
    relatedRuleCodes: ['DB001', 'DB003', 'DB009'],
    priority: 8,
  },

  // ── File Handling ──
  {
    id: 'TASK-FILE-001',
    title: 'Review file upload and storage security',
    description: 'Verify file uploads validate type via magic bytes, enforce size limits, store outside web root, and sanitize filenames against path traversal.',
    category: SecurityCategory.FileHandling,
    defaultInterval: TaskInterval.Monthly,
    autoCompleteTrigger: AutoCompleteTrigger.Manual,
    relatedRuleCodes: ['FILE002', 'FILE007', 'FILE001'],
    priority: 7,
  },

  // ── Frontend Security ──
  {
    id: 'TASK-FE-001',
    title: 'Review Content Security Policy headers',
    description: 'Verify CSP headers are set and do not allow unsafe-inline or unsafe-eval in production. Review postMessage origin validation and iframe sandbox attributes.',
    category: SecurityCategory.FrontendSecurity,
    defaultInterval: TaskInterval.Monthly,
    autoCompleteTrigger: AutoCompleteTrigger.Manual,
    relatedRuleCodes: ['FE005', 'FE003'],
    priority: 7,
  },

  // ── Business Logic & Payment ──
  {
    id: 'TASK-BIZ-001',
    title: 'Review payment and subscription security',
    description: 'Verify payment verification is server-side, subscription state is synced via webhooks, refund logic prevents duplicates, and premium features have server-side checks.',
    category: SecurityCategory.BusinessLogicPayment,
    defaultInterval: TaskInterval.Quarterly,
    autoCompleteTrigger: AutoCompleteTrigger.Manual,
    relatedRuleCodes: ['BIZ002', 'BIZ006', 'BIZ001'],
    priority: 6,
  },

  // ── General / Cross-Cutting ──
  {
    id: 'TASK-SCAN-001',
    title: 'Run full workspace security scan',
    description: 'Execute a complete Caspian Security scan across the entire workspace with all categories enabled to identify new issues.',
    category: SecurityCategory.InputValidationXSS,
    defaultInterval: TaskInterval.Weekly,
    autoCompleteTrigger: AutoCompleteTrigger.WorkspaceScan,
    relatedRuleCodes: [],
    priority: 9,
  },
];

export function getTaskDefinition(taskId: string): SecurityTaskDefinition | undefined {
  return SECURITY_TASK_CATALOG.find(t => t.id === taskId);
}

export function getTasksByCategory(category: SecurityCategory): SecurityTaskDefinition[] {
  return SECURITY_TASK_CATALOG.filter(t => t.category === category);
}
