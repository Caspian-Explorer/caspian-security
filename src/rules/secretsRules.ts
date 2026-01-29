import { SecurityRule, SecuritySeverity, SecurityCategory, RuleType } from '../types';

export const secretsRules: SecurityRule[] = [
  {
    code: 'CRED001',
    message: 'Hardcoded password or secret assignment',
    severity: SecuritySeverity.Error,
    patterns: [
      /(?:password|passwd|pwd)\s*[:=]\s*['"][^'"]{2,}['"]/i,
      /(?:secret|apiKey|api_key|apiSecret|api_secret)\s*[:=]\s*['"][^'"]{2,}['"]/i,
      /(?:access_token|auth_token|private_key)\s*[:=]\s*['"][^'"]{2,}['"]/i,
    ],
    suggestion: 'Use environment variables, a secrets manager, or vault for credentials',
    category: SecurityCategory.SecretsCredentials,
    ruleType: RuleType.CodeDetectable,
  },
  {
    code: 'CRED002',
    message: 'AWS access key pattern detected',
    severity: SecuritySeverity.Error,
    patterns: [
      /AKIA[0-9A-Z]{16}/,
      /aws_access_key_id\s*[:=]\s*['"][^'"]+['"]/i,
      /aws_secret_access_key\s*[:=]\s*['"][^'"]+['"]/i,
    ],
    suggestion: 'Use IAM roles, AWS Secrets Manager, or environment variables instead of hardcoded AWS keys',
    category: SecurityCategory.SecretsCredentials,
    ruleType: RuleType.CodeDetectable,
  },
  {
    code: 'CRED003',
    message: 'Private key content detected in source code',
    severity: SecuritySeverity.Error,
    patterns: [
      /-----BEGIN (?:RSA |EC |DSA )?PRIVATE KEY-----/,
      /-----BEGIN OPENSSH PRIVATE KEY-----/,
    ],
    suggestion: 'Never embed private keys in source code; load from secure file system or secrets manager',
    category: SecurityCategory.SecretsCredentials,
    ruleType: RuleType.CodeDetectable,
  },
  {
    code: 'CRED004',
    message: 'GitHub/GitLab personal access token pattern',
    severity: SecuritySeverity.Error,
    patterns: [
      /gh[pousr]_[A-Za-z0-9_]{36,}/,
      /glpat-[A-Za-z0-9\-_]{20,}/,
    ],
    suggestion: 'Revoke leaked tokens immediately and use environment variables for access tokens',
    category: SecurityCategory.SecretsCredentials,
    ruleType: RuleType.CodeDetectable,
  },
  {
    code: 'CRED005',
    message: 'Generic high-entropy secret in string literal',
    severity: SecuritySeverity.Warning,
    patterns: [
      /['"][A-Za-z0-9+\/]{40,}={0,2}['"]/,
    ],
    suggestion: 'Review this string literal: if it is a secret or token, move it to environment variables',
    category: SecurityCategory.SecretsCredentials,
    ruleType: RuleType.CodeDetectable,
  },
  {
    code: 'CRED006',
    message: 'Environment variable with sensitive default fallback',
    severity: SecuritySeverity.Warning,
    patterns: [
      /process\.env\.\w+\s*\|\|\s*['"][^'"]{8,}['"]/i,
      /os\.(?:environ|getenv)\s*\(.*,\s*['"][^'"]{8,}['"]/i,
    ],
    suggestion: 'Do not provide hardcoded fallback values for sensitive environment variables; fail fast instead',
    category: SecurityCategory.SecretsCredentials,
    ruleType: RuleType.CodeDetectable,
  },
  {
    code: 'CRED007',
    message: 'Sensitive file reference detected - ensure it is in .gitignore',
    severity: SecuritySeverity.Warning,
    patterns: [
      /\.env\b/,
      /credentials\.json/,
      /serviceAccountKey/i,
    ],
    suggestion: 'Ensure .env, credential files, and private keys are listed in .gitignore',
    category: SecurityCategory.SecretsCredentials,
    ruleType: RuleType.Informational,
  },
  {
    code: 'CRED008',
    message: 'Reminder: Rotate secrets regularly and audit access',
    severity: SecuritySeverity.Info,
    patterns: [
      /(?:api|secret|auth).*(?:key|token|credential)/i,
    ],
    suggestion: 'Implement a secret rotation policy; audit who and what has access to secrets',
    category: SecurityCategory.SecretsCredentials,
    ruleType: RuleType.Informational,
  },
  {
    code: 'CRED009',
    message: 'Reminder: Scan git history for leaked secrets and remove them',
    severity: SecuritySeverity.Info,
    patterns: [
      /\.gitignore/,
      /git\s+(?:commit|push|add)/i,
      /\.git\//,
    ],
    suggestion: 'Use tools like git-secrets, truffleHog, or gitleaks to scan commit history for accidentally committed secrets. If found, rotate the secret immediately and use git filter-branch or BFG Repo-Cleaner to purge from history',
    category: SecurityCategory.SecretsCredentials,
    ruleType: RuleType.Informational,
  },
];
