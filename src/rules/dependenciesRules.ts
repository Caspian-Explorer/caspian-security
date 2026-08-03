import { SecurityRule, SecuritySeverity, SecurityCategory, RuleType } from '../types';

/**
 * Dependency-manifest files. DEP001/DEP002 hunt for manifest syntax
 * (`"^1.2.3"`, `"dependencies":`) but were previously ungated, so they
 * fired on ordinary source code — DEP001 matched the `'*'` literals in a
 * glob parser, and DEP002 matched every `require(...)` call in every file.
 * Gating them to the files they were written for removes that whole class
 * of false positive.
 */
const MANIFEST_ONLY = {
  include: [
    /(?:^|[\\/])package\.json$/i,
    /(?:^|[\\/])(?:requirements[\w.-]*\.txt|Pipfile|pyproject\.toml)$/i,
    /(?:^|[\\/])(?:go\.mod|Cargo\.toml|pom\.xml|build\.gradle(?:\.kts)?)$/i,
    /(?:^|[\\/])(?:Gemfile|composer\.json)$/i,
  ],
};

export const dependenciesRules: SecurityRule[] = [
  {
    code: 'DEP001',
    message: 'Dependency version is not pinned to an exact version',
    severity: SecuritySeverity.Warning,
    patterns: [
      /["']\^[0-9]+\./,
      /["']~[0-9]+\./,
      /["']\*["']/,
      /["']>=\s*[0-9]+\./,
      /["']latest["']/,
    ],
    filePatterns: MANIFEST_ONLY,
    suggestion: 'Pin all dependencies to exact versions (e.g., "1.2.3" instead of "^1.2.3") to ensure deterministic builds and prevent unexpected breaking changes or supply chain attacks',
    category: SecurityCategory.DependenciesSupplyChain,
    ruleType: RuleType.CodeDetectable,
  },
  {
    code: 'DEP002',
    message: 'Reminder: Keep dependencies updated regularly to avoid known vulnerabilities',
    severity: SecuritySeverity.Info,
    patterns: [
      /["']dependencies["']\s*:/,
      /["']devDependencies["']\s*:/,
      /require\s*\(/,
    ],
    filePatterns: MANIFEST_ONLY,
    suggestion: 'Establish a regular schedule (at least monthly) to review and update dependencies. Use tools like npm outdated, pip list --outdated, or Dependabot to track stale packages',
    category: SecurityCategory.DependenciesSupplyChain,
    ruleType: RuleType.Informational,
  },
  {
    code: 'DEP003',
    message: 'Reminder: Apply security patches to dependencies within 48 hours of disclosure',
    severity: SecuritySeverity.Info,
    patterns: [
      /["']dependencies["']\s*:/,
      /require\s*\(/,
      /from\s+["'][a-z@]/,
    ],
    suggestion: 'Subscribe to security advisories (GitHub Dependabot, Snyk, npm audit) and apply critical patches within 48 hours. Define an SLA for patch response times',
    category: SecurityCategory.DependenciesSupplyChain,
    ruleType: RuleType.ProjectAdvisory,
  },
  {
    code: 'DEP004',
    message: 'Reminder: Run npm audit / pip-audit / dependency vulnerability scans weekly',
    severity: SecuritySeverity.Info,
    patterns: [
      /["']dependencies["']\s*:/,
      /require\s*\(/,
      /from\s+["'][a-z@]/,
    ],
    suggestion: 'Run dependency audit tools (npm audit, pip-audit, snyk test, cargo audit) at least weekly in CI/CD. Fail builds on critical or high severity vulnerabilities',
    category: SecurityCategory.DependenciesSupplyChain,
    ruleType: RuleType.ProjectAdvisory,
  },
  {
    code: 'DEP005',
    message: 'Reminder: Identify and remediate known vulnerable dependencies',
    severity: SecuritySeverity.Info,
    patterns: [
      /["']dependencies["']\s*:/,
      /require\s*\(/,
      /from\s+["'][a-z@]/,
    ],
    suggestion: 'Integrate vulnerability scanning into CI/CD (Snyk, npm audit, OWASP Dependency-Check). Track and remediate all known CVEs in your dependency tree',
    category: SecurityCategory.DependenciesSupplyChain,
    ruleType: RuleType.ProjectAdvisory,
  },
  {
    code: 'DEP006',
    message: 'Reminder: Monitor transitive (indirect) dependencies for vulnerabilities',
    severity: SecuritySeverity.Info,
    patterns: [
      /["']dependencies["']\s*:/,
      /require\s*\(/,
      /from\s+["'][a-z@]/,
    ],
    suggestion: 'Use tools that scan the full dependency tree including transitive dependencies (npm audit, snyk, pip-audit). Review lock files (package-lock.json, yarn.lock) for unexpected transitive packages',
    category: SecurityCategory.DependenciesSupplyChain,
    ruleType: RuleType.ProjectAdvisory,
  },
];
