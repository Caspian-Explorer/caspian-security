export enum SecuritySeverity {
  Info = 0,
  Warning = 1,
  Error = 2,
}

export enum SecurityCategory {
  AuthAccessControl = 'auth-access-control',
  InputValidationXSS = 'input-validation-xss',
  CSRFProtection = 'csrf-protection',
  CORSConfiguration = 'cors-configuration',
  EncryptionDataProtection = 'encryption-data-protection',
  APISecurity = 'api-security',
  DatabaseSecurity = 'database-security',
  FileHandling = 'file-handling',
  SecretsCredentials = 'secrets-credentials',
  FrontendSecurity = 'frontend-security',
  BusinessLogicPayment = 'business-logic-payment',
  LoggingMonitoring = 'logging-monitoring',
  DependenciesSupplyChain = 'dependencies-supply-chain',
  InfrastructureDeployment = 'infrastructure-deployment',
}

export enum RuleType {
  CodeDetectable = 'code-detectable',
  Informational = 'informational',
  ProjectAdvisory = 'project-advisory',
}

export interface SecurityRule {
  code: string;
  message: string;
  severity: SecuritySeverity;
  patterns: (RegExp | string)[];
  suggestion: string;
  category: SecurityCategory;
  ruleType: RuleType;
  contextAware?: boolean;
  negativePatterns?: (RegExp | string)[];
  suppressIfNearby?: RegExp[];
  filePatterns?: {
    include?: RegExp[];
    exclude?: RegExp[];
    reduceSeverityIn?: RegExp[];
  };
}

export interface SecurityIssue {
  line: number;
  column: number;
  message: string;
  severity: SecuritySeverity;
  suggestion: string;
  code: string;
  pattern: string;
  category: SecurityCategory;
  confidenceLevel?: 'critical' | 'safe' | 'verify-needed';
}

export interface ProjectAdvisory {
  code: string;
  message: string;
  suggestion: string;
  category: SecurityCategory;
  triggeredBy: string;
}

export const SEVERITY_LABELS: Record<SecuritySeverity, string> = {
  [SecuritySeverity.Error]: 'Error',
  [SecuritySeverity.Warning]: 'Warning',
  [SecuritySeverity.Info]: 'Info',
};

export const CATEGORY_LABELS: Record<SecurityCategory, string> = {
  [SecurityCategory.AuthAccessControl]: 'Authentication & Access Control',
  [SecurityCategory.InputValidationXSS]: 'Input Validation & XSS',
  [SecurityCategory.CSRFProtection]: 'CSRF Protection',
  [SecurityCategory.CORSConfiguration]: 'CORS Configuration',
  [SecurityCategory.EncryptionDataProtection]: 'Encryption & Data Protection',
  [SecurityCategory.APISecurity]: 'API Security',
  [SecurityCategory.DatabaseSecurity]: 'Database Security',
  [SecurityCategory.FileHandling]: 'File Handling',
  [SecurityCategory.SecretsCredentials]: 'Secrets & Credentials',
  [SecurityCategory.FrontendSecurity]: 'Frontend Security',
  [SecurityCategory.BusinessLogicPayment]: 'Business Logic & Payment Security',
  [SecurityCategory.LoggingMonitoring]: 'Logging & Monitoring',
  [SecurityCategory.DependenciesSupplyChain]: 'Dependencies & Supply Chain',
  [SecurityCategory.InfrastructureDeployment]: 'Infrastructure & Deployment',
};
