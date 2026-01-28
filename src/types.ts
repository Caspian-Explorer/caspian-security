export enum SecuritySeverity {
  Info = 0,
  Warning = 1,
  Error = 2,
}

export interface SecurityRule {
  code: string;
  message: string;
  severity: SecuritySeverity;
  patterns: (RegExp | string)[];
  suggestion: string;
}

export interface SecurityIssue {
  line: number;
  column: number;
  message: string;
  severity: SecuritySeverity;
  suggestion: string;
  code: string;
  pattern: string;
}

export interface DiagnosticData {
  issue: SecurityIssue;
}