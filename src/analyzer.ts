import * as vscode from 'vscode';
import { SecurityRule, SecurityIssue, SecuritySeverity } from './types';

export class SecurityAnalyzer {
  private rules: SecurityRule[];

  constructor() {
    this.rules = this.initializeRules();
  }

  async analyzeDocument(document: vscode.TextDocument): Promise<SecurityIssue[]> {
    try {
      const issues: SecurityIssue[] = [];
      const text = document.getText();
      const lines = text.split('\n');

      for (let lineNum = 0; lineNum < lines.length; lineNum++) {
        const line = lines[lineNum];
        
        for (const rule of this.rules) {
          for (const pattern of rule.patterns) {
            try {
              if (typeof pattern === 'string') {
                if (line.toLowerCase().includes(pattern.toLowerCase())) {
                  const index = line.toLowerCase().indexOf(pattern.toLowerCase());
                  issues.push({
                    line: lineNum,
                    column: index >= 0 ? index : 0,
                    message: rule.message,
                    severity: rule.severity,
                    suggestion: rule.suggestion,
                    code: rule.code,
                    pattern: pattern,
                  });
                }
              }
            } catch (e) {
              console.error('Error processing pattern:', e);
            }
          }
        }
      }

      return issues;
    } catch (error) {
      console.error('Error analyzing document:', error);
      return [];
    }
  }

  private initializeRules(): SecurityRule[] {
    return [
      {
        code: 'SEC001',
        message: 'Potential SQL Injection: Use parameterized queries',
        severity: SecuritySeverity.Error,
        patterns: ['WHERE id = " +', 'WHERE id = \' +'],
        suggestion: 'Use prepared statements with placeholders',
      },
      {
        code: 'SEC002',
        message: 'Hardcoded credentials detected',
        severity: SecuritySeverity.Error,
        patterns: ['password =', 'apiKey =', 'api_key =', 'secret ='],
        suggestion: 'Use environment variables instead of hardcoding secrets',
      },
      {
        code: 'SEC003',
        message: 'Weak cryptographic function',
        severity: SecuritySeverity.Warning,
        patterns: ['createCipher', 'md5', 'sha1'],
        suggestion: 'Use bcrypt, argon2, or PBKDF2 for secure hashing',
      },
      {
        code: 'SEC004',
        message: 'Unsafe eval() detected',
        severity: SecuritySeverity.Error,
        patterns: ['eval('],
        suggestion: 'Avoid using eval() - use safer alternatives',
      },
      {
        code: 'SEC005',
        message: 'Potential path traversal vulnerability',
        severity: SecuritySeverity.Warning,
        patterns: ['readFileSync', 'readFile'],
        suggestion: 'Validate and sanitize file paths',
      },
    ];
  }
}