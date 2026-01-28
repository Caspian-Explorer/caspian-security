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
          const matches = this.findMatches(line, rule.patterns);
          
          for (const match of matches) {
            issues.push({
              line: lineNum,
              column: match.startIndex,
              message: rule.message,
              severity: rule.severity,
              suggestion: rule.suggestion,
              code: rule.code,
              pattern: match.pattern,
            });
          }
        }
      }

      return issues;
    } catch (error) {
      console.error('Error analyzing document:', error);
      return [];
    }
  }

  private findMatches(
    line: string,
    patterns: (RegExp | string)[]
  ): Array<{ startIndex: number; pattern: string }> {
    const matches: Array<{ startIndex: number; pattern: string }> = [];

    for (const pattern of patterns) {
      try {
        if (typeof pattern === 'string') {
          const index = line.toLowerCase().indexOf(pattern.toLowerCase());
          if (index !== -1) {
            matches.push({ startIndex: index, pattern });
          }
        } else {
          try {
            const regex = new RegExp(pattern.source, pattern.flags);
            let match;
            while ((match = regex.exec(line)) !== null) {
              matches.push({ startIndex: match.index, pattern: match[0] });
            }
          } catch (e) {
            console.error('Regex error:', e);
          }
        }
      } catch (e) {
        console.error('Pattern matching error:', e);
      }
    }

    return matches;
  }

  private initializeRules(): SecurityRule[] {
    return [
      {
        code: 'SEC001',
        message: 'Potential SQL Injection: Use parameterized queries',
        severity: SecuritySeverity.Error,
        patterns: [
          /SELECT.*FROM.*WHERE.*\+/i,
        ],
        suggestion: 'Use prepared statements with placeholders',
      },
      {
        code: 'SEC002',
        message: 'Hardcoded credentials detected',
        severity: SecuritySeverity.Error,
        patterns: [
          /password\s*=\s*["'][^"']*["']/i,
          /apikey\s*=\s*["'][^"']*["']/i,
          /api.?key\s*=\s*["'][^"']*["']/i,
          /secret\s*=\s*["'][^"']*["']/i,
        ],
        suggestion: 'Use environment variables instead of hardcoding secrets',
      },
      {
        code: 'SEC003',
        message: 'Weak cryptographic function',
        severity: SecuritySeverity.Warning,
        patterns: [
          /crypto\.createCipher\(/i,
          /md5\s*\(/i,
          /sha1\s*\(/i,
        ],
        suggestion: 'Use bcrypt, argon2, or PBKDF2 for secure hashing',
      },
    ];
  }
}