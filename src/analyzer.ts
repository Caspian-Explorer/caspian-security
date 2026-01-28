import * as vscode from 'vscode';
import { SecurityRule, SecurityIssue, SecurityCategory, RuleType } from './types';
import { getAllRules, getRulesByCategory, getRuleByCode as registryGetRuleByCode } from './rules';

export class SecurityAnalyzer {
  private allRules: SecurityRule[];

  constructor() {
    this.allRules = getAllRules();
  }

  async analyzeDocument(
    document: vscode.TextDocument,
    categories?: SecurityCategory[]
  ): Promise<SecurityIssue[]> {
    try {
      const rules = this.resolveRules(categories);
      const issues: SecurityIssue[] = [];
      const text = document.getText();
      const lines = text.split('\n');
      const informationalFired = new Set<string>();

      for (let lineNum = 0; lineNum < lines.length; lineNum++) {
        const line = lines[lineNum];
        const lineLower = line.toLowerCase();

        for (const rule of rules) {
          if (rule.ruleType === RuleType.Informational && informationalFired.has(rule.code)) {
            continue;
          }

          for (const pattern of rule.patterns) {
            try {
              let matched = false;
              let column = 0;
              let matchText = '';

              if (typeof pattern === 'string') {
                const patternLower = pattern.toLowerCase();
                if (lineLower.includes(patternLower)) {
                  matched = true;
                  column = lineLower.indexOf(patternLower);
                  matchText = pattern;
                }
              } else if (pattern instanceof RegExp) {
                const match = pattern.exec(line);
                if (match) {
                  matched = true;
                  column = match.index;
                  matchText = match[0];
                }
              }

              if (matched) {
                issues.push({
                  line: lineNum,
                  column,
                  message: rule.message,
                  severity: rule.severity,
                  suggestion: rule.suggestion,
                  code: rule.code,
                  pattern: matchText,
                  category: rule.category,
                });

                if (rule.ruleType === RuleType.Informational) {
                  informationalFired.add(rule.code);
                }

                break;
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

  getRuleByCode(code: string): SecurityRule | undefined {
    return registryGetRuleByCode(code);
  }

  private resolveRules(categories?: SecurityCategory[]): SecurityRule[] {
    if (!categories || categories.length === 0) {
      return this.allRules;
    }
    return categories.flatMap(cat => getRulesByCategory(cat));
  }
}
