import * as vscode from 'vscode';
import { SecurityRule, SecurityIssue, SecurityCategory, SecuritySeverity, RuleType, ProjectAdvisory } from './types';
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
      const filePath = document.uri.fsPath;

      for (let lineNum = 0; lineNum < lines.length; lineNum++) {
        const line = lines[lineNum];
        const lineLower = line.toLowerCase();

        for (const rule of rules) {
          // Skip project advisories — they are handled at workspace scan level
          if (rule.ruleType === RuleType.ProjectAdvisory) {
            continue;
          }

          if (rule.ruleType === RuleType.Informational && informationalFired.has(rule.code)) {
            continue;
          }

          // File-pattern exclusion: skip if file doesn't match include or matches exclude
          if (rule.filePatterns) {
            if (rule.filePatterns.include && !rule.filePatterns.include.some(p => p.test(filePath))) {
              continue;
            }
            if (rule.filePatterns.exclude && rule.filePatterns.exclude.some(p => p.test(filePath))) {
              continue;
            }
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

              if (!matched) {
                continue;
              }

              // Context-aware filtering: skip matches inside comments, strings, or JSX text
              if (rule.contextAware) {
                if (isInsideComment(line, column) ||
                    isInsideStringContent(line, column) ||
                    isInsideJSXText(line, column)) {
                  continue;
                }
              }

              // Negative patterns: skip if any negative pattern matches the line
              if (rule.negativePatterns) {
                let negated = false;
                for (const neg of rule.negativePatterns) {
                  if (typeof neg === 'string') {
                    if (lineLower.includes(neg.toLowerCase())) {
                      negated = true;
                      break;
                    }
                  } else if (neg instanceof RegExp) {
                    if (neg.test(line)) {
                      negated = true;
                      break;
                    }
                  }
                }
                if (negated) {
                  continue;
                }
              }

              // SuppressIfNearby: check surrounding lines for suppression patterns
              if (rule.suppressIfNearby) {
                let suppressed = false;
                const startLine = Math.max(0, lineNum - 3);
                const endLine = Math.min(lines.length - 1, lineNum + 3);
                for (let nearby = startLine; nearby <= endLine; nearby++) {
                  if (nearby === lineNum) { continue; }
                  for (const suppressPattern of rule.suppressIfNearby) {
                    if (suppressPattern.test(lines[nearby])) {
                      suppressed = true;
                      break;
                    }
                  }
                  if (suppressed) { break; }
                }
                if (suppressed) {
                  continue;
                }
              }

              // Determine effective severity (file-pattern-based reduction)
              let effectiveSeverity = rule.severity;
              if (rule.filePatterns?.reduceSeverityIn) {
                if (rule.filePatterns.reduceSeverityIn.some(p => p.test(filePath))) {
                  effectiveSeverity = SecuritySeverity.Info;
                }
              }

              issues.push({
                line: lineNum,
                column,
                message: rule.message,
                severity: effectiveSeverity,
                suggestion: rule.suggestion,
                code: rule.code,
                pattern: matchText,
                category: rule.category,
              });

              if (rule.ruleType === RuleType.Informational) {
                informationalFired.add(rule.code);
              }

              break;
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

  collectProjectAdvisories(
    document: vscode.TextDocument,
    categories?: SecurityCategory[]
  ): ProjectAdvisory[] {
    const rules = this.resolveRules(categories);
    const advisories: ProjectAdvisory[] = [];
    const text = document.getText();
    const lines = text.split('\n');
    const fired = new Set<string>();

    for (let lineNum = 0; lineNum < lines.length; lineNum++) {
      const line = lines[lineNum];
      const lineLower = line.toLowerCase();

      for (const rule of rules) {
        if (rule.ruleType !== RuleType.ProjectAdvisory) { continue; }
        if (fired.has(rule.code)) { continue; }

        for (const pattern of rule.patterns) {
          let matched = false;
          if (typeof pattern === 'string') {
            if (lineLower.includes(pattern.toLowerCase())) { matched = true; }
          } else if (pattern instanceof RegExp) {
            if (pattern.test(line)) { matched = true; }
          }

          if (matched) {
            advisories.push({
              code: rule.code,
              message: rule.message,
              suggestion: rule.suggestion,
              category: rule.category,
              triggeredBy: document.uri.fsPath,
            });
            fired.add(rule.code);
            break;
          }
        }
      }
    }

    return advisories;
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

/**
 * Check if a match position falls inside a single-line comment (// ...)
 */
function isInsideComment(line: string, column: number): boolean {
  // Check for single-line comment
  const singleLineComment = line.indexOf('//');
  if (singleLineComment !== -1 && column > singleLineComment) {
    // Make sure the // is not inside a string
    const beforeSlash = line.substring(0, singleLineComment);
    const singleQuotes = (beforeSlash.match(/'/g) || []).length;
    const doubleQuotes = (beforeSlash.match(/"/g) || []).length;
    const backticks = (beforeSlash.match(/`/g) || []).length;
    if (singleQuotes % 2 === 0 && doubleQuotes % 2 === 0 && backticks % 2 === 0) {
      return true;
    }
  }

  // Check for block comment on same line: /* ... */
  const blockCommentStart = /\/\*/g;
  let blockMatch;
  while ((blockMatch = blockCommentStart.exec(line)) !== null) {
    const start = blockMatch.index;
    const endIdx = line.indexOf('*/', start + 2);
    const end = endIdx !== -1 ? endIdx + 2 : line.length;
    if (column >= start && column < end) {
      return true;
    }
  }

  return false;
}

/**
 * Check if a match position falls inside a string literal's content
 * (i.e., the match is text WITHIN quotes, not a code expression).
 * This handles simple cases — not nested template expressions.
 */
function isInsideStringContent(line: string, column: number): boolean {
  let inSingle = false;
  let inDouble = false;
  let inTemplate = false;
  let templateDepth = 0;

  for (let i = 0; i < column; i++) {
    const ch = line[i];
    const prev = i > 0 ? line[i - 1] : '';

    if (prev === '\\') { continue; }

    if (!inDouble && !inTemplate && ch === "'") {
      inSingle = !inSingle;
    } else if (!inSingle && !inTemplate && ch === '"') {
      inDouble = !inDouble;
    } else if (!inSingle && !inDouble && ch === '`') {
      inTemplate = !inTemplate;
    } else if (inTemplate && ch === '$' && i + 1 < line.length && line[i + 1] === '{') {
      templateDepth++;
    } else if (inTemplate && templateDepth > 0 && ch === '}') {
      templateDepth--;
    }
  }

  // If we're inside a string (and not inside a ${} expression), the match is in string content
  if (inSingle || inDouble) { return true; }
  if (inTemplate && templateDepth === 0) { return true; }

  return false;
}

/**
 * Check if a match position falls inside JSX text content (between > and <).
 * This is a heuristic: we look for a preceding > (end of opening tag) with no
 * subsequent < before our column.
 */
function isInsideJSXText(line: string, column: number): boolean {
  const before = line.substring(0, column);

  // Find the last > before the match
  const lastClose = before.lastIndexOf('>');
  if (lastClose === -1) { return false; }

  // Check there's no < between that > and our column (would mean a new tag started)
  const afterClose = before.substring(lastClose + 1);
  if (afterClose.includes('<')) { return false; }

  // Check there's a < after the match (closing tag)
  const after = line.substring(column);
  if (after.includes('<')) { return true; }

  return false;
}
