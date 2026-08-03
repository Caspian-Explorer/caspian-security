/**
 * Shared SARIF 2.1.0 writer. Both the CLI (`caspian scan --format sarif`)
 * and the extension's "Export as SARIF" produce their output here, so the
 * two can never drift apart (they used to be independent copies — one of
 * them shipped a hardcoded stale tool version for several releases).
 */

import * as fs from 'fs';
import * as path from 'path';
import { SecurityIssue, SecuritySeverity, CATEGORY_LABELS } from './types';

export interface SarifFileIssues {
  relativePath: string;
  issues: SecurityIssue[];
}

/** Read the extension/CLI version from package.json, with a safe fallback. */
export function resolveToolVersion(): string {
  try {
    const pkg = JSON.parse(fs.readFileSync(path.join(__dirname, '..', 'package.json'), 'utf-8'));
    return pkg.version || '0.0.0';
  } catch {
    return '0.0.0';
  }
}

export function buildSARIF(files: SarifFileIssues[], toolVersion: string): string {
  const rulesMap = new Map<string, { index: number; id: string; category: string; message: string; suggestion: string }>();
  const sarifResults: object[] = [];

  for (const file of files) {
    for (const issue of file.issues) {
      let rule = rulesMap.get(issue.code);
      if (!rule) {
        rule = {
          index: rulesMap.size,
          id: issue.code,
          category: CATEGORY_LABELS[issue.category] || issue.category,
          message: issue.message,
          suggestion: issue.suggestion,
        };
        rulesMap.set(issue.code, rule);
      }

      let level: string;
      switch (issue.severity) {
        case SecuritySeverity.Error: level = 'error'; break;
        case SecuritySeverity.Warning: level = 'warning'; break;
        default: level = 'note'; break;
      }

      sarifResults.push({
        ruleId: issue.code,
        ruleIndex: rule.index,
        level,
        message: { text: `${issue.message}\n\nSuggestion: ${issue.suggestion}` },
        locations: [{
          physicalLocation: {
            artifactLocation: {
              uri: file.relativePath.replace(/\\/g, '/'),
              uriBaseId: '%SRCROOT%',
            },
            region: { startLine: issue.line + 1, startColumn: issue.column + 1 },
          },
        }],
      });
    }
  }

  const sarifRules = Array.from(rulesMap.values()).map(rule => ({
    id: rule.id,
    shortDescription: { text: rule.message },
    fullDescription: { text: rule.suggestion },
    properties: { category: rule.category },
  }));

  return JSON.stringify({
    $schema: 'https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json',
    version: '2.1.0',
    runs: [{
      tool: {
        driver: {
          name: 'Caspian Security',
          version: toolVersion,
          informationUri: 'https://marketplace.visualstudio.com/items?itemName=CaspianTools.caspian-security',
          rules: sarifRules,
        },
      },
      results: sarifResults,
    }],
  }, null, 2);
}
