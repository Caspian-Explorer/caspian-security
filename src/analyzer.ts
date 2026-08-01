import * as vscode from 'vscode';
import { SecurityRule, SecurityIssue, SecurityCategory, RuleType, ProjectAdvisory } from './types';
import { getAllRules, getRulesByCategory, getRuleByCode as registryGetRuleByCode } from './rules';
import { AdaptiveConfidenceEngine } from './adaptiveConfidence';
import { CodebaseProfile } from './codebaseProfile';
import { isGeneratedFile } from './generatedFileDetector';
import { ConfigManager } from './configManager';
import { scanFile, ScanFileOptions, AdvisorySink } from './scanRunner';

export class SecurityAnalyzer {
  private allRules: SecurityRule[];
  private adaptiveConfidence: AdaptiveConfidenceEngine | undefined;
  private codebaseProfile: CodebaseProfile | undefined;

  constructor() {
    this.allRules = getAllRules();
  }

  setAdaptiveConfidence(engine: AdaptiveConfidenceEngine): void {
    this.adaptiveConfidence = engine;
  }

  setCodebaseProfile(profile: CodebaseProfile): void {
    this.codebaseProfile = profile;
  }

  /**
   * Scan a document with the shared engine in ./scanRunner (the same code
   * path the CLI and MCP server use), wiring in the extension-only
   * behaviours: config gates, the adaptive confidence engine, learned
   * safe-pattern suppression, and optional same-pass advisory collection.
   */
  async analyzeDocument(
    document: vscode.TextDocument,
    categories?: SecurityCategory[],
    advisorySink?: AdvisorySink
  ): Promise<SecurityIssue[]> {
    try {
      const rules = this.resolveRules(categories);
      const text = document.getText();
      const filePath = document.uri.fsPath;

      // Skip generated files if enabled (check BEFORE splitting into lines)
      const config = ConfigManager.getInstance();
      if (config.getSkipGeneratedFiles() && isGeneratedFile(filePath, text)) {
        return [];
      }

      // Skip files exceeding max size
      const maxFileSize = config.getMaxFileSize();
      if (maxFileSize > 0 && text.length > maxFileSize) {
        return [];
      }

      const adaptive = this.adaptiveConfidence;
      const profile = this.codebaseProfile;
      const options: ScanFileOptions = {
        runTaint: config.getEnableTaintTracking(),
        classify: adaptive
          ? (lines, lineNum, column, matchText, ruleCode) =>
              adaptive.classify(lines, lineNum, column, matchText, ruleCode, document.languageId, filePath)
          : undefined,
        isLineSuppressed: profile
          ? (ruleCode, line, lines, lineNum) =>
              profile.hasLearnedSuppression(ruleCode, line, lines, lineNum)
          : undefined,
        advisorySink,
      };

      return scanFile(filePath, text, rules, options);
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
