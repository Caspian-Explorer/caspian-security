import * as vscode from 'vscode';
import { PersistenceManager } from './persistenceManager';
import { RuleIntelligenceStore } from './ruleIntelligence';
import { FixTracker, FixStatus } from './fixTracker';

export interface SafePattern {
  functionName: string;
  neutralizesRules: string[];
  confidence: number;
  observedCount: number;
  source: 'ai_fix' | 'user_fp' | 'auto_detected';
}

export interface HotZone {
  directory: string;
  confirmedIssues: number;
  totalDetections: number;
  fpRate: number;
  riskScore: number;
}

export interface PostureSnapshot {
  scanId: string;
  timestamp: string;
  totalIssues: number;
  criticalIssues: number;
  resolvedSinceLastScan: number;
  newSinceLastScan: number;
}

export interface Regression {
  ruleCode: string;
  filePath: string;
  line: number;
  previouslyFixedAt: string;
  reappearedAt: string;
  acknowledged: boolean;
}

export interface CodebaseProfileData {
  version: 1;
  safePatterns: SafePattern[];
  hotZones: HotZone[];
  postureTrend: PostureSnapshot[];
  regressions: Regression[];
}

const STORE_FILE = 'codebase-profile.json';
const MAX_POSTURE_SNAPSHOTS = 100;

/** Well-known sanitizer/validator function names mapped to rule prefixes they neutralize. */
const KNOWN_SAFE_FUNCTIONS: Record<string, string[]> = {
  'DOMPurify.sanitize': ['XSS'],
  'sanitize': ['XSS'],
  'escape': ['XSS'],
  'escapeHtml': ['XSS'],
  'encodeURIComponent': ['XSS'],
  'encodeURI': ['XSS'],
  'validator.isEmail': ['XSS'],
  'validator.escape': ['XSS'],
  'xss': ['XSS'],
  'helmet': ['CORS', 'XSS', 'CSRF'],
  'csurf': ['CSRF'],
  'csrf': ['CSRF'],
  'bcrypt.hash': ['CRED', 'AUTH'],
  'argon2.hash': ['CRED', 'AUTH'],
  'crypto.createHash': ['ENC'],
  'parameterized': ['DB', 'SQL'],
  'prepare': ['DB', 'SQL'],
};

export class CodebaseProfile implements vscode.Disposable {
  private data: CodebaseProfileData;
  private persistence: PersistenceManager;

  constructor() {
    this.persistence = PersistenceManager.getInstance();
    this.data = { version: 1, safePatterns: [], hotZones: [], postureTrend: [], regressions: [] };
  }

  async load(): Promise<void> {
    this.data = await this.persistence.readStore<CodebaseProfileData>(
      STORE_FILE,
      { version: 1, safePatterns: [], hotZones: [], postureTrend: [], regressions: [] }
    );
  }

  // ---------------------------------------------------------------------------
  // Safe pattern learning
  // ---------------------------------------------------------------------------

  /**
   * Learn a safe pattern from an AI fix.
   * Scans the "after" code for known sanitizer functions and associates them
   * with the rule that was being fixed.
   */
  learnFromAIFix(ruleCode: string, afterLine: string): void {
    for (const [funcName, prefixes] of Object.entries(KNOWN_SAFE_FUNCTIONS)) {
      if (afterLine.includes(funcName)) {
        this.addSafePattern(funcName, ruleCode, 'ai_fix');
      }
    }
    this.save();
  }

  /**
   * Learn a safe pattern from a false positive dismissal.
   * If the dismissed line contains a known safe function, learn the association.
   */
  learnFromFalsePositive(ruleCode: string, lineText: string): void {
    for (const [funcName, prefixes] of Object.entries(KNOWN_SAFE_FUNCTIONS)) {
      if (lineText.includes(funcName)) {
        this.addSafePattern(funcName, ruleCode, 'user_fp');
      }
    }

    // Also learn custom functions: extract function calls from the line
    const funcCalls = lineText.match(/([a-zA-Z_$][\w$.]*)\s*\(/g);
    if (funcCalls) {
      for (const call of funcCalls) {
        const name = call.replace(/\s*\($/, '');
        // Skip very common/generic names
        if (['if', 'for', 'while', 'switch', 'function', 'return', 'require', 'import', 'console'].includes(name)) {
          continue;
        }
        // Only learn if name suggests sanitization/validation
        if (/sanitiz|valid|escap|encod|purg|clean|filter|strip/i.test(name)) {
          this.addSafePattern(name, ruleCode, 'user_fp');
        }
      }
    }
    this.save();
  }

  private addSafePattern(functionName: string, ruleCode: string, source: SafePattern['source']): void {
    const existing = this.data.safePatterns.find(p => p.functionName === functionName);
    if (existing) {
      if (!existing.neutralizesRules.includes(ruleCode)) {
        existing.neutralizesRules.push(ruleCode);
      }
      existing.observedCount++;
      existing.confidence = Math.min(1, existing.confidence + 0.1);
      // Upgrade source if from a stronger signal
      if (source === 'ai_fix' && existing.source !== 'ai_fix') {
        existing.source = source;
      }
    } else {
      this.data.safePatterns.push({
        functionName,
        neutralizesRules: [ruleCode],
        confidence: source === 'ai_fix' ? 0.7 : source === 'user_fp' ? 0.5 : 0.3,
        observedCount: 1,
        source,
      });
    }
  }

  /**
   * Check if a rule match should be suppressed based on learned safe patterns.
   * Looks for known safe functions on the matched line and surrounding lines.
   */
  hasLearnedSuppression(ruleCode: string, lineText: string, lines: string[], lineNum: number): boolean {
    // Get safe patterns that could neutralize this rule
    const relevant = this.data.safePatterns.filter(p =>
      p.confidence >= 0.6 && p.observedCount >= 2 &&
      (p.neutralizesRules.includes(ruleCode) ||
       p.neutralizesRules.some(r => ruleCode.startsWith(r)))
    );

    if (relevant.length === 0) { return false; }

    // Check the current line and ±3 surrounding lines
    const start = Math.max(0, lineNum - 3);
    const end = Math.min(lines.length - 1, lineNum + 3);
    for (let i = start; i <= end; i++) {
      for (const pattern of relevant) {
        if (lines[i].includes(pattern.functionName)) {
          return true;
        }
      }
    }

    return false;
  }

  // ---------------------------------------------------------------------------
  // Hot zones
  // ---------------------------------------------------------------------------

  /**
   * Rebuild hot zone rankings from rule intelligence data.
   */
  rebuildHotZones(ruleIntelligence: RuleIntelligenceStore): void {
    const dirStats = new Map<string, { confirmed: number; total: number; fps: number }>();

    for (const [, stats] of Object.entries(ruleIntelligence.getAllStats())) {
      for (const [pattern, patternStats] of Object.entries(stats.byFilePattern)) {
        const existing = dirStats.get(pattern) || { confirmed: 0, total: 0, fps: 0 };
        existing.total += patternStats.detections;
        existing.fps += patternStats.fps;
        dirStats.set(pattern, existing);
      }
    }

    // Add confirmed counts from fix data
    for (const [, stats] of Object.entries(ruleIntelligence.getAllStats())) {
      for (const [langOrPattern, langStats] of Object.entries(stats.byLanguage)) {
        // byLanguage uses languageId not file patterns, skip
      }
      // Use rule-level stats for confirmed issues
      for (const [pattern, patternStats] of Object.entries(stats.byFilePattern)) {
        const existing = dirStats.get(pattern);
        if (existing) {
          existing.confirmed = existing.total - existing.fps;
        }
      }
    }

    this.data.hotZones = Array.from(dirStats.entries())
      .map(([directory, s]) => ({
        directory,
        confirmedIssues: Math.max(0, s.confirmed),
        totalDetections: s.total,
        fpRate: s.total > 0 ? s.fps / s.total : 0,
        riskScore: s.total > 0 ? Math.max(0, s.confirmed) / s.total : 0,
      }))
      .filter(z => z.totalDetections >= 5)
      .sort((a, b) => b.riskScore - a.riskScore);

    this.save();
  }

  // ---------------------------------------------------------------------------
  // Posture tracking
  // ---------------------------------------------------------------------------

  recordPostureSnapshot(
    scanId: string,
    totalIssues: number,
    criticalIssues: number,
    resolvedSinceLastScan: number,
    newSinceLastScan: number
  ): void {
    this.data.postureTrend.push({
      scanId,
      timestamp: new Date().toISOString(),
      totalIssues,
      criticalIssues,
      resolvedSinceLastScan,
      newSinceLastScan,
    });

    if (this.data.postureTrend.length > MAX_POSTURE_SNAPSHOTS) {
      this.data.postureTrend = this.data.postureTrend.slice(-MAX_POSTURE_SNAPSHOTS);
    }

    this.save();
  }

  // ---------------------------------------------------------------------------
  // Regression detection
  // ---------------------------------------------------------------------------

  /**
   * Detect regressions: previously fixed issues that have reappeared.
   */
  detectRegressions(
    currentIssues: Array<{ code: string; filePath: string; line: number }>,
    fixTracker: FixTracker
  ): Regression[] {
    const newRegressions: Regression[] = [];

    for (const issue of currentIssues) {
      // Check if this issue was previously verified as fixed
      const records = fixTracker.getAllRecords().filter(
        r => r.issueCode === issue.code
          && r.relativePath === issue.filePath
          && r.status === FixStatus.Verified
      );

      for (const record of records) {
        // Check if we already know about this regression
        const known = this.data.regressions.find(
          r => r.ruleCode === issue.code && r.filePath === issue.filePath && r.line === issue.line
        );
        if (!known) {
          const regression: Regression = {
            ruleCode: issue.code,
            filePath: issue.filePath,
            line: issue.line,
            previouslyFixedAt: record.verifiedAt || record.fixedAt || '',
            reappearedAt: new Date().toISOString(),
            acknowledged: false,
          };
          newRegressions.push(regression);
          this.data.regressions.push(regression);
        }
      }
    }

    if (newRegressions.length > 0) {
      this.save();
    }

    return newRegressions;
  }

  acknowledgeRegression(ruleCode: string, filePath: string, line: number): void {
    const reg = this.data.regressions.find(
      r => r.ruleCode === ruleCode && r.filePath === filePath && r.line === line
    );
    if (reg) {
      reg.acknowledged = true;
      this.save();
    }
  }

  // ---------------------------------------------------------------------------
  // Accessors
  // ---------------------------------------------------------------------------

  getSafePatterns(): SafePattern[] { return [...this.data.safePatterns]; }
  getHotZones(): HotZone[] { return [...this.data.hotZones]; }
  getPostureTrend(): PostureSnapshot[] { return [...this.data.postureTrend]; }
  getRegressions(): Regression[] { return [...this.data.regressions]; }
  getUnacknowledgedRegressions(): Regression[] {
    return this.data.regressions.filter(r => !r.acknowledged);
  }

  clearAll(): void {
    this.data = { version: 1, safePatterns: [], hotZones: [], postureTrend: [], regressions: [] };
    this.save();
  }

  exportData(): CodebaseProfileData {
    return JSON.parse(JSON.stringify(this.data));
  }

  private save(): void {
    this.persistence.scheduleWrite(STORE_FILE, this.data, 5000);
  }

  dispose(): void {}
}
