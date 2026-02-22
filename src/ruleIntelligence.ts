import * as vscode from 'vscode';
import { PersistenceManager } from './persistenceManager';

export interface RuleStats {
  ruleCode: string;
  detections: number;
  falsePositives: number;
  fixed: number;
  ignored: number;
  verified: number;
  fixFailed: number;
  firstSeenAt: string;
  lastFiredAt: string;
  /** Cumulative resolution time in ms (divide by action count for average) */
  totalResolutionMs: number;
  /** Number of actions that contributed to totalResolutionMs */
  resolutionCount: number;
  byLanguage: Record<string, { detections: number; fps: number; fixed: number }>;
  byFilePattern: Record<string, { detections: number; fps: number }>;
}

export type RuleAction = 'fixed' | 'ignored' | 'false_positive' | 'verified' | 'fix_failed';

export interface RuleInsight {
  ruleCode: string;
  type: 'high_fp_rate' | 'highly_effective' | 'never_acted_on' | 'ai_fix_struggles';
  message: string;
  value: number;
}

export interface RuleIntelligenceData {
  version: 1;
  rules: Record<string, RuleStats>;
  totalScans: number;
  totalObservations: number;
}

const STORE_FILE = 'rule-intelligence.json';
const MIN_OBSERVATIONS_FOR_INSIGHTS = 5;

export class RuleIntelligenceStore implements vscode.Disposable {
  private data: RuleIntelligenceData;
  private persistence: PersistenceManager;
  private dirty = false;
  private _onDidChange = new vscode.EventEmitter<void>();
  readonly onDidChange = this._onDidChange.event;

  constructor() {
    this.persistence = PersistenceManager.getInstance();
    this.data = { version: 1, rules: {}, totalScans: 0, totalObservations: 0 };
  }

  async load(): Promise<void> {
    this.data = await this.persistence.readStore<RuleIntelligenceData>(
      STORE_FILE,
      { version: 1, rules: {}, totalScans: 0, totalObservations: 0 }
    );
  }

  // ---------------------------------------------------------------------------
  // Recording
  // ---------------------------------------------------------------------------

  recordDetection(ruleCode: string, languageId: string, filePath: string): void {
    const stats = this.getOrCreateStats(ruleCode);
    stats.detections++;
    stats.lastFiredAt = new Date().toISOString();

    const langStats = this.getOrCreateLangStats(stats, languageId);
    langStats.detections++;

    const pattern = classifyFilePattern(filePath);
    const patternStats = this.getOrCreatePatternStats(stats, pattern);
    patternStats.detections++;

    this.data.totalObservations++;
    this.markDirty();
  }

  recordDetectionBatch(issues: Array<{ ruleCode: string; languageId: string; filePath: string }>): void {
    for (const issue of issues) {
      this.recordDetection(issue.ruleCode, issue.languageId, issue.filePath);
    }
  }

  recordScanCompleted(): void {
    this.data.totalScans++;
    this.markDirty();
  }

  recordAction(
    ruleCode: string,
    action: RuleAction,
    languageId: string,
    filePath: string,
    detectedAt?: string
  ): void {
    const stats = this.getOrCreateStats(ruleCode);

    switch (action) {
      case 'fixed':
        stats.fixed++;
        break;
      case 'ignored':
        stats.ignored++;
        break;
      case 'false_positive':
        stats.falsePositives++;
        this.getOrCreateLangStats(stats, languageId).fps++;
        this.getOrCreatePatternStats(stats, classifyFilePattern(filePath)).fps++;
        break;
      case 'verified':
        stats.verified++;
        break;
      case 'fix_failed':
        stats.fixFailed++;
        break;
    }

    if (action === 'fixed' || action === 'verified') {
      this.getOrCreateLangStats(stats, languageId).fixed++;
    }

    // Track resolution time if we know when the issue was first detected
    if (detectedAt && (action === 'fixed' || action === 'ignored' || action === 'false_positive' || action === 'verified')) {
      const detected = new Date(detectedAt).getTime();
      if (!isNaN(detected)) {
        stats.totalResolutionMs += Date.now() - detected;
        stats.resolutionCount++;
      }
    }

    this.markDirty();
    this._onDidChange.fire();
  }

  // ---------------------------------------------------------------------------
  // Queries
  // ---------------------------------------------------------------------------

  getStats(ruleCode: string): RuleStats | undefined {
    return this.data.rules[ruleCode];
  }

  getAllStats(): Record<string, RuleStats> {
    return { ...this.data.rules };
  }

  getTotalScans(): number {
    return this.data.totalScans;
  }

  getTotalObservations(): number {
    return this.data.totalObservations;
  }

  /** FP rate = falsePositives / (falsePositives + fixed + verified). Returns 0 if no actions. */
  getFalsePositiveRate(ruleCode: string): number {
    const s = this.data.rules[ruleCode];
    if (!s) { return 0; }
    const actionable = s.falsePositives + s.fixed + s.verified;
    return actionable > 0 ? s.falsePositives / actionable : 0;
  }

  /** Effectiveness = (fixed + verified) / detections. Returns 0 if no detections. */
  getEffectivenessScore(ruleCode: string): number {
    const s = this.data.rules[ruleCode];
    if (!s || s.detections === 0) { return 0; }
    return (s.fixed + s.verified) / s.detections;
  }

  /** Fix rate = fixed / (fixed + fixFailed). Returns 0 if no fix attempts. */
  getAIFixSuccessRate(ruleCode: string): number {
    const s = this.data.rules[ruleCode];
    if (!s) { return 0; }
    const attempts = s.fixed + s.fixFailed;
    return attempts > 0 ? s.fixed / attempts : 0;
  }

  /** Average resolution time in ms, or 0 if no data. */
  getAvgResolutionMs(ruleCode: string): number {
    const s = this.data.rules[ruleCode];
    if (!s || s.resolutionCount === 0) { return 0; }
    return s.totalResolutionMs / s.resolutionCount;
  }

  /**
   * Combined "likely real" score (0-1) for an issue, considering:
   * - Base rate: 1 - FP rate
   * - Language-specific FP rate
   * - File-pattern-specific FP rate
   * Falls back to 0.5 (neutral) when insufficient data.
   */
  getLikelyRealScore(ruleCode: string, languageId: string, filePath: string): number {
    const s = this.data.rules[ruleCode];
    if (!s || s.detections < MIN_OBSERVATIONS_FOR_INSIGHTS) {
      return 0.5; // Neutral — not enough data
    }

    // Global FP rate for this rule
    const globalFP = this.getFalsePositiveRate(ruleCode);
    let score = 1 - globalFP;

    // Adjust for language-specific data
    const langKey = languageId;
    const langStats = s.byLanguage[langKey];
    if (langStats && (langStats.fps + langStats.fixed) >= 3) {
      const langFP = langStats.fps / (langStats.fps + langStats.fixed);
      // Blend: 60% global, 40% language-specific
      score = score * 0.6 + (1 - langFP) * 0.4;
    }

    // Adjust for file-pattern-specific data
    const pattern = classifyFilePattern(filePath);
    const patternStats = s.byFilePattern[pattern];
    if (patternStats && (patternStats.fps + patternStats.detections) >= 3) {
      const patternFP = patternStats.fps / patternStats.detections;
      // Nudge score toward pattern-specific rate
      score = score * 0.8 + (1 - patternFP) * 0.2;
    }

    return Math.max(0, Math.min(1, score));
  }

  /**
   * Generate high-level insights about rule effectiveness.
   */
  getInsights(): RuleInsight[] {
    const insights: RuleInsight[] = [];

    for (const [code, stats] of Object.entries(this.data.rules)) {
      const totalActions = stats.falsePositives + stats.fixed + stats.verified + stats.ignored;

      // High FP rate
      if (totalActions >= MIN_OBSERVATIONS_FOR_INSIGHTS) {
        const fpRate = this.getFalsePositiveRate(code);
        if (fpRate >= 0.7) {
          insights.push({
            ruleCode: code,
            type: 'high_fp_rate',
            message: `${code} has a ${Math.round(fpRate * 100)}% false positive rate (${stats.falsePositives} FPs out of ${totalActions} actions)`,
            value: fpRate,
          });
        }
      }

      // Highly effective
      if (stats.detections >= MIN_OBSERVATIONS_FOR_INSIGHTS) {
        const effectiveness = this.getEffectivenessScore(code);
        if (effectiveness >= 0.6) {
          insights.push({
            ruleCode: code,
            type: 'highly_effective',
            message: `${code} findings are acted on ${Math.round(effectiveness * 100)}% of the time`,
            value: effectiveness,
          });
        }
      }

      // Never acted on
      if (stats.detections >= 10 && totalActions === 0) {
        insights.push({
          ruleCode: code,
          type: 'never_acted_on',
          message: `${code} has fired ${stats.detections} times but was never fixed, ignored, or dismissed`,
          value: stats.detections,
        });
      }

      // AI fix struggles
      const fixAttempts = stats.fixed + stats.fixFailed;
      if (fixAttempts >= 3) {
        const failRate = stats.fixFailed / fixAttempts;
        if (failRate >= 0.5) {
          insights.push({
            ruleCode: code,
            type: 'ai_fix_struggles',
            message: `AI fixes for ${code} fail ${Math.round(failRate * 100)}% of the time (${stats.fixFailed}/${fixAttempts})`,
            value: failRate,
          });
        }
      }
    }

    // Sort by value descending (most notable first)
    insights.sort((a, b) => b.value - a.value);
    return insights;
  }

  // ---------------------------------------------------------------------------
  // Management
  // ---------------------------------------------------------------------------

  clearAll(): void {
    this.data = { version: 1, rules: {}, totalScans: 0, totalObservations: 0 };
    this.save();
    this._onDidChange.fire();
  }

  exportData(): RuleIntelligenceData {
    return JSON.parse(JSON.stringify(this.data));
  }

  // ---------------------------------------------------------------------------
  // Internals
  // ---------------------------------------------------------------------------

  private getOrCreateStats(ruleCode: string): RuleStats {
    if (!this.data.rules[ruleCode]) {
      this.data.rules[ruleCode] = {
        ruleCode,
        detections: 0,
        falsePositives: 0,
        fixed: 0,
        ignored: 0,
        verified: 0,
        fixFailed: 0,
        firstSeenAt: new Date().toISOString(),
        lastFiredAt: new Date().toISOString(),
        totalResolutionMs: 0,
        resolutionCount: 0,
        byLanguage: {},
        byFilePattern: {},
      };
    }
    return this.data.rules[ruleCode];
  }

  private getOrCreateLangStats(stats: RuleStats, languageId: string): { detections: number; fps: number; fixed: number } {
    if (!stats.byLanguage[languageId]) {
      stats.byLanguage[languageId] = { detections: 0, fps: 0, fixed: 0 };
    }
    return stats.byLanguage[languageId];
  }

  private getOrCreatePatternStats(stats: RuleStats, pattern: string): { detections: number; fps: number } {
    if (!stats.byFilePattern[pattern]) {
      stats.byFilePattern[pattern] = { detections: 0, fps: 0 };
    }
    return stats.byFilePattern[pattern];
  }

  private markDirty(): void {
    this.dirty = true;
    this.persistence.scheduleWrite(STORE_FILE, this.data, 2000);
  }

  private save(): void {
    this.persistence.scheduleWrite(STORE_FILE, this.data, 0);
  }

  dispose(): void {
    if (this.dirty) {
      // Attempt synchronous final write
      this.persistence.scheduleWrite(STORE_FILE, this.data, 0);
    }
    this._onDidChange.dispose();
  }
}

/**
 * Classify a file path into a coarse pattern bucket for per-pattern stats.
 * This avoids storing full paths while still capturing useful signal.
 */
function classifyFilePattern(filePath: string): string {
  const lower = filePath.toLowerCase().replace(/\\/g, '/');
  if (/(?:test|spec|__tests__|__mocks__|\.test\.|\.spec\.)/.test(lower)) {
    return 'test';
  }
  if (/(?:\/config\/|\.config\.|rc\.)/.test(lower)) {
    return 'config';
  }
  if (/(?:\/scripts?\/|\/tools?\/|\/utils?\/|\/helpers?\/)/.test(lower)) {
    return 'utility';
  }
  if (/(?:\/src\/|\/lib\/|\/app\/|\/components?\/)/.test(lower)) {
    return 'source';
  }
  if (/(?:\/api\/|\/routes?\/|\/controllers?\/)/.test(lower)) {
    return 'api';
  }
  return 'other';
}
