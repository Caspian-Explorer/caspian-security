import { RuleIntelligenceStore } from './ruleIntelligence';
import { FixPatternMemory } from './fixPatternMemory';
import { CodebaseProfile } from './codebaseProfile';
import { ScanHistoryStore } from './scanHistoryStore';

export type InsightType =
  | 'trend_improving'
  | 'trend_degrading'
  | 'regression_detected'
  | 'hot_zone'
  | 'rule_noisy'
  | 'rule_effective'
  | 'fix_pattern_available'
  | 'ai_fix_effective'
  | 'category_champion'
  | 'stale_issues';

export type InsightSeverity = 'info' | 'suggestion' | 'warning' | 'celebration';

export interface Insight {
  type: InsightType;
  severity: InsightSeverity;
  title: string;
  detail: string;
  actionLabel?: string;
  actionCommand?: string;
  data?: Record<string, any>;
}

/**
 * Generates actionable insights from accumulated learning data.
 * Computed on-demand — no persistence needed.
 */
export function generateInsights(
  ruleIntelligence: RuleIntelligenceStore,
  fixPatternMemory: FixPatternMemory,
  codebaseProfile: CodebaseProfile,
  scanHistory: ScanHistoryStore
): Insight[] {
  const insights: Insight[] = [];

  generateTrendInsights(insights, scanHistory);
  generateRuleInsights(insights, ruleIntelligence);
  generateFixPatternInsights(insights, fixPatternMemory, ruleIntelligence);
  generateRegressionInsights(insights, codebaseProfile);
  generateHotZoneInsights(insights, codebaseProfile);

  // Sort: warnings first, then suggestions, then celebrations, then info
  const severityOrder: Record<InsightSeverity, number> = {
    warning: 0, suggestion: 1, celebration: 2, info: 3,
  };
  insights.sort((a, b) => severityOrder[a.severity] - severityOrder[b.severity]);

  return insights;
}

function generateTrendInsights(insights: Insight[], scanHistory: ScanHistoryStore): void {
  const entries = scanHistory.getEntries();
  if (entries.length < 3) { return; }

  // Compare last 3 scans to previous 3
  const recent = entries.slice(-3);
  const previous = entries.slice(-6, -3);
  if (previous.length < 3) { return; }

  const recentAvg = recent.reduce((sum, e) => sum + e.totalIssues, 0) / recent.length;
  const previousAvg = previous.reduce((sum, e) => sum + e.totalIssues, 0) / previous.length;

  if (previousAvg === 0) { return; }

  const changePercent = ((recentAvg - previousAvg) / previousAvg) * 100;

  if (changePercent <= -10) {
    insights.push({
      type: 'trend_improving',
      severity: 'celebration',
      title: 'Security posture improving',
      detail: `Average issues decreased ${Math.abs(Math.round(changePercent))}% over the last ${recent.length} scans (${Math.round(recentAvg)} avg vs ${Math.round(previousAvg)} previously).`,
    });
  } else if (changePercent >= 15) {
    insights.push({
      type: 'trend_degrading',
      severity: 'warning',
      title: 'Security issues increasing',
      detail: `Average issues increased ${Math.round(changePercent)}% over the last ${recent.length} scans (${Math.round(recentAvg)} avg vs ${Math.round(previousAvg)} previously). Review recent commits.`,
    });
  }
}

function generateRuleInsights(insights: Insight[], ruleIntelligence: RuleIntelligenceStore): void {
  const ruleInsights = ruleIntelligence.getInsights();

  for (const ri of ruleInsights) {
    switch (ri.type) {
      case 'high_fp_rate':
        insights.push({
          type: 'rule_noisy',
          severity: 'suggestion',
          title: `${ri.ruleCode} has high false positive rate`,
          detail: ri.message,
          actionLabel: `Disable ${ri.ruleCode}`,
          data: { ruleCode: ri.ruleCode, fpRate: ri.value },
        });
        break;

      case 'highly_effective':
        insights.push({
          type: 'rule_effective',
          severity: 'info',
          title: `${ri.ruleCode} is highly effective`,
          detail: ri.message,
          data: { ruleCode: ri.ruleCode, effectiveness: ri.value },
        });
        break;

      case 'never_acted_on':
        insights.push({
          type: 'stale_issues',
          severity: 'suggestion',
          title: `${ri.ruleCode} findings are never addressed`,
          detail: ri.message,
          actionLabel: 'Review pending issues',
          actionCommand: 'caspian-security.showResultsPanel',
        });
        break;

      case 'ai_fix_struggles':
        insights.push({
          type: 'ai_fix_effective',
          severity: 'info',
          title: `AI fixes struggle with ${ri.ruleCode}`,
          detail: ri.message,
          data: { ruleCode: ri.ruleCode, failRate: ri.value },
        });
        break;
    }
  }

  // Category champion: find categories where all issues are resolved
  const allStats = ruleIntelligence.getAllStats();
  const categoryResolved = new Map<string, { total: number; resolved: number }>();

  for (const [, stats] of Object.entries(allStats)) {
    const cat = stats.ruleCode.replace(/\d+$/, '');
    const entry = categoryResolved.get(cat) || { total: 0, resolved: 0 };
    entry.total += stats.detections;
    entry.resolved += stats.fixed + stats.verified;
    categoryResolved.set(cat, entry);
  }

  for (const [cat, counts] of categoryResolved) {
    if (counts.total >= 5 && counts.resolved >= counts.total * 0.9) {
      insights.push({
        type: 'category_champion',
        severity: 'celebration',
        title: `${cat} issues nearly fully resolved`,
        detail: `${counts.resolved}/${counts.total} ${cat} findings have been fixed or verified.`,
      });
    }
  }
}

function generateFixPatternInsights(
  insights: Insight[],
  fixPatternMemory: FixPatternMemory,
  ruleIntelligence: RuleIntelligenceStore
): void {
  const stats = fixPatternMemory.getPatternStats();

  if (stats.total >= 5) {
    insights.push({
      type: 'fix_pattern_available',
      severity: 'info',
      title: `${stats.total} fix patterns learned`,
      detail: `Caspian has memorized ${stats.total} fix patterns from AI fixes (${stats.withSuccesses} verified successful). ${stats.totalReuses} total applications.`,
      actionLabel: 'View Learning Dashboard',
      actionCommand: 'caspian-security.showLearningDashboard',
    });
  }

  // AI fix effectiveness across all rules
  const allStats = ruleIntelligence.getAllStats();
  let totalAttempts = 0;
  let totalSuccess = 0;
  for (const [, s] of Object.entries(allStats)) {
    totalAttempts += s.fixed + s.fixFailed;
    totalSuccess += s.fixed;
  }

  if (totalAttempts >= 5) {
    const rate = Math.round((totalSuccess / totalAttempts) * 100);
    insights.push({
      type: 'ai_fix_effective',
      severity: rate >= 80 ? 'celebration' : 'info',
      title: `AI fix success rate: ${rate}%`,
      detail: `${totalSuccess}/${totalAttempts} AI fixes succeeded across all rules.`,
    });
  }
}

function generateRegressionInsights(insights: Insight[], codebaseProfile: CodebaseProfile): void {
  const regressions = codebaseProfile.getUnacknowledgedRegressions();
  if (regressions.length > 0) {
    const files = [...new Set(regressions.map(r => r.filePath))];
    insights.push({
      type: 'regression_detected',
      severity: 'warning',
      title: `${regressions.length} regression(s) detected`,
      detail: `${regressions.length} previously fixed issue(s) have reappeared in ${files.length} file(s): ${files.slice(0, 3).join(', ')}${files.length > 3 ? '...' : ''}.`,
      actionLabel: 'Review regressions',
      actionCommand: 'caspian-security.showLearningDashboard',
    });
  }
}

function generateHotZoneInsights(insights: Insight[], codebaseProfile: CodebaseProfile): void {
  const hotZones = codebaseProfile.getHotZones();
  const topZone = hotZones[0];

  if (topZone && topZone.riskScore >= 0.5 && topZone.confirmedIssues >= 5) {
    insights.push({
      type: 'hot_zone',
      severity: 'suggestion',
      title: `"${topZone.directory}" is a security hot zone`,
      detail: `${topZone.confirmedIssues} confirmed issues out of ${topZone.totalDetections} detections (${Math.round(topZone.riskScore * 100)}% risk score).`,
    });
  }
}
