import { classifyConfidence, ConfidenceLevel } from './confidenceAnalyzer';
import { RuleIntelligenceStore } from './ruleIntelligence';

const TEST_FILE_PATTERN = /(?:test|spec|__tests__|__mocks__|\.test\.|\.spec\.)/i;
const SOURCE_FILE_PATTERN = /(?:[\/\\]src[\/\\]|[\/\\]lib[\/\\]|[\/\\]app[\/\\]|[\/\\]components?[\/\\])/i;

/** Minimum number of user actions before we trust the learned data. */
const MIN_ACTIONS_FOR_ADJUSTMENT = 5;

/** FP rate threshold above which we downgrade confidence. */
const HIGH_FP_THRESHOLD = 0.7;

/** Fix rate threshold above which we upgrade confidence. */
const HIGH_FIX_THRESHOLD = 0.8;

/**
 * Adaptive confidence engine that wraps the static heuristic and adjusts
 * based on learned rule-intelligence data.
 *
 * The static heuristic (`classifyConfidence`) acts as the prior.
 * User actions (fix, FP, ignore, verify) shift confidence up or down.
 */
export class AdaptiveConfidenceEngine {
  constructor(private ruleIntelligence: RuleIntelligenceStore) {}

  /**
   * Classify confidence for an issue. Uses the static heuristic as a base,
   * then adjusts based on accumulated user behavior data.
   */
  classify(
    lines: string[],
    issueLine: number,
    issueColumn: number,
    matchedPattern: string,
    ruleCode: string,
    languageId: string,
    filePath: string
  ): ConfidenceLevel | undefined {
    // Start with the static heuristic
    let confidence = classifyConfidence(lines, issueLine, issueColumn, matchedPattern, ruleCode);

    // Get learned data for this rule
    const stats = this.ruleIntelligence.getStats(ruleCode);
    if (!stats) {
      return confidence;
    }

    const totalActions = stats.falsePositives + stats.fixed + stats.verified + stats.ignored;

    // Only adjust if we have enough data
    if (totalActions < MIN_ACTIONS_FOR_ADJUSTMENT) {
      return confidence;
    }

    const fpRate = this.ruleIntelligence.getFalsePositiveRate(ruleCode);
    const fixRate = (stats.fixed + stats.verified) / totalActions;

    // --- Bayesian-style adjustments ---

    // High FP rate: downgrade confidence
    if (fpRate >= HIGH_FP_THRESHOLD) {
      confidence = downgradeConfidence(confidence);
    }

    // High fix rate: upgrade confidence
    if (fixRate >= HIGH_FIX_THRESHOLD) {
      confidence = upgradeConfidence(confidence);
    }

    // --- File-path context adjustments ---

    // Test files: reduce confidence one level
    if (TEST_FILE_PATTERN.test(filePath)) {
      confidence = downgradeConfidence(confidence);
    }

    // Source files with high fix rate: boost confidence
    if (SOURCE_FILE_PATTERN.test(filePath)) {
      const langStats = stats.byLanguage[languageId];
      if (langStats && (langStats.fixed + langStats.fps) >= 3) {
        const langFixRate = langStats.fixed / (langStats.fixed + langStats.fps);
        if (langFixRate >= HIGH_FIX_THRESHOLD) {
          confidence = upgradeConfidence(confidence);
        }
      }
    }

    return confidence;
  }
}

function downgradeConfidence(level: ConfidenceLevel | undefined): ConfidenceLevel | undefined {
  if (level === 'critical') { return 'verify-needed'; }
  if (level === 'verify-needed') { return 'safe'; }
  return level;
}

function upgradeConfidence(level: ConfidenceLevel | undefined): ConfidenceLevel | undefined {
  if (level === 'safe') { return 'verify-needed'; }
  if (level === 'verify-needed') { return 'critical'; }
  // If undefined (no prior), assign verify-needed as a starting point
  if (level === undefined) { return 'verify-needed'; }
  return level;
}
