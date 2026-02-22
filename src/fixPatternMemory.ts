import * as vscode from 'vscode';
import { PersistenceManager } from './persistenceManager';

export interface FixPattern {
  id: string;
  ruleCode: string;
  languageId: string;
  /** The problematic line with identifiers replaced by placeholders */
  normalizedBefore: string;
  /** The fixed line (also normalized) */
  normalizedAfter: string;
  /** Original problematic line for display */
  originalBefore: string;
  /** Original fixed line for display */
  originalAfter: string;
  explanation: string;
  timesApplied: number;
  timesSucceeded: number;
  timesFailed: number;
  createdAt: string;
  lastUsedAt: string;
}

export interface FixPatternMemoryData {
  version: 1;
  patterns: FixPattern[];
}

export interface FixPatternMatch {
  pattern: FixPattern;
  /** The suggested replacement line with placeholders resolved back */
  suggestedFix: string;
  successRate: number;
}

const STORE_FILE = 'fix-patterns.json';
const MAX_PATTERNS = 500;

/** Keywords that should NOT be replaced during normalization. */
const PRESERVED_TOKENS = new Set([
  // JS/TS
  'const', 'let', 'var', 'function', 'return', 'if', 'else', 'for', 'while', 'class',
  'new', 'this', 'import', 'export', 'from', 'require', 'await', 'async', 'try', 'catch',
  'throw', 'typeof', 'instanceof', 'null', 'undefined', 'true', 'false',
  // Common security-related APIs (keep these literal for pattern matching)
  'process', 'env', 'DOMPurify', 'sanitize', 'escape', 'encodeURIComponent',
  'encodeURI', 'createHash', 'crypto', 'bcrypt', 'argon2', 'scrypt',
  'parameterized', 'prepare', 'execute', 'query',
  'innerHTML', 'textContent', 'createElement',
  'console', 'log', 'warn', 'error',
]);

export class FixPatternMemory implements vscode.Disposable {
  private data: FixPatternMemoryData;
  private persistence: PersistenceManager;

  constructor() {
    this.persistence = PersistenceManager.getInstance();
    this.data = { version: 1, patterns: [] };
  }

  async load(): Promise<void> {
    this.data = await this.persistence.readStore<FixPatternMemoryData>(
      STORE_FILE,
      { version: 1, patterns: [] }
    );
  }

  /**
   * Record a successful AI fix. Extracts the changed line, normalizes it,
   * and stores the pattern for future reuse.
   */
  recordFix(
    ruleCode: string,
    languageId: string,
    beforeLine: string,
    afterLine: string,
    explanation: string
  ): void {
    const normalizedBefore = normalizeLine(beforeLine);
    const normalizedAfter = normalizeLine(afterLine);

    // Don't store if normalization produces identical before/after
    if (normalizedBefore === normalizedAfter) { return; }

    // Check if we already have this exact normalized pattern
    const existing = this.data.patterns.find(
      p => p.ruleCode === ruleCode
        && p.languageId === languageId
        && p.normalizedBefore === normalizedBefore
        && p.normalizedAfter === normalizedAfter
    );

    if (existing) {
      existing.timesApplied++;
      existing.lastUsedAt = new Date().toISOString();
      this.save();
      return;
    }

    const pattern: FixPattern = {
      id: `${Date.now()}-${Math.random().toString(36).slice(2, 8)}`,
      ruleCode,
      languageId,
      normalizedBefore,
      normalizedAfter,
      originalBefore: beforeLine.trim(),
      originalAfter: afterLine.trim(),
      explanation,
      timesApplied: 1,
      timesSucceeded: 0,
      timesFailed: 0,
      createdAt: new Date().toISOString(),
      lastUsedAt: new Date().toISOString(),
    };

    this.data.patterns.push(pattern);

    // LRU eviction: remove oldest least-used patterns
    if (this.data.patterns.length > MAX_PATTERNS) {
      this.data.patterns.sort((a, b) => {
        // Keep patterns with high success; evict unused/failed ones
        const scoreA = a.timesSucceeded - a.timesFailed;
        const scoreB = b.timesSucceeded - b.timesFailed;
        if (scoreA !== scoreB) { return scoreB - scoreA; }
        return new Date(b.lastUsedAt).getTime() - new Date(a.lastUsedAt).getTime();
      });
      this.data.patterns = this.data.patterns.slice(0, MAX_PATTERNS);
    }

    this.save();
  }

  /**
   * Find a matching fix pattern for the given issue and problematic line.
   * Returns the best match with a suggested fix line, or null.
   */
  findMatchingPattern(ruleCode: string, languageId: string, problemLine: string): FixPatternMatch | null {
    const normalized = normalizeLine(problemLine);

    // Find patterns for the same rule + language with matching normalized before
    const candidates = this.data.patterns.filter(
      p => p.ruleCode === ruleCode
        && p.languageId === languageId
        && p.normalizedBefore === normalized
        && p.timesSucceeded > 0
    );

    if (candidates.length === 0) { return null; }

    // Pick the best: highest success rate, then most applied
    candidates.sort((a, b) => {
      const rateA = a.timesApplied > 0 ? a.timesSucceeded / a.timesApplied : 0;
      const rateB = b.timesApplied > 0 ? b.timesSucceeded / b.timesApplied : 0;
      if (rateA !== rateB) { return rateB - rateA; }
      return b.timesApplied - a.timesApplied;
    });

    const best = candidates[0];
    const suggestedFix = denormalizeLine(best.normalizedAfter, problemLine);
    const successRate = best.timesApplied > 0
      ? best.timesSucceeded / best.timesApplied
      : 0;

    return { pattern: best, suggestedFix, successRate };
  }

  /**
   * Record the outcome when a learned fix pattern is reused.
   */
  recordOutcome(patternId: string, success: boolean): void {
    const pattern = this.data.patterns.find(p => p.id === patternId);
    if (!pattern) { return; }

    if (success) {
      pattern.timesSucceeded++;
    } else {
      pattern.timesFailed++;
    }
    pattern.lastUsedAt = new Date().toISOString();
    this.save();
  }

  getPatternStats(): { total: number; withSuccesses: number; totalReuses: number; avgSuccessRate: number } {
    const total = this.data.patterns.length;
    const withSuccesses = this.data.patterns.filter(p => p.timesSucceeded > 0).length;
    const totalReuses = this.data.patterns.reduce((sum, p) => sum + p.timesApplied, 0);
    const rates = this.data.patterns
      .filter(p => p.timesApplied > 0)
      .map(p => p.timesSucceeded / p.timesApplied);
    const avgSuccessRate = rates.length > 0
      ? rates.reduce((a, b) => a + b, 0) / rates.length
      : 0;
    return { total, withSuccesses, totalReuses, avgSuccessRate };
  }

  getAllPatterns(): FixPattern[] {
    return [...this.data.patterns];
  }

  clearAll(): void {
    this.data = { version: 1, patterns: [] };
    this.save();
  }

  exportData(): FixPatternMemoryData {
    return JSON.parse(JSON.stringify(this.data));
  }

  private save(): void {
    this.persistence.scheduleWrite(STORE_FILE, this.data, 2000);
  }

  dispose(): void {}
}

// ---------------------------------------------------------------------------
// Normalization utilities
// ---------------------------------------------------------------------------

/**
 * Normalize a code line by replacing user-specific identifiers and string
 * literals with placeholders, while preserving structural tokens.
 *
 * Example: `const password = "admin123"` → `const $VAR1 = $STRING`
 */
function normalizeLine(line: string): string {
  let result = line.trim();

  // Replace string literals (single, double, backtick) with $STRING
  result = result.replace(/(['"`])(?:(?!\1|\\).|\\.)*\1/g, '$STRING');

  // Replace numbers with $NUM
  result = result.replace(/\b\d+(?:\.\d+)?\b/g, '$NUM');

  // Replace identifiers that are NOT preserved tokens
  let varCounter = 0;
  const varMap = new Map<string, string>();

  result = result.replace(/\b([a-zA-Z_$][a-zA-Z0-9_$]*)\b/g, (match) => {
    if (PRESERVED_TOKENS.has(match)) { return match; }
    if (match.startsWith('$')) { return match; } // Already a placeholder

    if (!varMap.has(match)) {
      varCounter++;
      varMap.set(match, `$VAR${varCounter}`);
    }
    return varMap.get(match)!;
  });

  return result;
}

/**
 * Attempt to denormalize a fix pattern back into a concrete line by
 * mapping placeholders from the original problem line.
 */
function denormalizeLine(normalizedFix: string, originalProblemLine: string): string {
  const trimmed = originalProblemLine.trim();

  // Extract identifiers from the original line in order
  const identifiers: string[] = [];
  const strings: string[] = [];
  const numbers: string[] = [];

  // Extract string literals
  const stringRegex = /(['"`])(?:(?!\1|\\).|\\.)*\1/g;
  let match;
  while ((match = stringRegex.exec(trimmed)) !== null) {
    strings.push(match[0]);
  }

  // Extract numbers
  const numRegex = /\b\d+(?:\.\d+)?\b/g;
  while ((match = numRegex.exec(trimmed)) !== null) {
    numbers.push(match[0]);
  }

  // Extract non-preserved identifiers
  const idRegex = /\b([a-zA-Z_$][a-zA-Z0-9_$]*)\b/g;
  while ((match = idRegex.exec(trimmed)) !== null) {
    if (!PRESERVED_TOKENS.has(match[1])) {
      identifiers.push(match[1]);
    }
  }

  // Replace placeholders with original values
  let result = normalizedFix;
  let varIdx = 0;
  let strIdx = 0;
  let numIdx = 0;

  result = result.replace(/\$VAR\d+/g, () => {
    return identifiers[varIdx++] || '_unknown_';
  });
  result = result.replace(/\$STRING/g, () => {
    return strings[strIdx++] || '""';
  });
  result = result.replace(/\$NUM/g, () => {
    return numbers[numIdx++] || '0';
  });

  // Preserve original indentation
  const indent = originalProblemLine.match(/^(\s*)/)?.[1] || '';
  return indent + result;
}
