export type ConfidenceLevel = 'critical' | 'safe' | 'verify-needed';

// Rule code prefixes that deal with hardcoded secrets
const SECRET_RULE_PREFIXES = ['CRED', 'AUTH001'];

// Rule code prefixes that deal with SQL/query injection
const QUERY_RULE_PREFIXES = ['SQL', 'DB001', 'DB002'];

/**
 * Classify the confidence level for a detected security issue based on
 * lightweight variable-source analysis.
 *
 * Returns undefined when the heuristic cannot make a confident determination.
 */
export function classifyConfidence(
  lines: string[],
  issueLine: number,
  issueColumn: number,
  matchedPattern: string,
  ruleCode: string
): ConfidenceLevel | undefined {
  if (issueLine < 0 || issueLine >= lines.length) {
    return undefined;
  }

  const lineText = lines[issueLine];

  // Check if this is a secrets/credentials rule
  if (isSecretRule(ruleCode)) {
    return classifySecret(lineText);
  }

  // Check if this is a SQL/query injection rule
  if (isQueryRule(ruleCode)) {
    return classifyQuery(lines, issueLine, lineText);
  }

  return undefined;
}

function isSecretRule(ruleCode: string): boolean {
  return SECRET_RULE_PREFIXES.some(prefix => ruleCode.startsWith(prefix));
}

function isQueryRule(ruleCode: string): boolean {
  return QUERY_RULE_PREFIXES.some(prefix => ruleCode.startsWith(prefix));
}

/**
 * Classify a secrets-related issue.
 * - Hardcoded string literal value → 'critical'
 * - Reference to env variable or config → 'verify-needed'
 */
function classifySecret(lineText: string): ConfidenceLevel | undefined {
  const trimmed = lineText.trim();

  // Check if the line has a direct string literal assignment
  // Patterns: = "...", = '...', = `...`
  if (/=\s*['"`][^'"`]{2,}['"`]/.test(trimmed)) {
    // Check if it's a reference to an env variable (not actually hardcoded)
    if (/process\.env|os\.environ|getenv|env\[|ENV\[/i.test(trimmed)) {
      return 'verify-needed';
    }
    return 'critical';
  }

  // Variable reference or function call — needs manual verification
  if (/=\s*\w+/.test(trimmed)) {
    return 'verify-needed';
  }

  return undefined;
}

/**
 * Classify a SQL/query injection issue.
 * - Pure static string (no concatenation or interpolation) → 'safe'
 * - String concatenation with + or template literal ${} → 'verify-needed'
 * - Dynamic variable in query → 'verify-needed'
 */
function classifyQuery(lines: string[], issueLine: number, lineText: string): ConfidenceLevel | undefined {
  const trimmed = lineText.trim();

  // Check for string concatenation with +
  if (/['"`]\s*\+/.test(trimmed) || /\+\s*['"`]/.test(trimmed)) {
    return 'verify-needed';
  }

  // Check for template literal interpolation ${}
  if (/\$\{/.test(trimmed)) {
    return 'verify-needed';
  }

  // Check for parameterized queries (safe patterns)
  if (/\?\s*[,)]/.test(trimmed) || /\$\d+/.test(trimmed) || /:[\w]+/.test(trimmed)) {
    return 'safe';
  }

  // Pure static string — check if it's a simple string assignment
  if (/=\s*['"`][^+$]*['"`]\s*[;,]?\s*$/.test(trimmed)) {
    return 'safe';
  }

  // Check surrounding lines for concatenation (multi-line query building)
  const startCheck = Math.max(0, issueLine - 2);
  const endCheck = Math.min(lines.length - 1, issueLine + 2);
  for (let i = startCheck; i <= endCheck; i++) {
    if (i === issueLine) { continue; }
    const nearby = lines[i];
    if (/\+\s*['"`]|['"`]\s*\+|\$\{/.test(nearby)) {
      return 'verify-needed';
    }
  }

  return undefined;
}
