import * as fs from 'fs';
import * as path from 'path';

export interface IgnoreEntry {
  ruleCode: string;
  filePath: string;
  line?: number;
  reason?: string;
}

const IGNORE_FILENAME = '.caspianignore';

const FILE_HEADER = `# Caspian Security Ignore File
# Format: RULE_CODE file/path.ts:line # optional reason
# Lines starting with # are comments
`;

/**
 * Load and parse the .caspianignore file from the workspace root.
 * Returns an empty array if the file doesn't exist.
 */
export function loadIgnoreFile(workspaceRoot: string): IgnoreEntry[] {
  const filePath = path.join(workspaceRoot, IGNORE_FILENAME);

  if (!fs.existsSync(filePath)) {
    return [];
  }

  const content = fs.readFileSync(filePath, 'utf-8');
  const entries: IgnoreEntry[] = [];

  for (const rawLine of content.split('\n')) {
    const line = rawLine.trim();
    if (!line || line.startsWith('#')) {
      continue;
    }

    const entry = parseLine(line);
    if (entry) {
      entries.push(entry);
    }
  }

  return entries;
}

/**
 * Parse a single line from .caspianignore.
 * Format: RULE_CODE file/path.ts[:line] [# reason]
 */
function parseLine(line: string): IgnoreEntry | undefined {
  // Split off comment
  const commentIdx = line.indexOf('#');
  const mainPart = commentIdx !== -1 ? line.substring(0, commentIdx).trim() : line.trim();
  const reason = commentIdx !== -1 ? line.substring(commentIdx + 1).trim() : undefined;

  // Split into rule code and file path
  const parts = mainPart.split(/\s+/);
  if (parts.length < 2) {
    return undefined;
  }

  const ruleCode = parts[0];
  const fileSpec = parts[1];

  // Parse optional line number from file:line format
  const colonIdx = fileSpec.lastIndexOf(':');
  let filePath: string;
  let lineNum: number | undefined;

  if (colonIdx !== -1) {
    const afterColon = fileSpec.substring(colonIdx + 1);
    const parsed = parseInt(afterColon, 10);
    if (!isNaN(parsed) && parsed > 0) {
      filePath = fileSpec.substring(0, colonIdx);
      lineNum = parsed;
    } else {
      filePath = fileSpec;
    }
  } else {
    filePath = fileSpec;
  }

  // Normalize path separators to forward slashes
  filePath = filePath.replace(/\\/g, '/');

  return { ruleCode, filePath, line: lineNum, reason: reason || undefined };
}

/**
 * Append an ignore entry to the .caspianignore file.
 * Creates the file with a header if it doesn't exist.
 */
export function appendIgnoreEntry(workspaceRoot: string, entry: IgnoreEntry): void {
  const filePath = path.join(workspaceRoot, IGNORE_FILENAME);
  const fileExists = fs.existsSync(filePath);

  let line = `${entry.ruleCode} ${entry.filePath.replace(/\\/g, '/')}`;
  if (entry.line !== undefined) {
    line += `:${entry.line}`;
  }
  if (entry.reason) {
    line += ` # ${entry.reason}`;
  }

  if (!fileExists) {
    fs.writeFileSync(filePath, FILE_HEADER + '\n' + line + '\n', 'utf-8');
  } else {
    // Ensure there's a newline before appending
    const existing = fs.readFileSync(filePath, 'utf-8');
    const separator = existing.endsWith('\n') ? '' : '\n';
    fs.appendFileSync(filePath, separator + line + '\n', 'utf-8');
  }
}

/**
 * Check if a specific issue is covered by an ignore entry.
 * Line numbers in entries are 1-based. The issueLine parameter is 0-based.
 */
export function isIgnored(
  entries: IgnoreEntry[],
  ruleCode: string,
  relativePath: string,
  issueLine?: number
): boolean {
  const normalizedPath = relativePath.replace(/\\/g, '/');

  for (const entry of entries) {
    if (entry.ruleCode !== ruleCode) {
      continue;
    }

    if (entry.filePath !== normalizedPath) {
      continue;
    }

    // If the entry specifies a line, it must match (entry line is 1-based, issueLine is 0-based)
    if (entry.line !== undefined && issueLine !== undefined) {
      if (entry.line !== issueLine + 1) {
        continue;
      }
    }

    return true;
  }

  return false;
}
