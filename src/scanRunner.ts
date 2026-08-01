/**
 * Workspace scan logic, extracted from src/cli/scan.ts so both the CLI
 * entry point and the MCP server share the same implementation. No I/O
 * concerns live here — that's the caller's job (writing SARIF, emitting
 * JSON to stdout, responding to an MCP tool-call, etc.).
 */

import * as fs from 'fs';
import * as path from 'path';
import { getAllRules } from './rules';
import {
  SecurityRule,
  SecurityIssue,
  SecuritySeverity,
  RuleType,
  ProjectAdvisory,
} from './types';
import { isGeneratedFile } from './generatedFileDetector';
import { buildLineStates, isInsideComment, isInsideStringContent, isInsideJSXText } from './scanContext';
import { classifyConfidence } from './confidenceAnalyzer';
import { runTaintAnalysis } from './taint';

export const DEFAULT_EXTENSIONS = new Set([
  'js', 'jsx', 'mjs', 'cjs',
  'ts', 'tsx', 'mts', 'cts',
  'py', 'java', 'cs', 'php', 'go', 'rs',
  'kt', 'kts',
  'yaml', 'yml',
  'tf', 'tfvars', 'hcl',
]);

export const DEFAULT_FILENAMES = new Set([
  'Dockerfile', 'dockerfile', 'Containerfile',
]);

export const EXT_TO_LANGUAGE: Record<string, string> = {
  js: 'javascript', jsx: 'javascriptreact', mjs: 'javascript', cjs: 'javascript',
  ts: 'typescript', tsx: 'typescriptreact', mts: 'typescript', cts: 'typescript',
  py: 'python',
  java: 'java', cs: 'csharp', php: 'php', go: 'go', rs: 'rust',
  kt: 'kotlin', kts: 'kotlin',
  yaml: 'yaml', yml: 'yaml',
  tf: 'terraform', tfvars: 'terraform', hcl: 'terraform',
};

export const FILENAME_TO_LANGUAGE: Record<string, string> = {
  Dockerfile: 'dockerfile', dockerfile: 'dockerfile', Containerfile: 'dockerfile',
};

export const DEFAULT_EXCLUDES = [
  'node_modules', '.git', 'dist', 'build', 'out', 'coverage',
  '.next', '.nuxt', 'vendor', '__pycache__', 'target',
  '.venv', 'venv', 'bower_components', '.terraform',
];

export interface RunScanOptions {
  workspace: string;
  include?: string[];
  exclude?: string[];
  maxFileSize?: number;
  runTaint?: boolean;
}

export interface FileResult {
  filePath: string;
  relativePath: string;
  languageId: string;
  issues: SecurityIssue[];
}

export interface RunScanResult {
  results: FileResult[];
  filesScanned: number;
  filesSkipped: number;
  totalIssues: number;
}

/** Shape of a worker's reply — mirrors ScanWorkerResult in scanWorker.ts. */
interface ScanWorkerResult {
  results: FileResult[];
  filesSkipped: number;
}

/**
 * Convert a glob pattern (`*`, `**`, `?`) to a RegExp over forward-slash
 * paths. A pattern without a `/` matches against the basename, so
 * `--include *.proto` finds .proto files at any depth.
 */
function globToRegExp(glob: string): { rx: RegExp; basenameOnly: boolean } {
  const basenameOnly = !glob.includes('/');
  let out = '';
  for (let i = 0; i < glob.length; i++) {
    const ch = glob[i];
    if (ch === '*') {
      if (glob[i + 1] === '*') {
        out += '.*';
        i++;
        if (glob[i + 1] === '/') { i++; }
      } else {
        out += '[^/]*';
      }
    } else if (ch === '?') {
      out += '[^/]';
    } else {
      out += ch.replace(/[.+^${}()|[\]\\]/g, '\\$&');
    }
  }
  return { rx: new RegExp(`^${out}$`), basenameOnly };
}

/**
 * Build a matcher for `--include` tokens. Tokens containing glob
 * metacharacters are treated as globs; plain tokens keep the historical
 * substring behaviour.
 */
export function buildIncludeMatcher(tokens: string[]): (fullPath: string) => boolean {
  const matchers = tokens.map(tok => {
    if (!/[*?]/.test(tok)) {
      return (p: string) => p.includes(tok);
    }
    const { rx, basenameOnly } = globToRegExp(tok);
    return (p: string) => {
      const normalized = p.replace(/\\/g, '/');
      return rx.test(basenameOnly ? path.posix.basename(normalized) : normalized);
    };
  });
  return (fullPath: string) => matchers.some(m => m(fullPath));
}

export function walkFiles(root: string, excludes: string[] = [], extraIncludes: string[] = []): string[] {
  const found: string[] = [];
  const skipSet = new Set(DEFAULT_EXCLUDES.concat(excludes));
  const includeMatcher = extraIncludes.length > 0 ? buildIncludeMatcher(extraIncludes) : null;

  const stack: string[] = [root];
  while (stack.length > 0) {
    const dir = stack.pop()!;
    let entries: fs.Dirent[];
    try {
      entries = fs.readdirSync(dir, { withFileTypes: true });
    } catch {
      continue;
    }

    for (const ent of entries) {
      const full = path.join(dir, ent.name);
      if (ent.isDirectory()) {
        if (skipSet.has(ent.name)) { continue; }
        stack.push(full);
        continue;
      }
      if (!ent.isFile()) { continue; }

      const ext = path.extname(ent.name).slice(1).toLowerCase();
      const includedByExt = DEFAULT_EXTENSIONS.has(ext);
      const includedByName = DEFAULT_FILENAMES.has(ent.name);
      const includedByFlag = includeMatcher !== null && includeMatcher(full);
      if (!includedByExt && !includedByName && !includedByFlag) { continue; }
      found.push(full);
    }
  }
  return found;
}

export function resolveLanguage(filePath: string): string {
  const base = path.basename(filePath);
  if (FILENAME_TO_LANGUAGE[base]) { return FILENAME_TO_LANGUAGE[base]; }
  const ext = path.extname(base).slice(1).toLowerCase();
  return EXT_TO_LANGUAGE[ext] || ext;
}

export type ConfidenceLevel = 'critical' | 'safe' | 'verify-needed';

/** Collector for workspace-level advisories, deduped by rule code. */
export interface AdvisorySink {
  fired: Set<string>;
  advisories: ProjectAdvisory[];
}

export interface ScanFileOptions {
  /** Run the intra-file taint pass (default true). */
  runTaint?: boolean;
  /**
   * Confidence classifier for a confirmed match. Defaults to the static
   * `classifyConfidence` heuristic; the extension passes its adaptive
   * (learning-based) engine here.
   */
  classify?: (
    lines: string[], lineNum: number, column: number,
    matchText: string, ruleCode: string
  ) => ConfidenceLevel | undefined;
  /**
   * Extra suppression check for a confirmed match (the extension wires the
   * learned safe-pattern profile in here). Return true to drop the match.
   */
  isLineSuppressed?: (
    ruleCode: string, line: string, lines: string[], lineNum: number
  ) => boolean;
  /**
   * When set, ProjectAdvisory rules are evaluated in the SAME pass and
   * appended here (deduped by code via `fired`), instead of requiring a
   * second full scan of the file.
   */
  advisorySink?: AdvisorySink;
}

/**
 * Per-rule data that is invariant across files: lower-cased string patterns
 * for case-insensitive matching. Computed once per rule (WeakMap-cached)
 * instead of on every line of every file.
 */
interface PreparedStrings {
  patterns: (string | undefined)[];
  negatives: (string | undefined)[];
}

const preparedStringsCache = new WeakMap<SecurityRule, PreparedStrings>();

/**
 * Default base confidence when neither the per-match heuristics nor the
 * rule author decided: a code-detectable match warrants human review;
 * an informational reminder is low-priority by nature.
 */
function defaultConfidence(rule: SecurityRule): ConfidenceLevel {
  return rule.ruleType === RuleType.Informational ? 'safe' : 'verify-needed';
}

function prepareStrings(rule: SecurityRule): PreparedStrings {
  let prepared = preparedStringsCache.get(rule);
  if (!prepared) {
    prepared = {
      patterns: rule.patterns.map(p => typeof p === 'string' ? p.toLowerCase() : undefined),
      negatives: (rule.negativePatterns || []).map(p => typeof p === 'string' ? p.toLowerCase() : undefined),
    };
    preparedStringsCache.set(rule, prepared);
  }
  return prepared;
}

/** A rule plus its per-file precomputed state (path filters already applied). */
interface ActiveRule {
  rule: SecurityRule;
  strings: PreparedStrings;
  reduceToInfo: boolean;
}

/**
 * Apply the file-level filters (ruleType, filePatterns) ONCE per file
 * instead of once per line × rule — on a 1,000-line file this removes
 * hundreds of thousands of redundant path-regex evaluations.
 */
function selectActiveRules(filePath: string, rules: SecurityRule[]): ActiveRule[] {
  const active: ActiveRule[] = [];
  for (const rule of rules) {
    if (rule.ruleType === RuleType.ProjectAdvisory) { continue; }
    if (rule.filePatterns) {
      if (rule.filePatterns.include && !rule.filePatterns.include.some(p => p.test(filePath))) { continue; }
      if (rule.filePatterns.exclude && rule.filePatterns.exclude.some(p => p.test(filePath))) { continue; }
    }
    active.push({
      rule,
      strings: prepareStrings(rule),
      reduceToInfo: !!rule.filePatterns?.reduceSeverityIn?.some(p => p.test(filePath)),
    });
  }
  return active;
}

export function scanFile(
  filePath: string,
  text: string,
  rules: SecurityRule[],
  optionsOrRunTaint: ScanFileOptions | boolean = {}
): SecurityIssue[] {
  const options: ScanFileOptions =
    typeof optionsOrRunTaint === 'boolean' ? { runTaint: optionsOrRunTaint } : optionsOrRunTaint;
  const classify = options.classify || classifyConfidence;

  const lines = text.split('\n');
  const issues: SecurityIssue[] = [];
  const lineStates = buildLineStates(text);
  const informationalFired = new Set<string>();
  const informationalCandidates = new Map<string, SecurityIssue[]>();
  const deadline = Date.now() + 3000;

  const activeRules = selectActiveRules(filePath, rules);
  const advisoryRules = options.advisorySink
    ? rules.filter(r => r.ruleType === RuleType.ProjectAdvisory)
    : [];

  for (let lineNum = 0; lineNum < lines.length; lineNum++) {
    if (lineNum % 25 === 0 && lineNum > 0 && Date.now() > deadline) { break; }
    const line = lines[lineNum];
    if (line.length > 2000) { continue; }
    const lineLower = line.toLowerCase();

    for (const { rule, strings, reduceToInfo } of activeRules) {
      if (rule.ruleType === RuleType.Informational && informationalFired.has(rule.code)) {
        const existing = informationalCandidates.get(rule.code);
        if (existing && existing.length >= 10) { continue; }
      }

      for (let p = 0; p < rule.patterns.length; p++) {
        const pattern = rule.patterns[p];
        let matched = false, column = 0, matchText = '';
        try {
          if (typeof pattern === 'string') {
            const pLower = strings.patterns[p]!;
            if (lineLower.includes(pLower)) {
              matched = true;
              column = lineLower.indexOf(pLower);
              matchText = pattern;
            }
          } else if (pattern instanceof RegExp) {
            const m = pattern.exec(line);
            if (m) { matched = true; column = m.index; matchText = m[0]; }
          }
        } catch {
          continue;
        }
        if (!matched) { continue; }

        if (rule.contextAware) {
          const ls = lineStates[lineNum];
          if (isInsideComment(line, column, ls) ||
              isInsideStringContent(line, column, ls) ||
              isInsideJSXText(line, column)) { continue; }
        }

        if (rule.negativePatterns) {
          let negated = false;
          for (let n = 0; n < rule.negativePatterns.length; n++) {
            const neg = rule.negativePatterns[n];
            if (typeof neg === 'string') {
              if (lineLower.includes(strings.negatives[n]!)) { negated = true; break; }
            } else if (neg instanceof RegExp) {
              if (neg.test(line)) { negated = true; break; }
            }
          }
          if (negated) { continue; }
        }

        if (rule.suppressIfNearby) {
          let suppressed = false;
          const window = rule.suppressNearbyWindow ?? 3;
          const s = Math.max(0, lineNum - window);
          const e = Math.min(lines.length - 1, lineNum + window);
          for (let j = s; j <= e && !suppressed; j++) {
            for (const sp of rule.suppressIfNearby) {
              if (sp.test(lines[j])) { suppressed = true; break; }
            }
          }
          if (suppressed) { continue; }
        }

        if (options.isLineSuppressed && options.isLineSuppressed(rule.code, line, lines, lineNum)) {
          continue;
        }

        // Confidence resolution order: per-match heuristics (or the
        // extension's adaptive engine) → rule author's base confidence →
        // default by rule type. Every finding ends up with a level.
        const confidenceLevel =
          classify(lines, lineNum, column, matchText, rule.code)
          ?? rule.confidence
          ?? defaultConfidence(rule);

        const issue: SecurityIssue = {
          line: lineNum,
          column,
          message: rule.message,
          severity: reduceToInfo ? SecuritySeverity.Info : rule.severity,
          suggestion: rule.suggestion,
          code: rule.code,
          pattern: matchText,
          category: rule.category,
          confidenceLevel,
        };

        if (rule.ruleType === RuleType.Informational) {
          if (!informationalCandidates.has(rule.code)) {
            informationalCandidates.set(rule.code, []);
          }
          informationalCandidates.get(rule.code)!.push(issue);
          informationalFired.add(rule.code);
        } else {
          issues.push(issue);
        }
        break;
      }
    }

    // Same-pass project advisory collection (workspace-level, fire-once).
    if (options.advisorySink && advisoryRules.length > options.advisorySink.fired.size) {
      const sink = options.advisorySink;
      for (const rule of advisoryRules) {
        if (sink.fired.has(rule.code)) { continue; }
        const strings = prepareStrings(rule);
        for (let p = 0; p < rule.patterns.length; p++) {
          const pattern = rule.patterns[p];
          let matched = false;
          if (typeof pattern === 'string') {
            if (lineLower.includes(strings.patterns[p]!)) { matched = true; }
          } else if (pattern instanceof RegExp) {
            if (pattern.test(line)) { matched = true; }
          }
          if (matched) {
            sink.fired.add(rule.code);
            sink.advisories.push({
              code: rule.code,
              message: rule.message,
              suggestion: rule.suggestion,
              category: rule.category,
              triggeredBy: filePath,
            });
            break;
          }
        }
      }
    }
  }

  if (options.runTaint !== false) {
    try {
      const taintFindings = runTaintAnalysis(text, 100);
      for (const t of taintFindings) { issues.push(t); }
    } catch { /* don't let taint failures hide regular findings */ }
  }

  for (const candidates of informationalCandidates.values()) {
    if (candidates.length === 0) { continue; }
    issues.push(pickBestInformationalCandidate(candidates, lines));
  }

  return issues;
}

export function pickBestInformationalCandidate(candidates: SecurityIssue[], lines: string[]): SecurityIssue {
  if (candidates.length === 1) { return candidates[0]; }
  const DECL = /^\s*(?:import\s|export\s(?:type|interface|default)|const\s|let\s|var\s|type\s|interface\s|class\s)/;
  const FN_BODY = /(?:function\s|=>\s*\{|\.(?:then|catch|map|forEach|filter|reduce)\s*\()/;
  let best = candidates[0];
  let bestScore = -1;
  for (const c of candidates) {
    const line = lines[c.line] || '';
    let score = 1;
    if (DECL.test(line)) { score = 0; }
    if (FN_BODY.test(line)) { score += 2; }
    if (/\w+\s*\(/.test(line) && !DECL.test(line)) { score += 1; }
    if (score > bestScore) { bestScore = score; best = c; }
  }
  return best;
}

/**
 * Scan every eligible file under `options.workspace` and return the
 * results. I/O-free beyond fs.readFileSync on the files themselves —
 * the caller chooses how to present / persist the data.
 */
export function runWorkspaceScan(options: RunScanOptions & { files?: string[] }): RunScanResult {
  const maxFileSize = options.maxFileSize ?? 500_000;
  const files = options.files ?? walkFiles(options.workspace, options.exclude || [], options.include || []);
  const { results, filesSkipped } = scanFileList(
    files, options.workspace, maxFileSize, options.runTaint !== false
  );
  const totalIssues = results.reduce((n, r) => n + r.issues.length, 0);
  return { results, filesScanned: files.length, filesSkipped, totalIssues };
}

/**
 * Scan an explicit list of file paths (read → size/generated filter →
 * scan). Shared by the sync scan, the CLI, and the worker thread so all
 * three apply identical per-file filtering.
 */
export function scanFileList(
  files: string[],
  workspace: string,
  maxFileSize: number,
  runTaint: boolean
): { results: FileResult[]; filesSkipped: number } {
  const rules = getAllRules();
  const results: FileResult[] = [];
  let filesSkipped = 0;

  for (const fp of files) {
    let stat: fs.Stats;
    try { stat = fs.statSync(fp); } catch { continue; }
    if (maxFileSize > 0 && stat.size > maxFileSize) { filesSkipped++; continue; }

    let text: string;
    try { text = fs.readFileSync(fp, 'utf-8'); } catch { continue; }

    if (isGeneratedFile(fp, text)) { filesSkipped++; continue; }

    const languageId = resolveLanguage(fp);
    const relativePath = path.relative(workspace, fp) || fp;
    const issues = scanFile(fp, text, rules, runTaint);
    if (issues.length > 0) {
      results.push({ filePath: fp, relativePath, languageId, issues });
    }
  }

  return { results, filesSkipped };
}

/**
 * Split `items` into at most `n` roughly-even contiguous chunks.
 * Exported for testing.
 */
export function chunkEvenly<T>(items: T[], n: number): T[][] {
  if (n <= 1 || items.length <= 1) { return items.length ? [items] : []; }
  const chunks: T[][] = [];
  const size = Math.ceil(items.length / n);
  for (let i = 0; i < items.length; i += size) {
    chunks.push(items.slice(i, i + size));
  }
  return chunks;
}

/**
 * Parallel workspace scan across worker threads. Falls back to the
 * synchronous {@link runWorkspaceScan} when the pool would be a single
 * worker, when the file count is below `minFilesForParallel`, or when
 * worker threads are unavailable. Results are order-independent, so the
 * merged output is deterministic given a deterministic file walk.
 */
export async function runWorkspaceScanParallel(
  options: RunScanOptions & {
    concurrency?: number;
    minFilesForParallel?: number;
    /** Pre-resolved file list (e.g. from a --changed-since filter). When
     * omitted, the workspace is walked. */
    files?: string[];
  }
): Promise<RunScanResult> {
  const maxFileSize = options.maxFileSize ?? 500_000;
  const runTaint = options.runTaint !== false;
  const files = options.files ?? walkFiles(options.workspace, options.exclude || [], options.include || []);
  const minFiles = options.minFilesForParallel ?? 200;

  // eslint-disable-next-line @typescript-eslint/no-var-requires
  const os = require('os') as typeof import('os');
  const cpuCount = Math.max(1, (os.cpus?.() || []).length || 1);
  const workerCount = Math.max(1, Math.min(options.concurrency ?? cpuCount, cpuCount));

  // Not worth the thread overhead — run inline.
  if (workerCount <= 1 || files.length < minFiles) {
    return runWorkspaceScan({ ...options, files, maxFileSize, runTaint });
  }

  let Worker: typeof import('worker_threads').Worker;
  try {
    ({ Worker } = require('worker_threads') as typeof import('worker_threads'));
  } catch {
    return runWorkspaceScan({ ...options, files, maxFileSize, runTaint });
  }

  // The compiled worker lives next to this module in out/. When running
  // from ts source (tests), fall back to the sync path.
  const workerPath = path.join(__dirname, 'scanWorker.js');
  if (!fs.existsSync(workerPath)) {
    return runWorkspaceScan({ ...options, files, maxFileSize, runTaint });
  }

  const chunks = chunkEvenly(files, workerCount);
  const merged: FileResult[] = [];
  let filesSkipped = 0;

  await Promise.all(chunks.map(chunk => new Promise<void>((resolve, reject) => {
    const worker = new Worker(workerPath, {
      workerData: { files: chunk, workspace: options.workspace, maxFileSize, runTaint },
    });
    worker.once('message', (res: ScanWorkerResult) => {
      merged.push(...res.results);
      filesSkipped += res.filesSkipped;
    });
    worker.once('error', reject);
    worker.once('exit', code => {
      if (code !== 0) { reject(new Error(`scan worker exited with code ${code}`)); }
      else { resolve(); }
    });
  })));

  // Stable ordering by path so output doesn't depend on which worker
  // finished first.
  merged.sort((a, b) => a.filePath.localeCompare(b.filePath));
  const totalIssues = merged.reduce((n, r) => n + r.issues.length, 0);
  return { results: merged, filesScanned: files.length, filesSkipped, totalIssues };
}
