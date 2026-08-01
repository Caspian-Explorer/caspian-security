/**
 * Intra-file taint tracking — Caspian's first dataflow-aware analysis.
 *
 * Scope, ruthlessly bounded so it ships:
 *   - One file at a time. No cross-file reasoning.
 *   - One function at a time. Variables go out of scope at the closing
 *     brace of the function they were tagged in.
 *   - Forward-only assignments. `x = req.body.foo`, then `sink(x)`.
 *     `y = x` propagates the taint. Aliases through arrays / objects /
 *     destructuring / function returns are NOT tracked.
 *   - Sanitisation is a *lexical* signal: if a known sanitiser call
 *     wraps a tainted variable on the way to a sink, the taint is
 *     dropped. False negatives are preferred over false positives here.
 *
 * What it gets us:
 *   The 60–70 % of vulnerabilities that happen in a single Express /
 *   Flask / FastAPI controller — secrets crossing one function boundary,
 *   user input flowing into a sink in the same handler, etc. The other
 *   30 % needs a real taint analyser (Semgrep, CodeQL) and is out of
 *   scope by design.
 *
 * Performance budget:
 *   - Hard limit of 200 lines per function.
 *   - Hard limit of 50 simultaneously-tracked tainted vars.
 *   - 100 ms per file deadline; on overrun, return whatever we have.
 *
 * The engine is regex-based, no AST. That's a deliberate constraint —
 * the moment we adopt a parser, we ship-stop on language-version skew
 * (TS 5.9 vs 5.10 vs Node-only JS) and grow a maintenance tax we don't
 * want.
 */

import {
  SecurityIssue,
  SecuritySeverity,
  SecurityCategory,
} from './types';

// ---------------------------------------------------------------------------
// Sources
// ---------------------------------------------------------------------------

interface Source {
  /** Human-readable label for the source (used in messages). */
  label: string;
  /** Pattern that matches the source EXPRESSION (not whole assignments). */
  expr: RegExp;
}

const SOURCES: Source[] = [
  { label: 'req.body / req.query / req.params / req.headers / req.cookies',
    expr: /\b(?:req|request|ctx|context)\.(?:body|query|params|headers|cookies|input|url)\b(?:\.[\w]+)*/ },
  { label: 'Flask / Django request data',
    expr: /\bflask\.request\.(?:args|form|json|values|cookies|headers|data)\b/ },
  { label: 'Express params (Koa-style ctx.request.body)',
    expr: /\bctx\.request\.(?:body|query|params|headers)\b/ },
  { label: 'PHP $_GET / $_POST / $_REQUEST / $_COOKIE',
    expr: /\$_(?:GET|POST|REQUEST|COOKIE|FILES|SERVER)\b(?:\[[^\]]+\])*/ },
  // NOTE: process.env / os.environ are deliberately NOT sources. Env vars
  // are trusted deployment config — treating them as attacker input made
  // every `jwt.sign(..., process.env.KEY)` → `res.json(token)` flow light
  // up as XSS, which is pure noise.
  { label: 'process.argv',
    expr: /\bprocess\.argv\b(?:\.[\w]+|\[[^\]]+\])*/ },
  { label: 'Python sys.argv',
    expr: /\bsys\.argv\b(?:\[[^\]]+\])?/ },
  { label: 'process stdin / readline input',
    expr: /\bprocess\.stdin\b|\breadline\s*\(\s*\)/ },
];

// ---------------------------------------------------------------------------
// Sinks — each ties to a specific TAINT00x rule code
// ---------------------------------------------------------------------------

export interface TaintSink {
  ruleCode: string;
  message: string;
  suggestion: string;
  category: SecurityCategory;
  /** Pattern that identifies the SINK CALL on a line. The argument list is checked separately for taint. */
  callPattern: RegExp;
}

const SINKS: TaintSink[] = [
  {
    ruleCode: 'TAINT001',
    message: 'Tainted user input flows into a shell-executing sink (command injection)',
    suggestion: 'Use child_process.execFile / spawn with an array of args (no shell). Validate against an allow-list before passing user input to any shell.',
    category: SecurityCategory.APISecurity,
    callPattern: /\b(?:child_process\.)?(?:exec|execSync|spawn(?:Sync)?)\s*\(/,
  },
  {
    ruleCode: 'TAINT002',
    message: 'Tainted user input flows into eval / new Function / vm — RCE',
    suggestion: 'eval / Function / vm.runInNewContext on user input is direct RCE. Use a safer parser, JSON.parse, or a dedicated expression evaluator like jsep with an allow-list of operations.',
    category: SecurityCategory.InputValidationXSS,
    callPattern: /\b(?:eval|new\s+Function|vm\.(?:runInNewContext|runInThisContext|runInContext))\s*\(/,
  },
  {
    ruleCode: 'TAINT003',
    message: 'Tainted user input flows into a filesystem path — possible path traversal',
    suggestion: 'Resolve the path with path.resolve(baseDir, userPart) and verify the result startsWith(baseDir). Reject any input containing "..", null bytes, or absolute paths.',
    category: SecurityCategory.FileHandling,
    callPattern: /\bfs\.(?:readFile(?:Sync)?|writeFile(?:Sync)?|unlink(?:Sync)?|appendFile(?:Sync)?|createReadStream|createWriteStream|open(?:Sync)?)\s*\(/,
  },
  {
    ruleCode: 'TAINT004',
    message: 'Tainted user input flows into a SQL sink — likely SQL injection',
    suggestion: 'Use parameterized queries (db.query("SELECT … WHERE id = $1", [id])). Never concatenate user input into a SQL string.',
    category: SecurityCategory.DatabaseSecurity,
    callPattern: /\.(?:query|execute|exec|raw|prepare)\s*\(/,
  },
  {
    ruleCode: 'TAINT005',
    message: 'Tainted user input flows into a redirect — open-redirect vulnerability',
    suggestion: 'Validate the redirect target against an allow-list of internal paths or origins. Never call res.redirect with raw user input.',
    category: SecurityCategory.APISecurity,
    callPattern: /\b(?:res|response)\.(?:redirect|sendRedirect|setHeader\s*\(\s*['"]Location)\s*\(/,
  },
  {
    ruleCode: 'TAINT006',
    message: 'Tainted user input flows into a response body / DOM sink — reflected XSS',
    suggestion: 'Escape the value with the appropriate context-encoder (HTML, JS, attribute). For browser sinks use textContent or DOMPurify.sanitize.',
    category: SecurityCategory.InputValidationXSS,
    callPattern: /\b(?:res|response)\.(?:send|write|end|json)\s*\(|\.innerHTML\s*=|\bdocument\.write(?:ln)?\s*\(/,
  },
  {
    ruleCode: 'TAINT007',
    message: 'Tainted user input flows into an outbound HTTP call — SSRF (with provenance)',
    suggestion: 'Validate the URL against an explicit host allow-list. Reject private IPs (127.0.0.0/8, 10/8, 172.16/12, 192.168/16, 169.254/16) and metadata endpoints.',
    category: SecurityCategory.APISecurity,
    callPattern: /\b(?:fetch|axios(?:\.\w+)?|https?\.(?:get|request)|requests\.(?:get|post|put|delete|patch|head))\s*\(/,
  },
  {
    ruleCode: 'TAINT008',
    message: 'Tainted user input merged into a trusted object — prototype pollution risk',
    suggestion: 'Object.assign / lodash.merge / spread of untrusted objects can pollute Object.prototype via __proto__. Validate keys against an allow-list, or use a structured-clone + Object.create(null) pattern.',
    category: SecurityCategory.FrontendSecurity,
    callPattern: /\b(?:Object\.assign|_\.merge(?:With)?|_\.defaultsDeep|jQuery\.extend)\s*\(/,
  },
];

// ---------------------------------------------------------------------------
// Sanitisers — if any of these wraps a tainted value before a sink, the taint clears
// ---------------------------------------------------------------------------

const SANITISER_PATTERNS: RegExp[] = [
  /\bvalidator\.(?:isURL|isEmail|isUUID|isAlpha|isAlphanumeric|isNumeric|isInt|isFloat|isJSON|escape|whitelist|trim)\s*\(/,
  /\bDOMPurify\.sanitize\s*\(/,
  /\bsanitize(?:Html|URL|String|Filename|Input)?\s*\(/i,
  /\bescape(?:Html|Sql|Shell|Url)?\s*\(/i,
  /\bencodeURI(?:Component)?\s*\(/,
  /\bzod\.\w+\.parse\s*\(|\bjoi\.\w+\.validate\s*\(/i,
  /\b(?:Number|parseInt|parseFloat|Boolean)\s*\(/,
  /\bnew\s+URL\s*\([^)]+\)/,
  /\bpath\.(?:resolve|normalize)\s*\([^)]+\)\.startsWith\s*\(/,
  /\bexpress-validator/,
];

function isSanitiserCall(line: string): boolean {
  return SANITISER_PATTERNS.some(p => p.test(line));
}

// ---------------------------------------------------------------------------
// Function-boundary detection — bracket counting starting from a probable
// function-declaration line. Imperfect but cheap and enough for controllers.
// ---------------------------------------------------------------------------

interface FunctionRange {
  startLine: number;
  endLine: number;
}

const FUNCTION_HEAD = /(?:^|\s)(?:async\s+)?function\s*[\w$]*\s*\(|=>\s*\{|^\s*[\w$]+\s*\([^)]*\)\s*\{|^\s*(?:export\s+)?(?:async\s+)?(?:const|let|var)\s+[\w$]+\s*=\s*(?:async\s*)?\([^)]*\)\s*=>\s*\{|^\s*(?:public|private|protected|static)?\s*(?:async\s+)?[\w$]+\s*\([^)]*\)\s*[:\s]?[^{]*\{/;

function findFunctionRanges(lines: string[], deadlineAt: number): FunctionRange[] {
  const out: FunctionRange[] = [];
  for (let i = 0; i < lines.length; i++) {
    // Range discovery does bracket-matching work proportional to file
    // size, so it must respect the same budget as the walk itself.
    if (i % 50 === 0 && Date.now() > deadlineAt) { break; }
    if (!FUNCTION_HEAD.test(lines[i])) { continue; }
    // Bracket-count forward to find the matching close.
    const range = bracketMatch(lines, i);
    if (range) { out.push(range); }
  }
  return out;
}

function bracketMatch(lines: string[], startLine: number): FunctionRange | null {
  let depth = 0;
  let started = false;
  for (let i = startLine; i < lines.length && i < startLine + 200; i++) {
    const line = lines[i];
    for (let j = 0; j < line.length; j++) {
      if (line[j] === '{') { depth++; started = true; }
      else if (line[j] === '}') {
        depth--;
        if (started && depth === 0) {
          return { startLine, endLine: i };
        }
      }
    }
  }
  return null;
}

// ---------------------------------------------------------------------------
// The walker
// ---------------------------------------------------------------------------

interface TaintedVar {
  name: string;
  sourceLine: number;
  sourceLabel: string;
}

const ASSIGN_DECL = /(?:^|\s)(?:const|let|var)\s+(\{[^}]+\}|\[[^\]]+\]|[\w$]+)\s*=\s*(.+);?$/;
const ASSIGN_REASSIGN = /^\s*([\w$]+)\s*=\s*(.+);?$/;
const SIMPLE_VAR = /^[\w$]+$/;
const MAX_TAINTED_VARS = 50;

/**
 * Run the taint analysis over a file's contents and return any findings.
 * `relativePath` and `languageId` are passed through onto each issue so
 * the caller can attach them when emitting the {@link SecurityIssue}.
 */
export function runTaintAnalysis(text: string, deadlineMs: number = 100): SecurityIssue[] {
  // The clock starts BEFORE range discovery — bracket matching is the
  // expensive half on dense files, so it must count against the budget.
  const startedAt = Date.now();
  const deadlineAt = startedAt + deadlineMs;
  const lines = text.split('\n');
  const ranges = findFunctionRanges(lines, deadlineAt);
  if (ranges.length === 0) { return []; }

  const issues: SecurityIssue[] = [];

  // Ranges arrive ordered by start line. Skip ranges fully contained in a
  // range we already walked (nested arrows inside a function): the outer
  // walk covers those lines, so re-walking wastes budget and can
  // double-report the same sink hit.
  let walkedMaxEnd = -1;
  for (const range of ranges) {
    if (Date.now() > deadlineAt) { break; }
    if (range.endLine <= walkedMaxEnd) { continue; }
    if (range.endLine - range.startLine > 200) { continue; }
    walkFunction(lines, range, issues);
    walkedMaxEnd = Math.max(walkedMaxEnd, range.endLine);
  }

  return issues;
}

function walkFunction(lines: string[], range: FunctionRange, issues: SecurityIssue[]): void {
  const tainted = new Map<string, TaintedVar>();

  for (let lineNum = range.startLine; lineNum <= range.endLine; lineNum++) {
    const line = lines[lineNum];
    if (!line) { continue; }

    // Sanitiser detection: drop tainted-vars whose names appear on this line
    // alongside a sanitiser call. Coarse but conservative.
    if (isSanitiserCall(line)) {
      for (const [name, _] of tainted) {
        // If the line mentions this var AS AN ARGUMENT to the sanitiser,
        // we drop it. Cheapest signal: the var name appears anywhere on the
        // line. False negatives possible (over-clears) but we prefer that
        // to over-flagging.
        if (containsIdentifier(line, name)) { tainted.delete(name); }
      }
    }

    // Assignment: `const x = req.body.foo` or `x = req.query.bar`.
    const assignVar = detectTaintingAssignment(line);
    if (assignVar) {
      // Cap tracked vars to keep the engine bounded.
      if (tainted.size >= MAX_TAINTED_VARS) {
        const oldestKey = tainted.keys().next().value;
        if (oldestKey) { tainted.delete(oldestKey); }
      }
      tainted.set(assignVar.name, {
        name: assignVar.name,
        sourceLine: lineNum,
        sourceLabel: assignVar.sourceLabel,
      });
      continue;
    }

    // Sink check: each known sink, against this line.
    for (const sink of SINKS) {
      if (!sink.callPattern.test(line)) { continue; }
      // Find the argument expression and see if it contains either a
      // tainted variable name or a raw source expression.
      const tainting = findTaintingInArgs(line, sink.callPattern, tainted);
      if (!tainting) { continue; }

      issues.push({
        line: lineNum,
        column: 0,
        message: tainting.kind === 'var'
          ? `${sink.message} — '${tainting.name}' was tainted at line ${tainting.sourceLine + 1} (source: ${tainting.sourceLabel})`
          : `${sink.message} — direct flow from ${tainting.sourceLabel}`,
        severity: SecuritySeverity.Error,
        suggestion: sink.suggestion,
        code: sink.ruleCode,
        pattern: sink.callPattern.source,
        category: sink.category,
        confidenceLevel: 'critical',
      });
      break; // one sink hit per line
    }
  }
}

interface TaintingAssignment {
  name: string;
  sourceLabel: string;
}

function detectTaintingAssignment(line: string): TaintingAssignment | null {
  // Try declaration first.
  const decl = ASSIGN_DECL.exec(line);
  if (decl) {
    const lhs = decl[1];
    const rhs = decl[2];
    const source = matchSource(rhs);
    // A sanitiser applied in the same assignment neutralises the source:
    // `const id = Number.parseInt(req.params.id, 10)` must not taint `id`.
    if (source && SIMPLE_VAR.test(lhs) && !isSanitiserCall(rhs)) {
      return { name: lhs, sourceLabel: source.label };
    }
  }
  // Then reassignment.
  const re = ASSIGN_REASSIGN.exec(line);
  if (re) {
    const lhs = re[1];
    const rhs = re[2];
    const source = matchSource(rhs);
    if (source && SIMPLE_VAR.test(lhs) && !isSanitiserCall(rhs)) {
      return { name: lhs, sourceLabel: source.label };
    }
  }
  return null;
}

function matchSource(expr: string): Source | null {
  for (const src of SOURCES) {
    if (src.expr.test(expr)) { return src; }
  }
  return null;
}

interface SinkArgsTaint {
  kind: 'var' | 'source';
  name: string;
  sourceLine: number;
  sourceLabel: string;
}

function findTaintingInArgs(
  line: string,
  callPattern: RegExp,
  tainted: Map<string, TaintedVar>
): SinkArgsTaint | null {
  const match = callPattern.exec(line);
  if (!match) { return null; }

  // Pull out everything after the opening `(` up to a balanced close (or EOL).
  const start = match.index + match[0].length;
  const args = extractCallArgs(line, start);

  // 1) Direct flow from a source expression — the strongest signal.
  for (const src of SOURCES) {
    if (src.expr.test(args)) {
      return { kind: 'source', name: '', sourceLine: 0, sourceLabel: src.label };
    }
  }

  // 2) Tainted variable referenced in the args.
  for (const [name, tv] of tainted) {
    if (containsIdentifier(args, name)) {
      return { kind: 'var', name, sourceLine: tv.sourceLine, sourceLabel: tv.sourceLabel };
    }
  }
  return null;
}

function extractCallArgs(line: string, openIdx: number): string {
  let depth = 1;
  for (let i = openIdx; i < line.length; i++) {
    if (line[i] === '(') { depth++; }
    else if (line[i] === ')') { depth--; if (depth === 0) { return line.substring(openIdx, i); } }
  }
  return line.substring(openIdx);
}

/**
 * Cache of compiled identifier regexes. containsIdentifier runs for every
 * tainted var on every sanitiser/sink line — compiling a fresh RegExp per
 * call was measurable. Bounded so it can't grow without limit.
 */
const identifierRegexCache = new Map<string, RegExp>();
const IDENTIFIER_CACHE_MAX = 500;

/** Word-boundary identifier match — avoids `foo` matching `foobar`. */
function containsIdentifier(text: string, name: string): boolean {
  // Fast path: cheap bail if the substring isn't even present.
  if (!text.includes(name)) { return false; }
  let rx = identifierRegexCache.get(name);
  if (!rx) {
    if (identifierRegexCache.size >= IDENTIFIER_CACHE_MAX) {
      identifierRegexCache.clear();
    }
    rx = new RegExp(`\\b${name.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}\\b`);
    identifierRegexCache.set(name, rx);
  }
  return rx.test(text);
}
