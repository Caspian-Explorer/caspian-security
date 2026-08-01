/**
 * Shared scan-context utilities.
 *
 * Problem these solve:
 *   Every rule with `contextAware: true` uses line-scoped heuristics to
 *   decide whether a match falls inside a string literal or comment. Those
 *   heuristics break on multi-line constructs — a template literal that
 *   opens on line 10 and closes on line 300 means lines 11-299 have zero
 *   backticks in their own text, so they look like "code" to a per-line
 *   check. F11 from the v9.2 self-audit.
 *
 * Fix:
 *   Walk the file once, keep a tiny state machine, emit one {@link LineState}
 *   per line that records how the line STARTS. Both `analyzer.ts` (extension
 *   host) and `cli/scan.ts` (CI / Action) consume this, so line-scoped
 *   helpers become multi-line-aware without every caller re-rolling the
 *   walker.
 */

/** Where a line begins, inherited from the previous line's terminal state. */
export interface LineState {
  /** Inside a single- or double-quoted string at char 0 of this line. Rare but legal via `\` line-continuation. */
  startsInsideQuotedString: boolean;
  /** Inside a backtick template literal at char 0 (the common multi-line case). */
  startsInsideTemplateLiteral: boolean;
  /** Inside an unterminated `/* … *\/` block comment. */
  startsInsideBlockComment: boolean;
  /** How many `${...}` template-literal expression levels we're nested into. `> 0` means "this line starts in template code, not template text". */
  templateExprDepth: number;
}

const CLEAN_STATE: LineState = Object.freeze({
  startsInsideQuotedString: false,
  startsInsideTemplateLiteral: false,
  startsInsideBlockComment: false,
  templateExprDepth: 0,
});

type ScanState =
  | 'code'
  | 'singleStr'
  | 'doubleStr'
  | 'templateStr'
  | 'blockComment';

/**
 * Walk `text` char-by-char and produce one {@link LineState} per line.
 *
 * Guaranteed: `result.length === text.split('\n').length`. The 0th entry is
 * always a "clean" state (files always start outside any construct).
 */
export function buildLineStates(text: string): LineState[] {
  const lines = text.split('\n');
  const states: LineState[] = new Array(lines.length);
  states[0] = CLEAN_STATE;

  let state: ScanState = 'code';
  // When we enter a `${}` expression inside a template literal, we push the
  // template-literal state here so nested templates work. Each stack frame
  // is the state we should return to on `}`.
  const exprStack: ScanState[] = [];
  // Current brace depth within the top template expression, so we know
  // which `}` closes the expression and which is just a regular `}`.
  let exprBraceDepth = 0;

  for (let lineIdx = 0; lineIdx < lines.length; lineIdx++) {
    const line = lines[lineIdx];

    for (let i = 0; i < line.length; i++) {
      const ch = line[i];
      const next = line[i + 1];

      switch (state) {
        case 'code': {
          if (ch === '/' && next === '/') { i = line.length; break; } // skip EOL comment
          if (ch === '/' && next === '*') { state = 'blockComment'; i++; break; }
          // Regex-literal recognition: a `/` after a punctuator or at the
          // start of a statement starts a JS regex literal — skip to the
          // matching close `/` so backticks/quotes inside the regex don't
          // confuse the string/comment tracker. Without this, `/\`/g` on a
          // line of code drops the walker into templateStr state for the
          // rest of the file.
          if (ch === '/' && isRegexLiteralStart(line, i)) {
            const closeIdx = findRegexClose(line, i + 1);
            if (closeIdx !== -1) { i = consumeRegexFlags(line, closeIdx); break; }
            // Unterminated on this line — treat the slash as an operator.
          }
          if (ch === "'") { state = 'singleStr'; break; }
          if (ch === '"') { state = 'doubleStr'; break; }
          if (ch === '`') { state = 'templateStr'; break; }
          // Track brace balance only while we're in a template expression
          // so the right `}` can close it.
          if (exprStack.length > 0) {
            if (ch === '{') { exprBraceDepth++; }
            else if (ch === '}') {
              if (exprBraceDepth === 0) {
                // This `}` closes the `${...}` — pop.
                state = exprStack.pop()!;
              } else {
                exprBraceDepth--;
              }
            }
          }
          break;
        }
        case 'singleStr': {
          if (ch === '\\') { i++; break; } // skip escaped char
          if (ch === "'") { state = 'code'; break; }
          break;
        }
        case 'doubleStr': {
          if (ch === '\\') { i++; break; }
          if (ch === '"') { state = 'code'; break; }
          break;
        }
        case 'templateStr': {
          if (ch === '\\') { i++; break; }
          if (ch === '`') { state = 'code'; break; }
          if (ch === '$' && next === '{') {
            exprStack.push('templateStr');
            exprBraceDepth = 0;
            state = 'code';
            i++;
            break;
          }
          break;
        }
        case 'blockComment': {
          if (ch === '*' && next === '/') { state = 'code'; i++; break; }
          break;
        }
      }
    }

    // End of line — single/double-quoted strings don't survive a raw newline
    // in JS/TS/Python/most languages Caspian targets, so close them
    // defensively. Template literals and block comments do survive; persist.
    if (state === 'singleStr' || state === 'doubleStr') {
      // A trailing `\` would legitimately continue the string; worth
      // emulating only for literal `\` at the true end-of-line.
      if (!line.endsWith('\\')) { state = 'code'; }
    }

    // Record the state that the NEXT line starts in.
    if (lineIdx + 1 < lines.length) {
      states[lineIdx + 1] = {
        startsInsideQuotedString: state === 'singleStr' || state === 'doubleStr',
        startsInsideTemplateLiteral: state === 'templateStr',
        startsInsideBlockComment: state === 'blockComment',
        templateExprDepth: exprStack.length,
      };
    }
  }

  return states;
}

/**
 * Multi-line-aware replacement for the line-scoped `isInsideComment` that
 * was previously duplicated in `analyzer.ts` and `cli/scan.ts`.
 *
 * Returns true when `column` in `line` is part of a comment — either a
 * block comment inherited from an earlier line, or one opened on this
 * line.
 */
export function isInsideComment(line: string, column: number, lineState: LineState = CLEAN_STATE): boolean {
  // If the line starts inside a block comment, we're inside until a `*/`
  // appears on this line; if it does, we're "inside" only up through that
  // close.
  if (lineState.startsInsideBlockComment) {
    const closeIdx = line.indexOf('*/');
    if (closeIdx === -1) { return true; }
    if (column < closeIdx + 2) { return true; }
    // After the close we fall through to per-line checks.
  }

  // Line-scoped single-line comment `// …`
  const slashIdx = line.indexOf('//');
  if (slashIdx !== -1 && column > slashIdx) {
    const before = line.substring(0, slashIdx);
    const s = (before.match(/'/g) || []).length;
    const d = (before.match(/"/g) || []).length;
    const b = (before.match(/`/g) || []).length;
    if (s % 2 === 0 && d % 2 === 0 && b % 2 === 0) { return true; }
  }

  // Line-scoped `/* … */` blocks that both open AND close within this line.
  const blockStart = /\/\*/g;
  let m: RegExpExecArray | null;
  while ((m = blockStart.exec(line)) !== null) {
    const start = m.index;
    const endIdx = line.indexOf('*/', start + 2);
    const end = endIdx !== -1 ? endIdx + 2 : line.length;
    if (column >= start && column < end) { return true; }
  }
  return false;
}

/**
 * Multi-line-aware replacement for `isInsideStringContent`.
 *
 * The same per-line walker used before F11 — but seeded with the state we
 * inherited from the previous line (template-literal-open, quoted-string,
 * or `${}` expression depth). That way, a file like
 *
 *   const html = `...multi-line...
 *     password = "hunter2"    ← line 42, no backticks of its own
 *   `;
 *
 * correctly reports column 10 of line 42 as "inside string content" even
 * though the line itself has zero backticks.
 */
export function isInsideStringContent(line: string, column: number, lineState: LineState = CLEAN_STATE): boolean {
  let inSingle = false;
  let inDouble = false;
  let inTemplate = lineState.startsInsideTemplateLiteral;
  let templateDepth = lineState.templateExprDepth;
  // Rare case — handled conservatively. We don't know single vs double
  // from just the state flag, so assume single; the behavioural difference
  // is whether `"` on this line closes the string, and for a
  // contextAware filter "probably a string" is the right default.
  if (lineState.startsInsideQuotedString) { inSingle = true; }

  for (let i = 0; i < column; i++) {
    const ch = line[i];
    const prev = i > 0 ? line[i - 1] : '';
    if (prev === '\\') { continue; }
    if (!inDouble && !inTemplate && ch === "'") { inSingle = !inSingle; }
    else if (!inSingle && !inTemplate && ch === '"') { inDouble = !inDouble; }
    else if (!inSingle && !inDouble && ch === '`') { inTemplate = !inTemplate; }
    else if (inTemplate && ch === '$' && i + 1 < line.length && line[i + 1] === '{') { templateDepth++; }
    else if (inTemplate && templateDepth > 0 && ch === '}') { templateDepth--; }
  }
  if (inSingle || inDouble) { return true; }
  if (inTemplate && templateDepth === 0) { return true; }
  return false;
}

/**
 * Convenience: the CLEAN state, handy for callers that want to bypass
 * multi-line handling or operate on a single line in isolation.
 */
export function cleanLineState(): LineState {
  return CLEAN_STATE;
}

/**
 * Heuristic: at position `slashIdx` is the `/` the start of a JS regex
 * literal, or a division operator?
 *
 * Rule of thumb (matches what the V8 / Acorn parsers do): a `/` is a
 * regex if the previous non-whitespace token is a punctuator that cannot
 * be the end of an expression (`(`, `,`, `=`, `:`, `[`, `{`, `;`, `&`,
 * `|`, `!`, `?`, `+`, `-`, `*`, `<`, `>`, `~`, `^`, `%`), a keyword
 * (`return`, `typeof`, `instanceof`, `in`, `new`, `delete`, `void`,
 * `yield`, `await`, `throw`), or there is no previous token at all
 * (start-of-line). Otherwise it's division.
 */
function isRegexLiteralStart(line: string, slashIdx: number): boolean {
  let j = slashIdx - 1;
  while (j >= 0 && (line[j] === ' ' || line[j] === '\t')) { j--; }
  if (j < 0) { return true; }
  const ch = line[j];
  if ('(,=:[{;&|!?+-*<>~^%'.indexOf(ch) !== -1) { return true; }
  // Keyword check — read backwards while alphanumeric.
  if (/[a-z]/.test(ch)) {
    let k = j;
    while (k >= 0 && /[a-zA-Z0-9_]/.test(line[k])) { k--; }
    const word = line.substring(k + 1, j + 1);
    if (['return', 'typeof', 'instanceof', 'in', 'of', 'new', 'delete', 'void', 'yield', 'await', 'throw'].indexOf(word) !== -1) {
      return true;
    }
  }
  return false;
}

/**
 * Walk forward from `start` (immediately after the opening `/`) to the
 * matching close `/`. Honours `\` escapes and `[...]` character classes
 * (inside which `/` is literal). Returns the index of the close `/`, or
 * -1 if the regex is unterminated on this line.
 */
function findRegexClose(line: string, start: number): number {
  let inCharClass = false;
  for (let i = start; i < line.length; i++) {
    const ch = line[i];
    if (ch === '\\') { i++; continue; }
    if (ch === '[') { inCharClass = true; continue; }
    if (ch === ']') { inCharClass = false; continue; }
    if (ch === '/' && !inCharClass) { return i; }
  }
  return -1;
}

/** Skip past the trailing flag chars of a regex literal. Returns the last consumed index. */
function consumeRegexFlags(line: string, closeIdx: number): number {
  let i = closeIdx;
  while (i + 1 < line.length && /[gimuysd]/.test(line[i + 1])) { i++; }
  return i;
}

/**
 * Check if a match position falls inside JSX text content (between > and <).
 * Heuristic: a preceding `>` (end of an opening tag) with no subsequent `<`
 * before the column, and a `<` somewhere after the match (the closing tag).
 * Shared by the extension analyzer and the CLI scan engine.
 */
export function isInsideJSXText(line: string, column: number): boolean {
  const before = line.substring(0, column);

  const lastClose = before.lastIndexOf('>');
  if (lastClose === -1) { return false; }

  const afterClose = before.substring(lastClose + 1);
  if (afterClose.includes('<')) { return false; }

  const after = line.substring(column);
  if (after.includes('<')) { return true; }

  return false;
}
