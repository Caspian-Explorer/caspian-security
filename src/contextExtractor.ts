import * as vscode from 'vscode';

export interface FunctionContext {
  functionName: string;
  functionBody: string;
  startLine: number;
  endLine: number;
}

export interface VariableDefinition {
  name: string;
  definitionLine: number;
  definitionText: string;
}

export interface SmartContext {
  functionContext?: FunctionContext;
  variableDefinitions: VariableDefinition[];
}

const FUNCTION_SYMBOL_KINDS = new Set([
  vscode.SymbolKind.Function,
  vscode.SymbolKind.Method,
  vscode.SymbolKind.Constructor,
]);

/**
 * Extract the enclosing function scope and relevant variable definitions
 * for a given issue line. Falls back gracefully when no symbol provider
 * is available.
 */
export async function extractSmartContext(
  uri: vscode.Uri,
  issueLine: number,
  issueLineText: string
): Promise<SmartContext> {
  const result: SmartContext = { variableDefinitions: [] };

  try {
    const symbols = await vscode.commands.executeCommand<vscode.DocumentSymbol[]>(
      'vscode.executeDocumentSymbolProvider',
      uri
    );

    if (!symbols || symbols.length === 0) {
      return result;
    }

    const enclosingFunction = findEnclosingFunction(symbols, issueLine);
    if (!enclosingFunction) {
      return result;
    }

    const document = await vscode.workspace.openTextDocument(uri);
    const startLine = enclosingFunction.range.start.line;
    const endLine = enclosingFunction.range.end.line;
    const functionLines: string[] = [];
    for (let i = startLine; i <= endLine; i++) {
      functionLines.push(document.lineAt(i).text);
    }

    result.functionContext = {
      functionName: enclosingFunction.name,
      functionBody: functionLines.join('\n'),
      startLine,
      endLine,
    };

    // Extract identifiers from the issue line and find their definitions
    const identifiers = extractIdentifiers(issueLineText);
    result.variableDefinitions = findVariableDefinitions(
      document, identifiers, issueLine, startLine, endLine
    );
  } catch {
    // Symbol provider not available or failed — return empty context
  }

  return result;
}

/**
 * Recursively find the smallest function/method/constructor symbol
 * that contains the given line.
 */
function findEnclosingFunction(
  symbols: vscode.DocumentSymbol[],
  line: number
): vscode.DocumentSymbol | undefined {
  let best: vscode.DocumentSymbol | undefined;

  for (const symbol of symbols) {
    if (!symbol.range.contains(new vscode.Position(line, 0))) {
      continue;
    }

    if (FUNCTION_SYMBOL_KINDS.has(symbol.kind)) {
      // Found a function containing our line — check children for a tighter match
      const childMatch = findEnclosingFunction(symbol.children, line);
      best = childMatch || symbol;
    } else if (symbol.children.length > 0) {
      // Not a function but may contain one (e.g., class, module)
      const childMatch = findEnclosingFunction(symbol.children, line);
      if (childMatch) {
        best = childMatch;
      }
    }
  }

  return best;
}

/**
 * Extract likely variable/function identifiers from a line of code.
 * Filters out common keywords and very short names.
 */
function extractIdentifiers(lineText: string): string[] {
  const JS_KEYWORDS = new Set([
    'const', 'let', 'var', 'function', 'return', 'if', 'else', 'for', 'while',
    'do', 'switch', 'case', 'break', 'continue', 'new', 'this', 'class',
    'import', 'export', 'from', 'default', 'async', 'await', 'try', 'catch',
    'throw', 'typeof', 'instanceof', 'void', 'delete', 'in', 'of', 'true',
    'false', 'null', 'undefined', 'yield', 'super', 'extends', 'implements',
    'interface', 'type', 'enum', 'public', 'private', 'protected', 'static',
    'readonly', 'abstract', 'as', 'is', 'keyof', 'never', 'unknown', 'any',
    'string', 'number', 'boolean', 'object', 'symbol', 'bigint',
  ]);

  const matches = lineText.match(/\b([a-zA-Z_$][\w$]*)\b/g);
  if (!matches) { return []; }

  const seen = new Set<string>();
  return matches.filter(id => {
    if (id.length < 2 || JS_KEYWORDS.has(id) || seen.has(id)) { return false; }
    seen.add(id);
    return true;
  });
}

const VAR_DEF_PATTERN = /(?:const|let|var)\s+(\w+)/;
const PARAM_PATTERN = /(?:function\s+\w+|=>)\s*\(/;

/**
 * Search backwards from the issue line within the function scope
 * to find where the given identifiers are defined.
 */
function findVariableDefinitions(
  document: vscode.TextDocument,
  identifiers: string[],
  issueLine: number,
  scopeStart: number,
  scopeEnd: number
): VariableDefinition[] {
  if (identifiers.length === 0) { return []; }

  const definitions: VariableDefinition[] = [];
  const found = new Set<string>();

  // Also check function parameters on the function declaration line
  const declLine = document.lineAt(scopeStart).text;
  const paramNames = extractParamNames(declLine);

  for (const id of identifiers) {
    if (paramNames.includes(id)) {
      definitions.push({
        name: id,
        definitionLine: scopeStart,
        definitionText: declLine.trim(),
      });
      found.add(id);
    }
  }

  // Search backwards from issue line to scope start for variable declarations
  for (let i = issueLine - 1; i >= scopeStart; i--) {
    if (found.size === identifiers.length) { break; }

    const lineText = document.lineAt(i).text;
    for (const id of identifiers) {
      if (found.has(id)) { continue; }

      // Match: const/let/var identifier, or identifier = (assignment)
      const declarationPattern = new RegExp(
        `(?:const|let|var)\\s+${escapeRegex(id)}\\b|\\b${escapeRegex(id)}\\s*=`
      );
      if (declarationPattern.test(lineText)) {
        definitions.push({
          name: id,
          definitionLine: i,
          definitionText: lineText.trim(),
        });
        found.add(id);
      }
    }
  }

  // Also search forward (variable may be defined after usage in some patterns)
  for (let i = issueLine + 1; i <= scopeEnd; i++) {
    if (found.size === identifiers.length) { break; }

    const lineText = document.lineAt(i).text;
    for (const id of identifiers) {
      if (found.has(id)) { continue; }

      const declarationPattern = new RegExp(
        `(?:const|let|var)\\s+${escapeRegex(id)}\\b`
      );
      if (declarationPattern.test(lineText)) {
        definitions.push({
          name: id,
          definitionLine: i,
          definitionText: lineText.trim(),
        });
        found.add(id);
      }
    }
  }

  return definitions;
}

/**
 * Extract parameter names from a function declaration line.
 */
function extractParamNames(declarationLine: string): string[] {
  const parenStart = declarationLine.indexOf('(');
  if (parenStart === -1) { return []; }

  const parenEnd = declarationLine.indexOf(')', parenStart);
  if (parenEnd === -1) { return []; }

  const paramsStr = declarationLine.substring(parenStart + 1, parenEnd);
  const params = paramsStr.split(',').map(p => p.trim());

  const names: string[] = [];
  for (const param of params) {
    // Handle destructuring, default values, type annotations
    const match = param.match(/^(\w+)/);
    if (match) {
      names.push(match[1]);
    }
  }
  return names;
}

function escapeRegex(str: string): string {
  return str.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}
