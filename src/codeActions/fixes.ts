/**
 * Mechanical auto-fix registry.
 *
 * Each entry is a pure function that takes a minimal document view and
 * the issue's line/column, and returns a {@link FixResult} describing
 * the edit to apply — or `null` if no mechanical fix is safe for the
 * specific matched text.
 *
 * Kept free of the `vscode` import so it's unit-testable without a fake
 * VS Code environment. The vscode-facing layer
 * (`src/codeActionProvider.ts`) converts the FixResult into a
 * `vscode.WorkspaceEdit`.
 *
 * Conservative by design: if the matched line looks even slightly
 * outside the expected shape, return null and let the user fix by
 * hand (or via AI). We'd rather have no auto-fix than a wrong one.
 */

/** Minimal document interface — matches what we need from `vscode.TextDocument`. */
export interface DocumentView {
  lineAt(line: number): { text: string };
  lineCount: number;
}

export interface FixEdit {
  startLine: number;
  startCol: number;
  endLine: number;
  endCol: number;
  newText: string;
}

export interface FixResult {
  edits: FixEdit[];
  title: string;
  /** Whether the fix should be marked as `isPreferred` in VS Code (appears as the default action). */
  preferred?: boolean;
}

export type FixFn = (doc: DocumentView, issueLine: number, issueColumn: number) => FixResult | null;

// --- Helpers --------------------------------------------------------------

/** Replace the FIRST occurrence of `needle` on `line` with `replacement`. Returns null if not present. */
function replaceOnLine(
  doc: DocumentView,
  lineNum: number,
  needle: RegExp | string,
  replacement: string,
  title: string,
): FixResult | null {
  if (lineNum < 0 || lineNum >= doc.lineCount) { return null; }
  const line = doc.lineAt(lineNum).text;
  if (needle instanceof RegExp) {
    const m = needle.exec(line);
    if (!m) { return null; }
    return {
      edits: [{
        startLine: lineNum, startCol: m.index,
        endLine: lineNum, endCol: m.index + m[0].length,
        newText: replacement,
      }],
      title,
      preferred: true,
    };
  }
  const idx = line.indexOf(needle);
  if (idx < 0) { return null; }
  return {
    edits: [{
      startLine: lineNum, startCol: idx,
      endLine: lineNum, endCol: idx + needle.length,
      newText: replacement,
    }],
    title,
    preferred: true,
  };
}

/** Remove an entire line (including its trailing newline). Used when the dangerous key is best deleted outright. */
function removeLine(doc: DocumentView, lineNum: number, title: string): FixResult | null {
  if (lineNum < 0 || lineNum >= doc.lineCount) { return null; }
  // End-col on the next line, start col 0, so the newline goes too.
  if (lineNum + 1 >= doc.lineCount) {
    // Last line — take from start-col 0 to end of that line.
    return {
      edits: [{
        startLine: lineNum, startCol: 0,
        endLine: lineNum, endCol: doc.lineAt(lineNum).text.length,
        newText: '',
      }],
      title,
      preferred: true,
    };
  }
  return {
    edits: [{
      startLine: lineNum, startCol: 0,
      endLine: lineNum + 1, endCol: 0,
      newText: '',
    }],
    title,
    preferred: true,
  };
}

// --- Per-rule fixes -------------------------------------------------------

const fixKubernetesPrivileged: FixFn = (doc, line) =>
  replaceOnLine(doc, line, /privileged:\s*true/, 'privileged: false', 'Set privileged: false');

const fixKubernetesHostNetwork: FixFn = (doc, line) =>
  removeLine(doc, line, 'Remove hostNetwork: true');

const fixKubernetesHostPidIpc: FixFn = (doc, line) => {
  const text = doc.lineAt(line).text;
  if (/hostPID:\s*true/.test(text)) { return removeLine(doc, line, 'Remove hostPID: true'); }
  if (/hostIPC:\s*true/.test(text)) { return removeLine(doc, line, 'Remove hostIPC: true'); }
  return null;
};

const fixKubernetesRootOrPrivEsc: FixFn = (doc, line) => {
  const text = doc.lineAt(line).text;
  if (/runAsUser:\s*0\b/.test(text)) {
    return replaceOnLine(doc, line, /runAsUser:\s*0\b/, 'runAsUser: 1000', 'Set runAsUser: 1000');
  }
  if (/allowPrivilegeEscalation:\s*true/.test(text)) {
    return replaceOnLine(
      doc, line,
      /allowPrivilegeEscalation:\s*true/,
      'allowPrivilegeEscalation: false',
      'Set allowPrivilegeEscalation: false',
    );
  }
  return null;
};

const fixTerraformPublicAccess: FixFn = (doc, line) =>
  replaceOnLine(
    doc, line,
    /publicly_accessible\s*=\s*true/,
    'publicly_accessible = false',
    'Set publicly_accessible = false',
  );

const fixTerraformPublicAcl: FixFn = (doc, line) =>
  replaceOnLine(
    doc, line,
    /acl\s*=\s*"(?:public-read|public-read-write|authenticated-read)"/,
    'acl = "private"',
    'Set S3 ACL to private',
  );

const fixJwtNoAlgorithms: FixFn = (doc, line) => {
  const text = doc.lineAt(line).text;
  // `jwt.verify(token, key)` or `jwt.verify(token, key,)` — add an options arg with algorithms.
  // Careful: don't touch calls that already have options.
  if (/algorithms?\s*:\s*\[/.test(text)) { return null; }
  const m = /\bjwt\.verify\s*\(\s*[\w.]+\s*,\s*[\w.]+(?=\s*\))/.exec(text);
  if (!m) { return null; }
  // Insert `, { algorithms: ['RS256'] }` right before the `)`.
  const insertAt = m.index + m[0].length;
  return {
    edits: [{
      startLine: line, startCol: insertAt,
      endLine: line, endCol: insertAt,
      newText: ", { algorithms: ['RS256'] }",
    }],
    title: "Add { algorithms: ['RS256'] } to jwt.verify",
    preferred: true,
  };
};

const fixJwtIgnoreExpiration: FixFn = (doc, line) => {
  const text = doc.lineAt(line).text;
  if (/ignoreExpiration\s*:\s*true/.test(text)) {
    // Remove ` ignoreExpiration: true,` or `ignoreExpiration: true ` forms — match the
    // key plus any leading/trailing comma & whitespace.
    return replaceOnLine(
      doc, line,
      /\s*,?\s*ignoreExpiration\s*:\s*true\s*,?/,
      '',
      'Remove ignoreExpiration: true',
    );
  }
  if (/verify_exp\s*=\s*False/.test(text)) {
    return replaceOnLine(doc, line, /verify_exp\s*=\s*False/, 'verify_exp=True', 'Set verify_exp=True');
  }
  return null;
};

const fixYamlUnsafeLoad: FixFn = (doc, line) => {
  const text = doc.lineAt(line).text;
  if (/\byaml\.unsafe_load\b/.test(text)) {
    return replaceOnLine(doc, line, /yaml\.unsafe_load/, 'yaml.safe_load', 'Replace yaml.unsafe_load → yaml.safe_load');
  }
  return null;
};

const fixYamlLoad: FixFn = (doc, line) => {
  const text = doc.lineAt(line).text;
  // Only replace `yaml.load(` that does NOT already have Loader=SafeLoader.
  if (/Loader\s*=\s*(?:yaml\.)?(?:SafeLoader|BaseLoader)/.test(text)) { return null; }
  if (!/\byaml\.load\s*\(/.test(text)) { return null; }
  return replaceOnLine(doc, line, /yaml\.load\s*\(/, 'yaml.safe_load(', 'Replace yaml.load( → yaml.safe_load(');
};

const fixRejectUnauthorized: FixFn = (doc, line) =>
  replaceOnLine(
    doc, line,
    /rejectUnauthorized\s*:\s*false/,
    'rejectUnauthorized: true',
    'Set rejectUnauthorized: true',
  );

const fixDockerfileHealthcheckNone: FixFn = (doc, line) => {
  const text = doc.lineAt(line).text;
  if (!/^\s*HEALTHCHECK\s+NONE\b/i.test(text)) { return null; }
  // Comment the line out — so it's recoverable, unlike deletion.
  const indent = text.match(/^\s*/)?.[0] || '';
  return {
    edits: [{
      startLine: line, startCol: 0,
      endLine: line, endCol: text.length,
      newText: `${indent}# ${text.slice(indent.length)}`,
    }],
    title: 'Comment out HEALTHCHECK NONE',
    preferred: true,
  };
};

const fixCorsWildcard: FixFn = (doc, line) => {
  const text = doc.lineAt(line).text;
  // Match `origin: '*'` / `origin: "*"` / `'Access-Control-Allow-Origin': '*'` style literals.
  if (/origin\s*:\s*['"]\*['"]/.test(text)) {
    return replaceOnLine(
      doc, line,
      /origin\s*:\s*['"]\*['"]/,
      "origin: false",
      'Replace origin: "*" with origin: false (reject by default; restore with an allow-list)',
    );
  }
  if (/['"]Access-Control-Allow-Origin['"]\s*:\s*['"]\*['"]/.test(text)) {
    return null; // Header literal case — replacement depends on context, skip auto-fix.
  }
  return null;
};

const fixWeakHash: FixFn = (doc, line) => {
  const text = doc.lineAt(line).text;
  // Node: createHash('md5') / createHash("sha1") → sha256.
  const nodeMatch = /createHash\s*\(\s*['"](md5|sha1)['"]/.exec(text);
  if (nodeMatch) {
    return replaceOnLine(
      doc, line,
      new RegExp(`(?<=createHash\\s*\\(\\s*['"])${nodeMatch[1]}(?=['"])`),
      'sha256',
      `Replace ${nodeMatch[1]} with sha256`,
    );
  }
  // Python: hashlib.md5( / hashlib.sha1( → hashlib.sha256(.
  const pyMatch = /hashlib\.(md5|sha1)\s*\(/.exec(text);
  if (pyMatch) {
    return replaceOnLine(
      doc, line,
      new RegExp(`hashlib\\.${pyMatch[1]}\\s*\\(`),
      'hashlib.sha256(',
      `Replace hashlib.${pyMatch[1]} with hashlib.sha256`,
    );
  }
  return null;
};

const fixHttpUrl: FixFn = (doc, line) => {
  const text = doc.lineAt(line).text;
  // Mirror ENC003's own guards: never touch localhost / loopback URLs.
  const m = /['"]http:\/\/(?!localhost|127\.0\.0\.1|0\.0\.0\.0)/.exec(text);
  if (!m) { return null; }
  return {
    edits: [{
      startLine: line, startCol: m.index + 1,
      endLine: line, endCol: m.index + 1 + 'http://'.length,
      newText: 'https://',
    }],
    title: 'Change http:// to https://',
    preferred: true,
  };
};

const fixTerraformPublicAccessBlock: FixFn = (doc, line) => {
  const text = doc.lineAt(line).text;
  const m = /\b(block_public_acls|block_public_policy|ignore_public_acls|restrict_public_buckets)\s*=\s*false/.exec(text);
  if (m) {
    return replaceOnLine(
      doc, line,
      new RegExp(`\\b${m[1]}\\s*=\\s*false`),
      `${m[1]} = true`,
      `Set ${m[1]} = true`,
    );
  }
  return null;
};

const fixDockerfileAddToCopy: FixFn = (doc, line) => {
  const text = doc.lineAt(line).text;
  // Only the local-path form (the DOCKER005 pattern already excludes URLs
  // and flag forms, but re-check here to stay safe when invoked directly).
  if (!/^\s*ADD\s+(?!https?:\/\/|--)/i.test(text)) { return null; }
  return replaceOnLine(doc, line, /ADD\b/i, 'COPY', 'Replace ADD with COPY');
};

const fixDockerfilePackageInstall: FixFn = (doc, line) => {
  const text = doc.lineAt(line).text;
  const apt = /^(\s*RUN\s+apt-get\s+install)\b(?!.*--no-install-recommends)/i.exec(text);
  if (apt) {
    return replaceOnLine(
      doc, line,
      /apt-get\s+install\b/i,
      'apt-get install --no-install-recommends',
      'Add --no-install-recommends',
    );
  }
  const apk = /^(\s*RUN\s+apk\s+add)\b(?!.*--no-cache)/i.exec(text);
  if (apk) {
    return replaceOnLine(doc, line, /apk\s+add\b/i, 'apk add --no-cache', 'Add --no-cache');
  }
  return null;
};

// --- Registry -------------------------------------------------------------

export const FIX_REGISTRY: Record<string, FixFn> = {
  // Kubernetes
  K8S001: fixKubernetesPrivileged,
  K8S002: fixKubernetesHostNetwork,
  K8S003: fixKubernetesHostPidIpc,
  K8S004: fixKubernetesRootOrPrivEsc,

  // Terraform
  TF002: (doc, line, col) =>
    fixTerraformPublicAcl(doc, line, col) ?? fixTerraformPublicAccessBlock(doc, line, col),
  TF004: fixTerraformPublicAccess,

  // JWT
  JWT002: fixJwtNoAlgorithms,
  JWT006: fixJwtIgnoreExpiration,

  // Python deserialization
  DESER003: fixYamlUnsafeLoad,
  DESER004: fixYamlLoad,

  // Encryption
  ENC001: fixWeakHash,
  ENC003: fixHttpUrl,
  ENC004: fixRejectUnauthorized,

  // Dockerfile
  DOCKER005: fixDockerfileAddToCopy,
  DOCKER006: fixDockerfilePackageInstall,
  DOCKER008: fixDockerfileHealthcheckNone,

  // CORS
  CORS001: fixCorsWildcard,
};

/**
 * Convenience: look up a fix for a rule code, return null if no handler
 * registered OR the specific matched text doesn't fit the handler's shape.
 */
export function resolveFix(
  ruleCode: string,
  doc: DocumentView,
  issueLine: number,
  issueColumn: number,
): FixResult | null {
  const fix = FIX_REGISTRY[ruleCode];
  if (!fix) { return null; }
  try {
    return fix(doc, issueLine, issueColumn);
  } catch {
    return null;
  }
}
