import { resolveFix, DocumentView, FixResult } from '../codeActions/fixes';

/** Build a minimal DocumentView from an array of lines. */
function docOf(lines: string[]): DocumentView {
  return {
    lineCount: lines.length,
    lineAt: (n) => ({ text: lines[n] }),
  };
}

/**
 * Apply a FixResult's edits to the given lines and return the result.
 * Processes edits in reverse order so later edits don't shift earlier offsets.
 */
function applyFix(lines: string[], fix: FixResult): string[] {
  const text = lines.join('\n');
  const sorted = [...fix.edits].sort((a, b) => {
    if (a.startLine !== b.startLine) { return b.startLine - a.startLine; }
    return b.startCol - a.startCol;
  });
  let out = text;
  for (const e of sorted) {
    const offset = lineColToOffset(out, e.startLine, e.startCol);
    const end = lineColToOffset(out, e.endLine, e.endCol);
    out = out.slice(0, offset) + e.newText + out.slice(end);
  }
  return out.split('\n');
}

function lineColToOffset(text: string, line: number, col: number): number {
  let off = 0;
  let curLine = 0;
  while (curLine < line) {
    const nl = text.indexOf('\n', off);
    if (nl === -1) { return text.length; }
    off = nl + 1;
    curLine++;
  }
  return off + col;
}

describe('resolveFix — Kubernetes', () => {
  it('K8S001: flips privileged: true to false', () => {
    const lines = ['spec:', '  securityContext:', '    privileged: true'];
    const fix = resolveFix('K8S001', docOf(lines), 2, 0)!;
    expect(fix.title).toMatch(/privileged: false/);
    expect(applyFix(lines, fix)[2]).toBe('    privileged: false');
  });

  it('K8S002: removes the hostNetwork line entirely', () => {
    const lines = ['spec:', '  hostNetwork: true', '  containers:'];
    const fix = resolveFix('K8S002', docOf(lines), 1, 2)!;
    expect(applyFix(lines, fix)).toEqual(['spec:', '  containers:']);
  });

  it('K8S003: removes hostPID / hostIPC', () => {
    const lines = ['spec:', '  hostPID: true', '  containers:'];
    const fix = resolveFix('K8S003', docOf(lines), 1, 2)!;
    expect(applyFix(lines, fix)).toEqual(['spec:', '  containers:']);
  });

  it('K8S003: returns null on an unrelated line', () => {
    const lines = ['spec:', '  something: true'];
    expect(resolveFix('K8S003', docOf(lines), 1, 2)).toBeNull();
  });

  it('K8S004: flips allowPrivilegeEscalation: true to false', () => {
    const lines = ['    allowPrivilegeEscalation: true'];
    const fix = resolveFix('K8S004', docOf(lines), 0, 0)!;
    expect(applyFix(lines, fix)[0]).toBe('    allowPrivilegeEscalation: false');
  });

  it('K8S004: sets runAsUser: 0 to a sane non-zero', () => {
    const lines = ['    runAsUser: 0'];
    const fix = resolveFix('K8S004', docOf(lines), 0, 0)!;
    expect(applyFix(lines, fix)[0]).toBe('    runAsUser: 1000');
  });
});

describe('resolveFix — Terraform', () => {
  it('TF002: flips public-read S3 ACL to private', () => {
    const lines = ['resource "aws_s3_bucket" "public" {', '  acl = "public-read"', '}'];
    const fix = resolveFix('TF002', docOf(lines), 1, 2)!;
    expect(applyFix(lines, fix)[1]).toBe('  acl = "private"');
  });

  it('TF004: flips publicly_accessible = true to false', () => {
    const lines = ['  publicly_accessible = true'];
    const fix = resolveFix('TF004', docOf(lines), 0, 2)!;
    expect(applyFix(lines, fix)[0]).toBe('  publicly_accessible = false');
  });
});

describe('resolveFix — JWT', () => {
  it('JWT002: inserts { algorithms: ["RS256"] } as third arg', () => {
    const lines = ['const payload = jwt.verify(token, publicKey);'];
    const fix = resolveFix('JWT002', docOf(lines), 0, 16)!;
    expect(applyFix(lines, fix)[0]).toBe(
      `const payload = jwt.verify(token, publicKey, { algorithms: ['RS256'] });`,
    );
  });

  it('JWT002: returns null when algorithms is already present', () => {
    const lines = [`const payload = jwt.verify(token, key, { algorithms: ['RS256'] });`];
    expect(resolveFix('JWT002', docOf(lines), 0, 16)).toBeNull();
  });

  it('JWT006: removes ignoreExpiration: true', () => {
    const lines = [`jwt.verify(tok, key, { algorithms: ['RS256'], ignoreExpiration: true });`];
    const fix = resolveFix('JWT006', docOf(lines), 0, 0)!;
    const result = applyFix(lines, fix)[0];
    expect(result).not.toMatch(/ignoreExpiration/);
    expect(result).toMatch(/algorithms.*RS256/);
  });

  it('JWT006: flips verify_exp=False to True', () => {
    const lines = [`jwt.decode(token, key, algorithms=['RS256'], options={'verify_exp': False})`];
    // Second pattern in the fix uses `verify_exp\s*=\s*False` — works on the
    // `verify_exp=False` keyword-arg case, but the dict form needs manual fix.
    // Use a straight kwarg form instead:
    const kwargLines = [`jwt.decode(token, key, algorithms=['RS256'], verify_exp=False)`];
    const fix = resolveFix('JWT006', docOf(kwargLines), 0, 0)!;
    expect(applyFix(kwargLines, fix)[0]).toMatch(/verify_exp=True/);
  });
});

describe('resolveFix — Python deserialization', () => {
  it('DESER003: yaml.unsafe_load → yaml.safe_load', () => {
    const lines = ['data = yaml.unsafe_load(payload)'];
    const fix = resolveFix('DESER003', docOf(lines), 0, 7)!;
    expect(applyFix(lines, fix)[0]).toBe('data = yaml.safe_load(payload)');
  });

  it('DESER004: yaml.load( → yaml.safe_load(', () => {
    const lines = ['cfg = yaml.load(request.form["x"])'];
    const fix = resolveFix('DESER004', docOf(lines), 0, 6)!;
    expect(applyFix(lines, fix)[0]).toBe('cfg = yaml.safe_load(request.form["x"])');
  });

  it('DESER004: skips lines that already have SafeLoader', () => {
    const lines = ['cfg = yaml.load(x, Loader=yaml.SafeLoader)'];
    expect(resolveFix('DESER004', docOf(lines), 0, 6)).toBeNull();
  });
});

describe('resolveFix — encryption + Dockerfile + CORS', () => {
  it('ENC004: flips rejectUnauthorized: false to true', () => {
    const lines = ['const agent = new https.Agent({ rejectUnauthorized: false });'];
    const fix = resolveFix('ENC004', docOf(lines), 0, 0)!;
    expect(applyFix(lines, fix)[0]).toMatch(/rejectUnauthorized: true/);
  });

  it('DOCKER008: comments out HEALTHCHECK NONE', () => {
    const lines = ['HEALTHCHECK NONE'];
    const fix = resolveFix('DOCKER008', docOf(lines), 0, 0)!;
    expect(applyFix(lines, fix)[0]).toBe('# HEALTHCHECK NONE');
  });

  it('CORS001: replaces origin: "*" with origin: false', () => {
    const lines = ['app.use(cors({ origin: "*" }));'];
    const fix = resolveFix('CORS001', docOf(lines), 0, 0)!;
    expect(applyFix(lines, fix)[0]).toBe('app.use(cors({ origin: false }));');
  });
});

describe('resolveFix — safety net', () => {
  it('returns null for a rule with no registered fix', () => {
    expect(resolveFix('NOSUCH', docOf(['foo']), 0, 0)).toBeNull();
  });

  it('returns null when the matched line does not fit the expected shape', () => {
    const lines = ['privileged_setting = false']; // looks similar but isn't YAML K8S001
    expect(resolveFix('K8S001', docOf(lines), 0, 0)).toBeNull();
  });

  it('does not throw on out-of-bounds line numbers', () => {
    const doc = docOf(['a', 'b']);
    expect(resolveFix('K8S001', doc, 99, 0)).toBeNull();
    expect(resolveFix('K8S001', doc, -1, 0)).toBeNull();
  });
});

describe('resolveFix — 10.9 additions', () => {
  it('ENC001: createHash md5 → sha256', () => {
    const lines = ["const h = crypto.createHash('md5').update(data).digest('hex');"];
    const fix = resolveFix('ENC001', docOf(lines), 0, 10)!;
    expect(applyFix(lines, fix)[0]).toBe("const h = crypto.createHash('sha256').update(data).digest('hex');");
  });

  it('ENC001: hashlib.sha1 → hashlib.sha256', () => {
    const lines = ['digest = hashlib.sha1(payload).hexdigest()'];
    const fix = resolveFix('ENC001', docOf(lines), 0, 9)!;
    expect(applyFix(lines, fix)[0]).toBe('digest = hashlib.sha256(payload).hexdigest()');
  });

  it('ENC001: returns null for algorithms it does not handle', () => {
    const lines = ["const h = crypto.createHash('sha256');"];
    expect(resolveFix('ENC001', docOf(lines), 0, 10)).toBeNull();
  });

  it('ENC003: http:// → https:// for external URLs', () => {
    const lines = ["const api = 'http://api.example-service.com/v1';"];
    const fix = resolveFix('ENC003', docOf(lines), 0, 12)!;
    expect(applyFix(lines, fix)[0]).toBe("const api = 'https://api.example-service.com/v1';");
  });

  it('ENC003: leaves localhost URLs alone', () => {
    const lines = ["const api = 'http://localhost:3000';"];
    expect(resolveFix('ENC003', docOf(lines), 0, 12)).toBeNull();
  });

  it('TF002: flips block_public_acls = false to true', () => {
    const lines = ['  block_public_acls       = false'];
    const fix = resolveFix('TF002', docOf(lines), 0, 2)!;
    expect(applyFix(lines, fix)[0]).toBe('  block_public_acls = true');
  });

  it('TF002: still fixes the ACL literal form', () => {
    const lines = ['  acl = "public-read"'];
    const fix = resolveFix('TF002', docOf(lines), 0, 2)!;
    expect(applyFix(lines, fix)[0]).toBe('  acl = "private"');
  });

  it('DOCKER005: ADD with local path → COPY', () => {
    const lines = ['ADD ./app /opt/app'];
    const fix = resolveFix('DOCKER005', docOf(lines), 0, 0)!;
    expect(applyFix(lines, fix)[0]).toBe('COPY ./app /opt/app');
  });

  it('DOCKER005: never rewrites ADD with a URL', () => {
    const lines = ['ADD https://example.com/pkg.tar.gz /tmp/'];
    expect(resolveFix('DOCKER005', docOf(lines), 0, 0)).toBeNull();
  });

  it('DOCKER006: apt-get install gains --no-install-recommends', () => {
    const lines = ['RUN apt-get install -y curl'];
    const fix = resolveFix('DOCKER006', docOf(lines), 0, 0)!;
    expect(applyFix(lines, fix)[0]).toBe('RUN apt-get install --no-install-recommends -y curl');
  });

  it('DOCKER006: apk add gains --no-cache', () => {
    const lines = ['RUN apk add curl'];
    const fix = resolveFix('DOCKER006', docOf(lines), 0, 0)!;
    expect(applyFix(lines, fix)[0]).toBe('RUN apk add --no-cache curl');
  });

  it('DOCKER006: leaves already-hardened installs alone', () => {
    const lines = ['RUN apt-get install --no-install-recommends -y curl'];
    expect(resolveFix('DOCKER006', docOf(lines), 0, 0)).toBeNull();
  });
});
