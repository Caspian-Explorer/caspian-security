import { SecurityRule, SecuritySeverity, SecurityCategory, RuleType } from '../types';

/**
 * Dockerfile / Containerfile rules.
 *
 * Scope is intentionally narrow: the seven or eight things that show up
 * in every "Dockerfile security best practices" doc, plus a couple that
 * appear in real container breakouts. Each rule is tied to the specific
 * Dockerfile instruction (`FROM`, `RUN`, `USER`, `COPY`, `ADD`, `HEALTHCHECK`)
 * it applies to.
 *
 * File-gated: only fires on files the CLI / analyzer labels as
 * `dockerfile` (basename is `Dockerfile` / `Containerfile` / `dockerfile`
 * or extension `.dockerfile`).
 *
 * We don't try to parse Dockerfile semantics. Pattern-matching on
 * instruction keywords at the start of a line is enough — real
 * Dockerfiles rarely indent.
 */

const cat = SecurityCategory.InfrastructureDeployment;
const ruleType = RuleType.CodeDetectable;

/** Only fire these rules on Dockerfile-shaped files. */
const DOCKERFILE_ONLY = {
  include: [/(^|[\\/])(?:Dockerfile|Containerfile|dockerfile)(?:\..*)?$/i, /\.dockerfile$/i],
};

export const dockerfileRules: SecurityRule[] = [
  {
    code: 'DOCKER001',
    message: 'Base image uses the mutable `latest` tag or no tag — build is not reproducible',
    severity: SecuritySeverity.Warning,
    patterns: [
      /^\s*FROM\s+[\w./\-]+(?::latest)?\s*$/i,
      /^\s*FROM\s+[\w./\-]+:latest(?:\s+AS\s+\w+)?\s*$/i,
    ],
    negativePatterns: [
      /^\s*FROM\s+scratch\b/i,
    ],
    filePatterns: DOCKERFILE_ONLY,
    suggestion:
      'Pin the base image to a specific version tag (`node:20.10.0-alpine3.19`) or, better, a digest ' +
      '(`node@sha256:...`). `:latest` changes on every rebuild — you lose reproducibility and the ' +
      'supply-chain audit trail.',
    category: cat,
    ruleType,
  },
  {
    code: 'DOCKER002',
    message: 'Dockerfile does not set a non-root USER — container runs as root by default',
    severity: SecuritySeverity.Warning,
    // Fires on every FROM. If a USER instruction appears in the file, the
    // whole-file advisory is still useful because users often forget to
    // switch back to the app user after installing packages.
    patterns: [
      /^\s*FROM\s+/i,
    ],
    suppressIfNearby: [
      /^\s*USER\s+(?!root\b|0\b)/im,
    ],
    // USER legitimately appears near the END of a Dockerfile while FROM is
    // line 1 — the default ±3-line window meant this rule fired on every
    // Dockerfile that DID set a non-root user.
    suppressNearbyWindow: 300,
    filePatterns: DOCKERFILE_ONLY,
    suggestion:
      'Add `USER appuser` (or a numeric UID) before the final CMD/ENTRYPOINT. Running as root inside ' +
      'the container means any RCE has root in the namespace — plus host-level mitigations like user ' +
      'namespaces become the only line of defence.',
    category: cat,
    ruleType: RuleType.Informational, // advisory-style — fire once
  },
  {
    code: 'DOCKER003',
    message: 'Secret value embedded in a RUN / ENV / ARG instruction — will end up in a Docker layer',
    severity: SecuritySeverity.Error,
    patterns: [
      /^\s*ENV\s+\w*(?:PASSWORD|SECRET|TOKEN|API_?KEY|PRIVATE_?KEY)\s*[=\s]\s*(?!["']?\$\{?)\S{6,}/i,
      /^\s*ARG\s+\w*(?:PASSWORD|SECRET|TOKEN|API_?KEY)\s*=\s*(?!["']?\$\{?)\S{6,}/i,
      /^\s*RUN\s+echo\s+["']?\w*(?:PASSWORD|SECRET|TOKEN|API_?KEY)\b[^>]*>/i,
    ],
    filePatterns: DOCKERFILE_ONLY,
    suggestion:
      'Anything written to the image is permanently in that layer — even `RUN rm` later does NOT remove ' +
      'it. Use BuildKit `--mount=type=secret,id=mysecret` to pass secrets at build time, or inject them at ' +
      'runtime via `--env-file` / a secrets manager. Never `ENV API_KEY=abc` or `ARG PASSWORD=...`.',
    category: cat,
    ruleType,
  },
  {
    code: 'DOCKER004',
    message: 'ADD used to fetch a remote URL — prefer RUN curl + checksum verification',
    severity: SecuritySeverity.Warning,
    patterns: [
      /^\s*ADD\s+https?:\/\//i,
    ],
    filePatterns: DOCKERFILE_ONLY,
    suggestion:
      'ADD with a URL silently downloads and caches — no checksum, no TLS pinning, no failure if the ' +
      'host is hijacked mid-build. Use `RUN curl -fsSL <url> -o /tmp/file && echo "<sha256>  /tmp/file" | sha256sum -c`.',
    category: cat,
    ruleType,
  },
  {
    code: 'DOCKER005',
    message: 'ADD used with a local path — prefer COPY unless you need tar auto-extraction',
    severity: SecuritySeverity.Info,
    patterns: [
      /^\s*ADD\s+(?!https?:\/\/|--chown=|--checksum=)[^\s]+\s+[^\s]+\s*$/i,
    ],
    filePatterns: DOCKERFILE_ONLY,
    suggestion:
      'ADD also unpacks tarballs — surprising and a minor code-path-broadening risk. Use COPY unless you ' +
      'explicitly want the tar behaviour.',
    category: cat,
    ruleType,
  },
  {
    code: 'DOCKER006',
    message: 'RUN installs packages without --no-install-recommends / pinned versions',
    severity: SecuritySeverity.Info,
    patterns: [
      /^\s*RUN\s+apt-get\s+install\b(?!.*--no-install-recommends)/i,
      /^\s*RUN\s+apk\s+add\b(?!.*--no-cache)/i,
    ],
    filePatterns: DOCKERFILE_ONLY,
    suggestion:
      'Use `apt-get install --no-install-recommends -y <pkg>=<version>` (or apk `--no-cache` + pinned ' +
      'versions) to shrink the attack surface and make builds reproducible.',
    category: cat,
    ruleType,
  },
  {
    code: 'DOCKER007',
    message: 'Running `curl | sh` or `wget | sh` inside a RUN — unverified remote code execution at build time',
    severity: SecuritySeverity.Error,
    patterns: [
      /^\s*RUN\s+.*\b(?:curl|wget)[^|]+\|\s*(?:bash|sh|zsh|ksh)\b/i,
      /^\s*RUN\s+.*\b(?:curl|wget)[^|]+\|\s*su\s+-/i,
    ],
    filePatterns: DOCKERFILE_ONLY,
    suggestion:
      'Piping curl / wget into a shell runs whatever the remote server delivers right now, with no ' +
      'integrity check. Download, verify a known checksum, then execute: ' +
      '`curl -fsSL <url> -o install.sh && echo "<sha256>  install.sh" | sha256sum -c && sh install.sh`.',
    category: cat,
    ruleType,
  },
  {
    code: 'DOCKER008',
    message: 'HEALTHCHECK disabled (NONE) — orchestrator loses visibility into container state',
    severity: SecuritySeverity.Info,
    patterns: [
      /^\s*HEALTHCHECK\s+NONE\b/i,
    ],
    filePatterns: DOCKERFILE_ONLY,
    suggestion:
      'HEALTHCHECK NONE is sometimes intentional (e.g. the orchestrator has its own probes) but disables ' +
      'Docker-native liveness signals. Document why if you keep this.',
    category: cat,
    ruleType,
  },
];
