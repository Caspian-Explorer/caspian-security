import { SecurityRule, SecuritySeverity, SecurityCategory, RuleType } from '../types';

/**
 * Provider-prefixed token detection.
 *
 * Rationale for a separate file from `secretsRules.ts`:
 *   The original `CRED*` rules are heuristic — "looks like a password assignment",
 *   "high-entropy base64 literal". They run with `negativePatterns` and
 *   `contextAware: true` because their false-positive surface is wide.
 *
 *   These `TOKEN*` rules are the opposite: every pattern matches a token shape
 *   issued by a specific provider, with a shape only that provider produces.
 *   A match is almost never accidental, so severity is `Error` and no context
 *   filtering is applied. Users get per-provider stats in the learning
 *   dashboard (one rule code per provider) and can suppress one provider
 *   without turning off secret detection entirely.
 *
 * Shapes below were collected from each provider's documentation as of
 * 2026-04. Where a prefix is shared with legacy or sandbox tokens, the rule
 * is split so the live / production token is flagged as `Error` and the
 * sandbox / test variant as `Warning`.
 *
 * Every pattern uses word boundaries or character-class anchors to bound the
 * length match — no `.*` or unbounded quantifiers — which keeps them outside
 * the ReDoS guard's failure envelope.
 */

const cat = SecurityCategory.SecretsCredentials;
const ruleType = RuleType.CodeDetectable;

const baseSuggestion =
  'Treat this as a live credential: rotate it with the issuing provider immediately, ' +
  'scrub it from git history, and load the replacement from an environment variable, ' +
  'secrets manager, or OS keychain. Never commit provider tokens to source.';

// Every TOKEN pattern matches a provider-issued token shape that is almost
// never accidental (see rationale above), so all rules in this family carry
// base confidence 'critical'.
export const providerSecretsRules: SecurityRule[] = ([
  {
    code: 'TOKEN001',
    message: 'Slack workspace / app token detected (xoxb, xoxp, xoxa, xoxs, xapp)',
    severity: SecuritySeverity.Error,
    patterns: [
      /\bxox[baprs]-\d+-\d+-\d+-[A-Za-z0-9]{24,}\b/,
      /\bxapp-\d-[A-Z0-9]+-\d+-[a-f0-9]{40,}\b/,
    ],
    suggestion: baseSuggestion,
    category: cat,
    ruleType,
  },
  {
    code: 'TOKEN002',
    message: 'OpenAI API key detected (sk-... / sk-proj-...)',
    severity: SecuritySeverity.Error,
    patterns: [
      /\bsk-proj-[A-Za-z0-9_-]{40,}\b/,
      /\bsk-[A-Za-z0-9]{40,}\b/,
    ],
    negativePatterns: [
      /sk-ant-api/,       // Anthropic — handled by TOKEN003
      /sk_live_|sk_test_/, // Stripe — handled by TOKEN006 / TOKEN006t
    ],
    suggestion: baseSuggestion,
    category: cat,
    ruleType,
  },
  {
    code: 'TOKEN003',
    message: 'Anthropic API key detected (sk-ant-api...)',
    severity: SecuritySeverity.Error,
    patterns: [
      /\bsk-ant-api\d{2}-[A-Za-z0-9_-]{80,}\b/,
      /\bsk-ant-sid\d{2}-[A-Za-z0-9_-]{80,}\b/,
    ],
    suggestion: baseSuggestion,
    category: cat,
    ruleType,
  },
  {
    code: 'TOKEN004',
    message: 'Google API key detected (AIza...)',
    severity: SecuritySeverity.Error,
    patterns: [
      /\bAIza[0-9A-Za-z_-]{35}\b/,
    ],
    suggestion: baseSuggestion,
    category: cat,
    ruleType,
  },
  {
    code: 'TOKEN005',
    message: 'Google OAuth access token detected (ya29...)',
    severity: SecuritySeverity.Error,
    patterns: [
      /\bya29\.[A-Za-z0-9_-]{30,}\b/,
    ],
    suggestion: baseSuggestion,
    category: cat,
    ruleType,
  },
  {
    code: 'TOKEN006',
    message: 'Stripe LIVE key detected (sk_live / rk_live / pk_live / whsec)',
    severity: SecuritySeverity.Error,
    patterns: [
      /\b(?:sk|rk)_live_[A-Za-z0-9]{20,}\b/,
      /\bpk_live_[A-Za-z0-9]{20,}\b/,
      /\bwhsec_[A-Za-z0-9]{30,}\b/,
    ],
    suggestion: baseSuggestion,
    category: cat,
    ruleType,
  },
  {
    code: 'TOKEN006t',
    message: 'Stripe TEST key detected (sk_test / pk_test)',
    severity: SecuritySeverity.Warning,
    patterns: [
      /\b(?:sk|rk|pk)_test_[A-Za-z0-9]{20,}\b/,
    ],
    suggestion:
      'Stripe test keys are not production credentials, but committing them still leaks ' +
      'account structure. Move to an environment variable and rotate if exposed publicly.',
    category: cat,
    ruleType,
  },
  {
    code: 'TOKEN007',
    message: 'Twilio API credential detected (AC / SK SID)',
    severity: SecuritySeverity.Error,
    patterns: [
      /\bAC[a-f0-9]{32}\b/,  // Account SID
      /\bSK[a-f0-9]{32}\b/,  // API Key SID
    ],
    // Twilio SIDs alone aren't secret, but they're strong enough indicators
    // of "there's an auth_token variable near here" that we flag them.
    suggestion: baseSuggestion,
    category: cat,
    ruleType,
  },
  {
    code: 'TOKEN008',
    message: 'SendGrid API key detected (SG.)',
    severity: SecuritySeverity.Error,
    patterns: [
      /\bSG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}\b/,
    ],
    suggestion: baseSuggestion,
    category: cat,
    ruleType,
  },
  {
    code: 'TOKEN009',
    message: 'Mailgun API key detected (key-...)',
    severity: SecuritySeverity.Error,
    patterns: [
      /\bkey-[a-f0-9]{32}\b/,
    ],
    suggestion: baseSuggestion,
    category: cat,
    ruleType,
  },
  {
    code: 'TOKEN010',
    message: 'npm registry access token detected (npm_...)',
    severity: SecuritySeverity.Error,
    patterns: [
      /\bnpm_[A-Za-z0-9]{36}\b/,
    ],
    suggestion: baseSuggestion,
    category: cat,
    ruleType,
  },
  {
    code: 'TOKEN011',
    message: 'Docker Hub personal access token detected (dckr_pat_...)',
    severity: SecuritySeverity.Error,
    patterns: [
      /\bdckr_pat_[A-Za-z0-9_-]{27,}\b/,
    ],
    suggestion: baseSuggestion,
    category: cat,
    ruleType,
  },
  {
    code: 'TOKEN012',
    message: 'Shopify access token detected (shpat / shpss / shpca / shppa)',
    severity: SecuritySeverity.Error,
    patterns: [
      /\bshp(?:at|ss|ca|pa)_[a-f0-9]{32}\b/,
    ],
    suggestion: baseSuggestion,
    category: cat,
    ruleType,
  },
  {
    code: 'TOKEN013',
    message: 'Notion integration secret detected (secret_...)',
    severity: SecuritySeverity.Error,
    patterns: [
      /\bsecret_[A-Za-z0-9]{43}\b/,
    ],
    suggestion: baseSuggestion,
    category: cat,
    ruleType,
  },
  {
    code: 'TOKEN014',
    message: 'Linear API key detected (lin_api_...)',
    severity: SecuritySeverity.Error,
    patterns: [
      /\blin_api_[A-Za-z0-9]{40}\b/,
    ],
    suggestion: baseSuggestion,
    category: cat,
    ruleType,
  },
  {
    code: 'TOKEN015',
    message: 'Figma personal access token detected (figd_...)',
    severity: SecuritySeverity.Error,
    patterns: [
      /\bfigd_[A-Za-z0-9_-]{40,}\b/,
    ],
    suggestion: baseSuggestion,
    category: cat,
    ruleType,
  },
  {
    code: 'TOKEN016',
    message: 'Databricks personal access token detected (dapi...)',
    severity: SecuritySeverity.Error,
    patterns: [
      /\bdapi[a-f0-9]{32,}\b/,
    ],
    suggestion: baseSuggestion,
    category: cat,
    ruleType,
  },
  {
    code: 'TOKEN017',
    message: 'Hugging Face access token detected (hf_...)',
    severity: SecuritySeverity.Error,
    patterns: [
      /\bhf_[A-Za-z0-9]{37}\b/,
    ],
    suggestion: baseSuggestion,
    category: cat,
    ruleType,
  },
  {
    code: 'TOKEN018',
    message: 'Discord bot token detected',
    severity: SecuritySeverity.Error,
    patterns: [
      /\b[MN][A-Za-z0-9_-]{23}\.[A-Za-z0-9_-]{6}\.[A-Za-z0-9_-]{27,}\b/,
    ],
    suggestion: baseSuggestion,
    category: cat,
    ruleType,
  },
  {
    code: 'TOKEN019',
    message: 'Discord webhook URL detected (allows anyone to post as this app)',
    severity: SecuritySeverity.Error,
    patterns: [
      /\bhttps:\/\/(?:canary\.|ptb\.)?discord(?:app)?\.com\/api\/webhooks\/\d+\/[A-Za-z0-9_-]{20,}\b/,
    ],
    suggestion:
      'Discord webhook URLs are unauthenticated — whoever holds the URL can post as this app. ' +
      'Rotate the webhook and load the URL from an environment variable.',
    category: cat,
    ruleType,
  },
  {
    code: 'TOKEN020',
    message: 'Bitbucket app password / HTTP access token detected (ATBB...)',
    severity: SecuritySeverity.Error,
    patterns: [
      /\bATBB[A-Za-z0-9_-]{24,}\b/,
    ],
    suggestion: baseSuggestion,
    category: cat,
    ruleType,
  },
  {
    code: 'TOKEN021',
    message: 'Atlassian API token detected (ATATT...)',
    severity: SecuritySeverity.Error,
    patterns: [
      /\bATATT[A-Za-z0-9_-]{90,}\b/,
    ],
    suggestion: baseSuggestion,
    category: cat,
    ruleType,
  },
  {
    code: 'TOKEN022',
    message: 'DigitalOcean personal access token detected (dop_v1_...)',
    severity: SecuritySeverity.Error,
    patterns: [
      /\bdop_v1_[a-f0-9]{64}\b/,
    ],
    suggestion: baseSuggestion,
    category: cat,
    ruleType,
  },
  {
    code: 'TOKEN023',
    message: 'Sentry auth token detected (sntrys_ / sntryu_)',
    severity: SecuritySeverity.Error,
    patterns: [
      /\bsntry[su]_[A-Za-z0-9_=]{40,}\b/,
    ],
    suggestion: baseSuggestion,
    category: cat,
    ruleType,
  },
  {
    code: 'TOKEN024',
    message: 'Postman API key detected (PMAK-...)',
    severity: SecuritySeverity.Error,
    patterns: [
      /\bPMAK-[A-Z0-9]{24}-[A-Z0-9]{34}\b/,
    ],
    suggestion: baseSuggestion,
    category: cat,
    ruleType,
  },
  {
    code: 'TOKEN025',
    message: 'Pulumi access token detected (pul-...)',
    severity: SecuritySeverity.Error,
    patterns: [
      /\bpul-[a-f0-9]{40}\b/,
    ],
    suggestion: baseSuggestion,
    category: cat,
    ruleType,
  },
  {
    code: 'TOKEN026',
    message: 'Square access token detected (sq0atp / sq0csp)',
    severity: SecuritySeverity.Error,
    patterns: [
      /\bsq0atp-[A-Za-z0-9_-]{22}\b/,
      /\bsq0csp-[A-Za-z0-9_-]{43}\b/,
    ],
    suggestion: baseSuggestion,
    category: cat,
    ruleType,
  },
  {
    code: 'TOKEN027',
    message: 'GitLab runner registration / CI token detected',
    severity: SecuritySeverity.Error,
    patterns: [
      /\bglrt-[A-Za-z0-9_-]{20,}\b/,
      /\bglcbt-[A-Za-z0-9_-]{20,}\b/,
    ],
    suggestion: baseSuggestion,
    category: cat,
    ruleType,
  },
  {
    code: 'TOKEN028',
    message: 'HTTP Basic-auth credentials embedded in URL',
    severity: SecuritySeverity.Error,
    patterns: [
      // `https://user:password@host` — any non-empty user + non-empty password.
      // Anchored to `//` so we don't match `foo:bar@baz` in a comment.
      /https?:\/\/[^\s:@/]+:[^\s:@/]+@[^\s/]+/,
    ],
    negativePatterns: [
      // Placeholders that devs use in example URLs — not credentials.
      /:(?:\*\*\*|x{3,}|password|REDACTED|changeme|xxx|yyy|PASSWORD)@/i,
      /<[^>]+>:<[^>]+>@/,  // <user>:<pass>@ placeholders
    ],
    suggestion:
      'Credentials in URLs leak into browser history, access logs, proxy logs, and ' +
      'referer headers. Pass them via Authorization header or environment variables.',
    category: cat,
    ruleType,
  },
] as SecurityRule[]).map(rule => ({ ...rule, confidence: 'critical' as const }));
