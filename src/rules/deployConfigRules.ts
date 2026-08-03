import { SecurityRule, SecuritySeverity, SecurityCategory, RuleType } from '../types';

/**
 * Deploy-configuration rules — the mistakes that most often expose
 * AI-built ("vibe-coded") apps in production:
 *
 *   - Firebase Firestore / Storage / Realtime Database rules left open
 *   - Supabase row-level security disabled or made a no-op
 *   - Server secrets exposed through client-bundled env-var prefixes
 *   - AI/LLM endpoints with no rate limit (unbounded model spend)
 *
 * These target platform config files (.rules, .sql migrations,
 * database.rules.json) and framework env conventions rather than
 * general-purpose code, which is what separates them from the API and
 * INFRA rule families.
 *
 * Messages follow the agent-loop writing rules: consequence first, plain
 * language, no CWE numbers — the reader may be a model deciding whether
 * to fix the file, or a human who has never heard of RLS.
 *
 * Confidence 'critical' is reserved for patterns that are unambiguous in
 * any context (a wide-open write rule is never a false positive); the
 * heuristic detections stay at Warning so they inform the loop without
 * blocking it.
 */

const ruleType = RuleType.CodeDetectable;

/** Firebase security-rules sources: firestore.rules, storage.rules, *.rules. */
const FIREBASE_RULES_FILES = [/\.rules$/i];
/** SQL sources — Supabase migrations and any schema SQL. */
const SQL_FILES = [/\.sql$/i];
/** Realtime Database rules ship as JSON (database.rules.json). */
const RTDB_RULES_FILES = [/database[^\\/]*\.rules\.json$/i, /\.rules\.json$/i];
/** Server-side HTTP entry points, where an unmetered LLM call is reachable. */
const ROUTE_FILES = [
  /[\\/](?:app|src)[\\/].*route\.[cm]?[jt]sx?$/i,   // Next.js app router
  /[\\/]pages[\\/]api[\\/]/i,                        // Next.js pages router
  /[\\/](?:api|routes?|controllers|handlers|functions)[\\/]/i,
  /[\\/]server[\\/]/i,
  /server\.[cm]?[jt]s$/i,
];

export const deployConfigRules: SecurityRule[] = [
  {
    code: 'DEPLOY001',
    message:
      'This rule lets anyone on the internet write to your database — no login needed. ' +
      'Anyone who finds your project ID can add, change, or delete every record.',
    severity: SecuritySeverity.Error,
    confidence: 'critical',
    patterns: [
      /allow\s+(?:read\s*,\s*write|write\s*,\s*read|write|create|update|delete)\s*:\s*if\s+true\b/i,
    ],
    suggestion:
      'Require authentication in the rule, e.g. `allow write: if request.auth != null` — ' +
      'and scope writes to the owning user where possible ' +
      '(`request.auth.uid == resource.data.ownerId`).',
    category: SecurityCategory.InfrastructureDeployment,
    ruleType,
    filePatterns: { include: FIREBASE_RULES_FILES },
  },
  {
    code: 'DEPLOY002',
    message:
      'This rule lets anyone read this data without logging in. Fine for genuinely public ' +
      'content; a data leak if user records, orders, or messages live here.',
    severity: SecuritySeverity.Warning,
    patterns: [
      /allow\s+(?:read|get|list)\s*:\s*if\s+true\b/i,
    ],
    negativePatterns: [
      /allow\s+(?:read\s*,\s*write|write)/i, // already flagged harder by DEPLOY001
    ],
    suggestion:
      'If this collection holds anything user-specific, require auth: ' +
      '`allow read: if request.auth != null`. Keep `if true` only for truly public data.',
    category: SecurityCategory.InfrastructureDeployment,
    ruleType,
    filePatterns: { include: FIREBASE_RULES_FILES },
  },
  {
    code: 'DEPLOY003',
    message:
      'Row Level Security is being switched off for this table. Every row becomes readable ' +
      'and writable to anyone holding the public anon key — which ships in your frontend.',
    severity: SecuritySeverity.Error,
    confidence: 'critical',
    patterns: [
      /\bdisable\s+row\s+level\s+security\b/i,
    ],
    negativePatterns: [
      /^\s*--/, // SQL line comment — the shared comment detector only knows C-style
    ],
    suggestion:
      'Keep RLS enabled (`alter table … enable row level security`) and grant access ' +
      'through policies instead. If a server job needs full access, use the service-role ' +
      'key on the server — never disable RLS for it.',
    category: SecurityCategory.InfrastructureDeployment,
    ruleType,
    skipComments: true,
    filePatterns: { include: SQL_FILES },
  },
  {
    code: 'DEPLOY004',
    message:
      'This policy grants access unconditionally (`true`), which makes Row Level Security ' +
      'a no-op for the operation it covers — any user, or anyone with the anon key, qualifies.',
    severity: SecuritySeverity.Warning,
    patterns: [
      /\busing\s*\(\s*true\s*\)/i,
      /\bwith\s+check\s*\(\s*true\s*\)/i,
    ],
    negativePatterns: [
      /^\s*--/, // SQL line comment
    ],
    suggestion:
      'Scope the policy to the requesting user, e.g. `using (auth.uid() = user_id)`. ' +
      'An unconditional policy is only appropriate for data that is deliberately public.',
    category: SecurityCategory.InfrastructureDeployment,
    ruleType,
    skipComments: true,
    filePatterns: { include: SQL_FILES },
  },
  {
    code: 'DEPLOY005',
    message:
      'A Supabase service-role key is being exposed through a client-bundled env prefix. ' +
      'The service-role key bypasses Row Level Security entirely — shipping it to the ' +
      'browser hands every visitor full read/write access to your database.',
    severity: SecuritySeverity.Error,
    confidence: 'critical',
    patterns: [
      /\b(?:NEXT_PUBLIC|VITE|REACT_APP|EXPO_PUBLIC|NUXT_PUBLIC|PUBLIC)_[A-Z0-9_]*SERVICE_ROLE[A-Z0-9_]*\b/,
    ],
    suggestion:
      'Remove the public prefix and read the service-role key only in server-side code. ' +
      'The browser should only ever see the anon key. Rotate the key if this was deployed.',
    category: SecurityCategory.SecretsCredentials,
    ruleType,
  },
  {
    code: 'DEPLOY006',
    message:
      'An env var named like a secret carries a client-bundled prefix, so its value is ' +
      'compiled into the browser bundle — readable by anyone who opens devtools.',
    severity: SecuritySeverity.Error,
    confidence: 'critical',
    patterns: [
      /\b(?:NEXT_PUBLIC|VITE|REACT_APP|EXPO_PUBLIC|NUXT_PUBLIC)_[A-Z0-9_]*(?:SECRET|PRIVATE_KEY|PASSWORD|CLIENT_SECRET)[A-Z0-9_]*\b/,
    ],
    negativePatterns: [
      /SERVICE_ROLE/, // more specific message from DEPLOY005
    ],
    suggestion:
      'Drop the public prefix and move any use of this value into server-side code ' +
      '(an API route or server action). Rotate the secret if it has been deployed.',
    category: SecurityCategory.SecretsCredentials,
    ruleType,
  },
  {
    code: 'DEPLOY007',
    message:
      'An env var named like an API key or token carries a client-bundled prefix, so its ' +
      'value ships in the browser bundle. Safe only if the provider designed the key to be ' +
      'public (a publishable key with server-side restrictions).',
    severity: SecuritySeverity.Warning,
    patterns: [
      /\b(?:NEXT_PUBLIC|VITE|REACT_APP|EXPO_PUBLIC|NUXT_PUBLIC)_[A-Z0-9_]*(?:API_KEY|APIKEY|ACCESS_TOKEN|AUTH_TOKEN)[A-Z0-9_]*\b/,
    ],
    negativePatterns: [
      /SERVICE_ROLE|SECRET|PRIVATE/, // covered at Error level above
      /MAPS_API_KEY|RECAPTCHA|FIREBASE_API_KEY|SUPABASE_ANON/i, // designed-public keys
    ],
    suggestion:
      'Confirm this key is a restricted, publishable one. If it bills your account or ' +
      'grants data access (OpenAI, Anthropic, Stripe secret keys…), move the call behind ' +
      'a server route and read the key there without the public prefix.',
    category: SecurityCategory.SecretsCredentials,
    ruleType,
  },
  {
    code: 'DEPLOY008',
    message:
      'This server endpoint calls a paid AI model with no rate limit in sight. Anyone who ' +
      'finds the URL can call it in a loop and run up an unbounded model bill — LLM ' +
      'endpoints are actively scanned for.',
    severity: SecuritySeverity.Warning,
    patterns: [
      /\.chat\.completions\.create\s*\(/,
      /\banthropic\.messages\.create\s*\(/i,
      /\b(?:generateText|streamText|generateObject|streamObject)\s*\(/,
      /\bgetGenerativeModel\s*\(/,
      /\breplicate\.run\s*\(/i,
    ],
    suppressIfNearby: [
      /rate[-_ ]?limit/i,
      /\blimiter\b/i,
      /\bupstash\b/i,
      /\bthrottl/i,
      /\barcjet\b/i,
      /\bslowdown\b/i,
    ],
    suppressNearbyWindow: 400,
    suggestion:
      'Add a per-IP or per-user rate limit before the model call (e.g. @upstash/ratelimit ' +
      'or express-rate-limit), and consider a spend cap with the model provider.',
    category: SecurityCategory.APISecurity,
    ruleType,
    contextAware: true,
    filePatterns: { include: ROUTE_FILES },
  },
  {
    code: 'DEPLOY009',
    message:
      'Realtime Database write access is open to the world (".write": true). Anyone can ' +
      'modify or delete this data without logging in.',
    severity: SecuritySeverity.Error,
    confidence: 'critical',
    patterns: [
      /"\.write"\s*:\s*(?:true|"true")/,
    ],
    suggestion:
      'Gate writes on auth: `".write": "auth != null"` — and scope to the owner where ' +
      'possible (`"auth.uid === $uid"`).',
    category: SecurityCategory.InfrastructureDeployment,
    ruleType,
    filePatterns: { include: RTDB_RULES_FILES },
  },
  {
    code: 'DEPLOY010',
    message:
      'Realtime Database read access is open to the world (".read": true). Fine for public ' +
      'content; a data leak if anything user-specific lives here.',
    severity: SecuritySeverity.Warning,
    patterns: [
      /"\.read"\s*:\s*(?:true|"true")/,
    ],
    suggestion:
      'If this path holds user data, require auth: `".read": "auth != null"`.',
    category: SecurityCategory.InfrastructureDeployment,
    ruleType,
    filePatterns: { include: RTDB_RULES_FILES },
  },
];

// The registry in ./index.ts is keyed by category, and this pack spans
// three; split views so each slots into the right bucket (the same shape
// kotlinAndroidRules uses).
export const deployConfigInfraRules = deployConfigRules.filter(
  r => r.category === SecurityCategory.InfrastructureDeployment
);
export const deployConfigSecretsRules = deployConfigRules.filter(
  r => r.category === SecurityCategory.SecretsCredentials
);
export const deployConfigApiRules = deployConfigRules.filter(
  r => r.category === SecurityCategory.APISecurity
);

/**
 * The subset the PreToolUse write-guard hard-blocks on: unambiguous,
 * catastrophic, never a false positive. Wide-open write rules and RLS
 * teardown qualify; the Warning-level heuristics deliberately do not.
 */
export const deployConfigBlockingRules = deployConfigRules.filter(
  r => r.confidence === 'critical'
);
