import { SecurityRule, SecuritySeverity, SecurityCategory, RuleType } from '../types';

export const inputValidationRules: SecurityRule[] = [
  {
    code: 'XSS001',
    message: 'Use of innerHTML can lead to XSS attacks',
    severity: SecuritySeverity.Error,
    patterns: [
      /\.innerHTML\s*=/,
      /\.outerHTML\s*=/,
    ],
    // F11 follow-up: contextAware so matches inside string literals (e.g. a
    // webview's getHtml() template literal that emits browser-bound JS) and
    // inside doc comments are skipped. A real `.innerHTML = userInput` in
    // browser code is not inside a string, so genuine vulns still fire.
    contextAware: true,
    suggestion: 'Use textContent, createElement, or a sanitization library like DOMPurify',
    category: SecurityCategory.InputValidationXSS,
    ruleType: RuleType.CodeDetectable,
  },
  {
    code: 'XSS002',
    message: 'Dangerous use of document.write()',
    severity: SecuritySeverity.Error,
    patterns: [
      /document\.write\s*\(/,
      /document\.writeln\s*\(/,
    ],
    contextAware: true,
    suggestion: 'Use DOM manipulation methods instead of document.write()',
    category: SecurityCategory.InputValidationXSS,
    ruleType: RuleType.CodeDetectable,
  },
  {
    code: 'XSS003',
    message: 'Unsanitized user input in HTML string concatenation',
    severity: SecuritySeverity.Warning,
    patterns: [
      /['"].*<[a-z].*['"].*\+.*(?:req|request|params|query|body)\./i,
    ],
    suggestion: 'Sanitize user input before embedding in HTML; use contextual escaping',
    category: SecurityCategory.InputValidationXSS,
    ruleType: RuleType.CodeDetectable,
  },
  {
    code: 'XSS004',
    message: 'Use of dangerouslySetInnerHTML in React component',
    severity: SecuritySeverity.Warning,
    patterns: [
      /dangerouslySetInnerHTML/,
    ],
    negativePatterns: [
      /JSON\.stringify/i,
      /DOMPurify/i,
      /sanitize\w*\s*\(/i,
      /purify/i,
    ],
    suppressIfNearby: [
      /JSON\.stringify/i,
      /DOMPurify\.sanitize/i,
      /sanitizeHtml/i,
      /application\/ld\+json/i,
    ],
    suggestion: 'Sanitize content with DOMPurify before using dangerouslySetInnerHTML',
    category: SecurityCategory.InputValidationXSS,
    ruleType: RuleType.CodeDetectable,
  },
  {
    code: 'XSS005',
    message: 'Unescaped output in template engine',
    severity: SecuritySeverity.Warning,
    patterns: [
      /\{!!.*!!\}/,
      /\|\s*safe\b/,
    ],
    suggestion: 'Use auto-escaping template syntax; only bypass escaping when input is fully sanitized',
    category: SecurityCategory.InputValidationXSS,
    ruleType: RuleType.CodeDetectable,
  },
  {
    code: 'XSS006',
    message: 'Request parameters used without validation',
    severity: SecuritySeverity.Warning,
    patterns: [
      /req\.(?:body|query|params)\.\w+\s*[;)]/,
      /request\.(?:GET|POST|form)\[/i,
    ],
    // Files that visibly use a validation library have addressed exactly
    // what this reminder asks for — don't nag them.
    suppressIfNearby: [
      /validationResult|express-validator|celebrate|\bjoi\b|\bzod\b|\byup\b|\.parse(?:Async)?\s*\(|isEmail\s*\(|normalizeEmail\s*\(/i,
    ],
    suppressNearbyWindow: 40,
    suggestion: 'Validate and sanitize all request parameters using a validation library (e.g., joi, zod, express-validator)',
    category: SecurityCategory.InputValidationXSS,
    ruleType: RuleType.Informational,
  },
  {
    code: 'XSS007',
    message: 'Angular security bypass function used',
    severity: SecuritySeverity.Warning,
    patterns: [
      /bypassSecurityTrust(?:Html|Script|Style|Url|ResourceUrl)/,
    ],
    suggestion: 'Avoid bypassing Angular sanitization unless input is fully trusted and validated',
    category: SecurityCategory.InputValidationXSS,
    ruleType: RuleType.CodeDetectable,
  },
  {
    code: 'XSS008',
    message: 'Reminder: Implement Content Security Policy (CSP) headers',
    severity: SecuritySeverity.Info,
    patterns: [
      /Content-Security-Policy/i,
    ],
    suggestion: 'Configure CSP headers to restrict inline scripts and resource origins',
    category: SecurityCategory.InputValidationXSS,
    ruleType: RuleType.Informational,
  },
  {
    code: 'XSS009',
    message: 'User input used without length validation',
    severity: SecuritySeverity.Warning,
    patterns: [
      /req\.(?:body|query|params)\.\w+\s*(?:&&|!==?\s*(?:undefined|null|''))/,
      /request\.(?:form|args|GET|POST)\[.*\]\s*(?:and|is\s+not\s+None|!=\s*None)/i,
    ],
    suggestion: 'Validate input length/size (e.g., maxLength, minLength) before processing to prevent buffer overflows and DoS',
    category: SecurityCategory.InputValidationXSS,
    ruleType: RuleType.Informational,
  },
  {
    code: 'XSS010',
    message: 'Possible user input in inline script context without encoding',
    severity: SecuritySeverity.Error,
    patterns: [
      /<script[^>]*>.*\$\{/,
      /<script[^>]*>.*\+\s*(?:req|request|params|query|body|user)/i,
      /['"]<script[^>]*>['"].*\+/,
    ],
    suggestion: 'Never interpolate user input into JavaScript context; use JSON.stringify() or data attributes with proper escaping',
    category: SecurityCategory.InputValidationXSS,
    ruleType: RuleType.CodeDetectable,
  },
  {
    code: 'XSS011',
    message: 'User input in URL without encoding',
    severity: SecuritySeverity.Warning,
    patterns: [
      /(?:href|src|action)\s*=\s*['"`].*\$\{.*(?:req|request|params|query|body|user)/i,
      /(?:redirect|url|link)\s*(?:=|\()\s*['"`].*\+\s*(?:req|request|params|query|body)\./i,
      /encodeURI(?:Component)?\s*\(\s*\)\s*/,
    ],
    suggestion: 'Always encode user input in URL context using encodeURIComponent(); validate URL scheme to prevent javascript: injection',
    category: SecurityCategory.InputValidationXSS,
    ruleType: RuleType.CodeDetectable,
  },
  {
    code: 'XSS012',
    message: 'Request handler without Content-Type validation',
    severity: SecuritySeverity.Warning,
    patterns: [
      /app\.(?:post|put|patch)\s*\(/i,
      /router\.(?:post|put|patch)\s*\(/i,
    ],
    suppressIfNearby: [/Content-Type/i, /express\.json/i, /bodyParser/i, /multer/i, /express\.urlencoded/i],
    // Body-parser middleware is registered at app setup, far from the
    // route handlers — a ±3-line window flagged every route in files that
    // DID configure express.json().
    suppressNearbyWindow: 100,
    suggestion:
      'Validate the Content-Type header on request handlers to ensure the body parser matches the expected format. Use express.json() or express.urlencoded() middleware.',
    category: SecurityCategory.InputValidationXSS,
    ruleType: RuleType.Informational,
  },
  {
    code: 'XSS013',
    message: 'Reminder: Use a server-side validation library (joi, zod, yup, express-validator)',
    severity: SecuritySeverity.Info,
    patterns: [
      /req\.body\.\w+/i,
    ],
    suppressIfNearby: [/joi\./i, /zod\./i, /yup\./i, /express-validator/i, /\.validate\s*\(/i, /\.parse\s*\(/i, /\.safeParse\s*\(/i],
    suggestion:
      'Validate all request body fields with a schema validation library (joi, zod, yup, or express-validator) to enforce types, lengths, and formats on the server side.',
    category: SecurityCategory.InputValidationXSS,
    ruleType: RuleType.Informational,
  },
  {
    code: 'XSS014',
    message: 'Response sends user input without HTML encoding',
    severity: SecuritySeverity.Warning,
    patterns: [
      /res\.(?:send|write)\s*\(.*(?:req|request)\./i,
      /response\.(?:send|write)\s*\(.*(?:req|request)\./i,
    ],
    negativePatterns: [/escapeHtml/i, /encode/i, /sanitize/i, /DOMPurify/i, /res\.json/i],
    suggestion:
      'Apply HTML entity encoding (e.g., escapeHtml, he.encode) before reflecting user input in HTML responses to prevent reflected XSS.',
    category: SecurityCategory.InputValidationXSS,
    ruleType: RuleType.CodeDetectable,
  },
  {
    code: 'XSS015',
    message: 'innerHTML assignment without sanitization library',
    severity: SecuritySeverity.Warning,
    patterns: [
      /\.innerHTML\s*=/,
    ],
    suppressIfNearby: [/DOMPurify/i, /sanitize-?html/i, /xss\s*\(/i, /sanitize\s*\(/i, /purify/i],
    suggestion:
      'Sanitize content with DOMPurify.sanitize() or sanitize-html before assigning to innerHTML. Prefer textContent or createElement for static text.',
    category: SecurityCategory.InputValidationXSS,
    ruleType: RuleType.CodeDetectable,
  },
  {
    code: 'XSS016',
    message: 'Reminder: Apply context-appropriate output encoding in templates',
    severity: SecuritySeverity.Info,
    patterns: [
      /res\.render\s*\(/i,
      /\.ejs/i,
      /\.hbs/i,
      /\.pug/i,
    ],
    suppressIfNearby: [/escapeHtml/i, /encodeURIComponent/i, /sanitize/i, /autoEscape/i],
    suggestion:
      'Ensure your template engine auto-escapes output by default. Use context-appropriate encoding: HTML entities for HTML context, encodeURIComponent for URLs, JSON.stringify for JS context.',
    category: SecurityCategory.InputValidationXSS,
    ruleType: RuleType.Informational,
  },
];
