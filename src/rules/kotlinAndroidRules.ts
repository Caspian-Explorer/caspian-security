import { SecurityRule, SecuritySeverity, SecurityCategory, RuleType } from '../types';

const ktOnly = { include: [/\.kts?$/i] };

export const kotlinAuthRules: SecurityRule[] = [
  {
    code: 'KT-AUTH001',
    message: 'WebView has JavaScript enabled',
    severity: SecuritySeverity.Warning,
    patterns: [/\.setJavaScriptEnabled\s*\(\s*true\s*\)/],
    suggestion:
      'Only enable JavaScript in WebView if strictly necessary. Validate all content loaded and use a Content Security Policy.',
    category: SecurityCategory.AuthAccessControl,
    ruleType: RuleType.CodeDetectable,
    filePatterns: ktOnly,
  },
  {
    code: 'KT-AUTH002',
    message: 'WebView exposes native interface to JavaScript (addJavascriptInterface)',
    severity: SecuritySeverity.Error,
    patterns: [/\.addJavascriptInterface\s*\(/],
    suggestion:
      'addJavascriptInterface exposes Kotlin/Java objects to JS. Restrict to trusted, first-party content and require API level >= 17 (@JavascriptInterface annotation).',
    category: SecurityCategory.AuthAccessControl,
    ruleType: RuleType.CodeDetectable,
    filePatterns: ktOnly,
  },
  {
    code: 'KT-AUTH003',
    message: 'Broadcast sent without receiver permission',
    severity: SecuritySeverity.Warning,
    patterns: [/sendBroadcast\s*\(\s*(?!.*permission)/],
    suggestion:
      'Use sendBroadcast(intent, receiverPermission) or LocalBroadcastManager to prevent other apps from receiving sensitive broadcasts.',
    category: SecurityCategory.AuthAccessControl,
    ruleType: RuleType.CodeDetectable,
    filePatterns: ktOnly,
  },
];

export const kotlinXssRules: SecurityRule[] = [
  {
    code: 'KT-XSS001',
    message: 'WebView file access enabled — allows file:// URI access',
    severity: SecuritySeverity.Warning,
    patterns: [/\.setAllowFileAccess\s*\(\s*true\s*\)/],
    suggestion:
      'setAllowFileAccess(true) lets web content read local files. Set to false unless your app explicitly requires it, and restrict to trusted origins.',
    category: SecurityCategory.InputValidationXSS,
    ruleType: RuleType.CodeDetectable,
    filePatterns: ktOnly,
  },
];

export const kotlinEncryptionRules: SecurityRule[] = [
  {
    code: 'KT-ENC001',
    message: 'Insecure random number generator (java.util.Random)',
    severity: SecuritySeverity.Warning,
    patterns: [
      /\bnew\s+Random\s*\(/,
      /\bRandom\s*\(\s*\)\b/,
      /java\.util\.Random\s*\(/,
    ],
    negativePatterns: [/SecureRandom/],
    suggestion:
      'Use java.security.SecureRandom for any security-sensitive randomness (tokens, session IDs, salts). java.util.Random is predictable.',
    category: SecurityCategory.EncryptionDataProtection,
    ruleType: RuleType.CodeDetectable,
    filePatterns: ktOnly,
  },
  {
    code: 'KT-ENC002',
    message: 'Unencrypted SharedPreferences — may expose sensitive data',
    severity: SecuritySeverity.Warning,
    patterns: [/getSharedPreferences\s*\(/],
    negativePatterns: [/EncryptedSharedPreferences/i],
    suggestion:
      'Use androidx.security.crypto.EncryptedSharedPreferences for any sensitive data (tokens, credentials, PII). Plain SharedPreferences are stored unencrypted on disk.',
    category: SecurityCategory.EncryptionDataProtection,
    ruleType: RuleType.CodeDetectable,
    filePatterns: ktOnly,
  },
];

export const kotlinFileRules: SecurityRule[] = [
  {
    code: 'KT-FILE001',
    message: 'File created with world-readable or world-writable mode',
    severity: SecuritySeverity.Error,
    patterns: [/MODE_WORLD_READABLE|MODE_WORLD_WRITEABLE/],
    suggestion:
      'MODE_WORLD_READABLE and MODE_WORLD_WRITEABLE are deprecated and insecure. Use MODE_PRIVATE (0) and share data via ContentProvider or FileProvider instead.',
    category: SecurityCategory.FileHandling,
    ruleType: RuleType.CodeDetectable,
    filePatterns: ktOnly,
  },
  {
    code: 'KT-FILE002',
    message: 'External storage access — data is not encrypted and accessible to other apps',
    severity: SecuritySeverity.Warning,
    patterns: [
      /getExternalStorageDirectory\s*\(/,
      /Environment\.getExternalStorage/,
    ],
    suggestion:
      'Prefer app-specific external storage (getExternalFilesDir) or internal storage for sensitive data. External storage is readable by any app with READ_EXTERNAL_STORAGE permission.',
    category: SecurityCategory.FileHandling,
    ruleType: RuleType.CodeDetectable,
    filePatterns: ktOnly,
  },
];

export const kotlinDatabaseRules: SecurityRule[] = [
  {
    code: 'KT-DB001',
    message: 'Room @RawQuery — ensure inputs are not user-controlled',
    severity: SecuritySeverity.Warning,
    patterns: [/@RawQuery/],
    suggestion:
      'Raw queries bypass Room\'s compile-time SQL verification. If user input drives the query, use parameterised queries (@Query with :param bindings) to prevent SQL injection.',
    category: SecurityCategory.DatabaseSecurity,
    ruleType: RuleType.CodeDetectable,
    filePatterns: ktOnly,
  },
];

export const kotlinLoggingRules: SecurityRule[] = [
  {
    code: 'KT-LOG001',
    message: 'Android log statement may expose sensitive data in production',
    severity: SecuritySeverity.Info,
    patterns: [
      /\bLog\.[dvie]\s*\(/,
      /\bLog\.wtf\s*\(/,
    ],
    suggestion:
      'Strip or guard debug/verbose log statements in release builds using ProGuard rules or a logging wrapper that respects BuildConfig.DEBUG. Logs are readable by other apps on rooted devices and via adb.',
    category: SecurityCategory.LoggingMonitoring,
    ruleType: RuleType.CodeDetectable,
    filePatterns: ktOnly,
  },
];
