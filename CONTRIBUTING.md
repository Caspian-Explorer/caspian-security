# Contributing to Caspian Security

Start with a reproducible example. Report the rule code, language, expected behavior, actual behavior, and scanner version. Replace real credentials with synthetic values; do not post private source or live secrets.

## Development

```sh
npm ci
npm run compile
npm run lint
npm run test:coverage -- --runInBand
npm run build:plugin
```

Tests include vulnerable and clean fixtures. CLI integration tests run compiled output, so compile before testing. Generated plugin bundles must be rebuilt when shared engine or hook behavior changes.

## Rule contributions

Every new or modified detection needs a vulnerable example, a safe example, relevant formatting variants, and a clear explanation of analysis limitations. Explain how the proposed fix changes behavior. Include a case proving that unrelated comments or imports cannot establish a security control.

Prefer a few useful findings over broad unsupported assertions. Keep severity separate from confidence. Do not label a token live merely because its shape matches a provider prefix. Avoid suppressing findings based on naming conventions alone.

## Integration contributions

Preserve existing project files, offer previews for setup changes, and avoid executing code from the project under inspection. GitHub Action inputs belong in environment variables and quoted argument arrays, never interpolated shell source. Test both Linux and Windows path behavior.

Reports must distinguish complete and incomplete checks. Include skipped-file reasons and redact credential patterns. New findings must not disappear solely because an unrelated old finding was fixed.

## Review checklist

Describe the concrete before/after behavior, include validation results, and call out migration or compatibility changes. Keep releases pinned and document the supported scope. Security reports belong through the process in SECURITY.md.
