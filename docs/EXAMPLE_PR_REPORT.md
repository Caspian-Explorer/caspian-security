## Caspian Security: Findings need review

1 file(s) analyzed; 0 skipped; 1 finding(s).
0 existing finding(s) excluded by baseline or PR comparison; 0 explicitly ignored.

Coverage is limited to supported file types and configured paths. This is not a deployment safety certification.

- **Error DEPLOY001** at firestore\.rules:1
  This rule lets anyone on the internet write to your database — no login needed\. Anyone who finds your project ID can add, change, or delete every record\.
  Fix: Require authentication in the rule, e\.g\. \`allow write: if request\.auth \!= null\` — and scope writes to the owning user where possible \(\`request\.auth\.uid == resource\.data\.ownerId\`\)\.

