---
description: Pre-deploy security check — open database rules, exposed secrets, unmetered AI endpoints
---

Run Caspian Security's deployment check on this project and act on the results.

1. Call the `check_deployment_security` MCP tool (from the caspian server) with the project root.
2. If the tool is unavailable, run `npx -y caspian-security ship-check . --json` instead and read the JSON.
3. Report what was found in plain language, worst findings first. For each finding, say what an attacker could do and show the exact fix.
4. Fix every critical and high finding (with my approval for anything architectural). Re-run the check afterwards to confirm it comes back clean.
5. Do not silence findings via ignore rules, baseline entries, or config changes — fix the underlying issue.
