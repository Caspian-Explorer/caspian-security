---
name: ship-check
description: Pre-deploy security check for AI-built apps. Use before any deploy, publish, or release step, when setting up a database or auth for the first time, when writing Firebase/Firestore/Supabase rules or SQL migrations, or whenever the user asks if their app is safe to launch. Catches open database rules, RLS left disabled, secrets in the client bundle, AI endpoints with no rate limit, and credential files committed to git.
---

# Ship check — is this app safe to launch?

Caspian Security's deployment check inspects platform configuration for the
mistakes that most often expose AI-built apps in production.

## When to run it

- Before any deploy, publish, or release step.
- Right after setting up a database, auth, or environment config for the first time.
- After editing `firestore.rules`, `storage.rules`, `database.rules.json`, or a
  Supabase SQL migration.
- Whenever the user asks "is this safe?", "can I ship this?", or similar.

## How to run it

Call the `check_deployment_security` MCP tool (caspian server) with the project
root. Fallback without MCP: `npx -y caspian-security ship-check . --json`.

The result includes pre-existing issues on purpose — this is the launch gate,
not a diff scan. A wide-open Firestore rule sinks the ship no matter when it
was written.

## How to act on results

- **critical / high** — fix before the deploy proceeds. These are remotely
  exploitable (open write rules, exposed service-role keys, live credentials).
- **medium** — tell the user, propose the fix, let them decide.
- Never add ignore rules, baseline entries, or config changes to make a
  finding disappear; fix the code or config it points at.
- Re-run the check after fixing until it reports clear.
