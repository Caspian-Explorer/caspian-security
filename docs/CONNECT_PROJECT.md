# Connect a project to Caspian

Caspian runs in your project's GitHub Actions runner. Your project stays in its own repository. Setup does not need an account, a provider API key, or a hosted Caspian service.

## Try the upcoming release from this checkout

These onboarding flags are source changes until this release is published. Compile Caspian, then point its CLI at your application:

```sh
npm run compile
node out/cli/caspian.js init ../your-app --github --dry-run
node out/cli/caspian.js init ../your-app --github
```

Review and commit the generated `.github/workflows/caspian-security.yml` in your application. It references Caspian's `main` branch, so the changes in this checkout must be merged there before the workflow can use them. Use `--action-ref <reviewed-commit-sha>` to select a specific revision instead.

Open a pull request. The workflow checks supported changed files, compares findings with the branch's merge base, and puts a readable report in the Actions job summary. A downloadable SARIF artifact contains the full report. Manual runs check the whole project.

The default is advisory: findings do not fail the check. Execution failures still fail; skipped files are explicitly reported as incomplete coverage. No pull-request comments or write permissions are needed. The workflow never installs or executes your project's dependencies.

See an [example PR report](EXAMPLE_PR_REPORT.md) produced by the scanner.

## Add your coding agent

```sh
node out/cli/caspian.js init ../your-app --github --agent --dry-run
node out/cli/caspian.js init ../your-app --github --agent
```

This also merges Caspian into `.mcp.json` and updates the existing agent instruction blocks. Existing MCP servers and an existing GitHub workflow are preserved. The MCP entry uses the published npm package; use your locally compiled server path when testing unreleased engine changes. Claude Code write-blocking hooks still require the separate Caspian plugin.

## Decide what should block a pull request

After reviewing the initial reports, change the workflow inputs:

```yaml
with:
  fail-on: error
  new-only: true
  strict: true
  upload-sarif: false
  changed-since: ${{ github.event.pull_request.base.sha || '' }}
```

Pin the action to a reviewed commit SHA before making its check required. Enable `strict` only after reviewing coverage gaps: generated files, oversized files, long lines, time limits, and unreadable paths make coverage incomplete. Supported extensions and explicitly excluded directories define the scan's scope; unsupported formats are not certified as safe.

Use branch protection to require the `scan` job once the policy is appropriate for your project. SARIF upload to the GitHub Security tab is optional and requires repository support plus `security-events: write`; job summaries and artifacts work without it.

## Existing findings and baselines

PR checks use `--new-only --changed-since <ref>` and do not require a committed baseline. Caspian reads Git objects from the merge base without checking out or executing that code. Renamed files are conservatively treated as new. Use a full scan periodically to review historical debt.

For local agent workflows, review existing findings before accepting them:

```sh
caspian scan . --format text
caspian baseline accept .
```

Setup no longer accepts findings automatically. `init --accept-baseline` is explicit opt-in. Incomplete scans cannot be accepted as a baseline.

New baselines use version 2 source fingerprints: hashes of the rule and source line, counted per file. Moving a line or changing its indentation preserves identity; replacing the offending expression does not. Identical occurrences are counted separately. No raw source or credential value is stored. This is line-based identity, not proof that surrounding code is semantically unchanged.

Version 1 count baselines remain readable for compatibility but retain their old replacement-finding limitation. Regenerate a reviewed baseline to migrate; the CLI warns when reading version 1.

## Interpret results honestly

- `passed`: no reported findings in completed checks.
- `findings`: reported findings need review; exit status depends on `fail-on`.
- `incomplete`: some eligible files or analysis were skipped, or no eligible files were found.

CLI exit codes remain 0 (below threshold), 1 (above threshold), and 2 (execution failure). `--strict` also returns 2 for any incomplete coverage. Read errors and analysis failures return 2 even in advisory mode. `ship-check` always rejects incomplete coverage with exit 2.

`--summary report.md` writes a Markdown report. JSON includes a `summary`; SARIF includes scan execution metadata. Credential patterns are redacted in CLI JSON and omitted from Markdown summaries.

Paid AI endpoint findings request verification of actual protection. A limiter import, TODO comment, or an unrelated limiter no longer silently suppresses the finding. Use a reviewed, narrowly scoped `.caspianignore` entry when protection exists outside the scanner's analysis.

## Scope of this release

Included: project setup, advisory PR checks, merge-base comparison, coverage reports, stronger baseline identity, and pre-write edit reconstruction.

A hosted GitHub App, managed organization policies, automatic fix PRs, and independently measured accuracy benchmarks are future work. This release does not provide a guarantee that a deployment is secure.
