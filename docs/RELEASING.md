# Release Caspian

Editor releases and npm releases are separate workflows. Merging code does not publish a new npm version. The onboarding flags introduced in 10.14.0 are available from a compiled checkout until their npm release is published.

## Verify the package

Run `npm ci`, `npm run lint`, `npm run compile`, `npm run test:coverage`, and `npm run test:package`. The package check compiles, creates a real tarball, checks its contents, installs it with production dependencies in a temporary project, and exercises the installed CLI. It needs registry access to install those dependencies. It never publishes.

The check covers command registration, version reporting, setup preview without writes, workflow creation, and detection of an open Firebase rule. CI runs it before VSIX packaging. Normal `npm pack` and `npm publish` create a fresh production build through the `prepack` script so a source checkout cannot silently publish missing build output. VSIX packaging uses the same fresh build. Stale output and compiled test fixtures are excluded; project guides are included.

## Prepare a version

1. Choose a new version and update both `package.json` and `package-lock.json` with `npm version <version> --no-git-tag-version`.
2. Move the Unreleased changelog entries into a dated version heading. Update instructions that describe those features as unreleased.
3. Rebuild the committed Claude plugin hooks if their sources changed. The plugin has its own version in `plugin/.claude-plugin/plugin.json`; bump that version when releasing plugin changes.
4. Merge the release preparation after CI passes. Run the existing **Release** workflow on that commit to create the matching `v<version>` tag, GitHub release, and VSIX. Marketplace publishing requires the existing marketplace credentials.

## Configure npm once

In the npm package settings for `caspian-security`, add a GitHub Actions trusted publisher:

- Organization/user: `CaspianTools`
- Repository: `caspian-security`
- Workflow filename: `npm-release.yml`
- Environment: leave blank (the workflow does not use a GitHub environment)
- Allow direct `npm publish`

This account-side setting is required; merging the workflow cannot configure npm for you. The workflow uses Node 24 and npm 11, and requests an OIDC token instead of storing an npm write token. See [npm's trusted publishing documentation](https://docs.npmjs.com/trusted-publishers/).

## Publish the CLI

Run **Publish npm package** from the `main` branch, supplying the existing release version without the `v` prefix. The workflow checks out that exact tag, verifies its package version, runs lint, the installed-package check, and the test suite, then publishes with provenance. Use a tag that includes the distribution-check scripts and workflow changes.

A tag mismatch, failed test, missing npm trust configuration, or already-published version fails the workflow. It does not silently report success. Verify `npm view caspian-security@<version> version` and `npx -y caspian-security@<version> --version` after publishing, then try `npx -y caspian-security@<version> init ../your-app --github --dry-run`.

Publish immutable versions; do not move an existing release tag to different source code. Consumers can pin the Caspian Action to the released commit SHA using `--action-ref <sha>`.
