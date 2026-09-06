/** Workflow installed into a consumer repository; source stays in their runner. */
export function buildGitHubWorkflow(actionRef = 'main'): string {
  if (!/^[A-Za-z0-9][A-Za-z0-9._/-]*$/.test(actionRef)) {
    throw new Error('Action ref must be a branch, tag, or commit SHA without whitespace.');
  }
  return [
    'name: Caspian Security', '',
    'on:', '  pull_request:', '  workflow_dispatch:', '',
    'permissions:', '  contents: read', '',
    'concurrency:', "  group: caspian-${{ github.workflow }}-${{ github.ref }}", '  cancel-in-progress: true', '',
    'jobs:', '  scan:', '    runs-on: ubuntu-latest', '    timeout-minutes: 10', '    steps:',
    '      - uses: actions/checkout@v4', '        with:', '          fetch-depth: 0',
    '          persist-credentials: false',
    '      # Pin the Caspian action to a reviewed commit SHA before enforcing it.',
    '      - uses: CaspianTools/caspian-security/.github/actions/scan@' + actionRef,
    '        with:', '          fail-on: never', '          new-only: true', '          upload-sarif: false',
    "          changed-since: ${{ github.event.pull_request.base.sha || '' }}",
    '      - name: Keep scan report', '        if: always()', '        uses: actions/upload-artifact@v4',
    '        with:', '          name: caspian-security-report', '          path: caspian-scan.sarif',
    '          if-no-files-found: ignore', '          retention-days: 7', '',
  ].join('\n');
}
