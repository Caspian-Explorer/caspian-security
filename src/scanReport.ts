import { FileResult, ScanDiagnostic } from './scanRunner';
import { SEVERITY_LABELS } from './types';

export interface ScanSummary {
  status: 'passed' | 'findings' | 'incomplete';
  filesScanned: number;
  filesSkipped: number;
  findings: number;
  baselined: number;
  ignored: number;
  diagnostics: ScanDiagnostic[];
}

// Paths and descriptions come from an untrusted checkout. Render them as text.
function escapeMarkdown(value: string): string {
  return value.replace(/[&<>]/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;' }[c]!))
    .replace(/[\\`*_{}[\]()#+.!|~-]/g, c => '\\' + c).replace(/[\r\n]/g, ' ');
}

export function formatScanSummary(summary: ScanSummary, results: FileResult[]): string {
  const title = summary.status === 'incomplete' ? 'Scan incomplete'
    : summary.status === 'findings' ? 'Findings need review' : 'No findings in completed checks';
  const lines = [
    '## Caspian Security: ' + title, '',
    summary.filesScanned + ' file(s) analyzed; ' + summary.filesSkipped + ' skipped; ' + summary.findings + ' finding(s).',
    summary.baselined + ' existing finding(s) excluded by baseline or PR comparison; ' + summary.ignored + ' explicitly ignored.', '',
    'Coverage is limited to supported file types and configured paths. This is not a deployment safety certification.', '',
  ];
  const findings = results.flatMap(r => r.issues.map(issue => ({ file: r.relativePath, issue })))
    .sort((a, b) => b.issue.severity - a.issue.severity);
  for (const { file, issue } of findings.slice(0, 20)) {
    lines.push('- **' + SEVERITY_LABELS[issue.severity] + ' ' + escapeMarkdown(issue.code) + '** at ' + escapeMarkdown(file) + ':' + (issue.line + 1),
      '  ' + escapeMarkdown(issue.message), '  Fix: ' + escapeMarkdown(issue.suggestion), '');
  }
  if (findings.length > 20) { lines.push('Additional findings are available in the scan artifact.', ''); }
  if (summary.diagnostics.length) {
    lines.push('### Coverage gaps', '');
    for (const d of summary.diagnostics.slice(0, 30)) {
      lines.push('- ' + escapeMarkdown(d.path) + (d.line ? ':' + d.line : '') + ': ' + d.reason);
    }
    if (summary.diagnostics.length > 30) { lines.push('- More coverage gaps are listed in the full report.'); }
  }
  return lines.join('\n') + '\n';
}
