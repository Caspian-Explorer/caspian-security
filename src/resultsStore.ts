import * as vscode from 'vscode';
import { SecurityIssue, SecuritySeverity, SecurityCategory, CATEGORY_LABELS, SEVERITY_LABELS, ProjectAdvisory } from './types';

export interface FileSecurityResult {
  filePath: string;
  relativePath: string;
  languageId: string;
  issues: SecurityIssue[];
  scannedAt: Date;
}

export interface ScanSummary {
  totalFiles: number;
  totalIssues: number;
  byCategory: Record<string, number>;
  bySeverity: Record<string, number>;
  byFile: { filePath: string; relativePath: string; count: number }[];
  projectAdvisories: ProjectAdvisory[];
  scanDuration: number;
  scanType: string;
  timestamp: Date;
}

export class ResultsStore implements vscode.Disposable {
  private results: Map<string, FileSecurityResult> = new Map();
  private _onDidChange = new vscode.EventEmitter<void>();
  readonly onDidChange = this._onDidChange.event;

  private _scanDuration = 0;
  private _scanType = '';
  private _debounceTimer: ReturnType<typeof setTimeout> | undefined;
  private _projectAdvisories: ProjectAdvisory[] = [];

  setFileResults(uriString: string, result: FileSecurityResult): void {
    this.results.set(uriString, result);
    this._debouncedFire();
  }

  private _debouncedFire(): void {
    if (this._debounceTimer) { clearTimeout(this._debounceTimer); }
    this._debounceTimer = setTimeout(() => {
      this._debounceTimer = undefined;
      this._onDidChange.fire();
    }, 300);
  }

  getFileResults(uriString: string): FileSecurityResult | undefined {
    return this.results.get(uriString);
  }

  getAllResults(): FileSecurityResult[] {
    return Array.from(this.results.values());
  }

  clearFileResults(uriString: string): void {
    this.results.delete(uriString);
    this._onDidChange.fire();
  }

  clearAll(): void {
    this.results.clear();
    this._projectAdvisories = [];
    this._onDidChange.fire();
  }

  setScanMeta(duration: number, scanType: string): void {
    this._scanDuration = duration;
    this._scanType = scanType;
  }

  setProjectAdvisories(advisories: ProjectAdvisory[]): void {
    // Deduplicate by code — keep only first occurrence of each advisory
    const seen = new Set<string>();
    this._projectAdvisories = advisories.filter(a => {
      if (seen.has(a.code)) { return false; }
      seen.add(a.code);
      return true;
    });
    this._debouncedFire();
  }

  getProjectAdvisories(): ProjectAdvisory[] {
    return this._projectAdvisories;
  }

  getTotalIssueCount(): number {
    let count = 0;
    for (const result of this.results.values()) {
      count += result.issues.length;
    }
    return count;
  }

  getSummary(): ScanSummary {
    const byCategory: Record<string, number> = {};
    const bySeverity: Record<string, number> = {};
    const byFile: { filePath: string; relativePath: string; count: number }[] = [];

    for (const result of this.results.values()) {
      if (result.issues.length > 0) {
        byFile.push({
          filePath: result.filePath,
          relativePath: result.relativePath,
          count: result.issues.length,
        });
      }
      for (const issue of result.issues) {
        const catLabel = CATEGORY_LABELS[issue.category] || issue.category;
        byCategory[catLabel] = (byCategory[catLabel] || 0) + 1;

        const sevLabel = SEVERITY_LABELS[issue.severity] || String(issue.severity);
        bySeverity[sevLabel] = (bySeverity[sevLabel] || 0) + 1;
      }
    }

    byFile.sort((a, b) => b.count - a.count);

    return {
      totalFiles: this.results.size,
      totalIssues: this.getTotalIssueCount(),
      byCategory,
      bySeverity,
      byFile,
      projectAdvisories: this._projectAdvisories,
      scanDuration: this._scanDuration,
      scanType: this._scanType,
      timestamp: new Date(),
    };
  }

  toJSON(): string {
    const allResults = this.getAllResults();
    const issues = allResults.flatMap(result =>
      result.issues.map(issue => ({
        file: result.relativePath,
        line: issue.line + 1,
        column: issue.column + 1,
        severity: SEVERITY_LABELS[issue.severity],
        code: issue.code,
        category: CATEGORY_LABELS[issue.category],
        message: issue.message,
        suggestion: issue.suggestion,
        pattern: issue.pattern,
      }))
    );
    const advisories = this._projectAdvisories.map(a => ({
      type: 'project-advisory',
      code: a.code,
      category: CATEGORY_LABELS[a.category],
      message: a.message,
      suggestion: a.suggestion,
    }));
    return JSON.stringify({ issues, projectAdvisories: advisories }, null, 2);
  }

  toCSV(): string {
    const header = 'File,Line,Column,Severity,Code,Category,Message,Suggestion';
    const rows: string[] = [header];

    for (const result of this.results.values()) {
      for (const issue of result.issues) {
        const csvEscape = (s: string) => `"${s.replace(/"/g, '""')}"`;
        rows.push([
          csvEscape(result.relativePath),
          issue.line + 1,
          issue.column + 1,
          SEVERITY_LABELS[issue.severity],
          issue.code,
          csvEscape(CATEGORY_LABELS[issue.category]),
          csvEscape(issue.message),
          csvEscape(issue.suggestion),
        ].join(','));
      }
    }

    return rows.join('\n');
  }

  toFormattedText(): string {
    const lines: string[] = [];
    const summary = this.getSummary();

    lines.push(`Caspian Security Scan Results`);
    lines.push(`${'='.repeat(50)}`);
    lines.push(`Total: ${summary.totalIssues} issue(s) in ${summary.totalFiles} file(s)`);
    if (this._projectAdvisories.length > 0) {
      lines.push(`Project Advisories: ${this._projectAdvisories.length}`);
    }
    lines.push('');

    for (const result of this.results.values()) {
      if (result.issues.length === 0) { continue; }
      lines.push(`--- ${result.relativePath} (${result.issues.length} issue(s)) ---`);
      for (const issue of result.issues) {
        const sev = SEVERITY_LABELS[issue.severity];
        lines.push(`  [${sev}] ${issue.code} (Line ${issue.line + 1}): ${issue.message}`);
        lines.push(`    Suggestion: ${issue.suggestion}`);
      }
      lines.push('');
    }

    if (this._projectAdvisories.length > 0) {
      lines.push(`${'='.repeat(50)}`);
      lines.push('Project-Level Security Advisories');
      lines.push(`${'-'.repeat(50)}`);
      for (const advisory of this._projectAdvisories) {
        const catLabel = CATEGORY_LABELS[advisory.category] || advisory.category;
        lines.push(`  [Advisory] ${advisory.code} [${catLabel}]: ${advisory.message}`);
        lines.push(`    Suggestion: ${advisory.suggestion}`);
      }
      lines.push('');
    }

    return lines.join('\n');
  }

  dispose(): void {
    if (this._debounceTimer) { clearTimeout(this._debounceTimer); }
    this._onDidChange.dispose();
    this.results.clear();
  }
}
