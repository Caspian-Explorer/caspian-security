import * as vscode from 'vscode';
import { SecurityIssue, SecuritySeverity, SecurityCategory, CATEGORY_LABELS, SEVERITY_LABELS } from './types';

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

  setFileResults(uriString: string, result: FileSecurityResult): void {
    this.results.set(uriString, result);
    this._onDidChange.fire();
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
    this._onDidChange.fire();
  }

  setScanMeta(duration: number, scanType: string): void {
    this._scanDuration = duration;
    this._scanType = scanType;
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
      scanDuration: this._scanDuration,
      scanType: this._scanType,
      timestamp: new Date(),
    };
  }

  toJSON(): string {
    const allResults = this.getAllResults();
    const output = allResults.flatMap(result =>
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
    return JSON.stringify(output, null, 2);
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

    return lines.join('\n');
  }

  dispose(): void {
    this._onDidChange.dispose();
    this.results.clear();
  }
}
