import * as vscode from 'vscode';
import { SecurityIssue, SecuritySeverity, CATEGORY_LABELS } from './types';

export class DiagnosticsManager {
  private diagnosticCollection: vscode.DiagnosticCollection;

  constructor() {
    this.diagnosticCollection = vscode.languages.createDiagnosticCollection('caspian-security');
  }

  createDiagnostics(document: vscode.TextDocument, issues: SecurityIssue[]): vscode.Diagnostic[] {
    return issues.map(issue => this.createDiagnostic(document, issue));
  }

  private createDiagnostic(document: vscode.TextDocument, issue: SecurityIssue): vscode.Diagnostic {
    const range = new vscode.Range(
      new vscode.Position(issue.line, issue.column),
      new vscode.Position(issue.line, issue.column + (issue.pattern?.length || 10))
    );

    const categoryLabel = CATEGORY_LABELS[issue.category] || '';
    const diagnostic = new vscode.Diagnostic(
      range,
      `[${categoryLabel}] ${issue.code}: ${issue.message}`,
      this.mapSeverity(issue.severity)
    );

    diagnostic.code = issue.code;
    diagnostic.source = 'Caspian Security';

    return diagnostic;
  }

  publishDiagnostics(uri: vscode.Uri, diagnostics: vscode.Diagnostic[]): void {
    this.diagnosticCollection.set(uri, diagnostics);
  }

  clearDiagnostics(uri: vscode.Uri): void {
    this.diagnosticCollection.delete(uri);
  }

  clearAll(): void {
    this.diagnosticCollection.clear();
  }

  dispose(): void {
    this.diagnosticCollection.dispose();
  }

  private mapSeverity(severity: SecuritySeverity): vscode.DiagnosticSeverity {
    switch (severity) {
      case SecuritySeverity.Error:
        return vscode.DiagnosticSeverity.Error;
      case SecuritySeverity.Warning:
        return vscode.DiagnosticSeverity.Warning;
      case SecuritySeverity.Info:
      default:
        return vscode.DiagnosticSeverity.Information;
    }
  }
}