import * as vscode from 'vscode';
import * as path from 'path';
import { ResultsStore, FileSecurityResult } from './resultsStore';
import { FixTracker, FixStatus } from './fixTracker';
import { SecurityIssue } from './types';
import { RuleIntelligenceStore } from './ruleIntelligence';
import { ConfigManager } from './configManager';

export class AutoVerifier implements vscode.Disposable {
  private disposables: vscode.Disposable[] = [];
  private depCheckTimeout: ReturnType<typeof setTimeout> | undefined;
  private static readonly DEP_CHECK_DEBOUNCE_MS = 5000;

  constructor(
    private resultsStore: ResultsStore,
    private fixTracker: FixTracker,
    private runDependencyCheck: () => Promise<void>,
    private ruleIntelligence?: RuleIntelligenceStore,
  ) {
    this.disposables.push(
      this.resultsStore.onWillUpdateFile(({ oldResult, newResult }) => {
        this.compareAndAutoVerify(oldResult, newResult);
      })
    );
  }

  registerDependencyWatchers(workspaceRoot: string): void {
    const packageJsonWatcher = vscode.workspace.createFileSystemWatcher(
      new vscode.RelativePattern(workspaceRoot, 'package.json')
    );
    const lockFileWatcher = vscode.workspace.createFileSystemWatcher(
      new vscode.RelativePattern(workspaceRoot, 'package-lock.json')
    );

    const triggerDepCheck = () => this.debouncedDepCheck();

    this.disposables.push(
      packageJsonWatcher.onDidChange(triggerDepCheck),
      lockFileWatcher.onDidChange(triggerDepCheck),
      lockFileWatcher.onDidCreate(triggerDepCheck),
      packageJsonWatcher,
      lockFileWatcher
    );
  }

  private debouncedDepCheck(): void {
    if (this.depCheckTimeout) {
      clearTimeout(this.depCheckTimeout);
    }
    this.depCheckTimeout = setTimeout(async () => {
      this.depCheckTimeout = undefined;
      await this.runDependencyCheck();
    }, AutoVerifier.DEP_CHECK_DEBOUNCE_MS);
  }

  private compareAndAutoVerify(
    oldResult: FileSecurityResult | undefined,
    newResult: FileSecurityResult
  ): void {
    const configManager = ConfigManager.getInstance();
    if (!configManager.get<boolean>('autoVerify', true)) {
      return;
    }

    if (!oldResult || oldResult.issues.length === 0) {
      return;
    }

    const newIssueSet = new Set(
      newResult.issues.map(i => this.issueFingerprint(i))
    );

    const resolvedIssues = oldResult.issues.filter(
      i => !newIssueSet.has(this.issueFingerprint(i))
    );

    if (resolvedIssues.length === 0) {
      return;
    }

    let autoVerifiedCount = 0;
    const relativePath = newResult.relativePath;

    for (const issue of resolvedIssues) {
      // Line-drift guard: if same code+pattern still exists at a different line, skip
      const isCodeFinding = issue.line > 0;
      if (isCodeFinding) {
        const stillExistsAtDifferentLine = newResult.issues.some(
          ni => ni.code === issue.code && ni.pattern === issue.pattern
        );
        if (stillExistsAtDifferentLine) {
          continue;
        }
      }

      const key = FixTracker.makeKey(relativePath, issue.code, issue.line, issue.pattern);
      const currentStatus = this.fixTracker.getStatus(key);

      if (currentStatus === FixStatus.Verified || currentStatus === FixStatus.Ignored) {
        continue;
      }

      this.fixTracker.markVerified(
        key,
        newResult.filePath,
        relativePath,
        issue.code,
        issue.line,
        issue.pattern
      );

      if (this.ruleIntelligence) {
        const langId = path.extname(newResult.filePath).slice(1).toLowerCase();
        this.ruleIntelligence.recordAction(issue.code, 'verified', langId, newResult.filePath);
      }

      autoVerifiedCount++;
    }

    if (autoVerifiedCount > 0) {
      const msg = autoVerifiedCount === 1
        ? 'Caspian Security: 1 finding auto-verified as resolved.'
        : `Caspian Security: ${autoVerifiedCount} findings auto-verified as resolved.`;
      vscode.window.setStatusBarMessage(msg, 5000);
    }
  }

  private issueFingerprint(issue: SecurityIssue): string {
    return `${issue.code}:${issue.line}:${issue.pattern}`;
  }

  dispose(): void {
    if (this.depCheckTimeout) {
      clearTimeout(this.depCheckTimeout);
    }
    for (const d of this.disposables) {
      d.dispose();
    }
  }
}
