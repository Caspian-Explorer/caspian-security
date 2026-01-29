import * as vscode from 'vscode';
import { execSync } from 'child_process';
import * as path from 'path';
import type { GitExtension, API, Repository } from './typings/git';

export class GitIntegration implements vscode.Disposable {
  private api: API | undefined;
  private disposables: vscode.Disposable[] = [];

  async initialize(): Promise<boolean> {
    try {
      const gitExtension = vscode.extensions.getExtension<GitExtension>('vscode.git');
      if (!gitExtension) {
        console.log('Caspian Security: Git extension not found, will use shell fallback');
        return false;
      }
      if (!gitExtension.isActive) {
        await gitExtension.activate();
      }
      this.api = gitExtension.exports.getAPI(1);
      return true;
    } catch (error) {
      console.log('Caspian Security: Failed to initialize git API, will use shell fallback', error);
      return false;
    }
  }

  isGitRepository(): boolean {
    if (this.api && this.api.repositories.length > 0) {
      return true;
    }
    // Fallback: check if git repo exists via shell
    const workspaceRoot = this.getWorkspaceRoot();
    if (!workspaceRoot) { return false; }
    try {
      execSync('git rev-parse --is-inside-work-tree', { cwd: workspaceRoot, stdio: 'pipe' });
      return true;
    } catch {
      return false;
    }
  }

  async getUncommittedFiles(): Promise<vscode.Uri[]> {
    if (this.api && this.api.repositories.length > 0) {
      return this.getUncommittedViaAPI(this.api.repositories[0]);
    }
    return this.getUncommittedViaShell();
  }

  private getUncommittedViaAPI(repo: Repository): vscode.Uri[] {
    const changes = [
      ...repo.state.workingTreeChanges,
      ...repo.state.indexChanges,
    ];

    // Add untracked changes if available
    if (repo.state.untrackedChanges) {
      changes.push(...repo.state.untrackedChanges);
    }

    // Deduplicate by URI string
    const seen = new Set<string>();
    const uris: vscode.Uri[] = [];
    for (const change of changes) {
      const key = change.uri.toString();
      if (!seen.has(key)) {
        seen.add(key);
        uris.push(change.uri);
      }
    }
    return uris;
  }

  private getUncommittedViaShell(): vscode.Uri[] {
    const workspaceRoot = this.getWorkspaceRoot();
    if (!workspaceRoot) { return []; }

    const fileNames = new Set<string>();

    try {
      // Modified but not staged
      const modified = execSync('git diff --name-only', { cwd: workspaceRoot, stdio: 'pipe' })
        .toString().trim();
      if (modified) {
        modified.split('\n').forEach(f => fileNames.add(f));
      }
    } catch { /* ignore */ }

    try {
      // Staged
      const staged = execSync('git diff --cached --name-only', { cwd: workspaceRoot, stdio: 'pipe' })
        .toString().trim();
      if (staged) {
        staged.split('\n').forEach(f => fileNames.add(f));
      }
    } catch { /* ignore */ }

    try {
      // Untracked
      const untracked = execSync('git ls-files --others --exclude-standard', { cwd: workspaceRoot, stdio: 'pipe' })
        .toString().trim();
      if (untracked) {
        untracked.split('\n').forEach(f => fileNames.add(f));
      }
    } catch { /* ignore */ }

    return Array.from(fileNames)
      .filter(f => f.length > 0)
      .map(f => vscode.Uri.file(path.join(workspaceRoot, f)));
  }

  private getWorkspaceRoot(): string | undefined {
    return vscode.workspace.workspaceFolders?.[0]?.uri.fsPath;
  }

  dispose(): void {
    this.disposables.forEach(d => d.dispose());
    this.disposables = [];
  }
}
