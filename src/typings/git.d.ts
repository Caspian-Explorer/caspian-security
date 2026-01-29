/**
 * Type definitions for the VS Code built-in Git extension API.
 * Subset of types needed by Caspian Security for detecting uncommitted files.
 * Based on https://github.com/microsoft/vscode/blob/main/extensions/git/src/api/git.d.ts
 */

export interface GitExtension {
  getAPI(version: 1): API;
}

export interface API {
  readonly repositories: Repository[];
  onDidOpenRepository: Event<Repository>;
  onDidCloseRepository: Event<Repository>;
}

export interface Repository {
  readonly rootUri: Uri;
  readonly state: RepositoryState;
  readonly inputBox: InputBox;
}

export interface RepositoryState {
  readonly HEAD: Branch | undefined;
  readonly refs: Ref[];
  readonly remotes: Remote[];
  readonly workingTreeChanges: Change[];
  readonly indexChanges: Change[];
  readonly mergeChanges: Change[];
  readonly untrackedChanges: Change[];
  readonly onDidChange: Event<void>;
}

export interface Branch {
  readonly name?: string;
  readonly commit?: string;
  readonly upstream?: { remote: string; name: string };
}

export interface Ref {
  readonly type: number;
  readonly name?: string;
  readonly commit?: string;
  readonly remote?: string;
}

export interface Remote {
  readonly name: string;
  readonly fetchUrl?: string;
  readonly pushUrl?: string;
}

export interface Change {
  readonly uri: Uri;
  readonly originalUri: Uri;
  readonly renameUri: Uri | undefined;
  readonly status: Status;
}

export enum Status {
  INDEX_MODIFIED = 0,
  INDEX_ADDED = 1,
  INDEX_DELETED = 2,
  INDEX_RENAMED = 3,
  INDEX_COPIED = 4,
  MODIFIED = 5,
  DELETED = 6,
  UNTRACKED = 7,
  IGNORED = 8,
  INTENT_TO_ADD = 9,
  INTENT_TO_RENAME = 10,
  TYPE_CHANGED = 11,
  ADDED_BY_US = 12,
  ADDED_BY_THEM = 13,
  DELETED_BY_US = 14,
  DELETED_BY_THEM = 15,
  BOTH_ADDED = 16,
  BOTH_DELETED = 17,
  BOTH_MODIFIED = 18,
}

export interface InputBox {
  value: string;
}

// Re-use vscode types
import { Uri, Event } from 'vscode';
