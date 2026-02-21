import * as vscode from 'vscode';
import { ResultsStore } from './resultsStore';
import { FixTracker } from './fixTracker';
import { ScanHistoryStore } from './scanHistoryStore';

export enum ScanState {
  Idle = 'idle',
  Scanning = 'scanning',
  Complete = 'complete',
}

export class StatusBarManager implements vscode.Disposable {
  private statusBarItem: vscode.StatusBarItem;
  private state: ScanState = ScanState.Idle;
  private scanHistoryStore?: ScanHistoryStore;

  constructor(
    private resultsStore: ResultsStore,
    private fixTracker?: FixTracker
  ) {
    this.statusBarItem = vscode.window.createStatusBarItem(
      vscode.StatusBarAlignment.Left,
      100
    );
    this.statusBarItem.command = 'caspian-security.showResultsPanel';
    this.showIdle();
    this.statusBarItem.show();

    this.resultsStore.onDidChange(() => {
      if (this.state === ScanState.Complete) {
        this.updateIssueCount();
      }
    });

    if (this.fixTracker) {
      this.fixTracker.onDidChange(() => {
        if (this.state === ScanState.Complete) {
          this.updateIssueCount();
        }
      });
    }
  }

  setScanHistoryStore(store: ScanHistoryStore): void {
    this.scanHistoryStore = store;
  }

  setState(state: ScanState): void {
    this.state = state;
    switch (state) {
      case ScanState.Idle:
        this.showIdle();
        break;
      case ScanState.Scanning:
        this.showScanning();
        break;
      case ScanState.Complete:
        this.showComplete();
        break;
    }
  }

  showIdle(): void {
    this.state = ScanState.Idle;
    this.statusBarItem.text = '$(shield) Caspian Security';
    this.statusBarItem.tooltip = 'Caspian Security - Click to show results';
    this.statusBarItem.backgroundColor = undefined;
  }

  showScanning(fileName?: string): void {
    this.state = ScanState.Scanning;
    const fileInfo = fileName ? `: ${fileName}` : '';
    this.statusBarItem.text = `$(loading~spin) Scanning${fileInfo}`;
    this.statusBarItem.tooltip = `Caspian Security - Scanning${fileInfo}`;
    this.statusBarItem.backgroundColor = undefined;
  }

  showComplete(): void {
    this.state = ScanState.Complete;
    this.updateIssueCount();
  }

  updateIssueCount(): void {
    const count = this.resultsStore.getTotalIssueCount();
    const fixSummary = this.fixTracker?.getSummary();
    const fixInfo = fixSummary && fixSummary.total > 0
      ? ` (${fixSummary.fixed} fixed, ${fixSummary.ignored} ignored)`
      : '';

    const lastScan = this.scanHistoryStore?.getLastScan();
    const lastScanInfo = lastScan
      ? `\nLast scan: ${new Date(lastScan.timestamp).toLocaleString()}`
      : '';

    if (count > 0) {
      this.statusBarItem.text = `$(warning) Caspian: ${count} issue${count !== 1 ? 's' : ''}${fixInfo}`;
      this.statusBarItem.tooltip = `Caspian Security - ${count} issue(s) found${fixInfo}. Click to view.${lastScanInfo}`;
      this.statusBarItem.backgroundColor = new vscode.ThemeColor('statusBarItem.warningBackground');
    } else {
      this.statusBarItem.text = '$(check) Caspian: No issues';
      this.statusBarItem.tooltip = `Caspian Security - No issues found${lastScanInfo}`;
      this.statusBarItem.backgroundColor = undefined;
    }
  }

  dispose(): void {
    this.statusBarItem.dispose();
  }
}
