import * as vscode from 'vscode';
import * as https from 'https';
import * as crypto from 'crypto';
import { RuleIntelligenceStore } from './ruleIntelligence';
import { FixPatternMemory } from './fixPatternMemory';

export interface TelemetryRuleStats {
  ruleCode: string;
  detections: number;
  falsePositives: number;
  fixed: number;
  ignored: number;
  verified: number;
  fixFailed: number;
  aiFixes: number;
  aiFixSuccessRate: number;
}

export interface TelemetryPayload {
  version: 1;
  extensionVersion: string;
  sessionId: string;
  vscodeVersion: string;
  platform: string;
  rules: TelemetryRuleStats[];
  totalScans: number;
  totalFilesScanned: number;
  languagesUsed: string[];
  aiProvider?: string;
  fixPatternsReused: number;
}

const TELEMETRY_ENDPOINT = 'https://telemetry.caspiansecurity.dev/v1/report';
const SEND_INTERVAL_MS = 24 * 60 * 60 * 1000; // 24 hours
const FIRST_RUN_KEY = 'caspianSecurity.telemetry.firstRunPromptShown';

export class TelemetryService implements vscode.Disposable {
  private timer: ReturnType<typeof setInterval> | undefined;
  private dirty = false;
  private sessionId: string;

  constructor(
    private ruleIntelligence: RuleIntelligenceStore,
    private fixPatternMemory: FixPatternMemory,
    private globalState: vscode.Memento,
    private extensionVersion: string
  ) {
    this.sessionId = crypto.randomUUID();

    // Mark dirty when rule intelligence changes
    this.ruleIntelligence.onDidChange(() => {
      this.dirty = true;
    });
  }

  /**
   * Start the telemetry service. Schedules daily sends if enabled.
   * On first run (per workspace), prompts the user to opt in.
   */
  async start(): Promise<void> {
    // Show first-run prompt if not seen before
    const promptShown = this.globalState.get<boolean>(FIRST_RUN_KEY, false);
    if (!promptShown && this.ruleIntelligence.getTotalScans() >= 1) {
      await this.globalState.update(FIRST_RUN_KEY, true);
      this.showOptInPrompt();
    }

    if (this.isEnabled()) {
      this.scheduleDaily();
    }
  }

  isEnabled(): boolean {
    return vscode.workspace.getConfiguration('caspianSecurity').get<boolean>('enableTelemetry', false);
  }

  /**
   * Collect the current telemetry payload. This is also used by the
   * "Preview Telemetry Data" command so users can see exactly what's sent.
   */
  collectPayload(): TelemetryPayload {
    const allStats = this.ruleIntelligence.getAllStats();
    const rules: TelemetryRuleStats[] = [];
    const languagesUsed = new Set<string>();

    for (const [code, stats] of Object.entries(allStats)) {
      const aiFixes = stats.fixed + stats.fixFailed;
      rules.push({
        ruleCode: code,
        detections: stats.detections,
        falsePositives: stats.falsePositives,
        fixed: stats.fixed,
        ignored: stats.ignored,
        verified: stats.verified,
        fixFailed: stats.fixFailed,
        aiFixes,
        aiFixSuccessRate: aiFixes > 0 ? stats.fixed / aiFixes : 0,
      });

      for (const lang of Object.keys(stats.byLanguage)) {
        languagesUsed.add(lang);
      }
    }

    const config = vscode.workspace.getConfiguration('caspianSecurity');
    const patternStats = this.fixPatternMemory.getPatternStats();

    return {
      version: 1,
      extensionVersion: this.extensionVersion,
      sessionId: this.sessionId,
      vscodeVersion: vscode.version,
      platform: process.platform,
      rules,
      totalScans: this.ruleIntelligence.getTotalScans(),
      totalFilesScanned: 0, // Not tracked at this level
      languagesUsed: Array.from(languagesUsed),
      aiProvider: config.get<string>('aiProvider'),
      fixPatternsReused: patternStats.totalReuses,
    };
  }

  /**
   * Send telemetry data. Fire-and-forget — errors are silently swallowed.
   */
  async send(): Promise<void> {
    if (!this.isEnabled() || !this.dirty) { return; }

    const payload = this.collectPayload();
    const body = JSON.stringify(payload);

    try {
      await this.httpsPost(body);
      this.dirty = false;
      // Rotate session ID daily
      this.sessionId = crypto.randomUUID();
    } catch {
      // Silently ignore — telemetry is best-effort
    }
  }

  /**
   * Open a read-only editor showing the exact payload that would be sent.
   */
  async showPreview(): Promise<void> {
    const payload = this.collectPayload();
    const content = JSON.stringify(payload, null, 2);
    const doc = await vscode.workspace.openTextDocument({
      content,
      language: 'json',
    });
    await vscode.window.showTextDocument(doc, { preview: true });
  }

  scheduleDaily(): void {
    if (this.timer) { return; }
    this.timer = setInterval(() => {
      this.send();
    }, SEND_INTERVAL_MS);
  }

  stopSchedule(): void {
    if (this.timer) {
      clearInterval(this.timer);
      this.timer = undefined;
    }
  }

  private async showOptInPrompt(): Promise<void> {
    const choice = await vscode.window.showInformationMessage(
      'Help improve Caspian Security? Share anonymized rule effectiveness statistics (no code or file data).',
      'View What\'s Shared',
      'Enable',
      'No Thanks'
    );

    if (choice === 'Enable') {
      await vscode.workspace.getConfiguration('caspianSecurity').update('enableTelemetry', true, true);
      this.scheduleDaily();
      vscode.window.showInformationMessage('Telemetry enabled. You can disable it anytime in settings.');
    } else if (choice === 'View What\'s Shared') {
      await this.showPreview();
      // Ask again after showing preview
      const followUp = await vscode.window.showInformationMessage(
        'Enable anonymous telemetry?',
        'Enable',
        'No Thanks'
      );
      if (followUp === 'Enable') {
        await vscode.workspace.getConfiguration('caspianSecurity').update('enableTelemetry', true, true);
        this.scheduleDaily();
      }
    }
  }

  private httpsPost(body: string): Promise<void> {
    return new Promise((resolve, reject) => {
      let url: URL;
      try {
        url = new URL(TELEMETRY_ENDPOINT);
      } catch {
        resolve(); // Invalid URL — silently skip
        return;
      }

      const options: https.RequestOptions = {
        hostname: url.hostname,
        port: 443,
        path: url.pathname,
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Content-Length': Buffer.byteLength(body),
        },
        timeout: 10000,
      };

      const req = https.request(options, (res) => {
        // Consume response data to free up memory
        res.on('data', () => {});
        res.on('end', () => resolve());
      });

      req.on('error', () => resolve()); // Silently ignore errors
      req.on('timeout', () => { req.destroy(); resolve(); });

      req.write(body);
      req.end();
    });
  }

  dispose(): void {
    this.stopSchedule();
    // Attempt final send on deactivation
    if (this.isEnabled() && this.dirty) {
      this.send();
    }
  }
}
