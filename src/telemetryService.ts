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

const DEFAULT_TELEMETRY_ENDPOINT = 'https://telemetry.caspiansecurity.dev/v1/report';
const SEND_INTERVAL_MS = 24 * 60 * 60 * 1000; // 24 hours
const FIRST_RUN_KEY = 'caspianSecurity.telemetry.firstRunPromptShown';

/**
 * Resolve the telemetry endpoint. Always returns an https:// URL — anything
 * else (http, missing, malformed) falls back to the default so a misconfigured
 * setting cannot downgrade the transport.
 */
function resolveEndpoint(): string {
  const raw = vscode.workspace
    .getConfiguration('caspianSecurity')
    .get<string>('telemetryEndpoint', DEFAULT_TELEMETRY_ENDPOINT);
  if (typeof raw !== 'string' || !raw.startsWith('https://')) {
    return DEFAULT_TELEMETRY_ENDPOINT;
  }
  try {
    new URL(raw);
    return raw;
  } catch {
    return DEFAULT_TELEMETRY_ENDPOINT;
  }
}

export class TelemetryService implements vscode.Disposable {
  private timer: ReturnType<typeof setInterval> | undefined;
  private dirty = false;
  private sessionId: string;
  private changeListener: vscode.Disposable;

  constructor(
    private ruleIntelligence: RuleIntelligenceStore,
    private fixPatternMemory: FixPatternMemory,
    private globalState: vscode.Memento,
    private extensionVersion: string
  ) {
    this.sessionId = crypto.randomUUID();

    // Mark dirty when rule intelligence changes
    this.changeListener = this.ruleIntelligence.onDidChange(() => {
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
    // Truthful summary of exactly what the payload carries. collectPayload() is
    // the source of truth — keep this in sync if the payload shape changes.
    const disclosure =
      'Sends: rule codes, detection/fix/FP counts, language IDs, AI provider ' +
      'name, extension version, VS Code version, platform, and a daily-rotated ' +
      'session UUID. Does NOT send: file content, file paths, identifiers, ' +
      'or workspace names.';

    const choice = await vscode.window.showInformationMessage(
      'Help improve Caspian Security with anonymous usage stats?',
      { modal: false, detail: disclosure },
      'View Exact Payload',
      'Enable (this workspace)',
      'No Thanks'
    );

    if (choice === 'Enable (this workspace)') {
      // Workspace scope so opting in here does not silently enable telemetry
      // in every other workspace the user opens.
      await vscode.workspace
        .getConfiguration('caspianSecurity')
        .update('enableTelemetry', true, vscode.ConfigurationTarget.Workspace);
      this.scheduleDaily();
      vscode.window.showInformationMessage(
        'Telemetry enabled for this workspace. Toggle it anytime under Settings → Caspian Security → Enable Telemetry.'
      );
    } else if (choice === 'View Exact Payload') {
      await this.showPreview();
      const followUp = await vscode.window.showInformationMessage(
        'Enable anonymous telemetry for this workspace?',
        'Enable (this workspace)',
        'No Thanks'
      );
      if (followUp === 'Enable (this workspace)') {
        await vscode.workspace
          .getConfiguration('caspianSecurity')
          .update('enableTelemetry', true, vscode.ConfigurationTarget.Workspace);
        this.scheduleDaily();
      }
    }
  }

  private httpsPost(body: string): Promise<void> {
    return new Promise((resolve, reject) => {
      let url: URL;
      try {
        url = new URL(resolveEndpoint());
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
    this.changeListener.dispose();
    this.stopSchedule();
    // Attempt final send on deactivation
    if (this.isEnabled() && this.dirty) {
      this.send();
    }
  }
}
