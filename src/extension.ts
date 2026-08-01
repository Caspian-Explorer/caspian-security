import * as vscode from 'vscode';
import * as path from 'path';
import * as fs from 'fs';
import { SecurityAnalyzer } from './analyzer';
import { DiagnosticsManager } from './diagnosticsManager';
import { ConfigManager, LANGUAGE_EXTENSIONS, LANGUAGE_FILENAMES } from './configManager';
import { SecurityCategory, SecuritySeverity, CATEGORY_LABELS } from './types';
import { AdvisorySink } from './scanRunner';
import { ResultsStore } from './resultsStore';
import { StatusBarManager, ScanState } from './statusBarManager';
import { ResultsPanel } from './resultsPanel';
import { GitIntegration } from './gitIntegration';
import { checkDependencies, formatResultsAsText, DependencyCheckResult } from './dependencyChecker';
import { AIFixService, AIProviderConfig, AIFixRequest, AIFixError } from './aiFixService';
import { FixTracker, FixStatus } from './fixTracker';
import { AISettingsPanel } from './aiSettingsPanel';
import { extractSmartContext } from './contextExtractor';
import { loadIgnoreFile, appendIgnoreEntry, isIgnored, IgnoreEntry } from './caspianIgnore';
import { PersistenceManager } from './persistenceManager';
import { FileStateTracker, FileChangeStatus } from './fileStateTracker';
import { FalsePositiveStore } from './falsePositiveStore';
import { ScanHistoryStore } from './scanHistoryStore';
import { RuleIntelligenceStore } from './ruleIntelligence';
import { AdaptiveConfidenceEngine } from './adaptiveConfidence';
import { FixPatternMemory } from './fixPatternMemory';
import { CodebaseProfile } from './codebaseProfile';
import { generateInsights } from './scanInsights';
import { TelemetryService } from './telemetryService';
import { LearningPanel } from './learningPanel';
import { TaskStore } from './taskStore';
import { TaskManager } from './taskManager';
import { TaskChecklistViewProvider } from './taskTreeProvider';
import { registerTaskCommands } from './taskCommands';
import { TaskDetailPanel } from './taskDetailPanel';
import { WelcomePanel } from './welcomePanel';
import { SecurityScoreService } from './securityScore';
import { registerCaspianCodeActionProvider } from './codeActions/provider';
import { AutoVerifier } from './autoVerifier';
import {
  AGENTS,
  MCP_CLIENTS,
  TRIGGERS,
  AgentId,
  McpClientId,
  TriggerMode,
  buildAgentInstructions,
  formatMcpConfigForDisplay,
} from './integration/agentSnippets';

const BATCH_SIZE = 50;

interface ScanBatch {
  label: string;
  language: string;
  files: vscode.Uri[];
}

function createScanBatches(files: vscode.Uri[]): ScanBatch[] {
  const extToLang: Record<string, string> = {};
  for (const [lang, exts] of Object.entries(LANGUAGE_EXTENSIONS)) {
    for (const ext of exts) { extToLang[ext] = lang; }
  }

  const groups = new Map<string, vscode.Uri[]>();
  for (const file of files) {
    const ext = path.extname(file.fsPath).slice(1).toLowerCase();
    const language = extToLang[ext] || LANGUAGE_FILENAMES[path.basename(file.fsPath)];
    if (!language) { continue; }
    if (!groups.has(language)) { groups.set(language, []); }
    groups.get(language)!.push(file);
  }

  // Sort language groups by file count descending
  const sortedGroups = Array.from(groups.entries())
    .sort((a, b) => b[1].length - a[1].length);

  const batches: ScanBatch[] = [];
  for (const [language, langFiles] of sortedGroups) {
    const displayName = language.charAt(0).toUpperCase() + language.slice(1);
    if (langFiles.length <= BATCH_SIZE) {
      batches.push({ label: displayName, language, files: langFiles });
    } else {
      const totalChunks = Math.ceil(langFiles.length / BATCH_SIZE);
      for (let c = 0; c < totalChunks; c++) {
        const chunk = langFiles.slice(c * BATCH_SIZE, (c + 1) * BATCH_SIZE);
        batches.push({
          label: `${displayName} (${c + 1}/${totalChunks})`,
          language,
          files: chunk,
        });
      }
    }
  }

  return batches;
}

function buildScanEstimate(files: vscode.Uri[], batches: ScanBatch[]): string {
  // Aggregate file counts per language
  const langCounts = new Map<string, { files: number; batches: number }>();
  for (const batch of batches) {
    const entry = langCounts.get(batch.language) || { files: 0, batches: 0 };
    entry.files += batch.files.length;
    entry.batches += 1;
    langCounts.set(batch.language, entry);
  }

  const parts: string[] = [];
  for (const [lang, info] of langCounts) {
    const name = lang.charAt(0).toUpperCase() + lang.slice(1);
    parts.push(`${name}: ${info.files}`);
  }

  return `Found ${files.length} files in ${batches.length} batch(es). ${parts.join(', ')}`;
}

let analyzer: SecurityAnalyzer;
let diagnosticsManager: DiagnosticsManager;
let configManager: ConfigManager;
let resultsStore: ResultsStore;
let statusBarManager: StatusBarManager;
let resultsPanel: ResultsPanel;
let gitIntegration: GitIntegration;
let dependencyOutputChannel: vscode.OutputChannel;
let aiFixService: AIFixService;
let fixTracker: FixTracker;
let aiSettingsPanel: AISettingsPanel;
let fixPreviewProvider: FixPreviewContentProvider;
let ignoreEntries: IgnoreEntry[] = [];
let fileStateTracker: FileStateTracker;
let falsePositiveStore: FalsePositiveStore;
let scanHistoryStore: ScanHistoryStore;
let ruleIntelligence: RuleIntelligenceStore;
let fixPatternMemory: FixPatternMemory;
let codebaseProfile: CodebaseProfile;
let telemetryService: TelemetryService;
let learningPanel: LearningPanel;
let taskStore: TaskStore;
let taskManager: TaskManager;
let taskChecklistProvider: TaskChecklistViewProvider;
let welcomePanel: WelcomePanel;
let securityScore: SecurityScoreService;

export function activate(context: vscode.ExtensionContext) {
  try {
    console.log('Caspian Security activated');

    configManager = ConfigManager.getInstance();
    diagnosticsManager = new DiagnosticsManager();
    analyzer = new SecurityAnalyzer();
    resultsStore = new ResultsStore();
    fixTracker = new FixTracker(context.workspaceState);
    aiFixService = new AIFixService(context.secrets);
    statusBarManager = new StatusBarManager(resultsStore, fixTracker);
    resultsPanel = new ResultsPanel(context.extensionUri, resultsStore, fixTracker);
    gitIntegration = new GitIntegration();
    dependencyOutputChannel = vscode.window.createOutputChannel('Caspian Security: Dependencies');
    aiSettingsPanel = new AISettingsPanel(context.extensionUri, context.secrets, aiFixService);
    fixPreviewProvider = new FixPreviewContentProvider();

    // Initialize welcome panel and security score
    const extVersion = context.extension?.packageJSON?.version || 'unknown';
    welcomePanel = new WelcomePanel(context.extensionUri, resultsStore, context.globalState, extVersion);
    securityScore = new SecurityScoreService(resultsStore, fixTracker);
    context.subscriptions.push(welcomePanel);
    context.subscriptions.push(securityScore);

    // v10.5: quick-fix lightbulb provider. Uses the same enabled-languages
    // setting as the analyzer, so users who disabled a language don't get
    // lightbulbs for it.
    registerCaspianCodeActionProvider(context, configManager.getEnabledLanguages());

    context.subscriptions.push(configManager);
    context.subscriptions.push(diagnosticsManager);
    context.subscriptions.push(resultsStore);
    context.subscriptions.push(fixTracker);
    context.subscriptions.push(aiFixService);
    context.subscriptions.push(statusBarManager);
    context.subscriptions.push(resultsPanel);
    context.subscriptions.push(gitIntegration);
    context.subscriptions.push(dependencyOutputChannel);
    context.subscriptions.push(aiSettingsPanel);
    context.subscriptions.push(
      vscode.workspace.registerTextDocumentContentProvider('caspian-fix-preview', fixPreviewProvider)
    );

    // Initialize persistence layer for scan caching and false positive memory
    const storageUri = context.storageUri || context.globalStorageUri;
    PersistenceManager.initialize(storageUri);
    fileStateTracker = new FileStateTracker();
    falsePositiveStore = new FalsePositiveStore(fileStateTracker);
    scanHistoryStore = new ScanHistoryStore();
    ruleIntelligence = new RuleIntelligenceStore();
    fixPatternMemory = new FixPatternMemory();
    codebaseProfile = new CodebaseProfile();
    context.subscriptions.push(PersistenceManager.getInstance());
    context.subscriptions.push(fileStateTracker);
    context.subscriptions.push(falsePositiveStore);
    context.subscriptions.push(scanHistoryStore);
    context.subscriptions.push(ruleIntelligence);
    context.subscriptions.push(fixPatternMemory);
    context.subscriptions.push(codebaseProfile);

    // Connect scan history to status bar
    statusBarManager.setScanHistoryStore(scanHistoryStore);

    // Load persistence stores (non-blocking). The file-state cache only
    // loads when the persistent cache is enabled; issues themselves are
    // never persisted, so there is nothing to "restore" beyond the
    // change-detection metadata that drives skip-unchanged-files.
    Promise.all([
      configManager.get<boolean>('enablePersistentCache', true)
        ? fileStateTracker.load()
        : Promise.resolve(),
      falsePositiveStore.load(),
      scanHistoryStore.load(),
      ruleIntelligence.load(),
      fixPatternMemory.load(),
      codebaseProfile.load(),
    ]).then(async () => {
      // Wire learning engines into the analyzer
      const adaptiveConfidence = new AdaptiveConfidenceEngine(ruleIntelligence);
      analyzer.setAdaptiveConfidence(adaptiveConfidence);
      analyzer.setCodebaseProfile(codebaseProfile);

      // Initialize telemetry and learning dashboard
      const extensionVersion = vscode.extensions.getExtension('caspian.caspian-security')?.packageJSON?.version || 'unknown';
      telemetryService = new TelemetryService(ruleIntelligence, fixPatternMemory, context.globalState, extensionVersion);
      context.subscriptions.push(telemetryService);
      telemetryService.start();

      learningPanel = new LearningPanel(
        context.extensionUri, ruleIntelligence, fixPatternMemory,
        codebaseProfile, scanHistoryStore
      );
      context.subscriptions.push(learningPanel);

      // Initialize Security Task Management
      taskStore = new TaskStore();
      await taskStore.load();
      taskStore.initializeFromCatalog();

      taskManager = new TaskManager(taskStore, configManager);
      taskChecklistProvider = new TaskChecklistViewProvider(context.extensionUri, taskStore);

      const taskDetailPanel = new TaskDetailPanel(context.extensionUri, taskStore);

      context.subscriptions.push(taskStore);
      context.subscriptions.push(taskManager);
      context.subscriptions.push(taskDetailPanel);

      context.subscriptions.push(
        vscode.window.registerWebviewViewProvider(
          TaskChecklistViewProvider.viewType,
          taskChecklistProvider,
          { webviewOptions: { retainContextWhenHidden: true } },
        )
      );
      context.subscriptions.push(taskChecklistProvider);

      registerTaskCommands(context, taskManager, taskStore, taskChecklistProvider, taskDetailPanel);

      vscode.commands.executeCommand('setContext', 'caspianSecurity.taskManagementEnabled',
        configManager.get<boolean>('enableTaskManagement', true));

      taskManager.startScheduler();

      // Initialize auto-verification of resolved findings
      const autoVerifier = new AutoVerifier(
        resultsStore, fixTracker,
        async () => { await runDependencyCheck(true); },
        ruleIntelligence
      );
      const avRoot = vscode.workspace.workspaceFolders?.[0]?.uri.fsPath;
      if (avRoot) {
        autoVerifier.registerDependencyWatchers(avRoot);
      }
      context.subscriptions.push(autoVerifier);
    }).catch(error => {
      console.error('Caspian Security: Failed to load persistence stores:', error);
    });

    // Initialize git integration (non-blocking)
    gitIntegration.initialize();

    // Load .caspianignore file and watch for changes
    const workspaceRoot = vscode.workspace.workspaceFolders?.[0]?.uri.fsPath;
    if (workspaceRoot) {
      ignoreEntries = loadIgnoreFile(workspaceRoot);
      const ignoreWatcher = vscode.workspace.createFileSystemWatcher(
        new vscode.RelativePattern(workspaceRoot, '.caspianignore')
      );
      ignoreWatcher.onDidChange(() => { ignoreEntries = loadIgnoreFile(workspaceRoot); });
      ignoreWatcher.onDidCreate(() => { ignoreEntries = loadIgnoreFile(workspaceRoot); });
      ignoreWatcher.onDidDelete(() => { ignoreEntries = []; });
      context.subscriptions.push(ignoreWatcher);
    }

    registerCommands(context);
    registerCategoryCommands(context);
    registerDocumentListeners(context);

    // Show welcome panel on first activation
    if (welcomePanel.shouldShowOnActivation()) {
      welcomePanel.show();
    }

    // Forward scan results to welcome panel (only updates if panel is already visible)
    context.subscriptions.push(
      resultsStore.onDidChange(() => {
        if (welcomePanel) {
          welcomePanel.updateResults();
        }
      })
    );

    console.log('Caspian Security initialized successfully');
  } catch (error) {
    console.error('Caspian Security failed to activate:', error);
    vscode.window.showErrorMessage('Caspian Security failed to activate. See Output for details.');
  }
}

function registerCommands(context: vscode.ExtensionContext) {
  // --- AI-agent / terminal integration -----------------------------------
  // These commands never write into a repo; they only copy paste-ready text so
  // the user can wire Caspian into any AI agent (Claude Code, Cursor,
  // Antigravity, ...) or MCP client at whatever interval/event they choose.
  context.subscriptions.push(
    vscode.commands.registerCommand('caspian-security.copyAgentInstructions', async () => {
      const agentPick = await vscode.window.showQuickPick(
        AGENTS.map(a => ({ label: a.label, description: `paste into ${a.placement}`, id: a.id })),
        { placeHolder: 'Which AI agent are you setting up to run Caspian Security?' }
      );
      if (!agentPick) { return; }
      const modePick = await vscode.window.showQuickPick(
        TRIGGERS.map(t => ({ label: t.label, id: t.id })),
        { placeHolder: 'When should the agent run Caspian?' }
      );
      if (!modePick) { return; }

      const block = buildAgentInstructions(agentPick.id as AgentId, modePick.id as TriggerMode);
      await vscode.env.clipboard.writeText(block);
      const placement = AGENTS.find(a => a.id === agentPick.id)?.placement ?? 'your agent config';
      const choice = await vscode.window.showInformationMessage(
        `Caspian: AI agent instructions copied — paste into ${placement}.`,
        'Show'
      );
      if (choice === 'Show') {
        const doc = await vscode.workspace.openTextDocument({ content: block, language: 'markdown' });
        await vscode.window.showTextDocument(doc, { preview: true });
      }
    })
  );

  context.subscriptions.push(
    vscode.commands.registerCommand('caspian-security.copyMcpConfig', async () => {
      const clientPick = await vscode.window.showQuickPick(
        MCP_CLIENTS.map(c => ({ label: c.label, description: c.configPath.split('\n')[0], id: c.id })),
        { placeHolder: 'Which MCP client should Caspian be wired into?' }
      );
      if (!clientPick) { return; }

      const blob = formatMcpConfigForDisplay(clientPick.id as McpClientId);
      await vscode.env.clipboard.writeText(blob);
      const choice = await vscode.window.showInformationMessage(
        `Caspian: MCP config for ${clientPick.label} copied to clipboard.`,
        'Show'
      );
      if (choice === 'Show') {
        const doc = await vscode.workspace.openTextDocument({ content: blob, language: 'jsonc' });
        await vscode.window.showTextDocument(doc, { preview: true });
      }
    })
  );

  context.subscriptions.push(
    vscode.commands.registerCommand('caspian-security.runCheck', async () => {
      const editor = vscode.window.activeTextEditor;
      if (editor) {
        await checkDocument(editor.document);
      } else {
        await runWorkspaceCheck();
      }
    })
  );

  context.subscriptions.push(
    vscode.commands.registerCommand('caspian-security.runCheckFile', async () => {
      const editor = vscode.window.activeTextEditor;
      if (!editor) {
        vscode.window.showWarningMessage('No active editor found');
        return;
      }
      await checkDocument(editor.document);
    })
  );

  context.subscriptions.push(
    vscode.commands.registerCommand('caspian-security.runCheckWorkspace', async () => {
      await runWorkspaceCheck();
    })
  );

  context.subscriptions.push(
    vscode.commands.registerCommand('caspian-security.runFullScan', async () => {
      const editor = vscode.window.activeTextEditor;
      if (!editor) {
        await runWorkspaceCheck();
        return;
      }
      if (!shouldCheckDocument(editor.document)) {
        vscode.window.showWarningMessage('Current file language is not enabled for security checks');
        return;
      }
      const allCategories = Object.values(SecurityCategory);
      await checkDocument(editor.document, allCategories);
      vscode.window.showInformationMessage('Caspian Security: Full scan completed');
      resultsPanel.show();
    })
  );

  context.subscriptions.push(
    vscode.commands.registerCommand('caspian-security.fixIssue', async (diagnostic: vscode.Diagnostic) => {
      if (!diagnostic || !diagnostic.code) {
        vscode.window.showInformationMessage('No fix suggestion available for this issue.');
        return;
      }
      const rule = analyzer.getRuleByCode(String(diagnostic.code));
      if (!rule) {
        vscode.window.showInformationMessage('No fix suggestion available for this issue.');
        return;
      }

      const providerConfig = await aiFixService.getProviderConfig();
      if (!providerConfig) {
        const choice = await vscode.window.showWarningMessage(
          'AI fix requires an API key. Configure one in AI Settings.',
          'Open AI Settings',
          'Show Suggestion Only'
        );
        if (choice === 'Open AI Settings') {
          aiSettingsPanel.show();
        } else if (choice === 'Show Suggestion Only') {
          vscode.window.showInformationMessage(`Fix: ${rule.suggestion}`);
        }
        return;
      }

      const editor = vscode.window.activeTextEditor;
      if (!editor) {
        vscode.window.showInformationMessage(`Fix: ${rule.suggestion}`);
        return;
      }

      const document = editor.document;
      const line = diagnostic.range.start.line;
      const column = diagnostic.range.start.character;
      const relativePath = vscode.workspace.asRelativePath(document.uri);
      const lines = document.getText().split('\n');
      const pattern = lines[line]?.substring(column, column + (diagnostic.range.end.character - column)) || '';

      await executeAIFixFromPanel({
        filePath: document.uri.fsPath,
        relativePath,
        line,
        column,
        code: String(diagnostic.code),
        pattern,
        message: rule.message,
        suggestion: rule.suggestion,
        category: rule.category,
        severity: String(rule.severity),
      }, providerConfig);
    })
  );

  // AI Settings command
  context.subscriptions.push(
    vscode.commands.registerCommand('caspian-security.openAISettings', () => {
      aiSettingsPanel.show();
    })
  );

  // AI Fix from results panel
  context.subscriptions.push(
    vscode.commands.registerCommand('caspian-security.aiFixIssue', async (issueData: {
      filePath: string; relativePath: string; line: number; column: number;
      code: string; pattern: string; message: string; suggestion: string;
      category: string; severity: string;
    }) => {
      const providerConfig = await aiFixService.getProviderConfig();
      if (!providerConfig) {
        const choice = await vscode.window.showWarningMessage(
          'AI fix requires an API key. Configure one in AI Settings.',
          'Open AI Settings'
        );
        if (choice === 'Open AI Settings') {
          aiSettingsPanel.show();
        }
        return;
      }
      await executeAIFixFromPanel(issueData, providerConfig);
    })
  );

  // Ignore issue
  context.subscriptions.push(
    vscode.commands.registerCommand('caspian-security.ignoreIssue', async (issueData: {
      filePath: string; relativePath: string; line: number; code: string; pattern: string;
    }) => {
      const key = FixTracker.makeKey(issueData.relativePath, issueData.code, issueData.line, issueData.pattern);
      fixTracker.markIgnored(key, issueData.filePath, issueData.relativePath, issueData.code, issueData.line, issueData.pattern);

      // Record for rule intelligence learning
      if (ruleIntelligence) {
        const langId = path.extname(issueData.filePath).slice(1).toLowerCase();
        ruleIntelligence.recordAction(issueData.code, 'ignored', langId, issueData.filePath);
      }

      // Prompt for optional reason and write to .caspianignore
      const reason = await vscode.window.showInputBox({
        prompt: `Reason for ignoring ${issueData.code} (optional)`,
        placeHolder: 'e.g. False positive, sanitized upstream',
      });

      const wsRoot = vscode.workspace.workspaceFolders?.[0]?.uri.fsPath;
      if (wsRoot) {
        appendIgnoreEntry(wsRoot, {
          ruleCode: issueData.code,
          filePath: issueData.relativePath,
          line: issueData.line + 1,
          reason: reason || undefined,
        });
      }

      vscode.window.showInformationMessage(`Issue ${issueData.code} marked as ignored.`);
    })
  );

  // Verify issue (re-scan file and check if issue is resolved)
  context.subscriptions.push(
    vscode.commands.registerCommand('caspian-security.verifyIssue', async (issueData: {
      filePath: string; relativePath: string; line: number; code: string; pattern: string;
    }) => {
      const key = FixTracker.makeKey(issueData.relativePath, issueData.code, issueData.line, issueData.pattern);

      try {
        // Re-scan just this file
        const uri = vscode.Uri.file(issueData.filePath);
        const document = await vscode.workspace.openTextDocument(uri);
        await checkDocument(document);

        // Check if the specific issue still exists
        const updatedResults = resultsStore.getFileResults(uri.toString());
        const stillPresent = updatedResults?.issues.some(
          i => i.code === issueData.code && i.line === issueData.line
        );

        if (stillPresent) {
          vscode.window.showWarningMessage(
            `Issue ${issueData.code} is still present at line ${issueData.line + 1}.`
          );
        } else {
          // Mark as verified
          fixTracker.markVerified(key, issueData.filePath, issueData.relativePath,
            issueData.code, issueData.line, issueData.pattern);

          // Record for rule intelligence learning
          if (ruleIntelligence) {
            const langId = path.extname(issueData.filePath).slice(1).toLowerCase();
            ruleIntelligence.recordAction(issueData.code, 'verified', langId, issueData.filePath);
          }

          vscode.window.showInformationMessage(
            `Issue ${issueData.code} verified as resolved.`
          );
        }
      } catch (error) {
        vscode.window.showErrorMessage(`Verification failed: ${error}`);
      }
    })
  );

  // Verify all fixed issues at once
  context.subscriptions.push(
    vscode.commands.registerCommand('caspian-security.verifyAllFixes', async () => {
      const allRecords = fixTracker.getAllRecords();
      const fixedRecords = allRecords.filter(r => r.status === FixStatus.Fixed);

      if (fixedRecords.length === 0) {
        vscode.window.showInformationMessage('Caspian Security: No fixed issues to verify.');
        return;
      }

      // Group by file to avoid re-scanning the same file multiple times
      const byFile = new Map<string, typeof fixedRecords>();
      for (const record of fixedRecords) {
        const key = record.filePath;
        if (!byFile.has(key)) {
          byFile.set(key, []);
        }
        byFile.get(key)!.push(record);
      }

      let verifiedCount = 0;
      let stillPresentCount = 0;
      let errorCount = 0;

      await vscode.window.withProgress(
        {
          location: vscode.ProgressLocation.Notification,
          title: 'Caspian Security: Verifying fixes',
          cancellable: true,
        },
        async (progress, token) => {
          const fileEntries = Array.from(byFile.entries());
          for (let i = 0; i < fileEntries.length; i++) {
            if (token.isCancellationRequested) { break; }

            const [filePath, records] = fileEntries[i];
            const relativePath = records[0].relativePath;

            progress.report({
              message: `(${i + 1}/${fileEntries.length}) ${relativePath}`,
              increment: (1 / fileEntries.length) * 100,
            });

            try {
              const uri = vscode.Uri.file(filePath);
              const document = await vscode.workspace.openTextDocument(uri);
              await checkDocument(document);

              const updatedResults = resultsStore.getFileResults(uri.toString());
              for (const record of records) {
                const stillPresent = updatedResults?.issues.some(
                  issue => issue.code === record.issueCode && issue.line === record.issueLine
                );

                if (stillPresent) {
                  stillPresentCount++;
                } else {
                  fixTracker.markVerified(
                    record.issueKey,
                    record.filePath,
                    record.relativePath,
                    record.issueCode,
                    record.issueLine,
                    record.issuePattern
                  );
                  if (ruleIntelligence) {
                    const langId = path.extname(record.filePath).slice(1).toLowerCase();
                    ruleIntelligence.recordAction(record.issueCode, 'verified', langId, record.filePath);
                  }
                  verifiedCount++;
                }
              }
            } catch (error) {
              errorCount += records.length;
              console.error(`Caspian Security: Failed to verify file ${filePath}:`, error);
            }
          }
        }
      );

      const parts: string[] = [];
      if (verifiedCount > 0) { parts.push(`${verifiedCount} verified`); }
      if (stillPresentCount > 0) { parts.push(`${stillPresentCount} still present`); }
      if (errorCount > 0) { parts.push(`${errorCount} failed`); }
      vscode.window.showInformationMessage(
        `Caspian Security: Verify All complete — ${parts.join(', ')}.`
      );
    })
  );

  // Reset fix tracker
  context.subscriptions.push(
    vscode.commands.registerCommand('caspian-security.resetFixTracker', () => {
      fixTracker.clearAll();
      vscode.window.showInformationMessage('Caspian Security: Fix tracker reset.');
    })
  );

  // New commands: Results Panel
  context.subscriptions.push(
    vscode.commands.registerCommand('caspian-security.showResultsPanel', () => {
      resultsPanel.show();
    })
  );

  // New commands: Export
  context.subscriptions.push(
    vscode.commands.registerCommand('caspian-security.exportJSON', async () => {
      const json = resultsStore.toJSON();
      const uri = await vscode.window.showSaveDialog({
        defaultUri: vscode.Uri.file('caspian-security-results.json'),
        filters: { 'JSON Files': ['json'] },
      });
      if (uri) {
        const fs = await import('fs');
        fs.writeFileSync(uri.fsPath, json, 'utf-8');
        vscode.window.showInformationMessage(`Caspian Security: Results exported to ${uri.fsPath}`);
      }
    })
  );

  context.subscriptions.push(
    vscode.commands.registerCommand('caspian-security.exportCSV', async () => {
      const csv = resultsStore.toCSV();
      const uri = await vscode.window.showSaveDialog({
        defaultUri: vscode.Uri.file('caspian-security-results.csv'),
        filters: { 'CSV Files': ['csv'] },
      });
      if (uri) {
        const fs = await import('fs');
        fs.writeFileSync(uri.fsPath, csv, 'utf-8');
        vscode.window.showInformationMessage(`Caspian Security: Results exported to ${uri.fsPath}`);
      }
    })
  );

  context.subscriptions.push(
    vscode.commands.registerCommand('caspian-security.exportSARIF', async () => {
      const sarif = resultsStore.toSARIF();
      const uri = await vscode.window.showSaveDialog({
        defaultUri: vscode.Uri.file('caspian-security-results.sarif'),
        filters: { 'SARIF Files': ['sarif'] },
      });
      if (uri) {
        const fs = await import('fs');
        fs.writeFileSync(uri.fsPath, sarif, 'utf-8');
        vscode.window.showInformationMessage(`Caspian Security: SARIF results exported to ${uri.fsPath}`);
      }
    })
  );

  // New command: Scan Uncommitted Files
  context.subscriptions.push(
    vscode.commands.registerCommand('caspian-security.runCheckUncommitted', async () => {
      await runUncommittedCheck();
    })
  );

  // Scan Branch Changes (PR-scoped)
  context.subscriptions.push(
    vscode.commands.registerCommand('caspian-security.scanBranchChanges', async () => {
      const branch = gitIntegration.getCurrentBranch();
      if (!branch || branch === 'main' || branch === 'master') {
        vscode.window.showInformationMessage('Caspian Security: You are on the main branch. Switch to a feature branch to scan branch changes.');
        return;
      }

      const changedFiles = await gitIntegration.getBranchChangedFiles();
      if (changedFiles.length === 0) {
        vscode.window.showInformationMessage(`Caspian Security: No changed files found on branch "${branch}".`);
        return;
      }

      // Filter to supported language files
      const enabledLanguages = configManager.get<string[]>('enabledLanguages', Object.keys(LANGUAGE_EXTENSIONS));
      const supportedExtensions = new Set<string>();
      for (const lang of enabledLanguages) {
        const exts = LANGUAGE_EXTENSIONS[lang];
        if (exts) { exts.forEach((ext: string) => supportedExtensions.add(ext)); }
      }
      const supportedFiles = changedFiles.filter(uri => {
        const ext = path.extname(uri.fsPath).slice(1).toLowerCase();
        return supportedExtensions.has(ext);
      });

      if (supportedFiles.length === 0) {
        vscode.window.showInformationMessage(`Caspian Security: No supported source files changed on branch "${branch}".`);
        return;
      }

      resultsStore.clearAll();

      await vscode.window.withProgress(
        { location: vscode.ProgressLocation.Notification, title: `Caspian: Scanning ${supportedFiles.length} changed file(s) on ${branch}`, cancellable: true },
        async (progress, token) => {
          const startTime = Date.now();

          for (let i = 0; i < supportedFiles.length; i++) {
            if (token.isCancellationRequested) { break; }
            progress.report({ increment: (100 / supportedFiles.length), message: path.basename(supportedFiles[i].fsPath) });

            try {
              const doc = await vscode.workspace.openTextDocument(supportedFiles[i]);
              await checkDocument(doc);
            } catch { /* file may not be accessible */ }
          }

          const duration = Date.now() - startTime;
          resultsStore.setScanMeta(duration, `Branch: ${branch}`);

          const totalIssues = resultsStore.getTotalIssueCount();
          vscode.window.showInformationMessage(
            `Caspian Security: Found ${totalIssues} issue(s) in ${supportedFiles.length} changed file(s) on branch "${branch}".`
          );
          resultsPanel.show();
        }
      );
    })
  );

  // New command: Check Dependency & Stack Updates
  context.subscriptions.push(
    vscode.commands.registerCommand('caspian-security.checkDependencyUpdates', async () => {
      await runDependencyCheck();
    })
  );

  // New command: Mark as False Positive
  context.subscriptions.push(
    vscode.commands.registerCommand('caspian-security.markFalsePositive', async (issueData: {
      filePath: string; relativePath: string; line: number; code: string; pattern: string;
    }) => {
      if (!falsePositiveStore || !issueData) { return; }

      const reason = await vscode.window.showInputBox({
        prompt: `Why is ${issueData.code} a false positive? (optional)`,
        placeHolder: 'e.g. Variable is always sanitized before use',
      });

      // User pressed Escape — cancel
      if (reason === undefined) { return; }

      await falsePositiveStore.dismiss(
        issueData.relativePath,
        issueData.filePath,
        issueData.code,
        issueData.line,
        issueData.pattern,
        reason || undefined
      );

      // Record for rule intelligence learning
      if (ruleIntelligence) {
        const langId = path.extname(issueData.filePath).slice(1).toLowerCase();
        ruleIntelligence.recordAction(issueData.code, 'false_positive', langId, issueData.filePath);
      }

      // Learn safe patterns from false positive context
      if (codebaseProfile) {
        try {
          const uri = vscode.Uri.file(issueData.filePath);
          const doc = await vscode.workspace.openTextDocument(uri);
          const lineText = doc.lineAt(issueData.line).text;
          codebaseProfile.learnFromFalsePositive(issueData.code, lineText);
        } catch {
          // File may not be accessible
        }
      }

      vscode.window.showInformationMessage(
        `${issueData.code} marked as false positive. It won't appear again unless the file changes.`
      );

      // Re-check the document to remove the finding from diagnostics
      try {
        const uri = vscode.Uri.file(issueData.filePath);
        const document = await vscode.workspace.openTextDocument(uri);
        await checkDocument(document);
      } catch {
        // File may not be open
      }
    })
  );

  // New command: Show Scan History
  context.subscriptions.push(
    vscode.commands.registerCommand('caspian-security.showScanHistory', async () => {
      if (!scanHistoryStore) { return; }

      const entries = scanHistoryStore.getEntries();
      if (entries.length === 0) {
        vscode.window.showInformationMessage('Caspian Security: No scan history yet');
        return;
      }

      const items = entries.reverse().map(entry => ({
        label: `$(clock) ${new Date(entry.timestamp).toLocaleString()}`,
        description: `${entry.scanType} — ${entry.totalIssues} issue(s) in ${entry.totalFiles} files`,
        detail: `Duration: ${(entry.duration / 1000).toFixed(1)}s`
          + (entry.filesSkippedUnchanged > 0 ? ` | ${entry.filesSkippedUnchanged} cached` : '')
          + (entry.falsePositivesFiltered > 0 ? ` | ${entry.falsePositivesFiltered} FP filtered` : ''),
      }));

      await vscode.window.showQuickPick(items, {
        placeHolder: 'Scan History (most recent first)',
        canPickMany: false,
      });
    })
  );

  // New command: Clear All False Positives
  context.subscriptions.push(
    vscode.commands.registerCommand('caspian-security.clearFalsePositives', async () => {
      if (!falsePositiveStore) { return; }

      const count = falsePositiveStore.getAllDismissals().length;
      if (count === 0) {
        vscode.window.showInformationMessage('Caspian Security: No false positive dismissals to clear');
        return;
      }

      const choice = await vscode.window.showWarningMessage(
        `Clear all ${count} false positive dismissal(s)? These findings will reappear on next scan.`,
        'Clear All',
        'Cancel'
      );

      if (choice === 'Clear All') {
        falsePositiveStore.clearAll();
        vscode.window.showInformationMessage('Caspian Security: All false positive dismissals cleared');
      }
    })
  );

  // Welcome Panel
  context.subscriptions.push(
    vscode.commands.registerCommand('caspian-security.showWelcome', () => {
      welcomePanel.show();
    })
  );

  // Security Score (show details)
  context.subscriptions.push(
    vscode.commands.registerCommand('caspian-security.showSecurityScore', () => {
      securityScore.showScoreDetails();
    })
  );

  // Learning Dashboard
  context.subscriptions.push(
    vscode.commands.registerCommand('caspian-security.showLearningDashboard', () => {
      if (learningPanel) {
        learningPanel.show();
      } else {
        vscode.window.showInformationMessage('Caspian Security: Learning system not yet initialized. Run a scan first.');
      }
    })
  );

  // Reset Learning Data
  context.subscriptions.push(
    vscode.commands.registerCommand('caspian-security.resetLearningData', async () => {
      const choice = await vscode.window.showWarningMessage(
        'Reset all Caspian learning data? This includes rule intelligence, fix patterns, and codebase profile. This cannot be undone.',
        'Reset All',
        'Cancel'
      );
      if (choice === 'Reset All') {
        if (ruleIntelligence) { ruleIntelligence.clearAll(); }
        if (fixPatternMemory) { fixPatternMemory.clearAll(); }
        if (codebaseProfile) { codebaseProfile.clearAll(); }
        vscode.window.showInformationMessage('Caspian Security: All learning data has been reset.');
      }
    })
  );

  // Export Learning Data
  context.subscriptions.push(
    vscode.commands.registerCommand('caspian-security.exportLearningData', async () => {
      const data = {
        ruleIntelligence: ruleIntelligence?.exportData(),
        fixPatterns: fixPatternMemory?.exportData(),
        codebaseProfile: codebaseProfile?.exportData(),
      };
      const uri = await vscode.window.showSaveDialog({
        defaultUri: vscode.Uri.file('caspian-learning-data.json'),
        filters: { 'JSON Files': ['json'] },
      });
      if (uri) {
        fs.writeFileSync(uri.fsPath, JSON.stringify(data, null, 2), 'utf-8');
        vscode.window.showInformationMessage(`Learning data exported to ${uri.fsPath}`);
      }
    })
  );

  // Telemetry preview
  context.subscriptions.push(
    vscode.commands.registerCommand('caspian-security.previewTelemetryData', async () => {
      if (telemetryService) {
        await telemetryService.showPreview();
      } else {
        vscode.window.showInformationMessage('Caspian Security: Telemetry service not yet initialized.');
      }
    })
  );

  // Ignore All By Rule — bulk-ignore all findings with a specific rule code
  context.subscriptions.push(
    vscode.commands.registerCommand('caspian-security.ignoreAllByRule', async (ruleCode: string) => {
      if (!ruleCode) { return; }

      const allResults = resultsStore.getAllResults();
      let count = 0;
      for (const result of allResults) {
        for (const issue of result.issues) {
          if (issue.code === ruleCode) {
            const key = FixTracker.makeKey(result.relativePath, issue.code, issue.line, issue.pattern);
            const record = fixTracker.getRecord(key);
            if (!record || record.status === 'pending') {
              fixTracker.markIgnored(key, result.filePath, result.relativePath, issue.code, issue.line, issue.pattern);
              count++;
            }
          }
        }
      }

      // Add a file-wide ignore entry to .caspianignore
      const wsRoot = vscode.workspace.workspaceFolders?.[0]?.uri.fsPath;
      if (wsRoot) {
        appendIgnoreEntry(wsRoot, {
          ruleCode,
          filePath: '*',
          reason: `Bulk-ignored all ${ruleCode} findings`,
        });
      }

      vscode.window.showInformationMessage(`Caspian Security: Ignored ${count} finding(s) for rule ${ruleCode}.`);
    })
  );

  // Explain Rule — show what the rule detects and why it matters
  context.subscriptions.push(
    vscode.commands.registerCommand('caspian-security.explainRule', async (ruleCode: string) => {
      if (!ruleCode) { return; }
      const rule = analyzer.getRuleByCode(ruleCode);
      if (!rule) {
        vscode.window.showInformationMessage(`No details found for rule ${ruleCode}.`);
        return;
      }

      const sevLabel = rule.severity === SecuritySeverity.Error ? 'Error'
        : rule.severity === SecuritySeverity.Warning ? 'Warning' : 'Info';
      const catLabel = CATEGORY_LABELS[rule.category] || rule.category;

      const detail = [
        `Rule: ${rule.code}`,
        `Category: ${catLabel}`,
        `Severity: ${sevLabel}`,
        ``,
        `What it detects:`,
        rule.message,
        ``,
        `Why it matters:`,
        rule.suggestion,
      ].join('\n');

      const choice = await vscode.window.showInformationMessage(
        `${rule.code} (${catLabel}) — ${rule.message}`,
        { modal: true, detail },
        'Got it'
      );
    })
  );

  // Triage Session — guided walkthrough of all pending issues
  context.subscriptions.push(
    vscode.commands.registerCommand('caspian-security.triageSession', async () => {
      const allResults = resultsStore.getAllResults();
      const pendingIssues: Array<{
        filePath: string; relativePath: string; line: number; column: number;
        code: string; pattern: string; message: string; suggestion: string;
        category: string; severity: string; issueKey: string;
      }> = [];

      for (const result of allResults) {
        for (const issue of result.issues) {
          const key = FixTracker.makeKey(result.relativePath, issue.code, issue.line, issue.pattern);
          const record = fixTracker.getRecord(key);
          if (!record || record.status === 'pending') {
            pendingIssues.push({
              filePath: result.filePath,
              relativePath: result.relativePath,
              line: issue.line,
              column: issue.column,
              code: issue.code,
              pattern: issue.pattern,
              message: issue.message,
              suggestion: issue.suggestion,
              category: CATEGORY_LABELS[issue.category] || issue.category,
              severity: issue.severity === SecuritySeverity.Error ? 'Error'
                : issue.severity === SecuritySeverity.Warning ? 'Warning' : 'Info',
              issueKey: key,
            });
          }
        }
      }

      if (pendingIssues.length === 0) {
        vscode.window.showInformationMessage('Caspian Security: No pending issues to triage. Run a workspace scan first.');
        return;
      }

      // Sort: errors first, then warnings, then info
      const sevOrder: Record<string, number> = { Error: 0, Warning: 1, Info: 2 };
      pendingIssues.sort((a, b) => (sevOrder[a.severity] ?? 3) - (sevOrder[b.severity] ?? 3));

      let idx = 0;
      while (idx < pendingIssues.length) {
        const issue = pendingIssues[idx];
        const remaining = pendingIssues.length - idx;

        // Navigate to the file/line
        try {
          const uri = vscode.Uri.file(issue.filePath);
          const doc = await vscode.workspace.openTextDocument(uri);
          const pos = new vscode.Position(issue.line, issue.column);
          await vscode.window.showTextDocument(doc, {
            selection: new vscode.Range(pos, pos),
            viewColumn: vscode.ViewColumn.One,
          });
        } catch { /* file may not exist */ }

        const choice = await vscode.window.showWarningMessage(
          `[${idx + 1}/${pendingIssues.length}] ${issue.severity}: ${issue.code} — ${issue.message}`,
          { modal: false, detail: `File: ${issue.relativePath}:${issue.line + 1}\nCategory: ${issue.category}\n\nSuggestion: ${issue.suggestion}` },
          'AI Fix',
          'Ignore',
          'False Positive',
          'Skip',
          'Stop Triage'
        );

        if (choice === 'AI Fix') {
          await vscode.commands.executeCommand('caspian-security.aiFixIssue', {
            filePath: issue.filePath, relativePath: issue.relativePath,
            line: issue.line, column: issue.column, code: issue.code,
            pattern: issue.pattern, message: issue.message,
            suggestion: issue.suggestion, category: issue.category,
            severity: issue.severity,
          });
          idx++;
        } else if (choice === 'Ignore') {
          await vscode.commands.executeCommand('caspian-security.ignoreIssue', {
            filePath: issue.filePath, relativePath: issue.relativePath,
            line: issue.line, code: issue.code, pattern: issue.pattern,
          });
          idx++;
        } else if (choice === 'False Positive') {
          await vscode.commands.executeCommand('caspian-security.markFalsePositive', {
            filePath: issue.filePath, relativePath: issue.relativePath,
            line: issue.line, code: issue.code, pattern: issue.pattern,
          });
          idx++;
        } else if (choice === 'Skip') {
          idx++;
        } else {
          // Stop Triage or dismiss
          break;
        }
      }

      if (idx >= pendingIssues.length) {
        vscode.window.showInformationMessage('Caspian Security: Triage complete! All issues reviewed.');
      } else {
        vscode.window.showInformationMessage(`Caspian Security: Triage paused. ${pendingIssues.length - idx} issue(s) remaining.`);
      }
    })
  );
}

function registerCategoryCommands(context: vscode.ExtensionContext) {
  for (const category of Object.values(SecurityCategory)) {
    const commandId = `caspian-security.check-${category}`;
    context.subscriptions.push(
      vscode.commands.registerCommand(commandId, async () => {
        const editor = vscode.window.activeTextEditor;
        if (!editor) {
          await runWorkspaceCheck([category as SecurityCategory]);
          return;
        }
        if (!shouldCheckDocument(editor.document)) {
          vscode.window.showWarningMessage('Current file language is not enabled for security checks');
          return;
        }
        const label = CATEGORY_LABELS[category as SecurityCategory];
        await checkDocumentByCategory(editor.document, category as SecurityCategory, label);
      })
    );
  }
}

async function checkDocumentByCategory(
  document: vscode.TextDocument,
  category: SecurityCategory,
  label: string
) {
  try {
    const issues = await analyzer.analyzeDocument(document, [category]);
    const diagnostics = diagnosticsManager.createDiagnostics(document, issues);

    const existingDiagnostics = vscode.languages.getDiagnostics(document.uri)
      .filter(d => d.source === 'Caspian Security' && !d.message.startsWith(`[${label}]`));
    diagnosticsManager.publishDiagnostics(document.uri, [...existingDiagnostics, ...diagnostics]);

    // Store results
    resultsStore.setFileResults(document.uri.toString(), {
      filePath: document.uri.fsPath,
      relativePath: vscode.workspace.asRelativePath(document.uri),
      languageId: document.languageId,
      issues,
      scannedAt: new Date(),
    });
    updateHasResultsContext();

    if (issues.length > 0) {
      vscode.window.showInformationMessage(
        `Caspian Security [${label}]: Found ${issues.length} issue(s)`
      );
    } else {
      vscode.window.showInformationMessage(
        `Caspian Security [${label}]: No issues found`
      );
    }
  } catch (error) {
    console.error(`Error during ${label} check:`, error);
  }
}

function registerDocumentListeners(context: vscode.ExtensionContext) {
  // One debounce timer PER document — a single shared timer would drop
  // file A's pending scan when the user switches to file B within 1s.
  const changeTimeouts = new Map<string, NodeJS.Timeout>();

  context.subscriptions.push(
    vscode.workspace.onDidChangeTextDocument((event) => {
      if (!shouldCheckDocument(event.document)) {
        return;
      }

      if (configManager.getAutoCheck()) {
        const key = event.document.uri.toString();
        const existing = changeTimeouts.get(key);
        if (existing) {
          clearTimeout(existing);
        }
        changeTimeouts.set(key, setTimeout(() => {
          changeTimeouts.delete(key);
          checkDocument(event.document);
        }, 1000));
      }
    })
  );

  context.subscriptions.push(
    vscode.workspace.onDidSaveTextDocument((document) => {
      if (!shouldCheckDocument(document)) {
        return;
      }

      if (configManager.getCheckOnSave()) {
        checkDocument(document);
      }
    })
  );

  context.subscriptions.push(
    vscode.workspace.onDidCloseTextDocument((document) => {
      const key = document.uri.toString();
      const pending = changeTimeouts.get(key);
      if (pending) {
        clearTimeout(pending);
        changeTimeouts.delete(key);
      }
      diagnosticsManager.clearDiagnostics(document.uri);
      resultsStore.clearFileResults(document.uri.toString());
    })
  );

  context.subscriptions.push({
    dispose: () => {
      for (const timer of changeTimeouts.values()) {
        clearTimeout(timer);
      }
      changeTimeouts.clear();
    }
  });
}

async function checkDocument(document: vscode.TextDocument, categories?: SecurityCategory[]) {
  if (!shouldCheckDocument(document)) {
    return;
  }

  try {
    const effectiveCategories = categories || configManager.getEnabledCategories();
    const allIssues = await analyzer.analyzeDocument(document, effectiveCategories);

    // Filter out issues covered by .caspianignore
    const relativePath = vscode.workspace.asRelativePath(document.uri);
    let issues = ignoreEntries.length > 0
      ? allIssues.filter(issue => !isIgnored(ignoreEntries, issue.code, relativePath, issue.line))
      : allIssues;

    // Filter out false positives
    if (falsePositiveStore) {
      issues = falsePositiveStore.filterFalsePositives(relativePath, issues);
    }

    // Filter out informational findings if the user has disabled them
    if (!configManager.getShowInformational()) {
      issues = issues.filter(issue => issue.severity !== SecuritySeverity.Info);
    }

    // Reduce severity for files in admin/scripts/internal paths
    if (configManager.getReduceInternalPathSeverity()) {
      const INTERNAL_PATH_PATTERNS = [
        /[\/\\]scripts?[\/\\]/i,
        /[\/\\]admin[\/\\]/i,
        /[\/\\]internal[\/\\]/i,
        /[\/\\]tools?[\/\\]/i,
        /[\/\\]seed[\/\\]/i,
        /[\/\\]migrations?[\/\\]/i,
        /[\/\\]fixtures?[\/\\]/i,
      ];
      const filePath = document.uri.fsPath;
      if (INTERNAL_PATH_PATTERNS.some(p => p.test(filePath))) {
        issues = issues
          .filter(issue => issue.severity !== SecuritySeverity.Info)
          .map(issue => issue.severity === SecuritySeverity.Warning
            ? { ...issue, severity: SecuritySeverity.Info }
            : issue
          );
      }
    }

    const diagnostics = diagnosticsManager.createDiagnostics(document, issues);
    diagnosticsManager.publishDiagnostics(document.uri, diagnostics);

    // Store results for the results panel and status bar
    resultsStore.setFileResults(document.uri.toString(), {
      filePath: document.uri.fsPath,
      relativePath: vscode.workspace.asRelativePath(document.uri),
      languageId: document.languageId,
      issues,
      scannedAt: new Date(),
    });
    updateHasResultsContext();

    // Record file state for persistent caching
    if (fileStateTracker) {
      fileStateTracker.recordScan(relativePath, document.uri.fsPath, document.languageId, issues, document.getText());
    }

    // Record detections for rule intelligence learning
    if (ruleIntelligence && issues.length > 0) {
      ruleIntelligence.recordDetectionBatch(
        issues.map(issue => ({
          ruleCode: issue.code,
          languageId: document.languageId,
          filePath: document.uri.fsPath,
        }))
      );
    }

    if (issues.length > 0) {
      console.log(`Found ${issues.length} security issues`);
    }
  } catch (error) {
    console.error('Error during security check:', error);
  }
}

async function runWorkspaceCheck(categoryFilter?: SecurityCategory[]) {
  const globPattern = configManager.getFileGlobPattern();
  if (!globPattern) {
    vscode.window.showWarningMessage('No languages enabled for security checks');
    return;
  }

  const excludePattern = '{**/node_modules/**,**/out/**,**/dist/**,**/build/**,**/.git/**,**/.next/**}';
  const files = await vscode.workspace.findFiles(globPattern, excludePattern);

  if (files.length === 0) {
    vscode.window.showInformationMessage('No supported files found in workspace');
    return;
  }

  const batches = createScanBatches(files);
  if (batches.length === 0) {
    vscode.window.showInformationMessage('No supported files found in workspace');
    return;
  }

  // Show pre-scan estimate and ask for confirmation
  const estimate = buildScanEstimate(files, batches);
  const startChoice = await vscode.window.showInformationMessage(
    `Caspian Security: ${estimate}`,
    'Run All',
    'Step-by-Step',
    'Cancel'
  );
  if (startChoice !== 'Run All' && startChoice !== 'Step-by-Step') {
    return;
  }
  const skipBatchConfirmations = startChoice === 'Run All';

  let totalIssueCount = 0;
  let totalFilesScanned = 0;
  let totalFilesSkipped = 0;
  let totalFalsePositivesFiltered = 0;
  const startTime = Date.now();

  resultsStore.clearAll();
  statusBarManager.setState(ScanState.Scanning);

  const skipUnchanged = configManager.get<boolean>('skipUnchangedFiles', true);

  // Project advisories are collected during the main scan pass (and from
  // cache-hit files below) instead of a second full re-scan of every file.
  const advisorySink: AdvisorySink = { fired: new Set<string>(), advisories: [] };

  let userStopped = false;

  for (let batchIndex = 0; batchIndex < batches.length; batchIndex++) {
    const batch = batches[batchIndex];
    let batchIssueCount = 0;
    let batchFilesScanned = 0;
    let batchCancelled = false;

    await vscode.window.withProgress(
      {
        location: vscode.ProgressLocation.Notification,
        title: `Caspian Security: Scanning ${batch.label}${categoryFilter ? ` [${CATEGORY_LABELS[categoryFilter[0]]}]` : ''} (batch ${batchIndex + 1}/${batches.length})`,
        cancellable: true,
      },
      async (progress, token) => {
        for (let i = 0; i < batch.files.length; i++) {
          if (token.isCancellationRequested) {
            batchCancelled = true;
            break;
          }

          // Yield to the event loop between files to keep VS Code
          // responsive. setImmediate, not setTimeout(0): timers clamp to
          // ~1ms each, which alone costs ~10s across a 10k-file workspace.
          if (i > 0) {
            await new Promise(resolve => setImmediate(resolve));
          }

          const file = batch.files[i];
          const relativePath = vscode.workspace.asRelativePath(file);
          const elapsed = ((Date.now() - startTime) / 1000).toFixed(1);

          progress.report({
            message: `(${i + 1}/${batch.files.length}) ${relativePath} | ${elapsed}s elapsed`,
            increment: (1 / batch.files.length) * 100,
          });

          statusBarManager.showScanning(relativePath);

          // Skip unchanged files if caching is enabled
          if (skipUnchanged && fileStateTracker) {
            const changeStatus = await fileStateTracker.getFileChangeStatus(relativePath, file.fsPath);
            if (changeStatus === FileChangeStatus.Unchanged) {
              const cachedIssues = fileStateTracker.getCachedIssues(relativePath);
              if (cachedIssues !== undefined) {
                // Apply false positive filtering to cached results
                let issues = falsePositiveStore
                  ? falsePositiveStore.filterFalsePositives(relativePath, cachedIssues)
                  : cachedIssues;

                const document = await vscode.workspace.openTextDocument(file);
                const diagnostics = diagnosticsManager.createDiagnostics(document, issues);
                diagnosticsManager.publishDiagnostics(document.uri, diagnostics);

                resultsStore.setFileResults(document.uri.toString(), {
                  filePath: document.uri.fsPath,
                  relativePath,
                  languageId: document.languageId,
                  issues,
                  scannedAt: new Date(),
                });

                // Cache hits skip the rule pass, so collect their
                // project advisories with the cheap advisory-only pass.
                for (const advisory of analyzer.collectProjectAdvisories(document, categoryFilter || configManager.getEnabledCategories())) {
                  if (!advisorySink.fired.has(advisory.code)) {
                    advisorySink.fired.add(advisory.code);
                    advisorySink.advisories.push(advisory);
                  }
                }

                batchIssueCount += issues.length;
                batchFilesScanned++;
                totalFilesSkipped++;
                continue;
              }
            }
          }

          const document = await vscode.workspace.openTextDocument(file);
          const categories = categoryFilter || configManager.getEnabledCategories();
          let issues = await analyzer.analyzeDocument(document, categories, advisorySink);

          // Apply false positive filtering
          if (falsePositiveStore) {
            const beforeCount = issues.length;
            issues = falsePositiveStore.filterFalsePositives(relativePath, issues);
            totalFalsePositivesFiltered += beforeCount - issues.length;
          }

          const diagnostics = diagnosticsManager.createDiagnostics(document, issues);
          diagnosticsManager.publishDiagnostics(document.uri, diagnostics);

          resultsStore.setFileResults(document.uri.toString(), {
            filePath: document.uri.fsPath,
            relativePath,
            languageId: document.languageId,
            issues,
            scannedAt: new Date(),
          });

          // Record file state for caching
          if (fileStateTracker) {
            fileStateTracker.recordScan(relativePath, file.fsPath, document.languageId, issues, document.getText());
          }

          batchIssueCount += issues.length;
          batchFilesScanned++;
        }
      }
    );

    totalIssueCount += batchIssueCount;
    totalFilesScanned += batchFilesScanned;
    updateHasResultsContext();

    if (batchCancelled) {
      userStopped = true;
      break;
    }

    const isLastBatch = batchIndex === batches.length - 1;
    if (!isLastBatch && !skipBatchConfirmations) {
      const nextBatch = batches[batchIndex + 1];
      const remainingBatches = batches.length - batchIndex - 1;
      const remainingFiles = batches.slice(batchIndex + 1).reduce((sum, b) => sum + b.files.length, 0);

      const choice = await vscode.window.showInformationMessage(
        `Caspian Security: ${batch.label} done — ${batchIssueCount} issue(s) in ${batchFilesScanned} files. `
        + `Next: ${nextBatch.label} (${nextBatch.files.length} files). `
        + `${remainingBatches} batch(es) remaining (${remainingFiles} files).`,
        'Continue',
        'Stop'
      );

      if (choice !== 'Continue') {
        userStopped = true;
        break;
      }
    }
  }

  // Run dependency check if enabled
  if (configManager.getDependencyCheckEnabled() &&
      configManager.getEnabledCategories().includes(SecurityCategory.DependenciesSupplyChain)) {
    try {
      const depResult = await runDependencyCheck();
      if (depResult) {
        totalIssueCount += depResult.outdatedPackages.length + depResult.auditSummary.totalVulnerabilities;
      }
    } catch (error) {
      console.error('Caspian Security: Dependency check failed during workspace scan:', error);
    }
  }

  // Project advisories were collected during the main scan pass.
  resultsStore.setProjectAdvisories(advisorySink.advisories);

  // CRED007a: Check .gitignore for .env entries
  checkGitignoreForSensitiveFiles();

  const duration = Date.now() - startTime;
  resultsStore.setScanMeta(duration, userStopped ? 'workspace (partial)' : 'workspace');
  statusBarManager.showComplete();
  updateHasResultsContext();

  // Record scan history
  if (scanHistoryStore) {
    const summary = resultsStore.getSummary();
    scanHistoryStore.recordScan({
      timestamp: new Date().toISOString(),
      scanType: userStopped ? 'workspace (partial)' : 'workspace',
      duration,
      totalFiles: totalFilesScanned,
      totalIssues: totalIssueCount,
      falsePositivesFiltered: totalFalsePositivesFiltered,
      filesSkippedUnchanged: totalFilesSkipped,
      bySeverity: summary.bySeverity,
      byCategory: summary.byCategory,
    });
  }

  // Record scan completion for rule intelligence
  if (ruleIntelligence) {
    ruleIntelligence.recordScanCompleted();
  }

  // Save file state cache
  if (fileStateTracker) {
    fileStateTracker.save();
  }

  // Auto-complete related security tasks
  if (taskManager) {
    taskManager.onWorkspaceScanCompleted();
  }

  const skippedNote = totalFilesSkipped > 0 ? ` (${totalFilesSkipped} cached)` : '';
  const advisoryNote = advisorySink.advisories.length > 0 ? ` + ${advisorySink.advisories.length} advisory(ies)` : '';
  vscode.window.showInformationMessage(
    `Caspian Security: Scan ${userStopped ? 'stopped' : 'complete'} — ${totalIssueCount} issue(s) found in ${totalFilesScanned} files${skippedNote}${advisoryNote}`
  );

  resultsPanel.show();
}

async function runUncommittedCheck() {
  if (!gitIntegration.isGitRepository()) {
    vscode.window.showWarningMessage('Caspian Security: No git repository found in workspace');
    return;
  }

  const changedFileUris = await gitIntegration.getUncommittedFiles();

  // Filter to supported languages
  const supportedFiles: vscode.Uri[] = [];
  for (const uri of changedFileUris) {
    try {
      const doc = await vscode.workspace.openTextDocument(uri);
      if (shouldCheckDocument(doc)) {
        supportedFiles.push(uri);
      }
    } catch {
      // File may have been deleted or be unreadable
    }
  }

  if (supportedFiles.length === 0) {
    vscode.window.showInformationMessage('Caspian Security: No uncommitted files to scan');
    return;
  }

  let issueCount = 0;
  const startTime = Date.now();
  const advisorySink: AdvisorySink = { fired: new Set<string>(), advisories: [] };

  resultsStore.clearAll();
  statusBarManager.setState(ScanState.Scanning);

  await vscode.window.withProgress(
    {
      location: vscode.ProgressLocation.Notification,
      title: 'Caspian Security: Scanning uncommitted files',
      cancellable: true,
    },
    async (progress, token) => {
      for (let i = 0; i < supportedFiles.length; i++) {
        if (token.isCancellationRequested) { break; }

        const relativePath = vscode.workspace.asRelativePath(supportedFiles[i]);
        const elapsed = ((Date.now() - startTime) / 1000).toFixed(1);
        const avgTimePerFile = (Date.now() - startTime) / (i + 1);
        const estimatedRemaining = Math.ceil((supportedFiles.length - i - 1) * avgTimePerFile / 1000);

        progress.report({
          message: `(${i + 1}/${supportedFiles.length}) ${relativePath} | ${elapsed}s elapsed | ~${estimatedRemaining}s remaining`,
          increment: (1 / supportedFiles.length) * 100,
        });

        statusBarManager.showScanning(relativePath);

        const document = await vscode.workspace.openTextDocument(supportedFiles[i]);
        const categories = configManager.getEnabledCategories();
        let issues = await analyzer.analyzeDocument(document, categories, advisorySink);

        // Apply false positive filtering
        if (falsePositiveStore) {
          issues = falsePositiveStore.filterFalsePositives(relativePath, issues);
        }

        const diagnostics = diagnosticsManager.createDiagnostics(document, issues);
        diagnosticsManager.publishDiagnostics(document.uri, diagnostics);

        resultsStore.setFileResults(document.uri.toString(), {
          filePath: document.uri.fsPath,
          relativePath,
          languageId: document.languageId,
          issues,
          scannedAt: new Date(),
        });

        // Record file state for caching
        if (fileStateTracker) {
          fileStateTracker.recordScan(relativePath, supportedFiles[i].fsPath, document.languageId, issues, document.getText());
        }

        issueCount += issues.length;
      }
    }
  );

  // Project advisories were collected during the main scan pass.
  resultsStore.setProjectAdvisories(advisorySink.advisories);

  // CRED007a: Check .gitignore for .env entries
  checkGitignoreForSensitiveFiles();

  const duration = Date.now() - startTime;
  resultsStore.setScanMeta(duration, 'uncommitted');
  statusBarManager.showComplete();
  updateHasResultsContext();

  // Record scan history
  if (scanHistoryStore) {
    const summary = resultsStore.getSummary();
    scanHistoryStore.recordScan({
      timestamp: new Date().toISOString(),
      scanType: 'uncommitted',
      duration,
      totalFiles: supportedFiles.length,
      totalIssues: issueCount,
      falsePositivesFiltered: 0,
      filesSkippedUnchanged: 0,
      bySeverity: summary.bySeverity,
      byCategory: summary.byCategory,
    });
  }

  // Record scan completion for rule intelligence
  if (ruleIntelligence) {
    ruleIntelligence.recordScanCompleted();
  }

  // Save file state cache
  if (fileStateTracker) {
    fileStateTracker.save();
  }

  // Auto-complete related security tasks
  if (taskManager) {
    taskManager.onWorkspaceScanCompleted();
  }

  vscode.window.showInformationMessage(
    `Caspian Security: Scan complete — ${issueCount} issue(s) found in ${supportedFiles.length} uncommitted files`
  );

  // Auto-open results panel after scan
  resultsPanel.show();
}

let depCheckInProgress = false;

async function runDependencyCheck(quiet = false): Promise<DependencyCheckResult | undefined> {
  if (depCheckInProgress) { return undefined; }
  depCheckInProgress = true;

  try {
    const workspaceRoot = vscode.workspace.workspaceFolders?.[0]?.uri.fsPath;
    if (!workspaceRoot) {
      if (!quiet) { vscode.window.showWarningMessage('Caspian Security: No workspace folder open'); }
      return undefined;
    }

    const includeOsv = ConfigManager.getInstance().get<boolean>('osvCheck', false);

    const fs = await import('fs');
    const packageJsonPath = path.join(workspaceRoot, 'package.json');
    if (!fs.existsSync(packageJsonPath) && !includeOsv) {
      if (!quiet) { vscode.window.showWarningMessage('Caspian Security: No package.json found in workspace root (enable caspianSecurity.osvCheck to scan non-npm manifests via OSV.dev)'); }
      return undefined;
    }

    let result: DependencyCheckResult | undefined;

    if (quiet) {
      result = await checkDependencies(workspaceRoot, { includeOsv });
    } else {
      await vscode.window.withProgress(
        {
          location: vscode.ProgressLocation.Notification,
          title: 'Caspian Security: Checking dependency updates...',
          cancellable: false,
        },
        async () => {
          result = await checkDependencies(workspaceRoot, { includeOsv });
        }
      );
    }

    if (result) {
      if (!quiet) {
        const output = formatResultsAsText(result);
        dependencyOutputChannel.clear();
        dependencyOutputChannel.appendLine('Caspian Security: Dependency & Stack Update Check');
        dependencyOutputChannel.appendLine(`Project: ${workspaceRoot}`);
        dependencyOutputChannel.appendLine('='.repeat(50));
        dependencyOutputChannel.appendLine('');
        dependencyOutputChannel.appendLine(output);
        dependencyOutputChannel.show(true);

        const outdatedCount = result.outdatedPackages.length;
        const vulnCount = result.auditSummary.totalVulnerabilities;
        const osvSuffix = result.osv ? `, ${result.osv.vulnerabilities.length} OSV.dev advisory(ies)` : '';
        vscode.window.showInformationMessage(
          `Caspian Security: ${outdatedCount} outdated package(s), ${vulnCount} vulnerability(ies)${osvSuffix} found. See Output panel.`
        );
      }

      storeDependencyResultsAsIssues(result, workspaceRoot);

      // Auto-complete related security tasks
      if (taskManager) {
        taskManager.onDependencyCheckCompleted();
      }
    }

    return result;
  } finally {
    depCheckInProgress = false;
  }
}

function storeDependencyResultsAsIssues(result: DependencyCheckResult, workspaceRoot: string): void {
  const issues: import('./types').SecurityIssue[] = [];

  for (const vuln of result.auditSummary.vulnerabilities) {
    issues.push({
      line: 0,
      column: 0,
      message: `Vulnerability in ${vuln.name}: ${vuln.title} (${vuln.severity})`,
      severity: mapAuditSeverity(vuln.severity),
      suggestion: vuln.fixAvailable
        ? `Fix available. Run npm audit fix or update ${vuln.name}. ${vuln.url ? 'Details: ' + vuln.url : ''}`
        : `No automatic fix available. ${vuln.url ? 'Review: ' + vuln.url : ''}`,
      code: 'DEP-AUDIT',
      pattern: vuln.name,
      category: SecurityCategory.DependenciesSupplyChain,
    });
  }

  for (const pkg of result.outdatedPackages) {
    issues.push({
      line: 0,
      column: 0,
      message: `${pkg.name} is outdated: ${pkg.current} -> ${pkg.latest} (${pkg.updateType} update)`,
      severity: pkg.updateType === 'major' ? SecuritySeverity.Warning : SecuritySeverity.Info,
      suggestion: `Update ${pkg.name} to ${pkg.latest}: npm install ${pkg.name}@${pkg.latest}`,
      code: 'DEP-OUTDATED',
      pattern: pkg.name,
      category: SecurityCategory.DependenciesSupplyChain,
    });
  }

  if (issues.length > 0) {
    const packageJsonPath = path.join(workspaceRoot, 'package.json');
    resultsStore.setFileResults(`dependency-check:${packageJsonPath}`, {
      filePath: packageJsonPath,
      relativePath: 'package.json',
      languageId: 'json',
      issues,
      scannedAt: new Date(),
    });
    updateHasResultsContext();
  }

  // OSV.dev findings attach to the manifest they were parsed from.
  if (result.osv) {
    const byManifest = new Map<string, import('./types').SecurityIssue[]>();
    for (const vuln of result.osv.vulnerabilities) {
      const issue: import('./types').SecurityIssue = {
        line: 0,
        column: 0,
        message: `${vuln.id}: ${vuln.packageName}@${vuln.packageVersion} — ${vuln.summary} (${vuln.severity})`,
        severity: mapAuditSeverity(vuln.severity === 'unknown' ? 'moderate' : vuln.severity),
        suggestion: vuln.fixedVersion
          ? `Update ${vuln.packageName} to ${vuln.fixedVersion} or later. Details: ${vuln.url}`
          : `No fixed version listed. Review: ${vuln.url}`,
        code: 'DEP-OSV',
        pattern: vuln.packageName,
        category: SecurityCategory.DependenciesSupplyChain,
      };
      const list = byManifest.get(vuln.manifest) || [];
      list.push(issue);
      byManifest.set(vuln.manifest, list);
    }
    for (const [manifest, manifestIssues] of byManifest) {
      const manifestPath = path.join(workspaceRoot, manifest);
      resultsStore.setFileResults(`dependency-check-osv:${manifestPath}`, {
        filePath: manifestPath,
        relativePath: manifest,
        languageId: 'plaintext',
        issues: manifestIssues,
        scannedAt: new Date(),
      });
    }
    if (byManifest.size > 0) {
      updateHasResultsContext();
    }
  }
}

function mapAuditSeverity(severity: string): import('./types').SecuritySeverity {
  switch (severity) {
    case 'critical':
    case 'high':
      return SecuritySeverity.Error;
    case 'moderate':
      return SecuritySeverity.Warning;
    default:
      return SecuritySeverity.Info;
  }
}

function checkGitignoreForSensitiveFiles(): void {
  const workspaceRoot = vscode.workspace.workspaceFolders?.[0]?.uri.fsPath;
  if (!workspaceRoot) { return; }

  const gitignorePath = path.join(workspaceRoot, '.gitignore');
  const sensitivePatterns = ['.env', 'credentials.json', 'serviceAccountKey'];
  const missingPatterns: string[] = [];

  if (fs.existsSync(gitignorePath)) {
    try {
      const content = fs.readFileSync(gitignorePath, 'utf-8');
      const lines = content.split('\n').map(l => l.trim());

      for (const pattern of sensitivePatterns) {
        // Check if any gitignore line covers this pattern
        const isCovered = lines.some(line => {
          if (line.startsWith('#') || line === '') { return false; }
          // Direct match or glob match
          return line === pattern || line === `${pattern}*` || line === `${pattern}.*`
            || line === `*${pattern}` || line === `**/${pattern}`
            || line.includes(pattern);
        });
        if (!isCovered) {
          missingPatterns.push(pattern);
        }
      }
    } catch {
      // Can't read .gitignore
      return;
    }
  } else {
    // No .gitignore at all
    missingPatterns.push(...sensitivePatterns);
  }

  if (missingPatterns.length > 0) {
    const issues: import('./types').SecurityIssue[] = [{
      line: 0,
      column: 0,
      message: `.gitignore is missing entries for sensitive files: ${missingPatterns.join(', ')}`,
      severity: SecuritySeverity.Warning,
      suggestion: `Add ${missingPatterns.join(', ')} to .gitignore to prevent accidental commits of sensitive data`,
      code: 'CRED007a',
      pattern: missingPatterns.join(', '),
      category: SecurityCategory.SecretsCredentials,
    }];

    const targetPath = fs.existsSync(gitignorePath) ? gitignorePath : path.join(workspaceRoot, '.gitignore (missing)');
    const relativePath = fs.existsSync(gitignorePath) ? '.gitignore' : '.gitignore (missing)';

    resultsStore.setFileResults(`gitignore-check:${gitignorePath}`, {
      filePath: targetPath,
      relativePath,
      languageId: 'ignore',
      issues,
      scannedAt: new Date(),
    });
  }
}

function updateHasResultsContext() {
  vscode.commands.executeCommand('setContext', 'caspian-security.hasResults', resultsStore.getTotalIssueCount() > 0);
}

function shouldCheckDocument(document: vscode.TextDocument): boolean {
  if (document.isUntitled || document.uri.scheme !== 'file') {
    return false;
  }

  const enabledLanguages = configManager.getEnabledLanguages();
  if (enabledLanguages.includes(document.languageId)) {
    return true;
  }

  // Fall back to resolving the language from the file path. Terraform has
  // no built-in VS Code language id (a .tf file opens as plaintext unless
  // the HashiCorp extension is installed), so a languageId check alone
  // would silently skip the infrastructure rules.
  const basename = path.basename(document.uri.fsPath);
  const byFilename = LANGUAGE_FILENAMES[basename];
  if (byFilename && enabledLanguages.includes(byFilename)) {
    return true;
  }
  const ext = path.extname(basename).slice(1).toLowerCase();
  for (const [lang, exts] of Object.entries(LANGUAGE_EXTENSIONS)) {
    if (exts.includes(ext)) {
      return enabledLanguages.includes(lang);
    }
  }
  return false;
}

async function executeAIFixFromPanel(
  issueData: {
    filePath: string; relativePath: string; line: number; column: number;
    code: string; pattern: string; message: string; suggestion: string;
    category: string; severity: string;
  },
  providerConfig: AIProviderConfig
): Promise<void> {
  const uri = vscode.Uri.file(issueData.filePath);
  let document: vscode.TextDocument;
  try {
    document = await vscode.workspace.openTextDocument(uri);
  } catch {
    vscode.window.showErrorMessage(`Cannot open file: ${issueData.filePath}`);
    return;
  }

  const fullContent = document.getText();
  const lines = fullContent.split('\n');
  const originalLine = lines[issueData.line] || '';

  // Check fix pattern memory for a cached fix before calling AI
  if (fixPatternMemory) {
    const cached = fixPatternMemory.findMatchingPattern(issueData.code, document.languageId, originalLine);
    if (cached && cached.successRate > 0) {
      const pct = Math.round(cached.successRate * 100);
      const choice = await vscode.window.showInformationMessage(
        `Caspian has a learned fix for this ${issueData.code} pattern (${pct}% success rate). Apply it?`,
        'Apply Learned Fix', 'Generate New AI Fix', 'Cancel'
      );
      if (choice === 'Apply Learned Fix') {
        const newLines = [...lines];
        newLines[issueData.line] = cached.suggestedFix;
        const fixedContent = newLines.join('\n');
        const applied = await showDiffAndApply(document, fullContent, {
          fixedFileContent: fixedContent,
          explanation: `Learned fix (from pattern memory): ${cached.pattern.explanation}`,
          confidence: 'high',
        });
        if (applied) {
          const key = FixTracker.makeKey(issueData.relativePath, issueData.code, issueData.line, issueData.pattern);
          fixTracker.markFixed(key, issueData.filePath, issueData.relativePath,
            issueData.code, issueData.line, issueData.pattern,
            cached.pattern.explanation, 'pattern-memory');
          if (ruleIntelligence) {
            ruleIntelligence.recordAction(issueData.code, 'fixed', document.languageId, issueData.filePath);
          }
          // Re-scan to verify the learned fix
          const updatedDoc = await vscode.workspace.openTextDocument(uri);
          await checkDocument(updatedDoc);
          const updatedResults = resultsStore.getFileResults(uri.toString());
          const stillPresent = updatedResults?.issues.some(
            i => i.code === issueData.code && i.line === issueData.line
          );
          fixPatternMemory.recordOutcome(cached.pattern.id, !stillPresent);
          if (stillPresent) {
            fixTracker.markFixFailed(key);
            if (ruleIntelligence) {
              ruleIntelligence.recordAction(issueData.code, 'fix_failed', document.languageId, issueData.filePath);
            }
            vscode.window.showWarningMessage('Learned fix applied but issue still detected. Try generating a new AI fix.');
          } else {
            vscode.window.showInformationMessage(`Issue ${issueData.code} fixed using learned pattern.`);
          }
        }
        return;
      } else if (choice === 'Cancel') {
        return;
      }
      // 'Generate New AI Fix' falls through to normal flow
    }
  }

  const startLine = Math.max(0, issueData.line - 10);
  const endLine = Math.min(lines.length, issueData.line + 11);
  const surroundingCode = lines.slice(startLine, endLine).join('\n');

  // Extract smart context: enclosing function scope + variable definitions
  const smartContext = await extractSmartContext(uri, issueData.line, originalLine);

  const functionScope = smartContext.functionContext?.functionBody;
  const variableDefinitions = smartContext.variableDefinitions.length > 0
    ? smartContext.variableDefinitions
        .map(v => `Line ${v.definitionLine + 1}: ${v.definitionText}`)
        .join('\n')
    : undefined;

  // F2 — explicit per-invocation consent + minimal-context default.
  // The dialog is shown BEFORE any network request so the user can cancel
  // before any file content leaves the workspace.
  const caspianConfig = vscode.workspace.getConfiguration('caspianSecurity');
  const minimalContext = caspianConfig.get<boolean>('aiFixMinimalContext', true);
  const requireConsent = caspianConfig.get<boolean>('aiFixRequireConsent', true);

  if (requireConsent) {
    const scopeDescription = minimalContext
      ? `~${endLine - startLine} lines around the finding (line ${issueData.line + 1})`
      : 'the ENTIRE file content';
    const consent = await vscode.window.showInformationMessage(
      `Send code to ${providerConfig.provider.toUpperCase()} to generate an AI fix?`,
      {
        modal: true,
        detail:
          `File: ${issueData.relativePath}\n` +
          `Provider: ${providerConfig.provider} (${providerConfig.model})\n` +
          `Scope: ${scopeDescription}\n\n` +
          `You pay the provider directly for API usage. You can change the scope in settings (caspianSecurity.aiFixMinimalContext).`,
      },
      'Send & Generate Fix',
      'Open AI Settings',
    );

    if (consent === 'Open AI Settings') {
      await vscode.commands.executeCommand('workbench.action.openSettings', 'caspianSecurity.aiFix');
      return;
    }
    if (consent !== 'Send & Generate Fix') {
      return; // user cancelled; nothing sent
    }
  }

  const request: AIFixRequest = {
    filePath: issueData.relativePath,
    languageId: document.languageId,
    issueCode: issueData.code,
    issueMessage: issueData.message,
    issueSuggestion: issueData.suggestion,
    issueCategory: issueData.category,
    issueSeverity: issueData.severity,
    issuePattern: issueData.pattern,
    issueLine: issueData.line,
    issueColumn: issueData.column,
    originalLineText: originalLine,
    surroundingCode,
    // In minimal mode we intentionally do NOT send the full file — only the
    // surroundingCode window. The response is spliced back into the file below.
    fullFileContent: minimalContext ? '' : fullContent,
    functionScope: minimalContext ? undefined : functionScope,
    variableDefinitions: minimalContext ? undefined : variableDefinitions,
    minimalContext,
    regionStartLine: minimalContext ? startLine : undefined,
    regionEndLine: minimalContext ? endLine - 1 : undefined,
  };

  await vscode.window.withProgress(
    {
      location: vscode.ProgressLocation.Notification,
      title: `Caspian Security: Generating AI fix for ${issueData.code}...`,
      cancellable: false,
    },
    async () => {
      try {
        const response = await aiFixService.generateFix(providerConfig, request);

        // In minimal-context mode the model returns only the fixed region; we
        // splice it back into the original file here so the rest of the flow
        // (diff preview, apply) can treat it uniformly as a full-file fix.
        let effectiveResponse = response;
        if (minimalContext) {
          const fixedRegion = response.fixedFileContent.replace(/\r\n/g, '\n');
          const before = lines.slice(0, startLine).join('\n');
          const after = lines.slice(endLine).join('\n');
          const reconstructed =
            (before ? before + '\n' : '') +
            fixedRegion +
            (after ? (fixedRegion.endsWith('\n') ? '' : '\n') + after : '');
          effectiveResponse = { ...response, fixedFileContent: reconstructed };
        }

        const applied = await showDiffAndApply(document, fullContent, effectiveResponse);
        if (applied) {
          const key = FixTracker.makeKey(issueData.relativePath, issueData.code, issueData.line, issueData.pattern);
          fixTracker.markFixed(
            key, issueData.filePath, issueData.relativePath,
            issueData.code, issueData.line, issueData.pattern,
            response.explanation, providerConfig.provider
          );

          // Record for rule intelligence learning
          if (ruleIntelligence) {
            ruleIntelligence.recordAction(issueData.code, 'fixed', document.languageId, issueData.filePath);
          }

          // Re-scan to verify
          const updatedDoc = await vscode.workspace.openTextDocument(uri);
          await checkDocument(updatedDoc);

          const updatedResults = resultsStore.getFileResults(uri.toString());
          if (updatedResults) {
            const stillPresent = updatedResults.issues.some(
              i => i.code === issueData.code && i.line === issueData.line
            );
            if (stillPresent) {
              fixTracker.markFixFailed(key);
              if (ruleIntelligence) {
                ruleIntelligence.recordAction(issueData.code, 'fix_failed', document.languageId, issueData.filePath);
              }
              vscode.window.showWarningMessage(
                `AI fix applied but issue ${issueData.code} still detected. The fix may be insufficient.`
              );
            } else {
              // Record successful fix pattern for future reuse
              if (fixPatternMemory || codebaseProfile) {
                const updatedDoc2 = await vscode.workspace.openTextDocument(uri);
                const updatedLines = updatedDoc2.getText().split('\n');
                const afterLine = updatedLines[issueData.line] || '';
                if (fixPatternMemory) {
                  fixPatternMemory.recordFix(
                    issueData.code, document.languageId,
                    originalLine, afterLine, response.explanation
                  );
                }
                if (codebaseProfile) {
                  codebaseProfile.learnFromAIFix(issueData.code, afterLine);
                }
              }
              vscode.window.showInformationMessage(`Issue ${issueData.code} fixed and verified.`);
            }
          }
        }
      } catch (error: any) {
        handleAIError(error);
      }
    }
  );
}

async function showDiffAndApply(
  document: vscode.TextDocument,
  originalContent: string,
  response: { fixedFileContent: string; explanation: string; confidence: string }
): Promise<boolean> {
  const choice = await vscode.window.showInformationMessage(
    `AI Fix Ready (confidence: ${response.confidence})`,
    { modal: true, detail: response.explanation },
    'Review Diff & Apply',
    'Cancel'
  );

  if (choice !== 'Review Diff & Apply') {
    return false;
  }

  // Show diff preview
  const proposedUri = vscode.Uri.parse(
    `caspian-fix-preview:${document.uri.path}?proposed&t=${Date.now()}`
  );
  fixPreviewProvider.setContent(proposedUri.toString(), response.fixedFileContent);

  await vscode.commands.executeCommand(
    'vscode.diff',
    document.uri,
    proposedUri,
    `${vscode.workspace.asRelativePath(document.uri)} (Original vs AI Fix)`,
    { preview: true }
  );

  const applyChoice = await vscode.window.showInformationMessage(
    'Apply this AI-generated fix?',
    'Apply',
    'Cancel'
  );

  if (applyChoice !== 'Apply') {
    return false;
  }

  const edit = new vscode.WorkspaceEdit();
  const fullRange = new vscode.Range(
    document.positionAt(0),
    document.positionAt(originalContent.length)
  );
  edit.replace(document.uri, fullRange, response.fixedFileContent);
  const success = await vscode.workspace.applyEdit(edit);

  if (success) {
    await document.save();
  } else {
    vscode.window.showErrorMessage('Failed to apply the fix. The file may be read-only.');
  }

  return success;
}

function handleAIError(error: any): void {
  if (error && error.type) {
    switch (error.type) {
      case 'auth':
        vscode.window.showErrorMessage('Caspian Security: Invalid API key. Please check your AI Settings.');
        break;
      case 'rate_limit':
        vscode.window.showErrorMessage('Caspian Security: API rate limit exceeded. Please try again later.');
        break;
      case 'network':
        vscode.window.showErrorMessage('Caspian Security: Network error. Check your internet connection.');
        break;
      case 'invalid_response':
        vscode.window.showErrorMessage('Caspian Security: AI returned an unexpected response. Try again or try a different model.');
        break;
      case 'no_key':
        vscode.window.showWarningMessage('Caspian Security: No API key configured. Open AI Settings to add one.');
        break;
      default:
        vscode.window.showErrorMessage(`Caspian Security: AI fix failed - ${error.message || 'Unknown error'}`);
    }
  } else {
    vscode.window.showErrorMessage(`Caspian Security: AI fix failed - ${String(error)}`);
  }
}

class FixPreviewContentProvider implements vscode.TextDocumentContentProvider {
  private contents = new Map<string, string>();
  private _onDidChange = new vscode.EventEmitter<vscode.Uri>();
  readonly onDidChange = this._onDidChange.event;

  setContent(uriString: string, content: string): void {
    this.contents.set(uriString, content);
    this._onDidChange.fire(vscode.Uri.parse(uriString));
  }

  provideTextDocumentContent(uri: vscode.Uri): string {
    return this.contents.get(uri.toString()) || '';
  }
}

export function deactivate() {
  console.log('Caspian Security deactivated');
}
