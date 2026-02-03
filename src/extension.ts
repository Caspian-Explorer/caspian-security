import * as vscode from 'vscode';
import * as path from 'path';
import * as fs from 'fs';
import { SecurityAnalyzer } from './analyzer';
import { DiagnosticsManager } from './diagnosticsManager';
import { ConfigManager, LANGUAGE_EXTENSIONS } from './configManager';
import { SecurityCategory, SecuritySeverity, CATEGORY_LABELS, ProjectAdvisory } from './types';
import { ResultsStore } from './resultsStore';
import { StatusBarManager, ScanState } from './statusBarManager';
import { ResultsPanel } from './resultsPanel';
import { GitIntegration } from './gitIntegration';
import { checkDependencies, formatResultsAsText, DependencyCheckResult } from './dependencyChecker';
import { AIFixService, AIProviderConfig, AIFixRequest, AIFixError } from './aiFixService';
import { FixTracker } from './fixTracker';
import { AISettingsPanel } from './aiSettingsPanel';

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
    const language = extToLang[ext];
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

export function activate(context: vscode.ExtensionContext) {
  try {
    console.log('Caspian Security Extension activated');

    configManager = new ConfigManager();
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

    // Initialize git integration (non-blocking)
    gitIntegration.initialize();

    registerCommands(context);
    registerCategoryCommands(context);
    registerDocumentListeners(context);

    console.log('Caspian Security Extension initialized successfully');
  } catch (error) {
    console.error('Caspian Security failed to activate:', error);
    vscode.window.showErrorMessage('Caspian Security failed to activate. See Output for details.');
  }
}

function registerCommands(context: vscode.ExtensionContext) {
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
    vscode.commands.registerCommand('caspian-security.ignoreIssue', (issueData: {
      filePath: string; relativePath: string; line: number; code: string; pattern: string;
    }) => {
      const key = FixTracker.makeKey(issueData.relativePath, issueData.code, issueData.line, issueData.pattern);
      fixTracker.markIgnored(key, issueData.filePath, issueData.relativePath, issueData.code, issueData.line, issueData.pattern);
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
          vscode.window.showInformationMessage(
            `Issue ${issueData.code} verified as resolved.`
          );
        }
      } catch (error) {
        vscode.window.showErrorMessage(`Verification failed: ${error}`);
      }
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

  // New command: Scan Uncommitted Files
  context.subscriptions.push(
    vscode.commands.registerCommand('caspian-security.runCheckUncommitted', async () => {
      await runUncommittedCheck();
    })
  );

  // New command: Check Dependency & Stack Updates
  context.subscriptions.push(
    vscode.commands.registerCommand('caspian-security.checkDependencyUpdates', async () => {
      await runDependencyCheck();
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
          vscode.window.showWarningMessage('No active editor found');
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
  let changeTimeout: NodeJS.Timeout | undefined;

  context.subscriptions.push(
    vscode.workspace.onDidChangeTextDocument((event) => {
      if (!shouldCheckDocument(event.document)) {
        return;
      }

      if (configManager.getAutoCheck()) {
        clearTimeout(changeTimeout);
        changeTimeout = setTimeout(() => {
          checkDocument(event.document);
        }, 1000);
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
      diagnosticsManager.clearDiagnostics(document.uri);
      resultsStore.clearFileResults(document.uri.toString());
    })
  );

  context.subscriptions.push({
    dispose: () => {
      if (changeTimeout) {
        clearTimeout(changeTimeout);
      }
    }
  });
}

async function checkDocument(document: vscode.TextDocument, categories?: SecurityCategory[]) {
  if (!shouldCheckDocument(document)) {
    return;
  }

  try {
    const effectiveCategories = categories || configManager.getEnabledCategories();
    const issues = await analyzer.analyzeDocument(document, effectiveCategories);
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

    if (issues.length > 0) {
      console.log(`Found ${issues.length} security issues`);
    }
  } catch (error) {
    console.error('Error during security check:', error);
  }
}

async function runWorkspaceCheck() {
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
    'Start Scan',
    'Cancel'
  );
  if (startChoice !== 'Start Scan') {
    return;
  }

  let totalIssueCount = 0;
  let totalFilesScanned = 0;
  const startTime = Date.now();

  resultsStore.clearAll();
  statusBarManager.setState(ScanState.Scanning);

  let userStopped = false;

  for (let batchIndex = 0; batchIndex < batches.length; batchIndex++) {
    const batch = batches[batchIndex];
    let batchIssueCount = 0;
    let batchFilesScanned = 0;
    let batchCancelled = false;

    await vscode.window.withProgress(
      {
        location: vscode.ProgressLocation.Notification,
        title: `Caspian Security: Scanning ${batch.label} (batch ${batchIndex + 1}/${batches.length})`,
        cancellable: true,
      },
      async (progress, token) => {
        for (let i = 0; i < batch.files.length; i++) {
          if (token.isCancellationRequested) {
            batchCancelled = true;
            break;
          }

          // Yield to the event loop every 10 files to keep VS Code responsive
          if (i % 10 === 0 && i > 0) {
            await new Promise(resolve => setTimeout(resolve, 0));
          }

          const file = batch.files[i];
          const relativePath = vscode.workspace.asRelativePath(file);
          const elapsed = ((Date.now() - startTime) / 1000).toFixed(1);

          progress.report({
            message: `(${i + 1}/${batch.files.length}) ${relativePath} | ${elapsed}s elapsed`,
            increment: (1 / batch.files.length) * 100,
          });

          statusBarManager.showScanning(relativePath);

          const document = await vscode.workspace.openTextDocument(file);
          const categories = configManager.getEnabledCategories();
          const issues = await analyzer.analyzeDocument(document, categories);
          const diagnostics = diagnosticsManager.createDiagnostics(document, issues);
          diagnosticsManager.publishDiagnostics(document.uri, diagnostics);

          resultsStore.setFileResults(document.uri.toString(), {
            filePath: document.uri.fsPath,
            relativePath,
            languageId: document.languageId,
            issues,
            scannedAt: new Date(),
          });

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
    if (!isLastBatch) {
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

  // Collect project-level advisories from scanned files
  const allAdvisories: ProjectAdvisory[] = [];
  const advisoryFired = new Set<string>();
  for (const result of resultsStore.getAllResults()) {
    try {
      const doc = await vscode.workspace.openTextDocument(vscode.Uri.file(result.filePath));
      const categories = configManager.getEnabledCategories();
      const fileAdvisories = analyzer.collectProjectAdvisories(doc, categories);
      for (const advisory of fileAdvisories) {
        if (!advisoryFired.has(advisory.code)) {
          advisoryFired.add(advisory.code);
          allAdvisories.push(advisory);
        }
      }
    } catch {
      // File may be unavailable
    }
  }
  resultsStore.setProjectAdvisories(allAdvisories);

  // CRED007a: Check .gitignore for .env entries
  checkGitignoreForSensitiveFiles();

  const duration = Date.now() - startTime;
  resultsStore.setScanMeta(duration, userStopped ? 'workspace (partial)' : 'workspace');
  statusBarManager.showComplete();
  updateHasResultsContext();

  const advisoryNote = allAdvisories.length > 0 ? ` + ${allAdvisories.length} advisory(ies)` : '';
  vscode.window.showInformationMessage(
    `Caspian Security: Scan ${userStopped ? 'stopped' : 'complete'} — ${totalIssueCount} issue(s) found in ${totalFilesScanned} files${advisoryNote}`
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
        const issues = await analyzer.analyzeDocument(document, categories);
        const diagnostics = diagnosticsManager.createDiagnostics(document, issues);
        diagnosticsManager.publishDiagnostics(document.uri, diagnostics);

        resultsStore.setFileResults(document.uri.toString(), {
          filePath: document.uri.fsPath,
          relativePath,
          languageId: document.languageId,
          issues,
          scannedAt: new Date(),
        });

        issueCount += issues.length;
      }
    }
  );

  // Collect project-level advisories from scanned files
  const uncommittedAdvisories: ProjectAdvisory[] = [];
  const uncommittedAdvisoryFired = new Set<string>();
  for (const result of resultsStore.getAllResults()) {
    try {
      const doc = await vscode.workspace.openTextDocument(vscode.Uri.file(result.filePath));
      const categories = configManager.getEnabledCategories();
      const fileAdvisories = analyzer.collectProjectAdvisories(doc, categories);
      for (const advisory of fileAdvisories) {
        if (!uncommittedAdvisoryFired.has(advisory.code)) {
          uncommittedAdvisoryFired.add(advisory.code);
          uncommittedAdvisories.push(advisory);
        }
      }
    } catch {
      // File may be unavailable
    }
  }
  resultsStore.setProjectAdvisories(uncommittedAdvisories);

  // CRED007a: Check .gitignore for .env entries
  checkGitignoreForSensitiveFiles();

  const duration = Date.now() - startTime;
  resultsStore.setScanMeta(duration, 'uncommitted');
  statusBarManager.showComplete();
  updateHasResultsContext();

  vscode.window.showInformationMessage(
    `Caspian Security: Scan complete — ${issueCount} issue(s) found in ${supportedFiles.length} uncommitted files`
  );

  // Auto-open results panel after scan
  resultsPanel.show();
}

async function runDependencyCheck(): Promise<DependencyCheckResult | undefined> {
  const workspaceRoot = vscode.workspace.workspaceFolders?.[0]?.uri.fsPath;
  if (!workspaceRoot) {
    vscode.window.showWarningMessage('Caspian Security: No workspace folder open');
    return undefined;
  }

  const fs = await import('fs');
  const packageJsonPath = path.join(workspaceRoot, 'package.json');
  if (!fs.existsSync(packageJsonPath)) {
    vscode.window.showWarningMessage('Caspian Security: No package.json found in workspace root');
    return undefined;
  }

  let result: DependencyCheckResult | undefined;

  await vscode.window.withProgress(
    {
      location: vscode.ProgressLocation.Notification,
      title: 'Caspian Security: Checking dependency updates...',
      cancellable: false,
    },
    async () => {
      result = await checkDependencies(workspaceRoot);
    }
  );

  if (result) {
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
    vscode.window.showInformationMessage(
      `Caspian Security: ${outdatedCount} outdated package(s), ${vulnCount} vulnerability(ies) found. See Output panel.`
    );

    storeDependencyResultsAsIssues(result, workspaceRoot);
  }

  return result;
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
  return enabledLanguages.includes(document.languageId);
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
  const startLine = Math.max(0, issueData.line - 10);
  const endLine = Math.min(lines.length, issueData.line + 11);
  const surroundingCode = lines.slice(startLine, endLine).join('\n');

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
    fullFileContent: fullContent,
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
        const applied = await showDiffAndApply(document, fullContent, response);
        if (applied) {
          const key = FixTracker.makeKey(issueData.relativePath, issueData.code, issueData.line, issueData.pattern);
          fixTracker.markFixed(
            key, issueData.filePath, issueData.relativePath,
            issueData.code, issueData.line, issueData.pattern,
            response.explanation, providerConfig.provider
          );

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
              vscode.window.showWarningMessage(
                `AI fix applied but issue ${issueData.code} still detected. The fix may be insufficient.`
              );
            } else {
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
  console.log('Caspian Security Extension deactivated');
}
