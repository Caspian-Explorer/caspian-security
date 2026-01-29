import * as vscode from 'vscode';
import * as path from 'path';
import { SecurityAnalyzer } from './analyzer';
import { DiagnosticsManager } from './diagnosticsManager';
import { ConfigManager, LANGUAGE_EXTENSIONS } from './configManager';
import { SecurityCategory, CATEGORY_LABELS } from './types';
import { ResultsStore } from './resultsStore';
import { StatusBarManager, ScanState } from './statusBarManager';
import { ResultsPanel } from './resultsPanel';
import { GitIntegration } from './gitIntegration';

interface LanguageBatch {
  language: string;
  displayName: string;
  files: vscode.Uri[];
}

function groupFilesByLanguage(files: vscode.Uri[]): LanguageBatch[] {
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

  return Array.from(groups.entries())
    .map(([language, langFiles]) => ({
      language,
      displayName: language.charAt(0).toUpperCase() + language.slice(1),
      files: langFiles,
    }))
    .sort((a, b) => b.files.length - a.files.length);
}

let analyzer: SecurityAnalyzer;
let diagnosticsManager: DiagnosticsManager;
let configManager: ConfigManager;
let resultsStore: ResultsStore;
let statusBarManager: StatusBarManager;
let resultsPanel: ResultsPanel;
let gitIntegration: GitIntegration;

export function activate(context: vscode.ExtensionContext) {
  try {
    console.log('Caspian Security Extension activated');

    configManager = new ConfigManager();
    diagnosticsManager = new DiagnosticsManager();
    analyzer = new SecurityAnalyzer();
    resultsStore = new ResultsStore();
    statusBarManager = new StatusBarManager(resultsStore);
    resultsPanel = new ResultsPanel(context.extensionUri, resultsStore);
    gitIntegration = new GitIntegration();

    context.subscriptions.push(configManager);
    context.subscriptions.push(diagnosticsManager);
    context.subscriptions.push(resultsStore);
    context.subscriptions.push(statusBarManager);
    context.subscriptions.push(resultsPanel);
    context.subscriptions.push(gitIntegration);

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
      if (diagnostic && diagnostic.code) {
        const rule = analyzer.getRuleByCode(String(diagnostic.code));
        if (rule) {
          vscode.window.showInformationMessage(`Fix: ${rule.suggestion}`);
          return;
        }
      }
      vscode.window.showInformationMessage('No fix suggestion available for this issue.');
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

  const batches = groupFilesByLanguage(files);
  if (batches.length === 0) {
    vscode.window.showInformationMessage('No supported files found in workspace');
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
        title: `Caspian Security: Scanning ${batch.displayName} files (batch ${batchIndex + 1}/${batches.length})`,
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
        `Caspian Security: ${batch.displayName} batch complete — ${batchIssueCount} issue(s) in ${batchFilesScanned} files. `
        + `${remainingBatches} batch(es) remaining (${remainingFiles} files). `
        + `Next: ${nextBatch.displayName} (${nextBatch.files.length} files)`,
        'Continue',
        'Stop'
      );

      if (choice !== 'Continue') {
        userStopped = true;
        break;
      }
    }
  }

  const duration = Date.now() - startTime;
  resultsStore.setScanMeta(duration, userStopped ? 'workspace (partial)' : 'workspace');
  statusBarManager.showComplete();
  updateHasResultsContext();

  vscode.window.showInformationMessage(
    `Caspian Security: Scan ${userStopped ? 'stopped' : 'complete'} — ${totalIssueCount} issue(s) found in ${totalFilesScanned} files`
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

export function deactivate() {
  console.log('Caspian Security Extension deactivated');
}
