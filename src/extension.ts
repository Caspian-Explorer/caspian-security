import * as vscode from 'vscode';
import { SecurityAnalyzer } from './analyzer';
import { DiagnosticsManager } from './diagnosticsManager';
import { ConfigManager } from './configManager';
import { SecurityCategory, CATEGORY_LABELS } from './types';

let analyzer: SecurityAnalyzer;
let diagnosticsManager: DiagnosticsManager;
let configManager: ConfigManager;

export function activate(context: vscode.ExtensionContext) {
  try {
    console.log('Caspian Security Extension activated');

    configManager = new ConfigManager();
    diagnosticsManager = new DiagnosticsManager();
    analyzer = new SecurityAnalyzer();

    context.subscriptions.push(configManager);
    context.subscriptions.push(diagnosticsManager);

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

  const excludePattern = '**/node_modules/**';
  const files = await vscode.workspace.findFiles(globPattern, excludePattern);

  if (files.length === 0) {
    vscode.window.showInformationMessage('No supported files found in workspace');
    return;
  }

  let issueCount = 0;

  await vscode.window.withProgress(
    {
      location: vscode.ProgressLocation.Notification,
      title: 'Caspian Security: Scanning workspace...',
      cancellable: true,
    },
    async (progress, token) => {
      for (let i = 0; i < files.length; i++) {
        if (token.isCancellationRequested) { break; }

        progress.report({
          message: `(${i + 1}/${files.length}) ${vscode.workspace.asRelativePath(files[i])}`,
          increment: (1 / files.length) * 100,
        });

        const document = await vscode.workspace.openTextDocument(files[i]);
        const categories = configManager.getEnabledCategories();
        const issues = await analyzer.analyzeDocument(document, categories);
        const diagnostics = diagnosticsManager.createDiagnostics(document, issues);
        diagnosticsManager.publishDiagnostics(document.uri, diagnostics);
        issueCount += issues.length;
      }
    }
  );

  vscode.window.showInformationMessage(
    `Caspian Security: Scan complete — ${issueCount} issue(s) found in ${files.length} files`
  );
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
