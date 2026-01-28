import * as vscode from 'vscode';
import { SecurityAnalyzer } from './analyzer';
import { DiagnosticsManager } from './diagnosticsManager';
import { ConfigManager } from './configManager';

let analyzer: SecurityAnalyzer;
let diagnosticsManager: DiagnosticsManager;
let configManager: ConfigManager;

export function activate(context: vscode.ExtensionContext) {
  console.log('Caspian Security Extension activated');

  configManager = new ConfigManager();
  diagnosticsManager = new DiagnosticsManager();
  analyzer = new SecurityAnalyzer();

  registerCommands(context);
  registerDocumentListeners();

  console.log('Caspian Security Extension initialized successfully');
}

function registerCommands(context: vscode.ExtensionContext) {
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
    vscode.commands.registerCommand('caspian-security.fixIssue', async (diagnostic: vscode.Diagnostic) => {
      const suggestion = (diagnostic as any).fixSuggestion;
      if (suggestion) {
        vscode.window.showInformationMessage(`Fix: ${suggestion}`);
      }
    })
  );
}

function registerDocumentListeners() {
  let changeTimeout: NodeJS.Timeout;

  vscode.workspace.onDidChangeTextDocument((event) => {
    if (!shouldCheckDocument(event.document)) {
      return;
    }

    const autoCheckEnabled = configManager.getAutoCheck();
    console.log('Auto check enabled:', autoCheckEnabled);

    if (autoCheckEnabled) {
      clearTimeout(changeTimeout);
      changeTimeout = setTimeout(() => {
        checkDocument(event.document);
      }, 1000);
    }
  });

  vscode.workspace.onDidSaveTextDocument((document) => {
    if (!shouldCheckDocument(document)) {
      return;
    }

    const checkOnSaveEnabled = configManager.getCheckOnSave();
    console.log('Check on save enabled:', checkOnSaveEnabled);

    if (checkOnSaveEnabled) {
      checkDocument(document);
    }
  });

  vscode.workspace.onDidCloseTextDocument((document) => {
    diagnosticsManager.clearDiagnostics(document.uri);
  });
}

async function checkDocument(document: vscode.TextDocument) {
  if (!shouldCheckDocument(document)) {
    return;
  }

  try {
    const issues = await analyzer.analyzeDocument(document);
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
  const documents = vscode.workspace.textDocuments.filter(doc => 
    shouldCheckDocument(doc)
  );

  if (documents.length === 0) {
    vscode.window.showInformationMessage('No supported files found in workspace');
    return;
  }

  vscode.window.withProgress(
    {
      location: vscode.ProgressLocation.Notification,
      title: 'Running security checks...',
      cancellable: false,
    },
    async (progress) => {
      for (const document of documents) {
        progress.report({
          message: `Checking ${document.fileName}`,
        });
        await checkDocument(document);
      }
    }
  );

  vscode.window.showInformationMessage('Security check completed');
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