import * as vscode from 'vscode';
import { SecurityAnalyzer } from './analyzer';
import { DiagnosticsManager } from './diagnosticsManager';
import { ConfigManager } from './configManager';

let analyzer: SecurityAnalyzer;
let diagnosticsManager: DiagnosticsManager;
let configManager: ConfigManager;

export function activate(context: vscode.ExtensionContext) {
  console.log('Caspian Security Extension activated');

  // Initialize managers
  configManager = new ConfigManager();
  diagnosticsManager = new DiagnosticsManager();
  analyzer = new SecurityAnalyzer();

  // Register commands
  registerCommands(context);

  // Register document listeners
  registerDocumentListeners();

  // Run initial check on open files
  runWorkspaceCheck();

  console.log('Caspian Security Extension initialized successfully');
}

function registerCommands(context: vscode.ExtensionContext) {
  // Check current file
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

  // Check entire workspace
  context.subscriptions.push(
    vscode.commands.registerCommand('caspian-security.runCheckWorkspace', async () => {
      await runWorkspaceCheck();
    })
  );

  // Show fix suggestion for diagnostic
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
  // Check on document open
  vscode.workspace.onDidOpenTextDocument(async (document) => {
    if (shouldCheckDocument(document)) {
      await checkDocument(document);
    }
  });

  // Check on document change (with debounce)
  let changeTimeout: NodeJS.Timeout;
  vscode.workspace.onDidChangeTextDocument((event) => {
    if (shouldCheckDocument(event.document) && configManager.getAutoCheck()) {
      clearTimeout(changeTimeout);
      changeTimeout = setTimeout(() => {
        checkDocument(event.document);
      }, 1000); // Debounce: wait 1 second after last change
    }
  });

  // Check on document save
  vscode.workspace.onDidSaveTextDocument((document) => {
    if (shouldCheckDocument(document) && configManager.getCheckOnSave()) {
      checkDocument(document);
    }
  });

  // Clear diagnostics when document is closed
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
      const count = issues.length;
      const severity = issues.reduce((max, issue) => 
        issue.severity > max ? issue.severity : max, 0
      );
      
      const severityLabel = ['Info', 'Warning', 'Error'][severity];
      console.log(`Found ${count} security ${severityLabel}(s) in ${document.fileName}`);
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
  // Skip untitled, git, and output documents
  if (document.isUntitled || document.uri.scheme !== 'file') {
    return false;
  }

  const enabledLanguages = configManager.getEnabledLanguages();
  return enabledLanguages.includes(document.languageId);
}

export function deactivate() {
  console.log('Caspian Security Extension deactivated');
}
