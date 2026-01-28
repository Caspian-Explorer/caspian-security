import * as vscode from 'vscode';

export class ConfigManager {
  private config: vscode.WorkspaceConfiguration;

  constructor() {
    this.config = vscode.workspace.getConfiguration('caspianSecurity');
    
    vscode.workspace.onDidChangeConfiguration((event) => {
      if (event.affectsConfiguration('caspianSecurity')) {
        this.config = vscode.workspace.getConfiguration('caspianSecurity');
      }
    });
  }

  getAutoCheck(): boolean {
    return this.config.get('autoCheck', true);
  }

  setAutoCheck(value: boolean): void {
    this.config.update('autoCheck', value, vscode.ConfigurationTarget.Global);
  }

  getCheckOnSave(): boolean {
    return this.config.get('checkOnSave', true);
  }

  setCheckOnSave(value: boolean): void {
    this.config.update('checkOnSave', value, vscode.ConfigurationTarget.Global);
  }

  getSeverityLevel(): string {
    return this.config.get('severity', 'warning');
  }

  setSeverityLevel(value: string): void {
    this.config.update('severity', value, vscode.ConfigurationTarget.Global);
  }

  getEnabledLanguages(): string[] {
    return this.config.get('enabledLanguages', [
      'javascript',
      'typescript',
      'python',
      'java',
      'csharp',
      'php',
      'go',
      'rust',
    ]);
  }

  setEnabledLanguages(languages: string[]): void {
    this.config.update('enabledLanguages', languages, vscode.ConfigurationTarget.Workspace);
  }

  isLanguageEnabled(languageId: string): boolean {
    return this.getEnabledLanguages().includes(languageId);
  }

  addLanguage(languageId: string): void {
    const languages = this.getEnabledLanguages();
    if (!languages.includes(languageId)) {
      languages.push(languageId);
      this.setEnabledLanguages(languages);
    }
  }

  removeLanguage(languageId: string): void {
    const languages = this.getEnabledLanguages().filter(lang => lang !== languageId);
    this.setEnabledLanguages(languages);
  }

  resetToDefaults(): void {
    this.config.update('autoCheck', true, vscode.ConfigurationTarget.Global);
    this.config.update('checkOnSave', true, vscode.ConfigurationTarget.Global);
    this.config.update('severity', 'warning', vscode.ConfigurationTarget.Global);
    this.config.update(
      'enabledLanguages',
      ['javascript', 'typescript', 'python', 'java', 'csharp', 'php', 'go', 'rust'],
      vscode.ConfigurationTarget.Global
    );
  }
}