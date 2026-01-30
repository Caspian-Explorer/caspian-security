import * as vscode from 'vscode';
import { SecurityCategory } from './types';

const CATEGORY_SETTING_KEYS: Record<SecurityCategory, string> = {
  [SecurityCategory.AuthAccessControl]: 'enableAuthAccessControl',
  [SecurityCategory.InputValidationXSS]: 'enableInputValidationXss',
  [SecurityCategory.CSRFProtection]: 'enableCsrfProtection',
  [SecurityCategory.CORSConfiguration]: 'enableCorsConfiguration',
  [SecurityCategory.EncryptionDataProtection]: 'enableEncryptionDataProtection',
  [SecurityCategory.APISecurity]: 'enableApiSecurity',
  [SecurityCategory.DatabaseSecurity]: 'enableDatabaseSecurity',
  [SecurityCategory.FileHandling]: 'enableFileHandling',
  [SecurityCategory.SecretsCredentials]: 'enableSecretsCredentials',
  [SecurityCategory.FrontendSecurity]: 'enableFrontendSecurity',
  [SecurityCategory.BusinessLogicPayment]: 'enableBusinessLogicPayment',
  [SecurityCategory.LoggingMonitoring]: 'enableLoggingMonitoring',
  [SecurityCategory.DependenciesSupplyChain]: 'enableDependenciesSupplyChain',
  [SecurityCategory.InfrastructureDeployment]: 'enableInfrastructureDeployment',
};

export const LANGUAGE_EXTENSIONS: Record<string, string[]> = {
  javascript: ['js', 'jsx', 'mjs', 'cjs'],
  typescript: ['ts', 'tsx', 'mts', 'cts'],
  python: ['py'],
  java: ['java'],
  csharp: ['cs'],
  php: ['php'],
  go: ['go'],
  rust: ['rs'],
};

export class ConfigManager {
  private config: vscode.WorkspaceConfiguration;
  private configChangeDisposable: vscode.Disposable;

  constructor() {
    this.config = vscode.workspace.getConfiguration('caspianSecurity');

    this.configChangeDisposable = vscode.workspace.onDidChangeConfiguration((event) => {
      if (event.affectsConfiguration('caspianSecurity')) {
        this.config = vscode.workspace.getConfiguration('caspianSecurity');
      }
    });
  }

  dispose(): void {
    this.configChangeDisposable.dispose();
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
    this.config.update('enabledLanguages', languages, vscode.ConfigurationTarget.Global);
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

  getFileGlobPattern(): string {
    const languages = this.getEnabledLanguages();
    const extensions = languages.flatMap(lang => LANGUAGE_EXTENSIONS[lang] || []);
    if (extensions.length === 0) { return ''; }
    if (extensions.length === 1) { return `**/*.${extensions[0]}`; }
    return `**/*.{${extensions.join(',')}}`;
  }

  getEnabledCategories(): SecurityCategory[] {
    return Object.values(SecurityCategory).filter(category => {
      const key = CATEGORY_SETTING_KEYS[category];
      return this.config.get(key, true);
    });
  }

  getDependencyCheckEnabled(): boolean {
    return this.config.get('includeDependencyCheck', true);
  }

  getAIProvider(): string {
    return this.config.get('aiProvider', 'anthropic');
  }

  setAIProvider(provider: string): void {
    this.config.update('aiProvider', provider, vscode.ConfigurationTarget.Global);
  }

  getAIModel(): string {
    return this.config.get('aiModel', '');
  }

  setAIModel(model: string): void {
    this.config.update('aiModel', model, vscode.ConfigurationTarget.Global);
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
    for (const key of Object.values(CATEGORY_SETTING_KEYS)) {
      this.config.update(key, true, vscode.ConfigurationTarget.Global);
    }
  }
}