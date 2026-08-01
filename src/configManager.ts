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
  kotlin: ['kt', 'kts'],
  yaml: ['yaml', 'yml'],
  terraform: ['tf', 'tfvars', 'hcl'],
  dockerfile: [],
};

/**
 * Extension-less files matched by name (Dockerfiles). Mirrors the CLI's
 * FILENAME_TO_LANGUAGE in scanRunner.ts so editor and CLI agree.
 */
export const LANGUAGE_FILENAMES: Record<string, string> = {
  Dockerfile: 'dockerfile',
  dockerfile: 'dockerfile',
  Containerfile: 'dockerfile',
};

export const DEFAULT_ENABLED_LANGUAGES = [
  'javascript',
  'typescript',
  'python',
  'java',
  'csharp',
  'php',
  'go',
  'rust',
  'kotlin',
  'yaml',
  'terraform',
  'dockerfile',
];

export class ConfigManager {
  private static instance: ConfigManager;
  private config: vscode.WorkspaceConfiguration;
  private configChangeDisposable: vscode.Disposable;

  private constructor() {
    this.config = vscode.workspace.getConfiguration('caspianSecurity');

    this.configChangeDisposable = vscode.workspace.onDidChangeConfiguration((event) => {
      if (event.affectsConfiguration('caspianSecurity')) {
        this.config = vscode.workspace.getConfiguration('caspianSecurity');
      }
    });
  }

  static getInstance(): ConfigManager {
    if (!ConfigManager.instance) {
      ConfigManager.instance = new ConfigManager();
    }
    return ConfigManager.instance;
  }

  dispose(): void {
    this.configChangeDisposable.dispose();
  }

  get<T>(key: string, defaultValue: T): T {
    return this.config.get<T>(key, defaultValue);
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
    return this.config.get('enabledLanguages', DEFAULT_ENABLED_LANGUAGES);
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
    const filenames = Object.entries(LANGUAGE_FILENAMES)
      .filter(([, lang]) => languages.includes(lang))
      .map(([name]) => name);
    const parts: string[] = [];
    if (extensions.length === 1) {
      parts.push(`*.${extensions[0]}`);
    } else if (extensions.length > 1) {
      parts.push(`*.{${extensions.join(',')}}`);
    }
    parts.push(...filenames);
    if (parts.length === 0) { return ''; }
    if (parts.length === 1) { return `**/${parts[0]}`; }
    return `**/{${parts.join(',')}}`;
  }

  getEnabledCategories(): SecurityCategory[] {
    return Object.values(SecurityCategory).filter(category => {
      const key = CATEGORY_SETTING_KEYS[category];
      return this.config.get(key, true);
    });
  }

  getAutoVerify(): boolean {
    return this.config.get('autoVerify', true);
  }

  getDependencyCheckEnabled(): boolean {
    return this.config.get('includeDependencyCheck', true);
  }

  getShowInformational(): boolean {
    return this.config.get('showInformational', true);
  }

  getReduceInternalPathSeverity(): boolean {
    return this.config.get('reduceInternalPathSeverity', true);
  }

  getSkipGeneratedFiles(): boolean {
    return this.config.get('skipGeneratedFiles', true);
  }

  setSkipGeneratedFiles(value: boolean): void {
    this.config.update('skipGeneratedFiles', value, vscode.ConfigurationTarget.Global);
  }

  getMaxFileSize(): number {
    return this.config.get('maxFileSize', 500000);
  }

  getEnableTaintTracking(): boolean {
    return this.config.get('enableTaintTracking', true);
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
      DEFAULT_ENABLED_LANGUAGES,
      vscode.ConfigurationTarget.Global
    );
    for (const key of Object.values(CATEGORY_SETTING_KEYS)) {
      this.config.update(key, true, vscode.ConfigurationTarget.Global);
    }
  }
}