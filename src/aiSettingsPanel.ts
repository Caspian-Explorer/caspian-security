import * as vscode from 'vscode';
import { AIFixService, AIProvider } from './aiFixService';

const DEFAULT_MODELS: Record<AIProvider, string> = {
  anthropic: 'claude-sonnet-4-20250514',
  openai: 'gpt-4o',
  gemini: 'gemini-2.0-flash',
};

const PROVIDER_LABELS: Record<AIProvider, string> = {
  anthropic: 'Anthropic Claude',
  openai: 'OpenAI GPT-4',
  gemini: 'Google Gemini',
};

const PROVIDER_LINKS: Record<AIProvider, string> = {
  anthropic: 'https://console.anthropic.com/settings/keys',
  openai: 'https://platform.openai.com/api-keys',
  gemini: 'https://aistudio.google.com/app/apikey',
};

export class AISettingsPanel implements vscode.Disposable {
  private panel: vscode.WebviewPanel | undefined;
  private disposables: vscode.Disposable[] = [];

  constructor(
    private extensionUri: vscode.Uri,
    private secretStorage: vscode.SecretStorage,
    private aiFixService: AIFixService,
  ) {}

  async show(): Promise<void> {
    if (this.panel) {
      this.panel.reveal(vscode.ViewColumn.One);
      await this.sendState();
      return;
    }

    this.panel = vscode.window.createWebviewPanel(
      'caspianAISettings',
      'Caspian Security - AI Settings',
      vscode.ViewColumn.One,
      {
        enableScripts: true,
        retainContextWhenHidden: true,
      }
    );

    this.panel.webview.html = this.getWebviewContent();
    this.panel.webview.onDidReceiveMessage(
      (message) => this.handleMessage(message),
      null,
      this.disposables
    );

    this.panel.onDidDispose(() => {
      this.panel = undefined;
    }, null, this.disposables);

    setTimeout(() => this.sendState(), 100);
  }

  private async sendState(): Promise<void> {
    if (!this.panel) { return; }

    const config = vscode.workspace.getConfiguration('caspianSecurity');
    const provider = config.get<AIProvider>('aiProvider', 'anthropic');
    const model = config.get<string>('aiModel', '') || DEFAULT_MODELS[provider];
    const hasKey = await this.aiFixService.hasApiKey(provider);

    this.panel.webview.postMessage({
      type: 'updateState',
      provider,
      model,
      hasKey,
      defaultModel: DEFAULT_MODELS[provider],
    });
  }

  private async handleMessage(message: any): Promise<void> {
    switch (message.type) {
      case 'saveKey': {
        const provider = message.provider as AIProvider;
        const key = message.key as string;
        if (key && key.length > 0) {
          await this.aiFixService.saveApiKey(provider, key);
          await this.sendState();
          this.panel?.webview.postMessage({
            type: 'keySaved',
            success: true,
          });
        }
        break;
      }
      case 'clearKey': {
        const provider = message.provider as AIProvider;
        await this.aiFixService.clearApiKey(provider);
        await this.sendState();
        this.panel?.webview.postMessage({
          type: 'keyCleared',
        });
        break;
      }
      case 'setProvider': {
        const provider = message.provider as AIProvider;
        const config = vscode.workspace.getConfiguration('caspianSecurity');
        await config.update('aiProvider', provider, vscode.ConfigurationTarget.Global);
        await this.sendState();
        break;
      }
      case 'setModel': {
        const model = message.model as string;
        const config = vscode.workspace.getConfiguration('caspianSecurity');
        await config.update('aiModel', model, vscode.ConfigurationTarget.Global);
        break;
      }
      case 'testConnection': {
        const providerConfig = await this.aiFixService.getProviderConfig();
        if (!providerConfig) {
          this.panel?.webview.postMessage({
            type: 'testResult',
            success: false,
            message: 'No API key configured for the selected provider.',
          });
          return;
        }
        const result = await this.aiFixService.testConnection(providerConfig);
        this.panel?.webview.postMessage({
          type: 'testResult',
          success: result.success,
          message: result.message,
        });
        break;
      }
    }
  }

  private getWebviewContent(): string {
    const nonce = getNonce();

    return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; script-src 'nonce-${nonce}';">
  <title>Caspian Security - AI Settings</title>
  <style>
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body {
      background: var(--vscode-editor-background);
      color: var(--vscode-editor-foreground);
      font-family: var(--vscode-font-family);
      font-size: var(--vscode-font-size, 13px);
      padding: 20px;
      max-width: 600px;
      margin: 0 auto;
    }

    h1 { font-size: 18px; font-weight: 600; margin-bottom: 8px; }
    .subtitle { color: var(--vscode-descriptionForeground); font-size: 13px; margin-bottom: 24px; }

    .section {
      margin-bottom: 24px;
      padding: 16px;
      border: 1px solid var(--vscode-panel-border);
      border-radius: 6px;
    }
    .section-title { font-size: 14px; font-weight: 600; margin-bottom: 12px; }

    .form-group { margin-bottom: 16px; }
    .form-group label {
      display: block;
      font-size: 12px;
      font-weight: 500;
      margin-bottom: 6px;
      color: var(--vscode-editor-foreground);
    }
    .form-group select, .form-group input {
      width: 100%;
      padding: 8px 10px;
      background: var(--vscode-input-background);
      color: var(--vscode-input-foreground);
      border: 1px solid var(--vscode-input-border, var(--vscode-panel-border));
      border-radius: 4px;
      font-size: 13px;
      font-family: inherit;
    }
    .form-group select:focus, .form-group input:focus {
      outline: none;
      border-color: var(--vscode-focusBorder);
    }
    .form-group small {
      display: block;
      margin-top: 4px;
      font-size: 11px;
      color: var(--vscode-descriptionForeground);
    }
    .form-group a {
      color: var(--vscode-textLink-foreground);
      text-decoration: none;
    }
    .form-group a:hover { text-decoration: underline; }

    .btn-row { display: flex; gap: 8px; margin-top: 12px; }

    .btn {
      background: var(--vscode-button-background);
      color: var(--vscode-button-foreground);
      border: none;
      padding: 8px 16px;
      cursor: pointer;
      font-size: 13px;
      border-radius: 4px;
    }
    .btn:hover { background: var(--vscode-button-hoverBackground); }
    .btn-secondary {
      background: var(--vscode-button-secondaryBackground);
      color: var(--vscode-button-secondaryForeground);
    }
    .btn-secondary:hover { background: var(--vscode-button-secondaryHoverBackground); }
    .btn-danger {
      background: transparent;
      color: var(--vscode-errorForeground, #f44336);
      border: 1px solid var(--vscode-errorForeground, #f44336);
    }
    .btn-danger:hover { background: rgba(244, 67, 54, 0.1); }

    .status-msg {
      padding: 8px 12px;
      border-radius: 4px;
      font-size: 12px;
      margin-top: 12px;
      display: none;
    }
    .status-msg.success {
      display: block;
      color: #4caf50;
      background: rgba(76, 175, 80, 0.1);
      border-left: 3px solid #4caf50;
    }
    .status-msg.error {
      display: block;
      color: var(--vscode-errorForeground, #f44336);
      background: rgba(244, 67, 54, 0.1);
      border-left: 3px solid var(--vscode-errorForeground, #f44336);
    }
    .status-msg.info {
      display: block;
      color: var(--vscode-descriptionForeground);
      background: rgba(33, 150, 243, 0.1);
      border-left: 3px solid var(--vscode-textLink-foreground);
    }

    .key-status {
      font-size: 12px;
      margin-bottom: 12px;
      padding: 6px 10px;
      border-radius: 4px;
    }
    .key-status.has-key {
      color: #4caf50;
      background: rgba(76, 175, 80, 0.1);
    }
    .key-status.no-key {
      color: var(--vscode-editorWarning-foreground, #ff9800);
      background: rgba(255, 152, 0, 0.1);
    }

    .info-box {
      padding: 12px;
      border-left: 3px solid var(--vscode-textLink-foreground);
      background: rgba(33, 150, 243, 0.05);
      border-radius: 4px;
      font-size: 12px;
      color: var(--vscode-descriptionForeground);
      margin-top: 16px;
    }
  </style>
</head>
<body>
  <h1>AI Fix Settings</h1>
  <p class="subtitle">Configure your AI provider to enable automatic security fix generation.</p>

  <div class="section">
    <div class="section-title">AI Provider</div>

    <div class="form-group">
      <label for="provider-select">Provider</label>
      <select id="provider-select">
        <option value="anthropic">Anthropic Claude</option>
        <option value="openai">OpenAI GPT-4</option>
        <option value="gemini">Google Gemini</option>
      </select>
    </div>

    <div class="form-group">
      <label for="model-input">Model</label>
      <input type="text" id="model-input" placeholder="Leave empty for provider default">
      <small>Default: <span id="default-model-label"></span></small>
    </div>
  </div>

  <div class="section">
    <div class="section-title">API Key</div>

    <div class="key-status no-key" id="key-status">No API key configured</div>

    <div class="form-group">
      <label for="api-key-input">API Key</label>
      <input type="password" id="api-key-input" placeholder="Paste your API key here...">
      <small>
        <a href="#" id="get-key-link">Get your API key</a> |
        Your key is stored securely in the OS keychain, never in settings.json.
      </small>
    </div>

    <div class="btn-row">
      <button class="btn" id="btn-save">Save Key</button>
      <button class="btn btn-secondary" id="btn-test">Test Connection</button>
      <button class="btn btn-danger" id="btn-clear">Clear Key</button>
    </div>

    <div class="status-msg" id="status-msg"></div>
  </div>

  <div class="info-box">
    Your API keys are stored in your operating system's secure keychain via VS Code's SecretStorage API.
    They are never written to settings.json or sent to any server other than the AI provider you selected.
    You pay the AI provider directly for API usage.
  </div>

<script nonce="${nonce}">
(function() {
  const vscode = acquireVsCodeApi();

  const providerSelect = document.getElementById('provider-select');
  const modelInput = document.getElementById('model-input');
  const defaultModelLabel = document.getElementById('default-model-label');
  const apiKeyInput = document.getElementById('api-key-input');
  const keyStatus = document.getElementById('key-status');
  const statusMsg = document.getElementById('status-msg');
  const getKeyLink = document.getElementById('get-key-link');

  const defaultModels = {
    anthropic: 'claude-sonnet-4-20250514',
    openai: 'gpt-4o',
    gemini: 'gemini-2.0-flash',
  };

  const keyLinks = {
    anthropic: 'https://console.anthropic.com/settings/keys',
    openai: 'https://platform.openai.com/api-keys',
    gemini: 'https://aistudio.google.com/app/apikey',
  };

  providerSelect.addEventListener('change', () => {
    const provider = providerSelect.value;
    vscode.postMessage({ type: 'setProvider', provider });
    defaultModelLabel.textContent = defaultModels[provider] || '';
    getKeyLink.href = keyLinks[provider] || '#';
    hideStatus();
  });

  modelInput.addEventListener('change', () => {
    vscode.postMessage({ type: 'setModel', model: modelInput.value });
  });

  document.getElementById('btn-save').addEventListener('click', () => {
    const key = apiKeyInput.value.trim();
    if (!key) {
      showStatus('Please enter an API key.', 'error');
      return;
    }
    vscode.postMessage({
      type: 'saveKey',
      provider: providerSelect.value,
      key: key,
    });
  });

  document.getElementById('btn-test').addEventListener('click', () => {
    showStatus('Testing connection...', 'info');
    vscode.postMessage({ type: 'testConnection' });
  });

  document.getElementById('btn-clear').addEventListener('click', () => {
    vscode.postMessage({
      type: 'clearKey',
      provider: providerSelect.value,
    });
    apiKeyInput.value = '';
  });

  window.addEventListener('message', event => {
    const msg = event.data;

    if (msg.type === 'updateState') {
      providerSelect.value = msg.provider;
      modelInput.value = msg.model !== msg.defaultModel ? msg.model : '';
      modelInput.placeholder = msg.defaultModel || 'Leave empty for default';
      defaultModelLabel.textContent = msg.defaultModel || '';
      getKeyLink.href = keyLinks[msg.provider] || '#';

      if (msg.hasKey) {
        keyStatus.textContent = 'API key is configured';
        keyStatus.className = 'key-status has-key';
      } else {
        keyStatus.textContent = 'No API key configured';
        keyStatus.className = 'key-status no-key';
      }
    }

    if (msg.type === 'keySaved') {
      showStatus('API key saved securely.', 'success');
      apiKeyInput.value = '';
      keyStatus.textContent = 'API key is configured';
      keyStatus.className = 'key-status has-key';
    }

    if (msg.type === 'keyCleared') {
      showStatus('API key cleared.', 'info');
      keyStatus.textContent = 'No API key configured';
      keyStatus.className = 'key-status no-key';
    }

    if (msg.type === 'testResult') {
      showStatus(msg.message, msg.success ? 'success' : 'error');
    }
  });

  function showStatus(text, type) {
    statusMsg.textContent = text;
    statusMsg.className = 'status-msg ' + type;
  }

  function hideStatus() {
    statusMsg.className = 'status-msg';
  }
})();
</script>
</body>
</html>`;
  }

  dispose(): void {
    this.panel?.dispose();
    this.disposables.forEach(d => d.dispose());
    this.disposables = [];
  }
}

function getNonce(): string {
  let text = '';
  const possible = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
  for (let i = 0; i < 32; i++) {
    text += possible.charAt(Math.floor(Math.random() * possible.length));
  }
  return text;
}
