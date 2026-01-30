import * as vscode from 'vscode';
import * as https from 'https';

export type AIProvider = 'anthropic' | 'openai' | 'gemini';

export interface AIProviderConfig {
  provider: AIProvider;
  apiKey: string;
  model: string;
}

export interface AIFixRequest {
  filePath: string;
  languageId: string;
  issueCode: string;
  issueMessage: string;
  issueSuggestion: string;
  issueCategory: string;
  issueSeverity: string;
  issuePattern: string;
  issueLine: number;
  issueColumn: number;
  originalLineText: string;
  surroundingCode: string;
  fullFileContent: string;
}

export interface AIFixResponse {
  fixedFileContent: string;
  explanation: string;
  confidence: 'high' | 'medium' | 'low';
}

export interface AIFixError {
  type: 'network' | 'auth' | 'rate_limit' | 'invalid_response' | 'no_key' | 'unknown';
  message: string;
  retryable: boolean;
}

const DEFAULT_MODELS: Record<AIProvider, string> = {
  anthropic: 'claude-sonnet-4-20250514',
  openai: 'gpt-4o',
  gemini: 'gemini-2.0-flash',
};

const SECRET_KEY_PREFIX = 'caspianSecurity.apiKey';

export function buildFixPrompt(request: AIFixRequest): { system: string; user: string } {
  const system = `You are a security-focused code repair tool. You receive a code file with a specific security vulnerability detected by a static analysis scanner. Your task is to fix ONLY the identified security issue while preserving all other functionality.

Rules:
1. Return the COMPLETE file content with the fix applied (not a diff, not a snippet).
2. Fix ONLY the security issue described. Do not refactor, rename, or change anything else.
3. The fix must be minimal and precise.
4. If the fix requires adding an import, add it at the top of the file.
5. Preserve all whitespace, formatting, and comments outside the fix area.
6. After the fixed file content, provide a brief explanation of what you changed and why.

Response format (you MUST follow this exactly):
---FIXED_FILE_START---
<entire fixed file content here>
---FIXED_FILE_END---
---EXPLANATION_START---
<brief explanation>
---EXPLANATION_END---
---CONFIDENCE_START---
<high|medium|low>
---CONFIDENCE_END---`;

  const user = `File: ${request.filePath}
Language: ${request.languageId}

Security Issue Detected:
- Code: ${request.issueCode}
- Message: ${request.issueMessage}
- Category: ${request.issueCategory}
- Severity: ${request.issueSeverity}
- Suggestion: ${request.issueSuggestion}
- Line: ${request.issueLine + 1} (1-based)
- Column: ${request.issueColumn + 1} (1-based)
- Matched pattern: ${request.issuePattern}

The problematic line:
\`\`\`
${request.originalLineText}
\`\`\`

Surrounding context (lines ${Math.max(1, request.issueLine - 9)}-${request.issueLine + 11}):
\`\`\`${request.languageId}
${request.surroundingCode}
\`\`\`

Complete file content to fix:
\`\`\`${request.languageId}
${request.fullFileContent}
\`\`\`

Apply ONLY the minimum fix needed to resolve the "${request.issueCode}" security issue.`;

  return { system, user };
}

export class AIFixService implements vscode.Disposable {
  constructor(private secretStorage: vscode.SecretStorage) {}

  async getProviderConfig(): Promise<AIProviderConfig | undefined> {
    const config = vscode.workspace.getConfiguration('caspianSecurity');
    const provider = config.get<AIProvider>('aiProvider', 'anthropic');
    const modelOverride = config.get<string>('aiModel', '');
    const model = modelOverride || DEFAULT_MODELS[provider];

    const apiKey = await this.secretStorage.get(`${SECRET_KEY_PREFIX}.${provider}`);
    if (!apiKey) {
      return undefined;
    }

    return { provider, apiKey, model };
  }

  async saveApiKey(provider: AIProvider, key: string): Promise<void> {
    await this.secretStorage.store(`${SECRET_KEY_PREFIX}.${provider}`, key);
  }

  async clearApiKey(provider: AIProvider): Promise<void> {
    await this.secretStorage.delete(`${SECRET_KEY_PREFIX}.${provider}`);
  }

  async hasApiKey(provider: AIProvider): Promise<boolean> {
    const key = await this.secretStorage.get(`${SECRET_KEY_PREFIX}.${provider}`);
    return !!key;
  }

  async generateFix(config: AIProviderConfig, request: AIFixRequest): Promise<AIFixResponse> {
    const { system, user } = buildFixPrompt(request);
    let raw: string;

    try {
      switch (config.provider) {
        case 'anthropic':
          raw = await this.callAnthropic(config.apiKey, config.model, system, user);
          break;
        case 'openai':
          raw = await this.callOpenAI(config.apiKey, config.model, system, user);
          break;
        case 'gemini':
          raw = await this.callGemini(config.apiKey, config.model, system, user);
          break;
        default:
          throw this.makeError('unknown', `Unsupported provider: ${config.provider}`, false);
      }
    } catch (error: any) {
      if (error.type) {
        throw error; // Already an AIFixError
      }
      throw this.makeError('network', error.message || 'Network request failed', true);
    }

    return this.parseResponse(raw);
  }

  async testConnection(config: AIProviderConfig): Promise<{ success: boolean; message: string }> {
    try {
      const testPrompt = 'Reply with exactly: CONNECTION_OK';
      let response: string;

      switch (config.provider) {
        case 'anthropic':
          response = await this.callAnthropic(config.apiKey, config.model, 'You are a test assistant.', testPrompt);
          break;
        case 'openai':
          response = await this.callOpenAI(config.apiKey, config.model, 'You are a test assistant.', testPrompt);
          break;
        case 'gemini':
          response = await this.callGemini(config.apiKey, config.model, 'You are a test assistant.', testPrompt);
          break;
        default:
          return { success: false, message: `Unsupported provider: ${config.provider}` };
      }

      return { success: true, message: `Connected to ${config.provider} (${config.model})` };
    } catch (error: any) {
      const msg = error.message || 'Connection failed';
      return { success: false, message: msg };
    }
  }

  private callAnthropic(apiKey: string, model: string, system: string, user: string): Promise<string> {
    const body = JSON.stringify({
      model,
      max_tokens: 8192,
      system,
      messages: [{ role: 'user', content: user }],
    });

    return this.httpsPost(
      'api.anthropic.com',
      '/v1/messages',
      {
        'Content-Type': 'application/json',
        'x-api-key': apiKey,
        'anthropic-version': '2023-06-01',
      },
      body,
      (parsed) => {
        if (parsed.content && parsed.content[0] && parsed.content[0].text) {
          return parsed.content[0].text;
        }
        throw this.makeError('invalid_response', 'Unexpected Anthropic response structure', true);
      }
    );
  }

  private callOpenAI(apiKey: string, model: string, system: string, user: string): Promise<string> {
    const body = JSON.stringify({
      model,
      max_tokens: 8192,
      messages: [
        { role: 'system', content: system },
        { role: 'user', content: user },
      ],
    });

    return this.httpsPost(
      'api.openai.com',
      '/v1/chat/completions',
      {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${apiKey}`,
      },
      body,
      (parsed) => {
        if (parsed.choices && parsed.choices[0] && parsed.choices[0].message) {
          return parsed.choices[0].message.content;
        }
        throw this.makeError('invalid_response', 'Unexpected OpenAI response structure', true);
      }
    );
  }

  private callGemini(apiKey: string, model: string, system: string, user: string): Promise<string> {
    const body = JSON.stringify({
      systemInstruction: { parts: [{ text: system }] },
      contents: [{ parts: [{ text: user }] }],
    });

    return this.httpsPost(
      'generativelanguage.googleapis.com',
      `/v1beta/models/${model}:generateContent?key=${apiKey}`,
      { 'Content-Type': 'application/json' },
      body,
      (parsed) => {
        if (parsed.candidates && parsed.candidates[0] && parsed.candidates[0].content) {
          const parts = parsed.candidates[0].content.parts;
          if (parts && parts[0] && parts[0].text) {
            return parts[0].text;
          }
        }
        throw this.makeError('invalid_response', 'Unexpected Gemini response structure', true);
      }
    );
  }

  private httpsPost(
    hostname: string,
    path: string,
    headers: Record<string, string>,
    body: string,
    extractContent: (parsed: any) => string
  ): Promise<string> {
    return new Promise((resolve, reject) => {
      const options: https.RequestOptions = {
        hostname,
        port: 443,
        path,
        method: 'POST',
        headers: {
          ...headers,
          'Content-Length': Buffer.byteLength(body),
        },
        timeout: 60000,
      };

      const req = https.request(options, (res) => {
        let data = '';
        res.on('data', (chunk) => { data += chunk; });
        res.on('end', () => {
          try {
            if (res.statusCode === 401 || res.statusCode === 403) {
              reject(this.makeError('auth', 'Invalid API key', false));
              return;
            }
            if (res.statusCode === 429) {
              reject(this.makeError('rate_limit', 'API rate limit exceeded', true));
              return;
            }
            if (res.statusCode && res.statusCode >= 400) {
              let msg = `API error (${res.statusCode})`;
              try {
                const parsed = JSON.parse(data);
                msg = parsed.error?.message || parsed.message || msg;
              } catch { /* use default message */ }
              reject(this.makeError('unknown', msg, res.statusCode >= 500));
              return;
            }

            const parsed = JSON.parse(data);
            resolve(extractContent(parsed));
          } catch (err: any) {
            if (err.type) {
              reject(err);
            } else {
              reject(this.makeError('invalid_response', `Failed to parse response: ${err.message}`, true));
            }
          }
        });
      });

      req.on('error', (err) => {
        reject(this.makeError('network', err.message, true));
      });

      req.on('timeout', () => {
        req.destroy();
        reject(this.makeError('network', 'Request timed out', true));
      });

      req.write(body);
      req.end();
    });
  }

  private parseResponse(raw: string): AIFixResponse {
    const fileMatch = raw.match(/---FIXED_FILE_START---\n?([\s\S]*?)\n?---FIXED_FILE_END---/);
    const explMatch = raw.match(/---EXPLANATION_START---\n?([\s\S]*?)\n?---EXPLANATION_END---/);
    const confMatch = raw.match(/---CONFIDENCE_START---\n?([\s\S]*?)\n?---CONFIDENCE_END---/);

    if (!fileMatch || !fileMatch[1]) {
      throw this.makeError('invalid_response', 'AI response missing fixed file content', true);
    }

    const fixedFileContent = fileMatch[1].trim();
    const explanation = explMatch ? explMatch[1].trim() : 'No explanation provided';
    const confidenceRaw = confMatch ? confMatch[1].trim().toLowerCase() : 'medium';
    const confidence = (['high', 'medium', 'low'].includes(confidenceRaw)
      ? confidenceRaw
      : 'medium') as 'high' | 'medium' | 'low';

    if (fixedFileContent.length === 0) {
      throw this.makeError('invalid_response', 'AI returned empty file content', true);
    }

    return { fixedFileContent, explanation, confidence };
  }

  private makeError(type: AIFixError['type'], message: string, retryable: boolean): AIFixError {
    return { type, message, retryable };
  }

  dispose(): void {}
}
