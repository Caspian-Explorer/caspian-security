/**
 * Shared I/O for Claude Code hook entry points.
 *
 * Contract (per the Claude Code hooks reference):
 *   - One JSON object arrives on stdin: { session_id, cwd, hook_event_name,
 *     tool_name, tool_input, stop_hook_active?, ... }.
 *   - PreToolUse denies via stdout JSON (hookSpecificOutput.permissionDecision)
 *     with exit 0.
 *   - PostToolUse blocks via exit 2 + stderr (fed back to the model), or adds
 *     non-blocking context via stdout JSON with exit 0. Stdout JSON is
 *     ignored on exit 2 — never mix.
 *   - Stop blocks stopping via exit 2 + stderr.
 *
 * FAIL OPEN, ALWAYS: any parse failure, engine crash, or unexpected state
 * exits 0 with no output. A security hook that breaks the agent loop gets
 * uninstalled within a day; a silently skipped scan does not.
 */

export interface HookInput {
  session_id?: string;
  cwd?: string;
  hook_event_name?: string;
  tool_name?: string;
  tool_input?: Record<string, unknown>;
  stop_hook_active?: boolean;
}

export function readStdin(): Promise<string> {
  return new Promise(resolve => {
    let data = '';
    let settled = false;
    const done = (): void => {
      if (!settled) { settled = true; resolve(data); }
    };
    // Guard against a caller that never closes stdin.
    const timer = setTimeout(done, 3000);
    timer.unref?.();
    process.stdin.setEncoding('utf-8');
    process.stdin.on('data', chunk => { data += chunk; });
    process.stdin.on('end', done);
    process.stdin.on('error', done);
  });
}

export function parseHookInput(raw: string): HookInput {
  try {
    const parsed = JSON.parse(raw);
    return parsed && typeof parsed === 'object' ? parsed as HookInput : {};
  } catch {
    return {};
  }
}

/**
 * Extract the text a Write/Edit/MultiEdit call is about to put in the file.
 * The exact tool_input schema is not formally documented, so every known
 * shape is checked defensively:
 *   Write     → { file_path, content }
 *   Edit      → { file_path, old_string, new_string }
 *   MultiEdit → { file_path, edits: [{ old_string, new_string }, ...] }
 */
export function extractWriteContent(toolInput: Record<string, unknown> | undefined): string {
  if (!toolInput) { return ''; }
  const parts: string[] = [];
  if (typeof toolInput.content === 'string') { parts.push(toolInput.content); }
  if (typeof toolInput.new_string === 'string') { parts.push(toolInput.new_string); }
  if (Array.isArray(toolInput.edits)) {
    for (const edit of toolInput.edits) {
      if (edit && typeof (edit as any).new_string === 'string') {
        parts.push((edit as any).new_string);
      }
    }
  }
  return parts.join('\n');
}

export function extractFilePath(toolInput: Record<string, unknown> | undefined): string | null {
  const p = toolInput?.file_path;
  return typeof p === 'string' && p.length > 0 ? p : null;
}

export type PermissionDecision = 'deny' | 'ask';

/** PreToolUse decision: stdout-only JSON, exit 0. */
export function emitPreToolUseDecision(decision: PermissionDecision, reason: string): void {
  process.stdout.write(JSON.stringify({
    hookSpecificOutput: {
      hookEventName: 'PreToolUse',
      permissionDecision: decision,
      permissionDecisionReason: reason,
    },
  }));
}

/** PostToolUse non-blocking context: stdout-only JSON, exit 0. */
export function emitPostToolUseContext(context: string): void {
  process.stdout.write(JSON.stringify({
    hookSpecificOutput: {
      hookEventName: 'PostToolUse',
      additionalContext: context,
    },
  }));
}

/**
 * Run a hook main function with the fail-open contract: the returned exit
 * code is used on success; ANY throw exits 0 silently.
 */
export async function runHook(main: (input: HookInput) => number | Promise<number>): Promise<void> {
  try {
    const input = parseHookInput(await readStdin());
    const code = await main(input);
    process.exit(code);
  } catch {
    process.exit(0);
  }
}
