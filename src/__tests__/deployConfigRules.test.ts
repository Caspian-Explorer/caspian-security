import {
  deployConfigRules,
  deployConfigBlockingRules,
} from '../rules/deployConfigRules';
import { getAllRules } from '../rules';
import { scanFile } from '../scanRunner';
import { SecuritySeverity } from '../types';

function scan(filePath: string, text: string) {
  return scanFile(filePath, text, deployConfigRules, { runTaint: false });
}

function codes(filePath: string, text: string): string[] {
  return scan(filePath, text).map(i => i.code);
}

describe('deployConfigRules registration', () => {
  it('is included in the full rule registry', () => {
    const all = getAllRules().map(r => r.code);
    for (const rule of deployConfigRules) {
      expect(all).toContain(rule.code);
    }
  });

  it('blocking subset contains exactly the critical-confidence rules', () => {
    expect(deployConfigBlockingRules.map(r => r.code).sort()).toEqual(
      ['DEPLOY001', 'DEPLOY003', 'DEPLOY005', 'DEPLOY006', 'DEPLOY009']
    );
    for (const rule of deployConfigBlockingRules) {
      expect(rule.severity).toBe(SecuritySeverity.Error);
    }
  });
});

describe('DEPLOY001/DEPLOY002 — Firebase Firestore/Storage rules', () => {
  const openWrite = `
service cloud.firestore {
  match /databases/{database}/documents {
    match /{document=**} {
      allow read, write: if true;
    }
  }
}`;

  it('flags a wide-open write rule as DEPLOY001', () => {
    expect(codes('/app/firestore.rules', openWrite)).toContain('DEPLOY001');
  });

  it('flags bare `allow write: if true`', () => {
    expect(codes('/app/storage.rules', 'allow write: if true;')).toContain('DEPLOY001');
  });

  it('flags open read-only access as DEPLOY002 (warning), not DEPLOY001', () => {
    const found = codes('/app/firestore.rules', 'allow read: if true;');
    expect(found).toContain('DEPLOY002');
    expect(found).not.toContain('DEPLOY001');
  });

  it('does not flag authenticated rules', () => {
    expect(codes('/app/firestore.rules', 'allow read, write: if request.auth != null;')).toEqual([]);
  });

  it('does not fire outside .rules files', () => {
    expect(codes('/app/src/index.ts', 'allow read, write: if true')).toEqual([]);
  });
});

describe('DEPLOY003/DEPLOY004 — Supabase RLS', () => {
  it('flags disabling row level security', () => {
    expect(
      codes('/app/supabase/migrations/001.sql', 'alter table orders disable row level security;')
    ).toContain('DEPLOY003');
  });

  it('flags a no-op policy (using (true))', () => {
    expect(
      codes('/app/supabase/migrations/002.sql', 'create policy p on orders for select using (true);')
    ).toContain('DEPLOY004');
  });

  it('does not flag enabling RLS or scoped policies', () => {
    const sql = [
      'alter table orders enable row level security;',
      'create policy p on orders for select using (auth.uid() = user_id);',
    ].join('\n');
    expect(codes('/app/supabase/migrations/003.sql', sql)).toEqual([]);
  });

  it('ignores commented-out SQL', () => {
    expect(
      codes('/app/schema.sql', '-- alter table orders disable row level security;')
    ).toEqual([]);
  });
});

describe('DEPLOY005–DEPLOY007 — client-exposed env vars', () => {
  it('flags a service-role key behind NEXT_PUBLIC as DEPLOY005', () => {
    const found = codes('/app/lib/db.ts', 'const key = process.env.NEXT_PUBLIC_SUPABASE_SERVICE_ROLE_KEY;');
    expect(found).toContain('DEPLOY005');
    expect(found).not.toContain('DEPLOY006');
  });

  it('flags a secret behind VITE_ as DEPLOY006', () => {
    expect(codes('/app/src/main.ts', 'const s = import.meta.env.VITE_STRIPE_CLIENT_SECRET;'))
      .toContain('DEPLOY006');
  });

  it('flags a generic API key behind NEXT_PUBLIC as DEPLOY007 (warning)', () => {
    expect(codes('/app/page.tsx', 'const k = process.env.NEXT_PUBLIC_OPENAI_API_KEY;'))
      .toContain('DEPLOY007');
  });

  it('does not flag designed-public keys or server-side env vars', () => {
    const clean = [
      'const maps = process.env.NEXT_PUBLIC_MAPS_API_KEY;',
      'const anon = process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY;',
      'const server = process.env.OPENAI_API_KEY;',
    ].join('\n');
    expect(codes('/app/lib/env.ts', clean)).toEqual([]);
  });
});

describe('DEPLOY008 — LLM endpoint with no rate limit', () => {
  const llmRoute = `
import OpenAI from 'openai';
const openai = new OpenAI();
export async function POST(req: Request) {
  const body = await req.json();
  const out = await openai.chat.completions.create({ model: 'gpt-4o', messages: body.messages });
  return Response.json(out);
}`;

  it('flags an unlimited LLM call in a route file', () => {
    expect(codes('/app/app/api/chat/route.ts', llmRoute)).toContain('DEPLOY008');
  });

  it('still requests review when only a rate limiter import is present', () => {
    const limited = `import { Ratelimit } from '@upstash/ratelimit';\n${llmRoute}`;
    expect(codes('/app/app/api/chat/route.ts', limited)).toContain('DEPLOY008');
  });

  it('does not fire outside route-like files', () => {
    expect(codes('/app/scripts/batch.ts', llmRoute)).toEqual([]);
  });

  it('covers the Vercel AI SDK and Anthropic shapes', () => {
    const aiSdk = 'const r = await streamText({ model, prompt });';
    const anthropic = 'const m = await anthropic.messages.create({ model, max_tokens: 1024 });';
    expect(codes('/app/app/api/gen/route.ts', aiSdk)).toContain('DEPLOY008');
    expect(codes('/app/pages/api/ask.ts', anthropic)).toContain('DEPLOY008');
  });
});

describe('DEPLOY009/DEPLOY010 — Realtime Database rules', () => {
  it('flags ".write": true as DEPLOY009', () => {
    expect(codes('/app/database.rules.json', '{ "rules": { ".write": true } }'))
      .toContain('DEPLOY009');
  });

  it('flags ".read": true as DEPLOY010 (warning)', () => {
    expect(codes('/app/database.rules.json', '{ "rules": { ".read": "true" } }'))
      .toContain('DEPLOY010');
  });

  it('does not flag auth-gated RTDB rules', () => {
    expect(codes('/app/database.rules.json', '{ "rules": { ".write": "auth != null" } }'))
      .toEqual([]);
  });

  it('does not fire on ordinary json-like source', () => {
    expect(codes('/app/src/config.ts', 'const rules = { ".write": true };')).toEqual([]);
  });
});
