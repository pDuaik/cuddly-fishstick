// lambda/api/update-theme.ts
import { DynamoDBClient } from '@aws-sdk/client-dynamodb';
import { DynamoDBDocumentClient, GetCommand } from '@aws-sdk/lib-dynamodb';
import { S3Client, PutObjectCommand } from '@aws-sdk/client-s3';

import { requireEnv } from './helpers';
import { secureHttp } from './secure-http';

const ddb = DynamoDBDocumentClient.from(new DynamoDBClient({}));
const s3 = new S3Client({});

function normalizeRadius(input: string, min: number, max: number): string | null {
  const v = String(input ?? '').trim().toLowerCase();
  if (!/^\d+px$/.test(v)) return null;
  const n = Number(v.replace('px', ''));
  if (!Number.isFinite(n) || n < min || n > max) return null;
  return `${n}px`;
}

function normalizePadding(input: string, min: number, max: number): string | null {
  const v = String(input ?? '').trim().toLowerCase();
  if (!/^\d+px$/.test(v)) return null;
  const n = Number(v.replace('px', ''));
  if (!Number.isFinite(n) || n < min || n > max) return null;
  return `${n}px`;
}

function normalizeHexColor(input: string): string | null {
  const v = (input ?? '').trim();
  if (!v) return null;
  if (!/^#[0-9a-fA-F]{6}$/.test(v)) return null;
  return v.toLowerCase();
}

function normalizePx(input: string, min: number, max: number): string | null {
  const v = String(input ?? '').trim().toLowerCase();
  if (!/^\d+px$/.test(v)) return null;
  const n = Number(v.replace('px', ''));
  if (!Number.isFinite(n) || n < min || n > max) return null;
  return `${n}px`;
}

// Keep shadow safe by using presets (recommended)
const SHADOW_PRESETS: Record<string, string> = {
  soft: '0 18px 50px rgba(0,0,0,0.28)',
  medium: '0 18px 50px rgba(0,0,0,0.35)',
  strong: '0 22px 70px rgba(0,0,0,0.42)',
};

type ThemeVars = Record<string, string>;

function validateThemeVars(input: any): { ok: true; vars: ThemeVars } | { ok: false; message: string } {
  const raw = input?.vars && typeof input.vars === 'object' ? input.vars : input;
  if (!raw || typeof raw !== 'object') return { ok: false, message: 'Expected JSON body like: { "vars": { ... } }' };

  const out: ThemeVars = {};

  // Button padding
  if (raw.btnPadX != null && raw.btnPadX !== '') {
    const v = normalizePadding(raw.btnPadX, 0, 32);
    if (!v) return { ok: false, message: 'Invalid btnPadX. Use "Npx" (0–32px).' };
    out['--btn-pad-x'] = v;
  }

  if (raw.btnPadY != null && raw.btnPadY !== '') {
    const v = normalizePadding(raw.btnPadY, 0, 16);
    if (!v) return { ok: false, message: 'Invalid btnPadY. Use "Npx" (0–16px).' };
    out['--btn-pad-y'] = v;
  }

  if (raw.btnRadius != null && raw.btnRadius !== '') {
    const v = normalizeRadius(raw.btnRadius, 0, 24);
    if (!v) return { ok: false, message: 'Invalid btnRadius. Use "Npx" (0–24px).' };
    out['--btn-radius'] = v;
  }

  // Allowlist mapping: API key -> CSS var name
  const COLOR_KEYS: Record<string, string> = {
    bg: '--bg',
    cardBg: '--card-bg',
    text: '--text',
    muted: '--muted',
    primary: '--primary',
    primaryHover: '--primary-hover',
    primaryActive: '--primary-active',
    btnLabel: '--btn-label',
  };

  for (const [k, cssVar] of Object.entries(COLOR_KEYS)) {
    if (raw[k] == null || raw[k] === '') continue;
    const c = normalizeHexColor(String(raw[k]));
    if (!c) return { ok: false, message: `Invalid ${k}. Use "#RRGGBB".` };
    out[cssVar] = c;
  }

  // Radius and page padding
  if (raw.radius != null && raw.radius !== '') {
    const v = normalizePx(String(raw.radius), 0, 32);
    if (!v) return { ok: false, message: 'Invalid radius. Use "Npx" (0–32px).' };
    out['--radius'] = v;
  }

  if (raw.pagePad != null && raw.pagePad !== '') {
    const v = normalizePx(String(raw.pagePad), 0, 64);
    if (!v) return { ok: false, message: 'Invalid pagePad. Use "Npx" (0–64px).' };
    out['--page-pad'] = v;
  }

  // Shadow preset
  if (raw.shadowPreset != null && raw.shadowPreset !== '') {
    const key = String(raw.shadowPreset).trim().toLowerCase();
    const preset = SHADOW_PRESETS[key];
    if (!preset) {
      return {
        ok: false,
        message: `Invalid shadowPreset. Use one of: ${Object.keys(SHADOW_PRESETS).join(', ')}`,
      };
    }
    out['--shadow'] = preset;
  }

  if (Object.keys(out).length === 0) {
    return { ok: false, message: 'No valid theme variables provided.' };
  }

  return { ok: true, vars: out };
}

function renderThemeCss(vars: ThemeVars): string {
  const lines = Object.keys(vars)
    .sort()
    .map((k) => `  ${k}: ${vars[k]};`);
  return `:root {\n${lines.join('\n')}\n}\n`;
}

export const handler = secureHttp(async (ctx, input) => {
  const validated = validateThemeVars(input.body);
  if (!validated.ok) {
    return { statusCode: 400, body: { ok: false, message: validated.message } };
  }

  const profileTable = requireEnv('USER_PROFILE_TABLE_NAME');
  const got = await ddb.send(
    new GetCommand({
      TableName: profileTable,
      Key: { user_sub: ctx.user_sub },
      ProjectionExpression: 'opaque_id',
    }),
  );

  const opaqueId = String(got.Item?.opaque_id ?? '');
  if (!opaqueId) {
    return { statusCode: 500, body: { ok: false, message: 'User profile missing opaque_id' } };
  }

  const bucket = requireEnv('USERS_BUCKET_NAME');
  const key = `u/${opaqueId}/theme.css`;

  const css = renderThemeCss(validated.vars);

  await s3.send(
    new PutObjectCommand({
      Bucket: bucket,
      Key: key,
      Body: css,
      ContentType: 'text/css; charset=utf-8',
      CacheControl: 'no-store, no-cache, must-revalidate, max-age=0',
    }),
  );

  return {
    key,
    vars: validated.vars,
  };
});
