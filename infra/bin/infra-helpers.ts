import * as fs from 'fs';
import * as path from 'path';
import type * as cdk from 'aws-cdk-lib';
import type { ExtraApiRoute } from '../lib/api-stack';

export type SettingsFile = {
  projectName?: string;
  stage?: string;
  enableWaf?: boolean;

  domain: string;
  certArnUsEast1: string;

  cfPublicKeyId: string;

  cfPrivateKeySecretArn: string;

  cfCookieDomain: string;
  cfCookiePath?: string;
  cfCookieTtlSeconds?: number;

  originVerifyHeaderName?: string;
  originVerifyHeaderValueSecretArn: string;

  extraApiRoutes?: {
    path: string;
    method: string;
    lambdaArn: string;
  }[];
};


export function ctx(app: cdk.App, key: string): string {
  return (app.node.tryGetContext(key) ?? '').toString().trim();
}

export function ctxBool(app: cdk.App, key: string, defaultValue = false): boolean {
  const raw = ctx(app, key);
  if (!raw) return defaultValue;
  return raw.toLowerCase() === 'true';
}

export function requireValue(name: string, value?: string): string {
  const v = (value ?? '').trim();
  if (!v || v === '__REQUIRED__') {
    throw new Error(`Missing required config "${name}". Set it in config/settings.json.`);
  }
  return v;
}

export function readSettingsOrThrow(settingsAbsPath: string): SettingsFile {
  if (!fs.existsSync(settingsAbsPath)) {
    throw new Error(`Missing config/settings.json (expected at ${settingsAbsPath}). Create it before deploying.`);
  }

  const raw = fs.readFileSync(settingsAbsPath, 'utf8');
  try {
    const parsed = JSON.parse(raw) as SettingsFile;
    if (!parsed || typeof parsed !== 'object') {
      throw new Error('settings.json did not contain a JSON object');
    }
    return parsed;
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    throw new Error(`Invalid JSON in config/settings.json: ${msg}`);
  }
}

export function normalizeExtraRoutes(input?: SettingsFile['extraApiRoutes']): ExtraApiRoute[] {
  const routes = input ?? [];
  if (!Array.isArray(routes)) return [];

  return routes.map((r, i) => {
    if (!r || typeof r !== 'object') throw new Error(`extraApiRoutes[${i}] must be an object`);

    const p = (r.path ?? '').toString().trim();
    const m = (r.method ?? '').toString().trim().toUpperCase();
    const arn = (r.lambdaArn ?? '').toString().trim();

    if (!p.startsWith('/api/')) throw new Error(`extraApiRoutes[${i}].path must start with "/api/": ${p}`);
    if (p.startsWith('/auth/')) throw new Error(`extraApiRoutes[${i}].path cannot be under "/auth/": ${p}`);

    const allowed = new Set(['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS', 'HEAD']);
    if (!allowed.has(m)) throw new Error(`extraApiRoutes[${i}].method not allowed: ${m}`);

    if (!arn.startsWith('arn:aws:lambda:')) throw new Error(`extraApiRoutes[${i}].lambdaArn must be a Lambda ARN: ${arn}`);

    return { path: p, method: m, lambdaArn: arn };
  });
}

export function repoPaths() {
  const repoRoot = path.resolve(__dirname, '..', '..');
  return {
    repoRoot,
    settingsAbs: path.join(repoRoot, 'config', 'settings.json'),
    websiteAbs: path.join(repoRoot, 'website'),
  };
}

export function assertFolderExists(absPath: string, label: string) {
  if (!fs.existsSync(absPath)) {
    throw new Error(`${label} folder not found (expected at ${absPath}).`);
  }
}
