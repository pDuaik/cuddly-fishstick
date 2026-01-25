// infra/bin/infra-helpers.ts
import * as fs from 'fs';
import * as path from 'path';
import type * as cdk from 'aws-cdk-lib';

export type SettingsFile = {
  projectName?: string;
  stage?: string;
  enableWaf?: boolean;

  allowedFrameSrc?: string[];
  allowedConnectSrc?: string[];

  domain: string;
  certArnUsEast1: string;

  cfPublicKeyId: string;

  cfPrivateKeySecretArn: string;

  cfCookieDomain: string;
  cfCookiePath?: string;
  cfCookieTtlSeconds?: number;

  originVerifyHeaderName?: string;
  originVerifyHeaderValueParameterArn: string;
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

export function settingsPath() {
  const repoRoot = path.resolve(__dirname, '..', '..');
  return {
    settingsAbs: path.join(repoRoot, 'settings.json'),
  };
}
