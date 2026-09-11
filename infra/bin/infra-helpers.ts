// infra/bin/infra-helpers.ts
import * as fs from 'fs';
import * as path from 'path';
import type * as cdk from 'aws-cdk-lib';

export type SettingsFile = {
  projectName?: string;
  stage?: string;

  allowedFrameSrc?: string[];
  allowedConnectSrc?: string[];

  domain: string;
  certArnUsEast1: string;

  cfPublicKeyId: string;

  cfPrivateKeyParameterArn: string;

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

export function requireValue(name: string, value?: unknown): string {
  if (value !== undefined && typeof value !== 'string') {
    throw new Error(`Invalid config "${name}". Expected a string in settings.json at the repository root.`);
  }
  const v = (value ?? '').trim();
  if (!v || v === '__REQUIRED__') {
    throw new Error(`Missing required config "${name}". Set it in settings.json at the repository root.`);
  }
  return v;
}

export function readSettingsOrThrow(settingsAbsPath: string): SettingsFile {
  if (!fs.existsSync(settingsAbsPath)) {
    throw new Error(`Missing settings.json (expected at ${settingsAbsPath}). Copy settings.example.json to settings.json at the repository root and populate it before deploying.`);
  }

  const raw = fs.readFileSync(settingsAbsPath, 'utf8');
  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    throw new Error(`Invalid JSON in settings.json at ${settingsAbsPath}: ${msg}`);
  }

  if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) {
    throw new Error('Invalid settings.json: expected a JSON object.');
  }

  const values = parsed as Record<string, unknown>;
  if ('cfPrivateKeySecretArn' in values) {
    throw new Error('Obsolete config "cfPrivateKeySecretArn" in settings.json. Store the CloudFront signing private key in SSM Parameter Store as a SecureString, set "cfPrivateKeyParameterArn" to that parameter ARN, and remove "cfPrivateKeySecretArn". A Secrets Manager ARN cannot be used as an SSM parameter ARN.');
  }

  for (const name of ['domain', 'certArnUsEast1', 'cfPublicKeyId', 'cfPrivateKeyParameterArn', 'cfCookieDomain', 'originVerifyHeaderValueParameterArn']) {
    values[name] = requireValue(name, values[name]);
  }

  for (const name of ['projectName', 'stage', 'originVerifyHeaderName', 'cfCookiePath']) {
    if (values[name] !== undefined) values[name] = requireValue(name, values[name]);
  }

  const hostname = /^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/i;
  if (!hostname.test(values.domain as string)) {
    throw new Error('Invalid config "domain": use a DNS hostname without a scheme, port, or path.');
  }
  if (!/^arn:[a-z0-9-]+:acm:us-east-1:\d{12}:certificate\/[a-z0-9-]+$/i.test(values.certArnUsEast1 as string)) {
    throw new Error('Invalid config "certArnUsEast1": CloudFront and the Cognito custom domain require an ACM certificate ARN in us-east-1.');
  }
  for (const name of ['cfPrivateKeyParameterArn', 'originVerifyHeaderValueParameterArn']) {
    if (!/^arn:[a-z0-9-]+:ssm:[a-z0-9-]+:\d{12}:parameter\/[a-zA-Z0-9_.\/-]+$/.test(values[name] as string)) {
      throw new Error(`Invalid config "${name}": expected an SSM parameter ARN (arn:aws:ssm:REGION:ACCOUNT:parameter/PATH).`);
    }
  }

  const domain = (values.domain as string).toLowerCase();
  values.domain = domain;
  values.cfCookieDomain = (values.cfCookieDomain as string).toLowerCase();
  const cookieDomain = (values.cfCookieDomain as string).replace(/^\./, '').toLowerCase();
  if (!hostname.test(cookieDomain) || (domain !== cookieDomain && !domain.endsWith(`.${cookieDomain}`))) {
    throw new Error('Invalid config "cfCookieDomain": it must match the app domain or a parent domain.');
  }
  if (values.cfCookiePath !== undefined && values.cfCookiePath !== '/') {
    throw new Error('Invalid config "cfCookiePath": use "/" so signed cookies cover the protected website paths.');
  }
  if (values.cfCookieTtlSeconds !== undefined &&
      (typeof values.cfCookieTtlSeconds !== 'number' || !Number.isSafeInteger(values.cfCookieTtlSeconds) || values.cfCookieTtlSeconds <= 0)) {
    throw new Error('Invalid config "cfCookieTtlSeconds": expected a positive integer number of seconds.');
  }
  if (values.originVerifyHeaderName !== undefined && !/^[!#$%&'*+.^_`|~0-9a-z-]+$/i.test(values.originVerifyHeaderName as string)) {
    throw new Error('Invalid config "originVerifyHeaderName": expected a valid HTTP header name.');
  }
  for (const name of ['allowedFrameSrc', 'allowedConnectSrc']) {
    const sources = values[name];
    if (sources !== undefined && (!Array.isArray(sources) || sources.some(source => typeof source !== 'string'))) {
      throw new Error(`Invalid config "${name}": expected an array of strings.`);
    }
  }

  return values as SettingsFile;
}

export function settingsPath() {
  const repoRoot = path.resolve(__dirname, '..', '..');
  return {
    settingsAbs: path.join(repoRoot, 'settings.json'),
  };
}
