#!/usr/bin/env node
import * as cdk from 'aws-cdk-lib';
import * as fs from 'fs';
import * as path from 'path';
import { DataStack } from '../lib/data-stack';
import { AuthStack } from '../lib/auth-stack';
import { ApiStack, type ExtraApiRoute } from '../lib/api-stack';
import type { AppConfig } from '../lib/config';

type SettingsFile = {
  // Template-ish defaults (optional overrides)
  projectName?: string;
  stage?: string;
  enableWaf?: boolean;

  // Required user inputs
  domain: string;
  cloudFrontCertArnUsEast1: string;
  cognitoDomainCertArn: string;

  // CloudFront signed cookies (required)
  cfKeyPairId: string;
  cfPrivateKeySecretArn: string;
  cfCookieDomain: string;
  cfCookiePath?: string;
  cfCookieTtlSeconds?: number;

  // CloudFront-only enforcement (required)
  originVerifyHeaderName?: string;
  originVerifyHeaderValue: string;

  // Future WebStack use
  cloudFrontPublicKeyPemPath?: string;

  // Optional user extensions
  extraApiRoutes?: {
    path: string;
    method: string;
    lambdaArn: string;
  }[];
};

const app = new cdk.App();

// Helpers
function ctx(key: string): string {
  return (app.node.tryGetContext(key) ?? '').toString().trim();
}

function ctxBool(key: string, defaultValue = false): boolean {
  const raw = ctx(key);
  if (!raw) return defaultValue;
  return raw.toLowerCase() === 'true';
}

function requireValue(name: string, value?: string): string {
  const v = (value ?? '').trim();
  if (!v || v === '__REQUIRED__') {
    throw new Error(`Missing required config "${name}". Set it in config/settings.json.`);
  }
  return v;
}

function readSettingsOrThrow(settingsAbsPath: string): SettingsFile {
  if (!fs.existsSync(settingsAbsPath)) {
    throw new Error(
      `Missing config/settings.json (expected at ${settingsAbsPath}). Create it before deploying.`,
    );
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

function normalizeExtraRoutes(input?: SettingsFile['extraApiRoutes']): ExtraApiRoute[] {
  const routes = input ?? [];
  if (!Array.isArray(routes)) return [];

  return routes.map((r, i) => {
    if (!r || typeof r !== 'object') {
      throw new Error(`extraApiRoutes[${i}] must be an object`);
    }

    const p = (r.path ?? '').toString().trim();
    const m = (r.method ?? '').toString().trim().toUpperCase();
    const arn = (r.lambdaArn ?? '').toString().trim();

    if (!p.startsWith('/api/')) {
      throw new Error(`extraApiRoutes[${i}].path must start with "/api/": ${p}`);
    }
    if (p.startsWith('/auth/')) {
      throw new Error(`extraApiRoutes[${i}].path cannot be under "/auth/": ${p}`);
    }

    const allowed = new Set(['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS', 'HEAD']);
    if (!allowed.has(m)) {
      throw new Error(`extraApiRoutes[${i}].method not allowed: ${m}`);
    }

    if (!arn.startsWith('arn:aws:lambda:')) {
      throw new Error(`extraApiRoutes[${i}].lambdaArn must be a Lambda ARN: ${arn}`);
    }

    return { path: p, method: m, lambdaArn: arn };
  });
}

// Standard project paths (user-owned, outside infra)
const repoRoot = path.resolve(__dirname, '..', '..');
const settingsAbs = path.join(repoRoot, 'config', 'settings.json');
const websiteAbs = path.join(repoRoot, 'website');

// Validate standard folders exist
if (!fs.existsSync(websiteAbs)) {
  throw new Error(`website folder not found (expected at ${websiteAbs}). Create ./website first.`);
}

const settings = readSettingsOrThrow(settingsAbs);

// Config (shared stack config)
const config: AppConfig = {
  // Defaults (template-owned), overridable by settings.json
  projectName: (settings.projectName ?? ctx('projectName') ?? '').trim() || 'cuddly-fishstick',
  stage: (settings.stage ?? ctx('stage') ?? '').trim() || 'dev',
  enableWaf: typeof settings.enableWaf === 'boolean' ? settings.enableWaf : ctxBool('enableWaf', false),

  // Required user inputs
  domain: requireValue('domain', settings.domain),
  cloudFrontCertArnUsEast1: requireValue('cloudFrontCertArnUsEast1', settings.cloudFrontCertArnUsEast1),
  cognitoDomainCertArn: requireValue('cognitoDomainCertArn', settings.cognitoDomainCertArn),

  // Standardized website path
  websitePath: 'website',
};

// Required API settings (template posture)
const originVerifyHeaderName = (settings.originVerifyHeaderName ?? 'X-Origin-Verify').toString().trim() || 'X-Origin-Verify';
const originVerifyHeaderValue = requireValue('originVerifyHeaderValue', settings.originVerifyHeaderValue);

const cfKeyPairId = requireValue('cfKeyPairId', settings.cfKeyPairId);
const cfPrivateKeySecretArn = requireValue('cfPrivateKeySecretArn', settings.cfPrivateKeySecretArn);
const cfCookieDomain = requireValue('cfCookieDomain', settings.cfCookieDomain);

const cfCookiePath = (settings.cfCookiePath ?? '/').toString().trim() || '/';
const cfCookieTtlSeconds =
  typeof settings.cfCookieTtlSeconds === 'number' && Number.isFinite(settings.cfCookieTtlSeconds)
    ? settings.cfCookieTtlSeconds
    : 3600;

const extraApiRoutes = normalizeExtraRoutes(settings.extraApiRoutes);

// Const
const env: cdk.Environment = {
  account: process.env.CDK_DEFAULT_ACCOUNT,
  region: process.env.CDK_DEFAULT_REGION,
};

// Data stack
const data = new DataStack(app, `${config.projectName}-${config.stage}-data`, {
  env,
  config,
});

// Auth stack
const auth = new AuthStack(app, `${config.projectName}-${config.stage}-auth`, {
  env,
  config,
  cognitoDomainCertArn: config.cognitoDomainCertArn,
});

// API stack
new ApiStack(app, `${config.projectName}-${config.stage}-api`, {
  env,
  config,

  sessionsTable: data.sessionsTable,

  // Deterministic Hosted UI domain from AuthStack
  cognitoDomain: auth.cognitoAuthDomain,
  cognitoClientId: auth.userPoolClient.userPoolClientId,

  // Signed cookies (required)
  cfKeyPairId,
  cfPrivateKeySecretArn,
  cfCookieDomain,
  cfCookiePath,
  cfCookieTtlSeconds,

  // CloudFront-only enforcement at day 1 (required)
  originVerifyHeaderName,
  originVerifyHeaderValue,

  // User extensions
  extraApiRoutes,
});
