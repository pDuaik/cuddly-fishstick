#!/usr/bin/env node
import * as cdk from 'aws-cdk-lib';
import * as fs from 'fs';
import * as path from 'path';
import { DataStack } from '../lib/data-stack';
import { AuthStack } from '../lib/auth-stack';
import type { AppConfig } from '../lib/config';

type SettingsFile = Partial<{
  projectName: string;
  stage: string;
  enableWaf: boolean;

  domain: string;
  cloudFrontCertArnUsEast1: string;
  cognitoDomainCertArn: string;

  // Keep in settings.json even if you don't use it yet:
  cloudFrontPublicKeyPemPath: string;
}>;

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
      `Missing config/settings.json (expected at ${settingsAbsPath}). ` +
        `Create it before deploying.`,
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

// Standard project paths (user-owned, outside infra)
const repoRoot = path.resolve(__dirname, '..', '..');
const settingsAbs = path.join(repoRoot, 'config', 'settings.json');
const websiteAbs = path.join(repoRoot, 'website');

// Validate standard folders exist
if (!fs.existsSync(websiteAbs)) {
  throw new Error(`website folder not found (expected at ${websiteAbs}). Create ./website first.`);
}

const settings = readSettingsOrThrow(settingsAbs);

// Config
const config: AppConfig = {
  // Template defaults, overridable by settings.json
  projectName: (settings.projectName ?? ctx('projectName') ?? '').trim() || 'cuddly-fishstick',
  stage: (settings.stage ?? ctx('stage') ?? '').trim() || 'dev',
  enableWaf: typeof settings.enableWaf === 'boolean' ? settings.enableWaf : ctxBool('enableWaf', false),

  // Required user inputs (settings.json is source of truth)
  domain: requireValue('domain', settings.domain),
  cloudFrontCertArnUsEast1: requireValue('cloudFrontCertArnUsEast1', settings.cloudFrontCertArnUsEast1),
  cognitoDomainCertArn: requireValue('cognitoDomainCertArn', settings.cognitoDomainCertArn),

  // Standard path (no longer configurable)
  websitePath: 'website',
};

// Const
const env: cdk.Environment = {
  account: process.env.CDK_DEFAULT_ACCOUNT,
  region: process.env.CDK_DEFAULT_REGION,
};

// Data stack
new DataStack(app, `${config.projectName}-${config.stage}-data`, {
  env,
  config,
});

// Auth stack
new AuthStack(app, `${config.projectName}-${config.stage}-auth`, {
  env,
  config,
  cognitoDomainCertArn: config.cognitoDomainCertArn,
});
