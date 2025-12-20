#!/usr/bin/env node
import * as cdk from 'aws-cdk-lib';
import * as fs from 'fs';
import * as path from 'path';
import { DataStack } from '../lib/data-stack';
import { AuthStack } from '../lib/auth-stack';
import type { AppConfig } from '../lib/config';

const app = new cdk.App();

// Helpers
function ctx(key: string): string {
  return (app.node.tryGetContext(key) ?? '').toString().trim();
}

function requireValue(name: string, value?: string): string {
  const v = (value ?? '').trim();
  if (!v || v === '__REQUIRED__') {
    throw new Error(`Missing required config "${name}". Set it in cdk.json context.`);
  }
  return v;
}

// Config
const config: AppConfig = {
  projectName: ctx('projectName') || 'cuddly-fishstick',
  stage: ctx('stage') || 'dev',

  domain: requireValue('domain', process.env.DOMAIN || ctx('domain')),

  cloudFrontCertArnUsEast1: requireValue(
    'cloudFrontCertArnUsEast1',
    process.env.CLOUDFRONT_CERT_ARN_US_EAST_1 || ctx('cloudFrontCertArnUsEast1'),
  ),

  cognitoDomainCertArn: requireValue(
    'cognitoDomainCertArn',
    process.env.COGNITO_DOMAIN_CERT_ARN || ctx('cognitoDomainCertArn'),
  ),

  websitePath: process.env.WEBSITE_PATH || ctx('websitePath') || 'assets/website-example',

  enableWaf: ctx('enableWaf').toLowerCase() === 'true',
};

// Const
const env: cdk.Environment = {
  account: process.env.CDK_DEFAULT_ACCOUNT,
  region: process.env.CDK_DEFAULT_REGION,
};

const websiteAbs = path.resolve(__dirname, '..', config.websitePath);
if (!fs.existsSync(websiteAbs)) {
  throw new Error(`websitePath not found: ${config.websitePath} (resolved to ${websiteAbs})`);
}

// Data stack
const data = new DataStack(app, `${config.projectName}-${config.stage}-data`, {
  env,
  config,
});

// Auth stack
new AuthStack(app, `${config.projectName}-${config.stage}-auth`, {
  env,
  config,
  cognitoDomainCertArn: config.cognitoDomainCertArn,
});
