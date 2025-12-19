#!/usr/bin/env node
import * as cdk from 'aws-cdk-lib';
import { DataStack } from '../lib/data-stack';
import { AuthStack } from '../lib/auth-stack';
import type { AppConfig } from '../lib/config';

const app = new cdk.App();

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

// ----------------------------------------------------------------------------
// Config (context-driven)
// ----------------------------------------------------------------------------
// New contract:
// - domain is REQUIRED (either "example.com" or "www.example.com")
// - cloudFrontCertArnUsEast1 is REQUIRED (ACM cert in us-east-1 for CloudFront)
// - cognitoDomainCertArn is REQUIRED (ACM cert in your deploy region for auth.<rootDomain>)
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

  enableWaf: ctx('enableWaf').toLowerCase() === 'true',
};

const env: cdk.Environment = {
  account: process.env.CDK_DEFAULT_ACCOUNT,
  region: process.env.CDK_DEFAULT_REGION,
};

// -----------------------------------------------------------------------------
// 1) Data stack (sessions table)
// -----------------------------------------------------------------------------
const data = new DataStack(app, `${config.projectName}-${config.stage}-data`, {
  env,
  config,
});

// -----------------------------------------------------------------------------
// 2) Auth stack (Cognito)
// - Custom domain is enforced by the stack itself as auth.<rootDomain>
// - Callback/logout URLs are derived from config.domain inside the stack
// -----------------------------------------------------------------------------
new AuthStack(app, `${config.projectName}-${config.stage}-auth`, {
  env,
  config,
  cognitoDomainCertArn: config.cognitoDomainCertArn,
});
