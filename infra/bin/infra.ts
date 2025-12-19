#!/usr/bin/env node
import * as cdk from 'aws-cdk-lib';
import { DataStack } from '../lib/data-stack';
import { AuthStack } from '../lib/auth-stack';
import type { AppConfig } from '../lib/config';

const app = new cdk.App();

function ctx(key: string): string {
  return (app.node.tryGetContext(key) ?? '').toString();
}

const config: AppConfig = {
  projectName: ctx('projectName') || 'cuddly-fishstick',
  stage: ctx('stage') || 'dev',

  domainName: process.env.DOMAIN_NAME || ctx('domainName') || undefined,
  hostedZoneName: process.env.HOSTED_ZONE_NAME || ctx('hostedZoneName') || undefined,

  enableCustomDomain: ctx('enableCustomDomain').toLowerCase() === 'true',
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
// For the template: no custom domain needed; use Cognito default domain.
// Callback/logout URLs can be updated later once CloudFront exists.
// -----------------------------------------------------------------------------
const callbackUrls = [
  // placeholder defaults for template; later replace with CloudFront/custom domain callback
  'http://localhost:3000/auth/callback',
];

const logoutUrls = [
  'http://localhost:3000/',
];

new AuthStack(app, `${config.projectName}-${config.stage}-auth`, {
  env,
  config,
  callbackUrls,
  logoutUrls,

  // Optional later (Cognito custom domain):
  // cognitoCustomDomain: `auth.${config.domainName}`,
  // cognitoDomainCertArn: process.env.COGNITO_DOMAIN_CERT_ARN,
});
