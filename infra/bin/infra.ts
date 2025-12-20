#!/usr/bin/env node
import * as cdk from 'aws-cdk-lib';
import { DataStack } from '../lib/data-stack';
import { AuthStack } from '../lib/auth-stack';
import { ApiStack } from '../lib/api-stack';
import type { AppConfig } from '../lib/config';
import {
  repoPaths,
  assertFolderExists,
  readSettingsOrThrow,
  requireValue,
  normalizeExtraRoutes,
  ctx,
  ctxBool,
} from './infra-helpers';

const app = new cdk.App();

const { settingsAbs, websiteAbs } = repoPaths();
assertFolderExists(websiteAbs, 'website');

const settings = readSettingsOrThrow(settingsAbs);

const config: AppConfig = {
  projectName: (settings.projectName ?? ctx(app, 'projectName') ?? '').trim() || 'cuddly-fishstick',
  stage: (settings.stage ?? ctx(app, 'stage') ?? '').trim() || 'dev',
  enableWaf: typeof settings.enableWaf === 'boolean' ? settings.enableWaf : ctxBool(app, 'enableWaf', false),

  domain: requireValue('domain', settings.domain),
  cloudFrontCertArnUsEast1: requireValue('cloudFrontCertArnUsEast1', settings.cloudFrontCertArnUsEast1),
  cognitoDomainCertArn: requireValue('cognitoDomainCertArn', settings.cognitoDomainCertArn),

  websitePath: 'website',
};

const originVerifyHeaderName =
  (settings.originVerifyHeaderName ?? 'X-Origin-Verify').toString().trim() || 'X-Origin-Verify';
const originVerifyHeaderValue = requireValue('originVerifyHeaderValue', settings.originVerifyHeaderValue);

const cfPublicKeyId = requireValue('cfPublicKeyId', settings.cfPublicKeyId);

const cfPrivateKeySecretArn = requireValue('cfPrivateKeySecretArn', settings.cfPrivateKeySecretArn);
const cfCookieDomain = requireValue('cfCookieDomain', settings.cfCookieDomain);

const cfCookiePath = (settings.cfCookiePath ?? '/').toString().trim() || '/';
const cfCookieTtlSeconds =
  typeof settings.cfCookieTtlSeconds === 'number' && Number.isFinite(settings.cfCookieTtlSeconds)
    ? settings.cfCookieTtlSeconds
    : 3600;

const extraApiRoutes = normalizeExtraRoutes(settings.extraApiRoutes);

const env: cdk.Environment = {
  account: process.env.CDK_DEFAULT_ACCOUNT,
  region: process.env.CDK_DEFAULT_REGION,
};

const data = new DataStack(app, `${config.projectName}-${config.stage}-data`, {
  env,
  config,
});

const auth = new AuthStack(app, `${config.projectName}-${config.stage}-auth`, {
  env,
  config,
  cognitoDomainCertArn: config.cognitoDomainCertArn,
});

new ApiStack(app, `${config.projectName}-${config.stage}-api`, {
  env,
  config,
  sessionsTable: data.sessionsTable,
  cognitoDomain: auth.cognitoAuthDomain,
  cognitoClientId: auth.userPoolClient.userPoolClientId,

  // ✅ Key Groups (Public Key ID)
  cfPublicKeyId,

  cfPrivateKeySecretArn,
  cfCookieDomain,
  cfCookiePath,
  cfCookieTtlSeconds,

  originVerifyHeaderName,
  originVerifyHeaderValue,

  extraApiRoutes,
});
