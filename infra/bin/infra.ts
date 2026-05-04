#!/usr/bin/env node
import * as cdk from 'aws-cdk-lib';
import { DataStack } from '../lib/data-stack';
import { AuthStack } from '../lib/auth-stack';
import { ApiStack } from '../lib/api-stack';
import { WebStack } from '../lib/web-stack';
import type { AppConfig } from '../lib/config';
import { settingsPath, readSettingsOrThrow, requireValue, ctx, ctxBool } from './infra-helpers';

const app = new cdk.App();

const { settingsAbs } = settingsPath();
const settings = readSettingsOrThrow(settingsAbs);

const config: AppConfig = {
  projectName: (settings.projectName ?? ctx(app, 'projectName') ?? '').trim() || 'cuddly-fishstick',
  stage: (settings.stage ?? ctx(app, 'stage') ?? '').trim() || 'dev',

  domain: requireValue('domain', settings.domain),
  certArnUsEast1: requireValue('certArnUsEast1', settings.certArnUsEast1),
};

const originVerifyHeaderName =
  (settings.originVerifyHeaderName ?? 'X-Origin-Verify').toString().trim() || 'X-Origin-Verify';

const originVerifyHeaderValueParameterArn = requireValue(
  'originVerifyHeaderValueParameterArn',
  settings.originVerifyHeaderValueParameterArn,
);

const cfPublicKeyId = requireValue('cfPublicKeyId', settings.cfPublicKeyId);

const cfPrivateKeySecretArn = requireValue('cfPrivateKeySecretArn', settings.cfPrivateKeySecretArn);
const cfCookieDomain = requireValue('cfCookieDomain', settings.cfCookieDomain);

const cfCookiePath = (settings.cfCookiePath ?? '/').toString().trim() || '/';
const cfCookieTtlSeconds =
  typeof settings.cfCookieTtlSeconds === 'number' && Number.isFinite(settings.cfCookieTtlSeconds)
    ? settings.cfCookieTtlSeconds
    : 3600;

const env: cdk.Environment = {
  account: process.env.CDK_DEFAULT_ACCOUNT,
  region: process.env.CDK_DEFAULT_REGION,
};

const allowedFrameSrc =
  Array.isArray(settings.allowedFrameSrc)
    ? settings.allowedFrameSrc.map(s => s.trim()).filter(Boolean)
    : [];

const allowedConnectSrc =
  Array.isArray(settings.allowedConnectSrc)
    ? settings.allowedConnectSrc.map(s => s.trim()).filter(Boolean)
    : [];

// -------------------------
// Stacks
// -------------------------

const data = new DataStack(app, `${config.projectName}-${config.stage}-data`, {
  env,
  config,
});

const auth = new AuthStack(app, `${config.projectName}-${config.stage}-auth`, {
  env,
  config,
  certArnUsEast1: config.certArnUsEast1,
});

const api = new ApiStack(app, `${config.projectName}-${config.stage}-api`, {
  env,
  config,
  sessionsTable: data.sessionsTable,
  userProfileTable: data.userProfileTable,
  usersBucket: data.usersBucket,
  cognitoDomain: auth.cognitoAuthDomain,
  cognitoClientId: auth.userPoolClient.userPoolClientId,
  cognitoUserPoolId: auth.userPool.userPoolId,
  cfPublicKeyId,
  cfPrivateKeySecretArn,
  cfCookieDomain,
  cfCookiePath,
  cfCookieTtlSeconds,
  originVerifyHeaderName,
  originVerifyHeaderValueParameterArn,
});

const apiDomainName = cdk.Fn.select(
  0,
  cdk.Fn.split('/', cdk.Fn.select(1, cdk.Fn.split('://', api.httpApi.apiEndpoint))),
);

new WebStack(app, `${config.projectName}-${config.stage}-web`, {
  env,
  domain: config.domain,
  certArnUsEast1: config.certArnUsEast1,
  siteBucket: data.siteBucket,
  usersBucket: data.usersBucket,
  apiDomain: apiDomainName,
  cfPublicKeyId,
  originVerifyHeaderName,
  originVerifyHeaderValueParameterArn,
  allowedFrameSrc,
  allowedConnectSrc,
});

