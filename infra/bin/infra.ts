#!/usr/bin/env node
import * as cdk from 'aws-cdk-lib';
import { InfraStack } from '../lib/infra-stack';

const app = new cdk.App();

function ctx(key: string): string {
  return (app.node.tryGetContext(key) ?? '').toString();
}

const config = {
  projectName: ctx('projectName') || 'cuddly-fishstick',
  stage: ctx('stage') || 'dev',

  // Safe defaults (may be empty until a user configures)
  domainName: process.env.DOMAIN_NAME || ctx('domainName'),
  hostedZoneName: process.env.HOSTED_ZONE_NAME || ctx('hostedZoneName'),

  enableCustomDomain: (process.env.ENABLE_CUSTOM_DOMAIN || ctx('enableCustomDomain') || 'false') === 'true',
  enableWaf: (process.env.ENABLE_WAF || ctx('enableWaf') || 'false') === 'true',
};

new InfraStack(app, `${config.projectName}-${config.stage}`, {
  // keep env “agnostic”
  env: {
    account: process.env.CDK_DEFAULT_ACCOUNT,
    region: process.env.CDK_DEFAULT_REGION,
  },
  config,
});
