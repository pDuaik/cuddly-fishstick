import * as cdk from 'aws-cdk-lib';
import { Template } from 'aws-cdk-lib/assertions';
import { createHmac } from 'crypto';
import * as vm from 'vm';
import { DataStack } from '../lib/data-stack';
import { WebStack } from '../lib/web-stack';
import { userPathFunctionBody } from '../lib/user-path-function';

const env = { account: '123456789012', region: 'eu-west-2' };
const config = {
  projectName: 'test', stage: 'dev', domain: 'example.com',
  certArnUsEast1: 'arn:aws:acm:us-east-1:123456789012:certificate/test',
};

function stacks(migration = false) {
  const app = new cdk.App({ context: { prepareBucketPolicyMigration: migration } });
  const data = new DataStack(app, 'Data', { env, config });
  const web = new WebStack(app, 'Web', {
    env, domain: config.domain, certArnUsEast1: config.certArnUsEast1,
    siteBucket: data.siteBucket, usersBucket: data.usersBucket,
    apiDomain: 'example.execute-api.eu-west-2.amazonaws.com',
    cfPublicKeyId: 'K1234567890', originVerifyHeaderName: 'X-Origin-Verify',
    originVerifyHeaderValueParameterArn: 'arn:aws:ssm:eu-west-2:123456789012:parameter/test/origin',
  });
  const assembly = app.synth();
  return {
    data: Template.fromJSON(assembly.getStackArtifact(data.artifactId).template),
    web: Template.fromJSON(assembly.getStackArtifact(web.artifactId).template),
  };
}

test('one owner per bucket preserves SSL enforcement, scoped OAC and cleanup grants', () => {
  const { data, web } = stacks();
  data.resourceCountIs('AWS::S3::BucketPolicy', 0);
  data.resourceCountIs('Custom::S3AutoDeleteObjects', 2);
  const policies = Object.values(web.findResources('AWS::S3::BucketPolicy'));
  expect(policies).toHaveLength(2);
  for (const policy of policies) {
    expect(policy.DeletionPolicy).toBe('Retain');
    const statements = policy.Properties.PolicyDocument.Statement;
    expect(statements).toEqual(expect.arrayContaining([
      expect.objectContaining({ Effect: 'Deny', Condition: { Bool: { 'aws:SecureTransport': 'false' } } }),
      expect.objectContaining({ Sid: 'AllowCloudFrontReadViaOAC', Principal: { Service: 'cloudfront.amazonaws.com' } }),
      expect.objectContaining({ Action: expect.arrayContaining(['s3:PutBucketPolicy', 's3:DeleteObject*']) }),
    ]));
    const oac = statements.find((s: any) => s.Sid === 'AllowCloudFrontReadViaOAC');
    expect(JSON.stringify(oac.Condition)).toContain('SiteDistribution');
    expect(JSON.stringify(oac.Condition)).not.toContain('distribution/*');
  }
});

test('migration stage retains the existing Data policy resources before removing their ownership', () => {
  const { data, web } = stacks(true);
  const policies = Object.values(data.findResources('AWS::S3::BucketPolicy'));
  expect(policies).toHaveLength(2);
  for (const policy of policies) expect(policy.DeletionPolicy).toBe('Retain');
  web.resourceCountIs('AWS::S3::BucketPolicy', 2);
});

test('protected content is no-store and the edge key uses an encoded SSM parameter', () => {
  const { web } = stacks();
  const template = web.toJSON();
  expect(template.Parameters.OriginVerifyValue).toMatchObject({
    Type: 'AWS::SSM::Parameter::Value<String>', Default: '/test/origin', NoEcho: true,
  });
  const fn: any = Object.values(web.findResources('AWS::CloudFront::Function'))[0];
  expect(fn.Properties.FunctionConfig.Runtime).toBe('cloudfront-js-2.0');
  expect(fn.Properties.FunctionCode['Fn::Join'][1]).toContainEqual({ 'Fn::Base64': { Ref: 'OriginVerifyValue' } });
  const distribution: any = Object.values(web.findResources('AWS::CloudFront::Distribution'))[0];
  const behaviors = distribution.Properties.DistributionConfig.CacheBehaviors;
  const app = behaviors.find((b: any) => b.PathPattern === '/app/*');
  const users = behaviors.find((b: any) => b.PathPattern === '/u/*');
  expect(app.ResponseHeadersPolicyId).toEqual(users.ResponseHeadersPolicyId);
  expect(users.TrustedKeyGroups).toHaveLength(1);
});

const secret = 'test-only-origin-secret-with-32-bytes';
const opaque = 'a'.repeat(43);
const other = 'b'.repeat(43);
const now = 1800000000;
function cookie(id = opaque, expiry = now + 60, host = config.domain) {
  const signature = createHmac('sha256', secret)
    .update(`user-cookie:v1\n${host}\n${id}\n${expiry}`).digest('hex');
  return `${id}.${expiry}.${signature}`;
}

function request(value?: string, uri = '/u/me/theme.css') {
  const sandbox: any = {
    crypto: require('crypto'), secret, Date: { now: () => now * 1000 },
  };
  vm.createContext(sandbox);
  vm.runInContext(userPathFunctionBody(config.domain), sandbox);
  return sandbox.handler({ request: { uri, cookies: value ? { '__Host-uk': { value } } : {} } });
}

test('edge allows an authenticated user cookie and preserves nested asset paths', () => {
  expect(request(cookie()).uri).toBe(`/u/${opaque}/theme.css`);
  expect(request(cookie(), '/u/me/assets/logo.png').uri).toBe(`/u/${opaque}/assets/logo.png`);
});

test.each([
  undefined,
  opaque,
  cookie().replace(opaque, other),
  cookie().replace(String(now + 60), String(now + 600)),
  cookie(opaque, now),
  cookie(opaque, now + 60, 'other.example.com'),
  `${cookie()}.extra`,
])('edge denies missing, old, altered, expired or foreign-host cookies (%s)', value => {
  expect(request(value).statusCode).toBe(403);
});

test.each([
  '/u/other/theme.css', '/u/me/', '/u/me/../other/theme.css', '/u/me/%2e%2e/other',
  '/u/me/%252e%252e/other', '/u/me/a%2fb', '/u/me/a%5cb', '/u/me/a\\b',
  '/u/me/%00file', '/u/me/a//b', '/u/me/%invalid',
])('edge rejects ambiguous or traversing path %s', uri => {
  expect(request(cookie(), uri).statusCode).toBe(403);
});

test('encoded SSM contents cannot inject executable function code', () => {
  const unusual = 'quote"; injected=true; //\nUnicode £ and \\ backslash';
  const code = 'var crypto = require("crypto"); var secret = Buffer.from("' +
    Buffer.from(unusual).toString('base64') + '","base64").toString("utf8").trim();\n' +
    userPathFunctionBody(config.domain);
  const sandbox: any = { require, Buffer };
  vm.createContext(sandbox);
  vm.runInContext(code, sandbox);
  expect(sandbox.secret).toBe(unusual);
  expect(sandbox.injected).toBeUndefined();
});
