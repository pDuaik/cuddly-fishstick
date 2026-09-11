import * as cdk from 'aws-cdk-lib';
import { Template } from 'aws-cdk-lib/assertions';
import * as s3 from 'aws-cdk-lib/aws-s3';
import { AuthStack } from '../lib/auth-stack';
import { DataStack } from '../lib/data-stack';
import { defaultRemovalPolicy } from '../lib/config';
import { bucketPolicyDocument } from '../lib/platform-bucket';

const config = {
  projectName: 'retention-test',
  stage: 'prod',
  domain: 'example.com',
  certArnUsEast1: 'arn:aws:acm:us-east-1:123456789012:certificate/00000000-0000-0000-0000-000000000000',
};

describe('stateful resource retention', () => {
  test.each(['prod', 'production', 'PROD', 'Production'])('retains production stages: %s', stage => {
    expect(defaultRemovalPolicy(stage)).toBe(cdk.RemovalPolicy.RETAIN);
  });

  test.each(['dev', 'test', 'staging'])('preserves disposable stage behavior: %s', stage => {
    expect(defaultRemovalPolicy(stage)).toBe(cdk.RemovalPolicy.DESTROY);
  });

  test('production Cognito users are retained on stack deletion and replacement', () => {
    const stack = new AuthStack(new cdk.App(), 'Auth', { config, certArnUsEast1: config.certArnUsEast1 });
    const template = Template.fromStack(stack);
    template.hasResource('AWS::Cognito::UserPool', {
      DeletionPolicy: 'Retain',
      UpdateReplacePolicy: 'Retain',
    });
    template.hasOutput('CognitoCloudFrontDistribution', {
      Value: { 'Fn::GetAtt': ['UserPoolDomain', 'CloudFrontDistribution'] },
    });
  });

  test('a direct stack consumer can explicitly request disposable Cognito users', () => {
    const stack = new AuthStack(new cdk.App(), 'Auth', {
      config,
      certArnUsEast1: config.certArnUsEast1,
      removalPolicy: cdk.RemovalPolicy.DESTROY,
    });
    Template.fromStack(stack).hasResource('AWS::Cognito::UserPool', {
      DeletionPolicy: 'Delete',
      UpdateReplacePolicy: 'Delete',
    });
  });

  test('production storage retains data without an automatic bucket emptying resource', () => {
    const stack = new DataStack(new cdk.App(), 'Data', { config });
    const template = Template.fromStack(stack);
    for (const resourceType of ['AWS::S3::Bucket', 'AWS::DynamoDB::Table']) {
      const resources = Object.values(template.findResources(resourceType));
      expect(resources).toHaveLength(2);
      for (const resource of resources) {
        expect(resource.DeletionPolicy).toBe('Retain');
        expect(resource.UpdateReplacePolicy).toBe('Retain');
      }
    }
    template.resourceCountIs('Custom::S3AutoDeleteObjects', 0);
  });

  test('development storage keeps its existing disposable behavior', () => {
    const stack = new DataStack(new cdk.App(), 'Data', { config: { ...config, stage: 'dev' } });
    const template = Template.fromStack(stack);
    template.allResources('AWS::S3::Bucket', { DeletionPolicy: 'Delete', UpdateReplacePolicy: 'Delete' });
    template.resourceCountIs('Custom::S3AutoDeleteObjects', 2);
  });

  test('standalone Data cleanup has identity permissions even before Web creates any bucket policy', () => {
    const stack = new DataStack(new cdk.App(), 'Data', { config: { ...config, stage: 'dev' } });
    const template = Template.fromStack(stack);
    template.resourceCountIs('AWS::S3::BucketPolicy', 0);
    const roles = Object.values(template.findResources('AWS::IAM::Role'));
    const statements = roles.flatMap(role => role.Properties.Policies ?? [])
      .flatMap(policy => policy.PolicyDocument.Statement)
      .filter(statement => statement.Effect === 'Allow');

    for (const bucket of [stack.siteBucket, stack.usersBucket]) {
      const requiredResources = stack.resolve([bucket.bucketArn, bucket.arnForObjects('*')]);
      const cleanupPermission = statements.find(statement => JSON.stringify(statement.Resource) === JSON.stringify(requiredResources));
      expect(cleanupPermission).toBeDefined();
      expect(cleanupPermission.Action).toEqual(expect.arrayContaining(['s3:GetBucket*', 's3:List*', 's3:DeleteObject*', 's3:PutBucketPolicy']));
    }
    expect(stack.dependencies).toEqual([]);
  });

  test('a plain Bucket cannot silently reintroduce a second policy owner', () => {
    const stack = new cdk.Stack(new cdk.App(), 'Data');
    const bucket = new s3.Bucket(stack, 'Bucket', { enforceSSL: true });
    expect(() => bucketPolicyDocument(bucket)).toThrow(/WebStack requires PlatformBucket/);
  });

  test('the explicit migration context retains the existing plain Bucket policy', () => {
    const stack = new cdk.Stack(new cdk.App({ context: { prepareBucketPolicyMigration: true } }), 'Data');
    const bucket = new s3.Bucket(stack, 'Bucket', { enforceSSL: true });
    expect(bucketPolicyDocument(bucket).statementCount).toBe(1);
    Template.fromStack(stack).hasResource('AWS::S3::BucketPolicy', {
      DeletionPolicy: 'Retain',
      UpdateReplacePolicy: 'Retain',
    });
  });
});
