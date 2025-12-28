/**
 * infra/test/api-stack.acceptance.test.ts
 *
 * Acceptance tests: prove extension wiring + guardrails don’t regress.
 */
import * as cdk from 'aws-cdk-lib';
import * as dynamodb from 'aws-cdk-lib/aws-dynamodb';
import * as s3 from 'aws-cdk-lib/aws-s3';

function baseProps(scope: cdk.Stack) {
  const sessionsTable = new dynamodb.Table(scope, 'Sessions', {
    partitionKey: { name: 'session_id', type: dynamodb.AttributeType.STRING },
  });

  const userProfileTable = new dynamodb.Table(scope, 'UserProfiles', {
    partitionKey: { name: 'user_sub', type: dynamodb.AttributeType.STRING },
  });

  const usersBucket = new s3.Bucket(scope, 'UsersBucket');

  return {
    config: {
      projectName: 'test',
      stage: 'dev',
      domain: 'example.com',
    },

    sessionsTable,
    usersBucket,
    userProfileTable,

    cognitoDomain: 'auth.example.com',
    cognitoClientId: 'client-id',

    cfPublicKeyId: 'K1234567890',
    cfPrivateKeySecretArn: 'arn:aws:secretsmanager:eu-west-2:123456789012:secret:test',
    cfCookieDomain: 'example.com',

    originVerifyHeaderName: 'X-Origin-Verify',
    originVerifyHeaderValueParameterArn: 'arn:aws:ssm:eu-west-2:123456789012:parameter/test/origin-verify',
  };
}

/**
 * IMPORTANT:
 * ApiStack uses NodejsFunction, which normally triggers esbuild bundling.
 * In Jest we don't want bundling; we just want to synth + verify wiring/guardrails.
 *
 * So we mock NodejsFunction and replace it with a plain lambda.Function that uses inline code.
 */
function mockNodejsFunctionNoBundling() {
  jest.doMock('aws-cdk-lib/aws-lambda-nodejs', () => {
    const lambda = require('aws-cdk-lib/aws-lambda');

    class NodejsFunction extends lambda.Function {
      constructor(scope: any, id: string, props: any) {
        super(scope, id, {
          runtime: props.runtime ?? lambda.Runtime.NODEJS_22_X,
          handler: 'index.handler',
          code: lambda.Code.fromInline('exports.handler=async()=>({statusCode:200,body:"ok"});'),
          environment: props.environment,
          timeout: props.timeout,
          memorySize: props.memorySize,
        });
      }
    }

    return { NodejsFunction };
  });
}

describe('ApiStack acceptance', () => {
  test('calls user.register(ctx)', () => {
    jest.isolateModules(() => {
      mockNodejsFunctionNoBundling();

      const registerSpy = jest.fn();
      jest.doMock('../user/index', () => ({ register: registerSpy }));

      const { ApiStack } = require('../lib/api-stack');

      const app = new cdk.App();
      const stack = new cdk.Stack(app, 'Root');

      new ApiStack(stack, 'Api', baseProps(stack));

      expect(registerSpy).toHaveBeenCalledTimes(1);
      expect(registerSpy.mock.calls[0]?.[0]).toBeTruthy();
    });
  });

  test('invalid extension route throws (path must start with /api/)', () => {
    jest.isolateModules(() => {
      mockNodejsFunctionNoBundling();

      jest.doMock('../user/index', () => ({
        register: (ctx: any) => {
          const fn = ctx.endpoint.createUserEndpoint({
            id: 'Bad',
            entryRelativeToUserDir: 'ping.ts',
          });

          ctx.api.registerApiRoute({
            path: '/not-api/ping',
            methods: ['GET'],
            fn,
          });
        },
      }));

      const { ApiStack } = require('../lib/api-stack');

      const app = new cdk.App();
      const stack = new cdk.Stack(app, 'Root');

      expect(() => new ApiStack(stack, 'Api', baseProps(stack))).toThrow(
        /path must start with "\/api\/"/,
      );
    });
  });

  test('invalid extension route throws (auth paths are rejected too)', () => {
    jest.isolateModules(() => {
      mockNodejsFunctionNoBundling();

      jest.doMock('../user/index', () => ({
        register: (ctx: any) => {
          const fn = ctx.endpoint.createUserEndpoint({
            id: 'BadAuth',
            entryRelativeToUserDir: 'ping.ts',
          });

          ctx.api.registerApiRoute({
            path: '/auth/evil',
            methods: ['GET'],
            fn,
          });
        },
      }));

      const { ApiStack } = require('../lib/api-stack');

      const app = new cdk.App();
      const stack = new cdk.Stack(app, 'Root');

      // With current guard order, /auth/* fails the "/api/" check first.
      expect(() => new ApiStack(stack, 'Api', baseProps(stack))).toThrow(
        /path must start with "\/api\/"/,
      );
    });
  });
});
