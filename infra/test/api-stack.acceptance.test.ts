/**
 * infra/test/api-stack.acceptance.test.ts
 *
 * Acceptance tests: prove extension wiring + guardrails don’t regress.
 */
import * as cdk from 'aws-cdk-lib';
import { Template } from 'aws-cdk-lib/assertions';
import * as dynamodb from 'aws-cdk-lib/aws-dynamodb';
import * as s3 from 'aws-cdk-lib/aws-s3';

function baseProps(scope: cdk.Stack) {
  const sessionsTable = new dynamodb.Table(scope, 'Sessions', {
    tableName: 'test-sessions',
    partitionKey: { name: 'session_id', type: dynamodb.AttributeType.STRING },
  });

  const userProfileTable = new dynamodb.Table(scope, 'UserProfiles', {
    tableName: 'test-user-profiles',
    partitionKey: { name: 'user_sub', type: dynamodb.AttributeType.STRING },
  });

  const usersBucket = new s3.Bucket(scope, 'UsersBucket', {
    bucketName: 'test-users-bucket',
  });

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
    cognitoUserPoolId: 'user-pool-id',

    cfPublicKeyId: 'K1234567890',
    cfPrivateKeyParameterArn: 'arn:aws:ssm:eu-west-2:123456789012:parameter/test',
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
      expect(registerSpy.mock.calls[0]?.[0].platform.cognitoUserPoolId).toBe('user-pool-id');
      expect(registerSpy.mock.calls[0]?.[0].publicEndpoint.createPublicEndpoint).toBeInstanceOf(Function);
      expect(registerSpy.mock.calls[0]?.[0].publicApi.registerPublicApiRoute).toBeInstanceOf(Function);
    });
  });

  test('public extension route is not authenticated', () => {
    jest.isolateModules(() => {
      mockNodejsFunctionNoBundling();

      jest.doMock('../user/index', () => ({
        register: (ctx: any) => {
          const fn = ctx.publicEndpoint.createPublicEndpoint({
            id: 'PublicPing',
            entryRelativeToUserDir: 'ping.ts',
          });

          ctx.publicApi.registerPublicApiRoute({
            path: '/api/public/ping',
            methods: ['GET'],
            fn,
          });
        },
      }));

      const { ApiStack } = require('../lib/api-stack');

      const app = new cdk.App();
      const stack = new cdk.Stack(app, 'Root');

      const apiStack = new ApiStack(stack, 'Api', baseProps(stack));
      const template = Template.fromStack(apiStack).toJSON();
      const routes = Object.values(template.Resources as Record<string, any>)
        .filter((resource: any) => resource.Type === 'AWS::ApiGatewayV2::Route');
      const publicRoute = routes.find((resource: any) => resource.Properties?.RouteKey === 'GET /api/public/ping');

      expect(publicRoute).toBeTruthy();
      expect(publicRoute.Properties.AuthorizationType).toBe('NONE');
      expect(publicRoute.Properties.AuthorizerId).toBeUndefined();
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

  test('private extension route rejects public namespace', () => {
    jest.isolateModules(() => {
      mockNodejsFunctionNoBundling();

      jest.doMock('../user/index', () => ({
        register: (ctx: any) => {
          const fn = ctx.endpoint.createUserEndpoint({
            id: 'BadPublicNamespace',
            entryRelativeToUserDir: 'ping.ts',
          });

          ctx.api.registerApiRoute({
            path: '/api/public/ping',
            methods: ['GET'],
            fn,
          });
        },
      }));

      const { ApiStack } = require('../lib/api-stack');

      const app = new cdk.App();
      const stack = new cdk.Stack(app, 'Root');

      expect(() => new ApiStack(stack, 'Api', baseProps(stack))).toThrow(
        /reserved for registerPublicApiRoute/,
      );
    });
  });

  test('invalid public extension route throws (path must start with /api/public/)', () => {
    jest.isolateModules(() => {
      mockNodejsFunctionNoBundling();

      jest.doMock('../user/index', () => ({
        register: (ctx: any) => {
          const fn = ctx.publicEndpoint.createPublicEndpoint({
            id: 'BadPublic',
            entryRelativeToUserDir: 'ping.ts',
          });

          ctx.publicApi.registerPublicApiRoute({
            path: '/api/not-public/ping',
            methods: ['GET'],
            fn,
          });
        },
      }));

      const { ApiStack } = require('../lib/api-stack');

      const app = new cdk.App();
      const stack = new cdk.Stack(app, 'Root');

      expect(() => new ApiStack(stack, 'Api', baseProps(stack))).toThrow(
        /path must start with "\/api\/public\/"/,
      );
    });
  });

  test('invalid public extension route throws (write methods are rejected)', () => {
    jest.isolateModules(() => {
      mockNodejsFunctionNoBundling();

      jest.doMock('../user/index', () => ({
        register: (ctx: any) => {
          const fn = ctx.publicEndpoint.createPublicEndpoint({
            id: 'BadPublicMethod',
            entryRelativeToUserDir: 'ping.ts',
          });

          ctx.publicApi.registerPublicApiRoute({
            path: '/api/public/ping',
            methods: ['POST'],
            fn,
          });
        },
      }));

      const { ApiStack } = require('../lib/api-stack');

      const app = new cdk.App();
      const stack = new cdk.Stack(app, 'Root');

      expect(() => new ApiStack(stack, 'Api', baseProps(stack))).toThrow(
        /registerPublicApiRoute: method not allowed: POST/,
      );
    });
  });
});
