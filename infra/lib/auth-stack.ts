// lib/auth-stack.ts
import * as cdk from 'aws-cdk-lib';
import { Construct } from 'constructs';
import * as cognito from 'aws-cdk-lib/aws-cognito';
import type { AppConfig } from './config';

export interface AuthStackProps extends cdk.StackProps {
  config: AppConfig;
  certArnUsEast1: string;
}

/**
 * Domain rules:
 * - config.domain is the PUBLIC APP domain, either:
 *     - example.com (if DNS supports apex flattening), OR
 *     - www.example.com (if DNS does not support apex; user will redirect apex -> www)
 *
 * - Cognito Hosted UI will always be: auth.<rootDomain>
 *   where rootDomain = domain with "www." stripped if present.
 */
export class AuthStack extends cdk.Stack {
  public readonly userPool: cognito.UserPool;
  public readonly userPoolClient: cognito.UserPoolClient;

  public readonly issuerUrl: string;

  /** Base URL of Hosted UI, e.g. https://auth.example.com */
  public readonly hostedUiBaseUrl: string;

  /** Derived app base url, e.g. https://example.com or https://www.example.com */
  public readonly appBaseUrl: string;

  /** Derived auth domain, e.g. auth.example.com */
  public readonly cognitoAuthDomain: string;

  constructor(scope: Construct, id: string, props: AuthStackProps) {
    super(scope, id, props);

    const { projectName, stage, domain } = props.config;

    // ---------------------------------------------
    // Domain derivation
    // ---------------------------------------------
    // App domain is exactly what user provided (www or apex)
    this.appBaseUrl = `https://${domain}`;

    // Root domain removes leading "www." if present
    const rootDomain = domain.toLowerCase().startsWith('www.') ? domain.slice(4) : domain;

    // Cognito custom domain is always auth.<root>
    this.cognitoAuthDomain = `auth.${rootDomain}`;
    this.hostedUiBaseUrl = `https://${this.cognitoAuthDomain}`;

    const callbackUrls = [`${this.appBaseUrl}/auth/callback`];
    const logoutUrls = [`${this.appBaseUrl}/`];

    // ---------------------------------------------------------------------
    // User Pool
    // ---------------------------------------------------------------------
    this.userPool = new cognito.UserPool(this, 'UserPool', {
      userPoolName: `${projectName}-${stage}-user-pool`,
      selfSignUpEnabled: false,
      signInAliases: { email: true },
      autoVerify: { email: true },
      standardAttributes: {
        email: { required: true, mutable: true },
      },
      passwordPolicy: {
        minLength: 12,
        requireLowercase: true,
        requireUppercase: true,
        requireDigits: true,
        requireSymbols: false,
      },
      accountRecovery: cognito.AccountRecovery.EMAIL_ONLY,
      removalPolicy: cdk.RemovalPolicy.DESTROY, // dev/POC friendly
    });

    // ---------------------------------------------------------------------
    // App Client (public client: no secret)
    // Hosted UI uses OAuth Authorization Code Grant
    // ---------------------------------------------------------------------
    this.userPoolClient = new cognito.UserPoolClient(this, 'UserPoolClient', {
      userPool: this.userPool,
      userPoolClientName: `${projectName}-${stage}-web-client`,
      generateSecret: false,
      preventUserExistenceErrors: true,

      oAuth: {
        flows: {
          authorizationCodeGrant: true,
          implicitCodeGrant: false,
          clientCredentials: false,
        },
        scopes: [cognito.OAuthScope.OPENID, cognito.OAuthScope.EMAIL, cognito.OAuthScope.PROFILE],
        callbackUrls,
        logoutUrls,
      },

      accessTokenValidity: cdk.Duration.minutes(15),
      idTokenValidity: cdk.Duration.minutes(15),
      refreshTokenValidity: cdk.Duration.days(30),
    });

    // ---------------------------------------------------------------------
    // Cognito custom domain: auth.<rootDomain>
    // Requires ACM certificate ARN in same region as this stack.
    // ---------------------------------------------------------------------
    const domainRes = new cognito.CfnUserPoolDomain(this, 'UserPoolDomain', {
      domain: this.cognitoAuthDomain,
      userPoolId: this.userPool.userPoolId,
      customDomainConfig: {
        certificateArn: props.certArnUsEast1,
      },
    });
    domainRes.node.addDependency(this.userPool);

    // Issuer URL (useful for verification / docs)
    this.issuerUrl = `https://cognito-idp.${this.region}.amazonaws.com/${this.userPool.userPoolId}`;

    // ---------------------------------------------------------------------
    // Outputs
    // ---------------------------------------------------------------------
    new cdk.CfnOutput(this, 'UserPoolId', { value: this.userPool.userPoolId });
    new cdk.CfnOutput(this, 'UserPoolClientId', { value: this.userPoolClient.userPoolClientId });
    new cdk.CfnOutput(this, 'Issuer', { value: this.issuerUrl });

    new cdk.CfnOutput(this, 'AppBaseUrl', { value: this.appBaseUrl });
    new cdk.CfnOutput(this, 'CallbackUrl', { value: callbackUrls[0] });
    new cdk.CfnOutput(this, 'LogoutUrl', { value: logoutUrls[0] });

    new cdk.CfnOutput(this, 'CognitoAuthDomain', { value: this.cognitoAuthDomain });
    new cdk.CfnOutput(this, 'HostedUiBaseUrl', { value: this.hostedUiBaseUrl });
    new cdk.CfnOutput(this, 'AuthorizeEndpoint', { value: `${this.hostedUiBaseUrl}/oauth2/authorize` });
    new cdk.CfnOutput(this, 'TokenEndpoint', { value: `${this.hostedUiBaseUrl}/oauth2/token` });
    new cdk.CfnOutput(this, 'LogoutEndpoint', { value: `${this.hostedUiBaseUrl}/logout` });
  }
}
