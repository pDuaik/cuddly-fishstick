import * as cdk from 'aws-cdk-lib';
import { Construct } from 'constructs';
import * as cognito from 'aws-cdk-lib/aws-cognito';
import type { AppConfig } from './config';

export interface AuthStackProps extends cdk.StackProps {
  config: AppConfig;

  // URLs for your app (CloudFront domain or custom domain later)
  callbackUrls: string[];
  logoutUrls: string[];

  // Optional: if you want a Cognito custom domain like auth.example.com
  // NOTE: this is NOT your CloudFront cert. It must be an ACM cert in the SAME region as this stack.
  cognitoCustomDomain?: string;     // e.g. "auth.example.com"
  cognitoDomainCertArn?: string;    // ACM cert ARN in same region as user pool
}

export class AuthStack extends cdk.Stack {
  public readonly userPool: cognito.UserPool;
  public readonly userPoolClient: cognito.UserPoolClient;
  public readonly issuerUrl: string;

  // This will be either the default Cognito domain (if set) or your custom domain (if provided)
  public readonly hostedUiBaseUrl: string;

  constructor(scope: Construct, id: string, props: AuthStackProps) {
    super(scope, id, props);

    const { projectName, stage } = props.config;

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
        // keep symbols optional unless you really need them
        requireSymbols: false,
      },
      accountRecovery: cognito.AccountRecovery.EMAIL_ONLY,
      removalPolicy: cdk.RemovalPolicy.DESTROY, // POC/dev friendly; flip to RETAIN for prod later
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
        callbackUrls: props.callbackUrls,
        logoutUrls: props.logoutUrls,
      },

      accessTokenValidity: cdk.Duration.minutes(15),
      idTokenValidity: cdk.Duration.minutes(15),
      refreshTokenValidity: cdk.Duration.days(30),
    });

    // ---------------------------------------------------------------------
    // Domain for Hosted UI
    //
    // Default (recommended for template): Cognito domain prefix
    // Optional: custom domain (auth.example.com) requires ACM cert in SAME region
    // ---------------------------------------------------------------------
    const wantsCustomDomain = Boolean(props.cognitoCustomDomain);

    if (wantsCustomDomain) {
      if (!props.cognitoDomainCertArn) {
        throw new Error('cognitoDomainCertArn is required when cognitoCustomDomain is set.');
      }

      // L1 because custom domain needs certificate ARN; this is reliable and explicit
      const domain = new cognito.CfnUserPoolDomain(this, 'UserPoolDomain', {
        domain: props.cognitoCustomDomain!,
        userPoolId: this.userPool.userPoolId,
        customDomainConfig: {
          certificateArn: props.cognitoDomainCertArn,
        },
      });

      domain.node.addDependency(this.userPool);

      this.hostedUiBaseUrl = `https://${props.cognitoCustomDomain}`;
    } else {
      // Default Cognito domain (no certificate, no DNS)
      const prefix = `${projectName}-${stage}`.toLowerCase().replace(/[^a-z0-9-]/g, '-');

      const domain = this.userPool.addDomain('UserPoolDomain', {
        cognitoDomain: { domainPrefix: prefix.substring(0, 63) },
      });

      this.hostedUiBaseUrl = `https://${domain.domainName}`;
    }

    // Issuer URL (used for token validation if needed)
    this.issuerUrl = `https://cognito-idp.${this.region}.amazonaws.com/${this.userPool.userPoolId}`;

    // ---------------------------------------------------------------------
    // Outputs
    // ---------------------------------------------------------------------
    new cdk.CfnOutput(this, 'UserPoolId', { value: this.userPool.userPoolId });
    new cdk.CfnOutput(this, 'UserPoolClientId', { value: this.userPoolClient.userPoolClientId });
    new cdk.CfnOutput(this, 'Issuer', { value: this.issuerUrl });

    new cdk.CfnOutput(this, 'HostedUiBaseUrl', { value: this.hostedUiBaseUrl });
    new cdk.CfnOutput(this, 'AuthorizeEndpoint', { value: `${this.hostedUiBaseUrl}/oauth2/authorize` });
    new cdk.CfnOutput(this, 'TokenEndpoint', { value: `${this.hostedUiBaseUrl}/oauth2/token` });
    new cdk.CfnOutput(this, 'LogoutEndpoint', { value: `${this.hostedUiBaseUrl}/logout` });
  }
}
