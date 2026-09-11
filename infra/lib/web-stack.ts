// lib/web-stack.ts
import * as cdk from 'aws-cdk-lib';
import { Construct } from 'constructs';
import * as acm from 'aws-cdk-lib/aws-certificatemanager';
import * as cloudfront from 'aws-cdk-lib/aws-cloudfront';
import * as s3 from 'aws-cdk-lib/aws-s3';
import * as iam from 'aws-cdk-lib/aws-iam';
import { bucketPolicyDocument } from './platform-bucket';
import { userPathFunctionBody } from './user-path-function';

export interface WebStackProps extends cdk.StackProps {
  domain: string; // example.com or www.example.com
  certArnUsEast1: string; // ACM cert in us-east-1 for CloudFront

  siteBucket: s3.IBucket; // from DataStack (static site + /app + /config)
  usersBucket: s3.IBucket; // from DataStack (per-user /u/* artifacts)

  apiDomain: string; // hostname only (no scheme), e.g. abc.execute-api.eu-west-2.amazonaws.com
  cfPublicKeyId: string; // CloudFront Public Key ID (Key Groups)

  originVerifyHeaderName: string; // e.g. X-Origin-Verify
  originVerifyHeaderValueParameterArn: string; // SSM parameter ARN (Type=String)  

  allowedFrameSrc?: string[];
  allowedConnectSrc?: string[];
}

function ssmParameterName(paramArn: string): string {
  // Accepts: arn:aws:ssm:REGION:ACCOUNT:parameter/PATH/NAME
  // CloudFormation resolves this name through an SSM parameter-value parameter.
  const marker = ':parameter/';
  const idx = paramArn.indexOf(marker);
  if (idx === -1) throw new Error(`Invalid SSM parameter ARN: ${paramArn}`);

  let name = paramArn.slice(idx + marker.length).trim();
  if (!name) throw new Error(`Invalid SSM parameter ARN (missing name): ${paramArn}`);

  if (!name.startsWith('/')) name = '/' + name;

  return name;
}

function validateCspSource(src: string): string {
  const s = src.trim();

  if (!s) throw new Error('CSP source cannot be empty');

  if (/[;\r\n'"]/.test(s)) {
    throw new Error(`Invalid CSP source (contains illegal characters): ${src}`);
  }

  // Allow:
  // https://example.com
  // https://*.example.com
  // blob:
  // data:
  const allowed = /^(https:\/\/(\*\.)?[a-z0-9.-]+|blob:|data:)$/i;

  if (!allowed.test(s)) {
    throw new Error(`Invalid CSP source format: ${src}`);
  }

  return s;
}


export class WebStack extends cdk.Stack {
  public readonly distributionId: string;
  public readonly distributionDomainName: string;

  constructor(scope: Construct, id: string, props: WebStackProps) {
    super(scope, id, props);

    const siteDomain = (props.domain ?? '').trim();
    if (!siteDomain) throw new Error('WebStack: props.domain is required.');

    const apiDomain = (props.apiDomain ?? '').trim();
    if (!apiDomain) throw new Error('WebStack: props.apiDomain is required.');

    // Defensive: CloudFront origin domainName must be hostname only (no scheme/port/path)
    if (apiDomain.includes('://') || apiDomain.includes('/') || apiDomain.includes(':')) {
      throw new Error(`WebStack: props.apiDomain must be a hostname only (no scheme/port/path). Got: ${apiDomain}`);
    }

    const cert = acm.Certificate.fromCertificateArn(this, 'SiteCert', props.certArnUsEast1);

    // -------------------------
    // OAC (L1) - can be reused across S3 origins
    // -------------------------
    const oac = new cloudfront.CfnOriginAccessControl(this, 'S3OAC', {
      originAccessControlConfig: {
        name: `${id}-s3-oac`,
        description: 'OAC for private S3 origins',
        originAccessControlOriginType: 's3',
        signingBehavior: 'always',
        signingProtocol: 'sigv4',
      },
    });

    // -------------------------
    // Response headers policies
    // -------------------------
    const frameSrc = [
      "'self'",
      ...(props.allowedFrameSrc ?? []).map(validateCspSource),
    ].join(' ');

    const connectSrc = [
      "'self'",
      ...(props.allowedConnectSrc ?? []).map(validateCspSource),
    ].join(' ');

    const csp =
      "default-src 'self'; " +
      "base-uri 'self'; " +
      "object-src 'none'; " +
      "frame-ancestors 'self'; " +
      `frame-src ${frameSrc}; ` +
      "form-action 'self'; " +
      "script-src 'self'; " +
      "style-src 'self'; " +
      "img-src 'self' data:; " +
      `connect-src ${connectSrc}; ` +
      "font-src 'self'; " +
      "upgrade-insecure-requests";

    const securityHeadersBehavior: cloudfront.ResponseSecurityHeadersBehavior = {
      contentSecurityPolicy: { contentSecurityPolicy: csp, override: true },
      strictTransportSecurity: {
        accessControlMaxAge: cdk.Duration.days(365),
        includeSubdomains: true,
        preload: true,
        override: true,
      },
      xssProtection: { protection: true, modeBlock: true, override: true },
      contentTypeOptions: { override: true },
      frameOptions: { frameOption: cloudfront.HeadersFrameOption.DENY, override: true },
      referrerPolicy: {
        referrerPolicy: cloudfront.HeadersReferrerPolicy.STRICT_ORIGIN_WHEN_CROSS_ORIGIN,
        override: true,
      },
    };

    const baseSecurityPolicy = new cloudfront.ResponseHeadersPolicy(this, 'BaseSecurityPolicy', {
      comment: 'CSP + standard security headers',
      securityHeadersBehavior,
    });

    const noStoreSecurityPolicy = new cloudfront.ResponseHeadersPolicy(this, 'NoStoreSecurityPolicy', {
      comment: 'CSP + security headers + no-store',
      securityHeadersBehavior,
      customHeadersBehavior: {
        customHeaders: [
          { header: 'Cache-Control', value: 'no-store, no-cache, must-revalidate, max-age=0', override: true },
          { header: 'Pragma', value: 'no-cache', override: true },
          { header: 'Expires', value: '0', override: true },
        ],
      },
    });

    // -------------------------
    // Key Group for signed cookies
    // -------------------------
    const importedPublicKey = cloudfront.PublicKey.fromPublicKeyId(this, 'SignedCookiesPublicKey', props.cfPublicKeyId);
    const keyGroup = new cloudfront.KeyGroup(this, 'SignedCookiesKeyGroup', {
      items: [importedPublicKey],
      comment: 'KeyGroup for signed cookies protection',
    });

    // -------------------------
    // Resolve once for both the origin header and safely encoded edge HMAC key.
    // -------------------------
    const originVerifyHeaderName = (props.originVerifyHeaderName || 'X-Origin-Verify').trim() || 'X-Origin-Verify';
    const originVerifyValue = new cdk.CfnParameter(this, 'OriginVerifyValue', {
      type: 'AWS::SSM::Parameter::Value<String>',
      default: ssmParameterName(props.originVerifyHeaderValueParameterArn),
      noEcho: true,
      description: 'SSM String parameter used for origin verification and user-cookie authentication.',
    });
    const originVerifyHeaderValue = originVerifyValue.valueAsString;

    // Managed policy IDs
    const cacheOptimizedId = cloudfront.CachePolicy.CACHING_OPTIMIZED.cachePolicyId;
    const cacheDisabledId = cloudfront.CachePolicy.CACHING_DISABLED.cachePolicyId;
    const orpAllViewerExceptHostId =
      cloudfront.OriginRequestPolicy.ALL_VIEWER_EXCEPT_HOST_HEADER.originRequestPolicyId;

    // S3 origin domain names (regional)
    const siteS3DomainName = props.siteBucket.bucketRegionalDomainName;
    const usersS3DomainName = props.usersBucket.bucketRegionalDomainName;

    // -------------------------
    // CloudFront Function: rewrite /u/me/* -> /u/<opaque>/*
    // and deny direct /u/<opaque>/* (forces callers to use /u/me/*)
    // -------------------------
    const uMeRewriteFn = new cloudfront.Function(this, 'UPathRewriteFn', {
      comment: 'Verify signed user cookie, then rewrite /u/me/* to the authenticated prefix',
      runtime: cloudfront.FunctionRuntime.JS_2_0,
      code: cloudfront.FunctionCode.fromInline(cdk.Fn.join('', [
        'var crypto = require("crypto");\nvar secret = Buffer.from("',
        cdk.Fn.base64(originVerifyValue.valueAsString),
        '", "base64").toString("utf8").trim();\n',
        userPathFunctionBody(siteDomain),
      ])),
    });

    // -------------------------
    // CloudFront Distribution (L1)
    // -------------------------
    const dist = new cloudfront.CfnDistribution(this, 'SiteDistribution', {
      distributionConfig: {
        enabled: true,
        comment: 'Template (static + sessions + signed-cookie protected /app and /u)',
        aliases: [siteDomain],
        defaultRootObject: 'index.html',
        httpVersion: 'http2',
        priceClass: 'PriceClass_100',
        viewerCertificate: {
          acmCertificateArn: cert.certificateArn,
          sslSupportMethod: 'sni-only',
          minimumProtocolVersion: 'TLSv1.2_2021',
        },

        origins: [
          // Origin 0: Site bucket (OAC attached)
          {
            id: 'SiteS3Origin',
            domainName: siteS3DomainName,
            originAccessControlId: oac.ref,
            s3OriginConfig: {},
          },

          // Origin 1: Users bucket (OAC attached)
          {
            id: 'UsersS3Origin',
            domainName: usersS3DomainName,
            originAccessControlId: oac.ref,
            s3OriginConfig: {},
          },

          // Origin 2: API Gateway domain (custom origin)
          {
            id: 'ApiOrigin',
            domainName: apiDomain,
            customOriginConfig: {
              originProtocolPolicy: 'https-only',
              originSslProtocols: ['TLSv1.2'],
            },
            originCustomHeaders: [
              {
                headerName: originVerifyHeaderName,
                headerValue: originVerifyHeaderValue,
              },
            ],
          },
        ],

        defaultCacheBehavior: {
          targetOriginId: 'SiteS3Origin',
          viewerProtocolPolicy: 'redirect-to-https',
          allowedMethods: ['GET', 'HEAD', 'OPTIONS'],
          cachedMethods: ['GET', 'HEAD', 'OPTIONS'],
          cachePolicyId: cacheOptimizedId,
          responseHeadersPolicyId: baseSecurityPolicy.responseHeadersPolicyId,
          compress: true,
        },

        cacheBehaviors: [
          // /auth/* -> API
          {
            pathPattern: '/auth/*',
            targetOriginId: 'ApiOrigin',
            viewerProtocolPolicy: 'https-only',
            allowedMethods: ['GET', 'HEAD', 'OPTIONS', 'PUT', 'PATCH', 'POST', 'DELETE'],
            cachedMethods: ['GET', 'HEAD', 'OPTIONS'],
            cachePolicyId: cacheDisabledId,
            originRequestPolicyId: orpAllViewerExceptHostId,
            responseHeadersPolicyId: baseSecurityPolicy.responseHeadersPolicyId,
            compress: true,
          },

          // /api/* -> API
          {
            pathPattern: '/api/*',
            targetOriginId: 'ApiOrigin',
            viewerProtocolPolicy: 'https-only',
            allowedMethods: ['GET', 'HEAD', 'OPTIONS', 'PUT', 'PATCH', 'POST', 'DELETE'],
            cachedMethods: ['GET', 'HEAD', 'OPTIONS'],
            cachePolicyId: cacheDisabledId,
            originRequestPolicyId: orpAllViewerExceptHostId,
            responseHeadersPolicyId: baseSecurityPolicy.responseHeadersPolicyId,
            compress: true,
          },

          // /app/* -> Site bucket protected by signed cookies
          {
            pathPattern: '/app/*',
            targetOriginId: 'SiteS3Origin',
            viewerProtocolPolicy: 'redirect-to-https',
            allowedMethods: ['GET', 'HEAD', 'OPTIONS'],
            cachedMethods: ['GET', 'HEAD', 'OPTIONS'],
            cachePolicyId: cacheDisabledId,
            responseHeadersPolicyId: noStoreSecurityPolicy.responseHeadersPolicyId,
            trustedKeyGroups: [keyGroup.keyGroupId],
            compress: true,
          },

          // /u/* -> Users bucket protected by signed cookies + rewrite function
          {
            pathPattern: '/u/*',
            targetOriginId: 'UsersS3Origin',
            viewerProtocolPolicy: 'redirect-to-https',
            allowedMethods: ['GET', 'HEAD', 'OPTIONS'],
            cachedMethods: ['GET', 'HEAD', 'OPTIONS'],
            cachePolicyId: cacheDisabledId,
            responseHeadersPolicyId: noStoreSecurityPolicy.responseHeadersPolicyId,
            trustedKeyGroups: [keyGroup.keyGroupId],
            compress: true,
            functionAssociations: [
              {
                eventType: 'viewer-request',
                functionArn: uMeRewriteFn.functionArn,
              },
            ],
          },

          // /config/* -> Site bucket (no-store)
          {
            pathPattern: '/config/*',
            targetOriginId: 'SiteS3Origin',
            viewerProtocolPolicy: 'redirect-to-https',
            allowedMethods: ['GET', 'HEAD', 'OPTIONS'],
            cachedMethods: ['GET', 'HEAD', 'OPTIONS'],
            cachePolicyId: cacheDisabledId,
            responseHeadersPolicyId: noStoreSecurityPolicy.responseHeadersPolicyId,
            compress: true,
          },
        ],
      },
    });

    // One policy resource per bucket, owned here to avoid a Data -> Web cycle.
    // Include every statement collected during bucket creation and extension setup.
    for (const [policyId, bucket] of [
      ['SiteBucketPolicy', props.siteBucket],
      ['UsersBucketPolicy', props.usersBucket],
    ] as const) {
      const document = bucketPolicyDocument(bucket);
      document.addStatements(new iam.PolicyStatement({
        sid: 'AllowCloudFrontReadViaOAC',
        principals: [new iam.ServicePrincipal('cloudfront.amazonaws.com')],
        actions: ['s3:GetObject'],
        resources: [bucket.arnForObjects('*')],
        conditions: {
          StringEquals: {
            'AWS:SourceArn': cdk.Fn.join('', [
              'arn:', this.partition, ':cloudfront::', this.account, ':distribution/', dist.ref,
            ]),
          },
        },
      }));
      const policy = new s3.CfnBucketPolicy(this, policyId, {
        bucket: bucket.bucketName,
        policyDocument: document,
      });
      // Web is removed before Data. Retain the policy so the DataStack cleanup
      // provider can still empty disposable buckets; persistent buckets keep SSL enforcement.
      policy.applyRemovalPolicy(cdk.RemovalPolicy.RETAIN);
    }

    // Outputs
    this.distributionId = dist.ref;
    this.distributionDomainName = dist.attrDomainName;

    new cdk.CfnOutput(this, 'CloudFrontDomainName', { value: dist.attrDomainName });
    new cdk.CfnOutput(this, 'DistributionId', { value: dist.ref });
    new cdk.CfnOutput(this, 'OacId', { value: oac.ref });
    new cdk.CfnOutput(this, 'KeyGroupId', { value: keyGroup.keyGroupId });
    new cdk.CfnOutput(this, 'URewriteFunctionArn', { value: uMeRewriteFn.functionArn });
  }
}
