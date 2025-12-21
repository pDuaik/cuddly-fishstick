// lib/web-stack.ts
import * as cdk from 'aws-cdk-lib';
import { Construct } from 'constructs';
import * as acm from 'aws-cdk-lib/aws-certificatemanager';
import * as cloudfront from 'aws-cdk-lib/aws-cloudfront';
import * as s3 from 'aws-cdk-lib/aws-s3';
import * as s3deploy from 'aws-cdk-lib/aws-s3-deployment';

export interface WebStackProps extends cdk.StackProps {
  domain: string; // example.com or www.example.com
  certArnUsEast1: string; // ACM cert in us-east-1 for CloudFront

  siteBucket: s3.IBucket; // from DataStack

  apiDomain: string; // no scheme, e.g. abc.execute-api.eu-west-2.amazonaws.com
  cfPublicKeyId: string; // CloudFront Public Key ID (Key Groups)

  originVerifyHeaderName: string; // e.g. X-Origin-Verify
  originVerifyHeaderValueParameterArn: string; // SSM parameter ARN (SecureString recommended)

  websiteAbsPath: string; // absolute path to website folder
}

function ssmDynamicReferenceFromParamArn(paramArn: string): string {
  const marker = ':parameter/';
  const idx = paramArn.indexOf(marker);
  if (idx === -1) throw new Error(`Invalid SSM parameter ARN: ${paramArn}`);

  // After ":parameter/" comes "shared/parameter-store" (no leading slash in ARN)
  let name = paramArn.slice(idx + marker.length).trim();
  if (!name) throw new Error(`Invalid SSM parameter ARN (missing name): ${paramArn}`);

  // Your actual parameter name starts with "/" -> add it
  if (!name.startsWith('/')) name = '/' + name;

  // CloudFront supports non-secure SSM dynamic refs here
  return `{{resolve:ssm:${name}:1}}`;
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

    const cert = acm.Certificate.fromCertificateArn(this, 'SiteCert', props.certArnUsEast1);

    // -------------------------
    // OAC (L1)
    // -------------------------
    const oac = new cloudfront.CfnOriginAccessControl(this, 'SiteOAC', {
      originAccessControlConfig: {
        name: `${id}-site-bucket-oac`,
        description: 'OAC for private S3 origin',
        originAccessControlOriginType: 's3',
        signingBehavior: 'always',
        signingProtocol: 'sigv4',
      },
    });

    // -------------------------
    // Response headers policies (L2 -> we only need the IDs)
    // -------------------------
    const csp =
      "default-src 'self'; " +
      "base-uri 'self'; " +
      "object-src 'none'; " +
      "frame-ancestors 'none'; " +
      "form-action 'self'; " +
      "script-src 'self'; " +
      "style-src 'self'; " +
      "img-src 'self' data:; " +
      "connect-src 'self'; " +
      "font-src 'self'; " +
      'upgrade-insecure-requests';

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
    // Key Group for signed cookies (no need to create PublicKey resource)
    // -------------------------
    const importedPublicKey = cloudfront.PublicKey.fromPublicKeyId(this, 'SignedCookiesPublicKey', props.cfPublicKeyId);

    const keyGroup = new cloudfront.KeyGroup(this, 'SignedCookiesKeyGroup', {
      items: [importedPublicKey],
      comment: 'KeyGroup for signed cookies protection',
    });

    // -------------------------
    // CloudFront Distribution (L1) - avoids deprecated origins + avoids CDK bucket-policy mutation
    // -------------------------
    const originVerifyHeaderName =
      (props.originVerifyHeaderName || 'X-Origin-Verify').trim() || 'X-Origin-Verify';
    const originVerifyHeaderValue = ssmDynamicReferenceFromParamArn(
      props.originVerifyHeaderValueParameterArn,
    );

    // Managed policy IDs
    const cacheOptimizedId = cloudfront.CachePolicy.CACHING_OPTIMIZED.cachePolicyId;
    const cacheDisabledId = cloudfront.CachePolicy.CACHING_DISABLED.cachePolicyId;
    const orpAllViewerExceptHostId =
      cloudfront.OriginRequestPolicy.ALL_VIEWER_EXCEPT_HOST_HEADER.originRequestPolicyId;

    // S3 origin domain name (regional)
    const s3DomainName = props.siteBucket.bucketRegionalDomainName;

    const dist = new cloudfront.CfnDistribution(this, 'SiteDistribution', {
      distributionConfig: {
        enabled: true,
        comment: 'Template (static + sessions + signed-cookie protected /app)',
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
          // Origin 0: S3 (OAC attached)
          {
            id: 'S3Origin',
            domainName: s3DomainName,
            originAccessControlId: oac.ref,
            s3OriginConfig: {}, // OAC replaces OAI
          },
          // Origin 1: API Gateway domain (custom origin)
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
          targetOriginId: 'S3Origin',
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

          // /assets/config.json -> S3 (no-store)
          {
            pathPattern: '/assets/config.json',
            targetOriginId: 'S3Origin',
            viewerProtocolPolicy: 'redirect-to-https',
            allowedMethods: ['GET', 'HEAD', 'OPTIONS'],
            cachedMethods: ['GET', 'HEAD', 'OPTIONS'],
            cachePolicyId: cacheDisabledId,
            responseHeadersPolicyId: noStoreSecurityPolicy.responseHeadersPolicyId,
            compress: true,
          },

          // /app/* -> S3 protected by signed cookies
          {
            pathPattern: '/app/*',
            targetOriginId: 'S3Origin',
            viewerProtocolPolicy: 'redirect-to-https',
            allowedMethods: ['GET', 'HEAD', 'OPTIONS'],
            cachedMethods: ['GET', 'HEAD', 'OPTIONS'],
            cachePolicyId: cacheDisabledId,
            responseHeadersPolicyId: baseSecurityPolicy.responseHeadersPolicyId,
            trustedKeyGroups: [keyGroup.keyGroupId],
            compress: true,
          },
        ],
      },
    });

    // -------------------------
    // Bucket policy (L1) in WebStack => avoids cross-stack cycle
    // -------------------------
    new s3.CfnBucketPolicy(this, 'SiteBucketPolicy', {
      bucket: props.siteBucket.bucketName,
      policyDocument: {
        Version: '2012-10-17',
        Statement: [
          {
            Sid: 'AllowCloudFrontReadViaOAC',
            Effect: 'Allow',
            Principal: { Service: 'cloudfront.amazonaws.com' },
            Action: 's3:GetObject',
            Resource: `${props.siteBucket.bucketArn}/*`,
            Condition: {
              StringEquals: {
                'AWS:SourceArn': `arn:aws:cloudfront::${this.account}:distribution/${dist.ref}`,
              },
            },
          },
        ],
      },
    });

    // -------------------------
    // Deploy website
    // -------------------------
    new s3deploy.BucketDeployment(this, 'DeployWebsite', {
      sources: [s3deploy.Source.asset(props.websiteAbsPath)],
      destinationBucket: props.siteBucket,
    });

    // If you want invalidation to happen automatically, keep it simple:
    // - You can add a tiny custom resource later.
    // For now: deployment uploads assets; you can invalidate manually or with a script.

    // Outputs
    this.distributionId = dist.ref;
    this.distributionDomainName = dist.attrDomainName;

    new cdk.CfnOutput(this, 'CloudFrontDomainName', { value: dist.attrDomainName });
    new cdk.CfnOutput(this, 'DistributionId', { value: dist.ref });
    new cdk.CfnOutput(this, 'OacId', { value: oac.ref });
    new cdk.CfnOutput(this, 'KeyGroupId', { value: keyGroup.keyGroupId });
  }
}
