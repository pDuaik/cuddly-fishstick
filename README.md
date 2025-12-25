# cuddly-fishstick
AWS serverless web application focused on security hardening, Well-Architected best practices, and cost-effective design.

# Roadmap
1) Session TTL 10 minutes.
2) Auto-refresh cookies.
3) Update html real time
4) Create error page and make cloudfront route users to things like not authorized or filed or missing page.

# Project Philosophy

This project prioritizes correct security boundaries, least privilege, and fail-closed behavior from the start.

It is designed to be used as a foundation for proof-of-concepts and early-stage products where security and architecture decisions matter, even before scale.

# Setup
add A record 192.0.2.1 to your domain as a placeholder, or Cognito will throw an error.

# Prerequisites: DNS & Certificates (Read This First)

This project **requires a custom domain**.
You must complete the DNS and certificate setup **before running `cdk deploy`**.

If this is not done first, the deployment **will fail**.

---

## 1. Domain Requirements

You must own and control a public domain, for example:

```text
example.com
```

You may choose **one** of the following as your application domain:

* `example.com` (apex / root domain)
* `www.example.com`

This value is referred to throughout the project as:

```text
domain
```

You will set this value in `cdk.json`.

---

## 2. Certificate Requirements (Mandatory)

You need **two ACM certificates**, in **two different regions**.

---

### 2.1 CloudFront Certificate (us-east-1)

CloudFront **only accepts certificates from `us-east-1`**.

Create an ACM certificate in **us-east-1** that covers **your chosen domain**.

Examples:

* If your app domain is `example.com`
  → the certificate must include `example.com`

* If your app domain is `www.example.com`
  → the certificate must include `www.example.com`

**Recommended options:**

* A certificate containing:

  * `example.com`
  * `www.example.com`
* Or:

  * `example.com`
  * `*.example.com`

> ⚠️ Wildcard certificates (`*.example.com`) **do NOT** cover `example.com` (the apex).
> If you plan to use the apex domain, it must be listed explicitly.

You will need the **certificate ARN** later.

---

### 2.2 Cognito Certificate (Deployment Region)

Cognito **does NOT use us-east-1 certificates**.

Create a second ACM certificate in **the same region where you deploy this stack**
(e.g. `eu-west-2`).

This certificate **must cover**:

```text
auth.<your-domain>
```

Examples:

* `auth.example.com`
* `auth.www.example.com` (supported, but not recommended)

This certificate is used **only** for the Cognito Hosted UI domain.

---

## 3. DNS Records (What You Must Create)

### 3.1 CloudFront (Main Application Domain)

After deployment, CloudFront will output a domain similar to:

```text
d123abcd.cloudfront.net
```

You must point your **application domain** to this value.

---

#### If your DNS provider supports ANAME / ALIAS (Recommended)

Create:

```text
example.com   →   ALIAS / ANAME → d123abcd.cloudfront.net
```

This works for **apex/root domains**.

Most modern DNS providers support this:

* Route53 (ALIAS)
* Cloudflare
* DNSimple
* Namecheap (ANAME)
* Others

---

#### If your DNS provider does NOT support ANAME at the apex

Use `www` instead:

```text
www.example.com → CNAME → d123abcd.cloudfront.net
```

Then configure a redirect:

```text
example.com → www.example.com
```

> This is a DNS limitation, not an AWS limitation.

---

### 3.2 Cognito Hosted UI Domain

Cognito creates a CloudFront-backed endpoint for the Hosted UI.

You must create a DNS record for:

```text
auth.<your-domain>
```

Example:

```text
auth.example.com → CNAME → <cognito-domain-output>
```

The exact target value is available:

* In the Cognito console
* Or via CDK stack outputs

This record is required for:

* Login
* Logout
* OAuth redirects

---

## 4. Configuration Summary

Before deploying, you must have:

* ✅ Domain ownership
* ✅ DNS access
* ✅ ACM certificate in **us-east-1** for CloudFront
* ✅ ACM certificate in **deployment region** for Cognito
* ✅ DNS records ready (or planned)

Then set the following values in `cdk.json`:

```json
{
  "appDomain": "example.com",
  "cloudFrontCertArnUsEast1": "arn:aws:acm:us-east-1:123456789012:certificate/xxxx"
}
```

---

## 5. After Deployment (Final Step)

Once `cdk deploy` completes:

1. Update DNS:

   * Point your application domain to CloudFront
   * Point `auth.<domain>` to Cognito

2. Wait for DNS propagation (usually minutes, sometimes longer).

3. Access:

   * App: `https://<your-domain>`
   * Login: `https://auth.<your-domain>/login`

---

## 6. Why This Is Required

This template intentionally enforces:

* Single-pass deployment
* Deterministic URLs
* No post-deploy rewiring
* Production-grade security defaults

If you are not ready to manage DNS and certificates, **this template is not for you** — and that is intentional.

# License

This project is licensed under the MIT License.

You are free to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the software, provided that the original copyright and license notice are included.

See the [LICENSE](./LICENSE) file for full details.
