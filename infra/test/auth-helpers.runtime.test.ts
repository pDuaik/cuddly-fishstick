import { SSMClient } from '@aws-sdk/client-ssm';
import { createHmac } from 'crypto';
import { enforceOriginVerify, safeAbsoluteHttpsUrl, safePostLoginRedirect, signUserCookie, validateCognitoIdToken } from '../lambda/api/helpers';

describe('login redirect validation', () => {
  test.each([
    '/\\attacker.example/path',
    '//attacker.example/path',
    '/\t/attacker.example/path',
    '/\r\n/attacker.example/path',
    '/safe/..//attacker.example/path',
    'https://attacker.example/path',
    'https://example.com@attacker.example/path',
    'http://example.com/path',
    'https://example.com:444/path',
    'javascript:alert(1)',
  ])('rejects external or ambiguous target %j', (target) => {
    expect(safePostLoginRedirect(target, '/app/', 'example.com')).toBe('/app/');
  });

  test.each([
    ['/app/one/../two?filter=https://elsewhere.example#details', '/app/two?filter=https://elsewhere.example#details'],
    ['https://example.com/app/home', '/app/home'],
    ['/app/a%2Fb?next=%2Fapp%2Fhome', '/app/a%2Fb?next=%2Fapp%2Fhome'],
    ['/app/%252Fexample', '/app/%252Fexample'],
  ])('normalizes a same-origin target without decoding path escapes', (target, expected) => {
    const result = safePostLoginRedirect(target, '/app/', 'example.com');
    expect(result).toBe(expected);
    expect(new URL(result, 'https://example.com').origin).toBe('https://example.com');
  });

  test('does not trust an unsafe configured fallback', () => {
    expect(safePostLoginRedirect('', '/\\attacker.example', 'example.com')).toBe('/');
  });

  test('parses absolute HTTPS logout URLs instead of trusting a prefix', () => {
    expect(safeAbsoluteHttpsUrl('https://example.com/path', '/')).toBe('https://example.com/path');
    expect(safeAbsoluteHttpsUrl('https://', '/')).toBe('/');
    expect(safeAbsoluteHttpsUrl('https://example.com\r\nlocation: evil', '/')).toBe('/');
    expect(safeAbsoluteHttpsUrl('https://user:pass@example.com/', '/')).toBe('/');
  });
});

describe('direct Cognito token response claims', () => {
  const issuer = 'https://cognito-idp.eu-west-2.amazonaws.com/eu-west-2_pool';
  const now = 1_800_000_000;
  const validClaims = { iss: issuer, aud: 'client', token_use: 'id', iat: now, exp: now + 3600, sub: 'user-123' };
  const token = (claims: unknown) => `eyJhbGciOiJSUzI1NiJ9.${Buffer.from(JSON.stringify(claims)).toString('base64url')}.c2ln`;

  test('accepts claims bound to the configured user pool and client', () => {
    expect(validateCognitoIdToken(token(validClaims), issuer, 'client', now).sub).toBe('user-123');
  });

  test.each([
    { iss: 'https://cognito-idp.eu-west-2.amazonaws.com/another-pool' },
    { aud: 'another-client' },
    { aud: ['client'] },
    { token_use: 'access' },
    { exp: now },
    { exp: now - 1 },
    { exp: String(now + 3600) },
    { exp: undefined },
    { iat: undefined },
    { iat: String(now) },
    { iat: now + 0.5 },
    { iat: -1 },
    { iat: now + 61 },
    { iat: now + 30, exp: now + 30 },
    { iat: now + 60, exp: now + 30 },
    { sub: '' },
    { sub: ' ' },
    { sub: undefined },
    { sub: 'unknown' },
    { sub: { id: 'user-123' } },
  ])('rejects invalid or absent claim %j', (overrides) => {
    expect(() => validateCognitoIdToken(token({ ...validClaims, ...overrides }), issuer, 'client', now)).toThrow();
  });

  test('allows up to 60 seconds of issuer clock skew', () => {
    expect(validateCognitoIdToken(token({ ...validClaims, iat: now + 60 }), issuer, 'client', now).sub).toBe('user-123');
  });

  test.each(['not-a-jwt', 'e30.e30.', 'e30.e30.c2ln.extra', token(null), token([])])('rejects malformed JWT %s', (value) => {
    expect(() => validateCognitoIdToken(value, issuer, 'client', now)).toThrow();
  });
});

describe('origin verification cache', () => {
  const originalEnv = process.env;

  afterEach(() => {
    process.env = originalEnv;
    jest.restoreAllMocks();
  });

  test('refreshes a warm-instance cache after 60 seconds and stops accepting the old value', async () => {
    process.env = {
      ...originalEnv,
      PLATFORM_ORIGIN_VERIFY_HEADER_NAME: 'X-Origin-Verify',
      PLATFORM_ORIGIN_VERIFY_HEADER_VALUE_SSM_PARAM_ARN: '/test/cache-refresh',
    };
    let now = 1_800_000_000_000;
    jest.spyOn(Date, 'now').mockImplementation(() => now);
    const send = jest.spyOn(SSMClient.prototype, 'send')
      .mockResolvedValueOnce({ Parameter: { Value: 'first-value' } } as never)
      .mockResolvedValueOnce({ Parameter: { Value: 'replacement-value' } } as never);
    const request = (value: string) => ({ headers: { 'x-origin-verify': value } });

    expect((await enforceOriginVerify(request('first-value'))).ok).toBe(true);
    now += 59_999;
    expect((await enforceOriginVerify(request('first-value'))).ok).toBe(true);
    expect(send).toHaveBeenCalledTimes(1);
    now += 1;
    expect((await enforceOriginVerify(request('replacement-value'))).ok).toBe(true);
    expect((await enforceOriginVerify(request('first-value'))).ok).toBe(false);
    expect(send).toHaveBeenCalledTimes(2);
    expect((send.mock.calls[0][0] as any).input).toEqual({ Name: '/test/cache-refresh', WithDecryption: true });
  });

  test('fails closed when refreshing an expired value fails', async () => {
    process.env = {
      ...originalEnv,
      PLATFORM_ORIGIN_VERIFY_HEADER_NAME: 'X-Origin-Verify',
      PLATFORM_ORIGIN_VERIFY_HEADER_VALUE_SSM_PARAM_ARN: '/test/cache-failure',
    };
    let now = 1_800_000_000_000;
    jest.spyOn(Date, 'now').mockImplementation(() => now);
    jest.spyOn(SSMClient.prototype, 'send')
      .mockResolvedValueOnce({ Parameter: { Value: 'old-value' } } as never)
      .mockRejectedValueOnce(new Error('SSM unavailable') as never);
    const event = { headers: { 'x-origin-verify': 'old-value' } };
    expect((await enforceOriginVerify(event)).ok).toBe(true);
    now += 60_000;
    expect(await enforceOriginVerify(event)).toMatchObject({ ok: false, statusCode: 500 });
  });
});

describe('authenticated user-prefix cookie', () => {
  const originalEnv = process.env;
  const opaqueId = 'a'.repeat(43);
  const expires = 1_800_000_060;

  beforeEach(() => {
    process.env = {
      ...originalEnv,
      PLATFORM_ORIGIN_VERIFY_HEADER_VALUE_SSM_PARAM_ARN: '/test/user-cookie-signing',
    };
    jest.spyOn(Date, 'now').mockReturnValue(1_800_000_000_000);
    jest.spyOn(SSMClient.prototype, 'send').mockResolvedValue({ Parameter: { Value: 'origin-value' } } as never);
  });

  afterEach(() => {
    process.env = originalEnv;
    jest.restoreAllMocks();
  });

  test('binds user, expiry, purpose and application host to the same MAC', async () => {
    const signed = await signUserCookie(opaqueId, expires, 'EXAMPLE.com');
    const message = (id: string, expiry: number, host: string, purpose = 'user-cookie:v1') =>
      `${purpose}\n${host}\n${id}\n${expiry}`;
    const mac = (value: string) => createHmac('sha256', 'origin-value').update(value).digest('hex');
    const signature = signed.split('.')[2];
    expect(signed).toBe(`${opaqueId}.${expires}.${mac(message(opaqueId, expires, 'example.com'))}`);
    expect(signature).not.toBe(mac(message('b'.repeat(43), expires, 'example.com')));
    expect(signature).not.toBe(mac(message(opaqueId, expires + 3600, 'example.com')));
    expect(signature).not.toBe(mac(message(opaqueId, expires, 'other.example.com')));
    expect(signature).not.toBe(mac(message(opaqueId, expires, 'example.com', 'another-purpose')));
  });

  test.each(['', '../other-user', 'a'.repeat(42), 'a'.repeat(44)])('refuses an invalid stored user selector %j', async (id) => {
    await expect(signUserCookie(id, expires, 'example.com')).rejects.toThrow();
  });

  test('fails closed without the SSM signing value', async () => {
    process.env.PLATFORM_ORIGIN_VERIFY_HEADER_VALUE_SSM_PARAM_ARN = '/test/user-cookie-empty';
    jest.mocked(SSMClient.prototype.send).mockResolvedValueOnce({ Parameter: { Value: '' } } as never);
    await expect(signUserCookie(opaqueId, expires, 'example.com')).rejects.toThrow('unavailable');
  });
});
