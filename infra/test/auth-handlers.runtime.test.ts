import * as crypto from 'crypto';
import { SSMClient } from '@aws-sdk/client-ssm';
import { DynamoDBDocumentClient, DeleteCommand, GetCommand, PutCommand, UpdateCommand } from '@aws-sdk/lib-dynamodb';
import { handler as start } from '../lambda/api/auth-start';
import { handler as callback } from '../lambda/api/auth-callback';
import { handler as logout } from '../lambda/api/auth-logout';
import { handler as authorize } from '../lambda/api/session-authorizer';

const originalEnv = process.env;
const issuer = 'https://cognito-idp.eu-west-2.amazonaws.com/eu-west-2_pool';
const now = 1_800_000_000;
const validClaims = { iss: issuer, aud: 'client-id', token_use: 'id', iat: now, exp: now + 3600, sub: 'user-123' };
const token = (claims: unknown) => `eyJhbGciOiJSUzI1NiJ9.${Buffer.from(JSON.stringify(claims)).toString('base64url')}.c2ln`;
const privateKey = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 }).privateKey
  .export({ format: 'pem', type: 'pkcs8' }).toString();
let serial = 0;

function event(extra: Record<string, unknown> = {}): any {
  return {
    headers: { 'x-origin-verify': 'origin-value' },
    cookies: ['oauth_state=expected-state', 'pkce_verifier=verifier-value'],
    queryStringParameters: { code: 'authorization-code', state: 'expected-state' },
    ...extra,
  };
}

function cookie(response: any, name: string): string | undefined {
  return response.cookies?.find((value: string) => value.startsWith(`${name}=`));
}

beforeEach(() => {
  process.env = {
    ...originalEnv,
    PLATFORM_ORIGIN_VERIFY_HEADER_NAME: 'X-Origin-Verify',
    PLATFORM_ORIGIN_VERIFY_HEADER_VALUE_SSM_PARAM_ARN: `/test/auth-origin-${++serial}`,
    SESSIONS_TABLE_NAME: 'sessions',
    USER_PROFILE_TABLE_NAME: 'profiles',
    COGNITO_DOMAIN: 'auth.example.com',
    COGNITO_CLIENT_ID: 'client-id',
    COGNITO_ISSUER: issuer,
    REDIRECT_URI: 'https://example.com/auth/callback',
    POST_LOGIN_REDIRECT: '/app/',
    POST_LOGOUT_REDIRECT: 'https://example.com/',
    SESSION_TTL_SECONDS: '3600',
    CF_PUBLIC_KEY_ID: 'key-id',
    CF_PRIVATE_KEY_PARAMETER_ARN: '/test/cf-key',
    CF_APP_RESOURCE: 'https://example.com/*',
    COOKIE_NAME: 'session',
    CF_COOKIE_DOMAIN: '',
    CF_COOKIE_PATH: '/',
  };
  jest.spyOn(Date, 'now').mockReturnValue(now * 1000);
  jest.spyOn(SSMClient.prototype, 'send').mockImplementation((async (command: any) => ({
    Parameter: { Value: command.input.Name === '/test/cf-key' ? privateKey : 'origin-value' },
  })) as any);
  jest.spyOn(globalThis, 'fetch').mockResolvedValue({
    ok: true,
    status: 200,
    text: async () => JSON.stringify({ id_token: token(validClaims), access_token: 'access-token', refresh_token: 'refresh-token' }),
  } as Response);
});

afterEach(() => {
  process.env = originalEnv;
  jest.restoreAllMocks();
});

describe('auth start and callback redirects', () => {
  test.each(['/\\attacker.example', '/safe/..//attacker.example', '/\t/attacker.example'])('blocks redirect bypass through both handlers: %j', async (next) => {
    const response: any = await start(event({ queryStringParameters: { next } }));
    expect(response.statusCode).toBe(302);
    expect(cookie(response, 'post_login')).toContain(`post_login=${encodeURIComponent('/app/')};`);

    jest.spyOn(DynamoDBDocumentClient.prototype, 'send').mockImplementation((async (command: any) => {
      return command instanceof UpdateCommand ? { Attributes: { opaque_id: 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa' } } : {};
    }) as any);
    const callbackResponse: any = await callback(event({
      cookies: [...event().cookies, `post_login=${encodeURIComponent(next)}`],
    }));
    expect(callbackResponse.statusCode).toBe(302);
    expect(callbackResponse.headers.location).toBe('/app/');
  });

  test('retains encoded path and query characters through the complete cookie roundtrip', async () => {
    const next = '/app/a%2Fb?filter=%252F';
    const response: any = await start(event({ queryStringParameters: { next } }));
    const postLoginCookie = cookie(response, 'post_login')!.split(';')[0];
    jest.spyOn(DynamoDBDocumentClient.prototype, 'send').mockImplementation((async (command: any) => {
      return command instanceof UpdateCommand ? { Attributes: { opaque_id: 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa' } } : {};
    }) as any);
    const callbackResponse: any = await callback(event({ cookies: [...event().cookies, postLoginCookie] }));
    expect(callbackResponse.headers.location).toBe(next);
  });
});

describe('login credential issuance', () => {
  test.each([{ sub: undefined }, { aud: 'wrong-client' }, { iss: 'wrong-pool' }, { token_use: 'access' }, { exp: now }, { iat: undefined }, { iat: now + 61 }])('rejects untrusted identity before any data write: %j', async (claims) => {
    jest.mocked(fetch).mockResolvedValueOnce({
      ok: true,
      text: async () => JSON.stringify({ id_token: token({ ...validClaims, ...claims }), access_token: 'access-token' }),
    } as Response);
    const send = jest.spyOn(DynamoDBDocumentClient.prototype, 'send').mockResolvedValue({} as never);
    const response = await callback(event());
    expect(response.statusCode).toBe(502);
    expect(send).not.toHaveBeenCalled();
    expect(cookie(response, 'session')).toBeUndefined();
    expect(cookie(response, 'CloudFront-Policy')).toBeUndefined();
  });

  test('does not write a session or issue credentials if signing configuration is missing', async () => {
    delete process.env.CF_PRIVATE_KEY_PARAMETER_ARN;
    const send = jest.spyOn(DynamoDBDocumentClient.prototype, 'send').mockResolvedValue({} as never);
    const response = await callback(event());
    expect(response.statusCode).toBe(500);
    expect(send).not.toHaveBeenCalled();
    expect(fetch).not.toHaveBeenCalled();
    expect(cookie(response, 'session')).toBeUndefined();
  });

  test('does not write a session or issue credentials when SSM key loading fails', async () => {
    jest.mocked(SSMClient.prototype.send).mockImplementation((async (command: any) => {
      if (command.input.Name === '/test/cf-key') throw new Error('SSM unavailable');
      return { Parameter: { Value: 'origin-value' } };
    }) as any);
    const send = jest.spyOn(DynamoDBDocumentClient.prototype, 'send').mockResolvedValue({
      Attributes: { opaque_id: 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa' },
    } as never);
    const response = await callback(event());
    expect(response.statusCode).toBe(502);
    expect(send.mock.calls.every(([command]) => command instanceof UpdateCommand)).toBe(true);
    expect(cookie(response, 'session')).toBeUndefined();
    expect(cookie(response, '__Host-uk')).toBeUndefined();
    expect(cookie(response, 'CloudFront-Policy')).toBeUndefined();
    expect(response.cookies.every((value: string) => value.includes('Max-Age=0'))).toBe(true);
  });

  test('does not issue credentials when committing the session fails', async () => {
    jest.spyOn(DynamoDBDocumentClient.prototype, 'send').mockImplementation((async (command: any) => {
      if (command instanceof PutCommand) throw new Error('DynamoDB unavailable');
      return { Attributes: { opaque_id: 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa' } };
    }) as any);
    const response = await callback(event());
    expect(response.statusCode).toBe(503);
    expect(cookie(response, 'session')).toBeUndefined();
    expect(cookie(response, 'CloudFront-Policy')).toBeUndefined();
  });

  test('does not create a session when the stored opaque user selector is invalid', async () => {
    const send = jest.spyOn(DynamoDBDocumentClient.prototype, 'send').mockResolvedValue({
      Attributes: { opaque_id: '../another-user' },
    } as never);
    const response = await callback(event());
    expect(response.statusCode).toBe(502);
    expect(send.mock.calls.every(([command]) => command instanceof UpdateCommand)).toBe(true);
    expect(cookie(response, '__Host-uk')).toBeUndefined();
    expect(cookie(response, 'session')).toBeUndefined();
  });

  test('bounds the signed user cookie to the shorter CloudFront expiry', async () => {
    process.env.CF_COOKIE_TTL_SECONDS = '120';
    jest.spyOn(DynamoDBDocumentClient.prototype, 'send').mockImplementation((async (command: any) => {
      return command instanceof UpdateCommand ? { Attributes: { opaque_id: 'a'.repeat(43) } } : {};
    }) as any);
    const response = await callback(event());
    expect(response.statusCode).toBe(302);
    expect(cookie(response, '__Host-uk')).toContain(`__Host-uk=${'a'.repeat(43)}.${now + 120}.`);
    expect(cookie(response, '__Host-uk')).toContain('Max-Age=120');
  });

  test('persists a validated identity and returns all credentials after signing succeeds', async () => {
    const send = jest.spyOn(DynamoDBDocumentClient.prototype, 'send').mockImplementation((async (command: any) => {
      return command instanceof UpdateCommand ? { Attributes: { opaque_id: 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa' } } : {};
    }) as any);
    const response = await callback(event());
    expect(response.statusCode).toBe(302);
    const put = send.mock.calls.find(([command]) => command instanceof PutCommand)![0] as PutCommand;
    expect(put.input.Item).toMatchObject({ user_sub: 'user-123', expires_at: now + 3600 });
    const persistedSessionId = put.input.Item!.session_id;
    expect(cookie(response, 'session')).toContain(`session=${persistedSessionId};`);
    expect(cookie(response, '__Host-uk')).toContain('aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa');
    expect(cookie(response, 'CloudFront-Signature')).toBeDefined();
    expect(fetch).toHaveBeenCalledWith('https://auth.example.com/oauth2/token', expect.objectContaining({
      redirect: 'error', signal: expect.any(AbortSignal),
    }));
  });
});

describe('session revocation and authorization', () => {
  test('keeps the GET logout contract and redirects only after deleting the session', async () => {
    const send = jest.spyOn(DynamoDBDocumentClient.prototype, 'send').mockResolvedValue({} as never);
    const response: any = await logout(event({ cookies: ['session=session-id'], requestContext: { http: { method: 'GET' } } }));
    expect(response.statusCode).toBe(302);
    expect(send.mock.calls[0][0]).toBeInstanceOf(DeleteCommand);
    expect((send.mock.calls[0][0] as DeleteCommand).input.Key).toEqual({ session_id: 'session-id' });
    expect(cookie(response, 'session')).toContain('Max-Age=0');
  });

  test('reports deletion failure without a success redirect and allows revocation retry', async () => {
    jest.spyOn(DynamoDBDocumentClient.prototype, 'send').mockRejectedValue(new Error('DynamoDB unavailable') as never);
    const response: any = await logout(event({ cookies: ['session=session-id'] }));
    expect(response.statusCode).toBe(503);
    expect(response.headers.location).toBeUndefined();
    expect(cookie(response, 'session')).toBeUndefined();
    expect(cookie(response, 'CloudFront-Policy')).toContain('Max-Age=0');
    expect(response.body).toContain('retry');
  });

  test('uses a strongly consistent lookup for each session decision', async () => {
    const send = jest.spyOn(DynamoDBDocumentClient.prototype, 'send').mockResolvedValue({
      Item: { user_sub: 'user-123', expires_at: now + 60 },
    } as never);
    expect(await authorize(event({ cookies: ['session=session-id'] }))).toEqual({
      isAuthorized: true, context: { user_sub: 'user-123', session_id: 'session-id' },
    });
    expect(send.mock.calls[0][0]).toBeInstanceOf(GetCommand);
    expect((send.mock.calls[0][0] as GetCommand).input.ConsistentRead).toBe(true);
    send.mockResolvedValueOnce({} as never);
    expect(await authorize(event({ cookies: ['session=session-id'] }))).toEqual({ isAuthorized: false });
  });

  test.each([
    { expires_at: now + 60 },
    { user_sub: 'unknown', expires_at: now + 60 },
    { user_sub: ' ', expires_at: now + 60 },
    { user_sub: 'user-123', expires_at: now },
  ])('rejects invalid stored sessions %j', async (item) => {
    jest.spyOn(DynamoDBDocumentClient.prototype, 'send').mockResolvedValue({ Item: item } as never);
    expect(await authorize(event({ cookies: ['session=session-id'] }))).toEqual({ isAuthorized: false });
  });
});
