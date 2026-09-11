import { SSMClient } from '@aws-sdk/client-ssm';
import { secureHttp } from '../lambda/api/secure-http';
import { publicHttp } from '../lambda/api/public-http';

const originalEnv = process.env;
let serial = 0;

function privateEvent(): any {
  return {
    headers: { 'x-origin-verify': 'origin-value', 'x-csrf-token': 'csrf-value' },
    cookies: ['__Host-csrf=csrf-value'],
    requestContext: {
      requestId: 'request-123',
      http: { method: 'POST' },
      authorizer: { lambda: { session_id: 'session-123', user_sub: 'user-123' } },
    },
    body: JSON.stringify({ theme: 'dark' }),
    isBase64Encoded: false,
  };
}

function publicEvent(method = 'GET'): any {
  return {
    headers: { 'x-origin-verify': 'origin-value' },
    requestContext: { requestId: 'request-public', http: { method } },
  };
}

beforeEach(() => {
  process.env = {
    ...originalEnv,
    PLATFORM_ORIGIN_VERIFY_HEADER_NAME: 'X-Origin-Verify',
    PLATFORM_ORIGIN_VERIFY_HEADER_VALUE_SSM_PARAM_ARN: `/test/gatekeeper-origin-${++serial}`,
    PLATFORM_CSRF_COOKIE_NAME: '__Host-csrf',
    PLATFORM_CSRF_HEADER_NAME: 'X-CSRF-Token',
  };
  jest.spyOn(SSMClient.prototype, 'send').mockResolvedValue({ Parameter: { Value: 'origin-value' } } as never);
});

afterEach(() => {
  process.env = originalEnv;
  jest.restoreAllMocks();
});

describe('private API gatekeeper', () => {
  test.each([undefined, 'wrong-origin'])('does not invoke business without the expected origin secret: %s', async (origin) => {
    const event = privateEvent();
    event.headers['x-origin-verify'] = origin;
    const business = jest.fn(() => ({ saved: true }));
    const response: any = await secureHttp(business)(event);
    expect(response.statusCode).toBe(403);
    expect(business).not.toHaveBeenCalled();
  });

  test('fails closed on an SSM error before invoking business', async () => {
    jest.mocked(SSMClient.prototype.send).mockRejectedValueOnce(new Error('SSM unavailable') as never);
    const business = jest.fn(() => ({ saved: true }));
    const response: any = await secureHttp(business)(privateEvent());
    expect(response.statusCode).toBe(500);
    expect(business).not.toHaveBeenCalled();
  });

  test.each([
    undefined,
    {},
    { lambda: {} },
    { lambda: { session_id: 'session-123' } },
    { lambda: { user_sub: 'user-123' } },
  ])('does not invoke business without complete authorization context: %j', async (authorizer) => {
    const event = privateEvent();
    event.requestContext.authorizer = authorizer;
    const business = jest.fn(() => ({ saved: true }));
    const response: any = await secureHttp(business)(event);
    expect(response.statusCode).toBe(401);
    expect(business).not.toHaveBeenCalled();
  });

  test.each([
    { cookie: undefined, header: 'csrf-value' },
    { cookie: 'csrf-value', header: undefined },
    { cookie: undefined, header: undefined },
    { cookie: 'csrf-value', header: 'wrong-value' },
    { cookie: 'csrf-value', header: 'same-size!' },
  ])('does not invoke business when write CSRF validation fails: %j', async ({ cookie, header }) => {
    const event = privateEvent();
    event.cookies = cookie ? [`__Host-csrf=${cookie}`] : [];
    event.headers['x-csrf-token'] = header;
    const business = jest.fn(() => ({ saved: true }));
    const response: any = await secureHttp(business)(event);
    expect(response.statusCode).toBe(403);
    expect(business).not.toHaveBeenCalled();
  });

  test.each([false, true])('does not invoke business on invalid JSON, base64=%s', async (encoded) => {
    const event = privateEvent();
    event.body = encoded ? Buffer.from('{invalid-json').toString('base64') : '{invalid-json';
    event.isBase64Encoded = encoded;
    const business = jest.fn(() => ({ saved: true }));
    const response: any = await secureHttp(business)(event);
    expect(response.statusCode).toBe(400);
    expect(JSON.parse(response.body).message).toBe('Invalid JSON body');
    expect(business).not.toHaveBeenCalled();
  });

  test.each([false, true])('passes a valid authorized POST and decoded body to business, base64=%s', async (encoded) => {
    const event = privateEvent();
    if (encoded) event.body = Buffer.from(event.body).toString('base64');
    event.isBase64Encoded = encoded;
    const business = jest.fn(() => ({ saved: true }));
    const response: any = await secureHttp(business)(event);
    expect(response.statusCode).toBe(200);
    expect(JSON.parse(response.body)).toEqual({ ok: true, saved: true });
    expect(response.headers['cache-control']).toBe('no-store');
    expect(business).toHaveBeenCalledTimes(1);
    expect(business).toHaveBeenCalledWith(
      { session_id: 'session-123', user_sub: 'user-123', method: 'POST', requestId: 'request-123' },
      { body: { theme: 'dark' }, event },
    );
  });
});

describe('public API gatekeeper', () => {
  test.each([undefined, 'wrong-origin'])('denies unauthenticated GET without the expected origin secret: %s', async (origin) => {
    const event = publicEvent();
    event.headers['x-origin-verify'] = origin;
    const business = jest.fn(() => ({ version: '1' }));
    const response: any = await publicHttp(business)(event);
    expect(response.statusCode).toBe(403);
    expect(business).not.toHaveBeenCalled();
  });

  test('allows a GET through the origin gate without authentication or CSRF cookies', async () => {
    const event = publicEvent();
    const business = jest.fn(() => ({ version: '1' }));
    const response: any = await publicHttp(business)(event);
    expect(response.statusCode).toBe(200);
    expect(JSON.parse(response.body)).toEqual({ ok: true, version: '1' });
    expect(business).toHaveBeenCalledWith({ method: 'GET', requestId: 'request-public' }, { event });
    expect(business).toHaveBeenCalledTimes(1);
  });

  test.each(['POST', 'PUT', 'PATCH', 'DELETE'])('denies %s without calling public business code', async (method) => {
    const business = jest.fn(() => ({ changed: true }));
    const response: any = await publicHttp(business)(publicEvent(method));
    expect(response.statusCode).toBe(405);
    expect(response.headers.allow).toBe('GET, HEAD, OPTIONS');
    expect(business).not.toHaveBeenCalled();
  });

  test.each(['HEAD', 'OPTIONS'])('%s returns no content without calling public business code', async (method) => {
    const business = jest.fn(() => ({ version: '1' }));
    const response: any = await publicHttp(business)(publicEvent(method));
    expect(response.statusCode).toBe(204);
    expect(response.body).toBe('');
    expect(business).not.toHaveBeenCalled();
  });

  test.each(['HEAD', 'OPTIONS'])('%s still requires the origin secret', async (method) => {
    const event = publicEvent(method);
    event.headers = {};
    const business = jest.fn(() => ({ version: '1' }));
    const response: any = await publicHttp(business)(event);
    expect(response.statusCode).toBe(403);
    expect(business).not.toHaveBeenCalled();
  });
});
