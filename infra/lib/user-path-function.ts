/** CloudFront Functions runtime 2.0 source; secret is injected separately after Base64 encoding. */
export function userPathFunctionBody(appHost: string): string {
  return `
var appHost = ${JSON.stringify(appHost.toLowerCase())};

function forbidden() {
  return {
    statusCode: 403,
    statusDescription: 'Forbidden',
    headers: {
      'cache-control': { value: 'no-store' },
      'content-type': { value: 'text/plain; charset=utf-8' }
    },
    body: 'Forbidden'
  };
}

function constantTimeEqual(a, b) {
  if (a.length !== b.length) return false;
  var difference = 0;
  for (var i = 0; i < a.length; i++) difference |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return difference === 0;
}

function handler(event) {
  var req = event.request;
  var uri = req.uri || '/';
  if (uri.indexOf('/u/me/') !== 0) return forbidden();

  var rest = uri.substring('/u/me/'.length);
  var decoded;
  try { decoded = decodeURIComponent(rest); } catch (_) { return forbidden(); }
  // Reject traversal and encoded delimiters before rewriting under a user's prefix.
  if (!rest || /%2f|%5c/i.test(rest) || /[\\x00-\\x1f\\x7f\\\\?#%]/.test(decoded)) return forbidden();
  var segments = decoded.split('/');
  for (var i = 0; i < segments.length; i++) {
    if (!segments[i] || segments[i] === '.' || segments[i] === '..') return forbidden();
  }

  var cookie = (req.cookies || {})['__Host-uk'];
  if (!cookie || cookie.multiValue || !cookie.value || !secret) return forbidden();
  var parts = cookie.value.split('.');
  if (parts.length !== 3 || !/^[A-Za-z0-9_-]{43}$/.test(parts[0]) ||
      !/^[1-9][0-9]{0,10}$/.test(parts[1]) || !/^[0-9a-f]{64}$/.test(parts[2])) return forbidden();

  var expires = Number(parts[1]);
  if (expires <= Math.floor(Date.now() / 1000)) return forbidden();
  var message = 'user-cookie:v1\\n' + appHost + '\\n' + parts[0] + '\\n' + parts[1];
  var signature = crypto.createHmac('sha256', secret).update(message).digest('hex');
  if (!constantTimeEqual(signature, parts[2])) return forbidden();

  req.uri = '/u/' + parts[0] + '/' + rest;
  return req;
}
`.trim();
}
