import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import { readSettingsOrThrow, requireValue, settingsPath } from '../bin/infra-helpers';

describe('deployment settings', () => {
  let directory: string;
  let settingsFile: string;
  const validSettings = JSON.parse(fs.readFileSync(path.resolve(__dirname, '../../settings.example.json'), 'utf8'));

  beforeEach(() => {
    directory = fs.mkdtempSync(path.join(os.tmpdir(), 'cuddly-fishstick-settings-'));
    settingsFile = path.join(directory, 'settings.json');
  });

  afterEach(() => {
    if (fs.existsSync(settingsFile)) fs.unlinkSync(settingsFile);
    fs.rmdirSync(directory);
  });

  function readWith(overrides: Record<string, unknown>) {
    fs.writeFileSync(settingsFile, JSON.stringify({ ...validSettings, ...overrides }));
    return readSettingsOrThrow(settingsFile);
  }

  test('the committed example contains the complete supported schema', () => {
    expect(readWith({})).toEqual(validSettings);
    expect(settingsPath().settingsAbs).toBe(path.resolve(__dirname, '../../settings.json'));
  });

  test('missing settings explains the actual root path and example', () => {
    expect(() => readSettingsOrThrow(settingsFile)).toThrow(/Copy settings.example.json to settings.json at the repository root/);
    expect(() => requireValue('domain')).toThrow(/settings.json at the repository root/);
  });

  test.each([null, [], 'example.com'])('rejects a non-object settings document: %p', value => {
    fs.writeFileSync(settingsFile, JSON.stringify(value));
    expect(() => readSettingsOrThrow(settingsFile)).toThrow(/expected a JSON object/);
  });

  test('reports malformed JSON separately from invalid fields', () => {
    fs.writeFileSync(settingsFile, '{');
    expect(() => readSettingsOrThrow(settingsFile)).toThrow(/Invalid JSON in settings.json/);
    expect(() => readWith({ domain: null })).toThrow(/Invalid config "domain"/);
  });

  test('rejects the obsolete Secrets Manager field with the SSM migration instruction', () => {
    expect(() => readWith({ cfPrivateKeySecretArn: 'arn:aws:secretsmanager:eu-west-2:123456789012:secret:old' }))
      .toThrow(/set "cfPrivateKeyParameterArn" to that parameter ARN/);
    expect(() => readWith({ cfPrivateKeyParameterArn: 'arn:aws:secretsmanager:eu-west-2:123456789012:secret:old' }))
      .toThrow(/expected an SSM parameter ARN/);
  });

  test.each(['domain', 'certArnUsEast1', 'cfPublicKeyId', 'cfPrivateKeyParameterArn', 'cfCookieDomain', 'originVerifyHeaderValueParameterArn'])
    ('rejects a missing required setting: %s', name => {
      expect(() => readWith({ [name]: undefined })).toThrow(`Missing required config "${name}"`);
    });

  test.each([
    { domain: 'https://example.com' },
    { certArnUsEast1: 'arn:aws:acm:eu-west-2:123456789012:certificate/abcd' },
    { cfCookieDomain: 'unrelated.example.org' },
    { cfCookiePath: '/app' },
    { cfCookieTtlSeconds: 0 },
    { cfCookieTtlSeconds: 1.5 },
    { cfCookieTtlSeconds: '3600' },
    { originVerifyHeaderName: 'X-Origin\r\nInjected: yes' },
    { allowedFrameSrc: [123] },
    { allowedConnectSrc: 'https://example.com' },
  ])('fails early for an invalid setting: %p', overrides => {
    expect(() => readWith(overrides)).toThrow(/Invalid config/);
  });

  test('accepts a leading-dot parent cookie domain and trims values', () => {
    expect(readWith({ domain: 'www.example.com ', cfCookieDomain: '.example.com', stage: 'prod ' }))
      .toEqual(expect.objectContaining({ domain: 'www.example.com', cfCookieDomain: '.example.com', stage: 'prod' }));
  });
});
