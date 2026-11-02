import { test } from 'node:test';
import assert from 'node:assert/strict';
import { loadConfig, infisicalSettings } from '../src/infisical.js';

const settingsEnv = () => ({
  INFISICAL_URL: 'https://infisical.test/',
  INFISICAL_CLIENT_ID: 'id',
  INFISICAL_CLIENT_SECRET: 'secret',
  INFISICAL_PROJECT_ID: 'project',
});

function fakeInfisical(initial) {
  let secrets = initial;
  const calls = [];
  const fetchImpl = async (url, init = {}) => {
    calls.push(url);
    if (url.endsWith('/universal-auth/login'))
      return Response.json(
        JSON.parse(init.body).clientSecret === 'secret' ? { accessToken: 'tok' } : {},
        {
          status: JSON.parse(init.body).clientSecret === 'secret' ? 200 : 401,
        },
      );
    if (init.headers?.Authorization !== 'Bearer tok') return new Response('', { status: 403 });
    return Response.json({
      secrets: Object.entries(secrets).map(([secretKey, secretValue]) => ({
        secretKey,
        secretValue,
      })),
    });
  };
  return { fetchImpl, calls, set: (next) => (secrets = next) };
}

test('without Infisical settings, env is used unchanged', async () => {
  const env = { MCP_TOKEN: 'local' };
  const result = await loadConfig(['MCP_TOKEN'], { env, fetchImpl: () => assert.fail('no fetch') });
  assert.equal(result.source, 'env');
  assert.equal(env.MCP_TOKEN, 'local');
  assert.equal(infisicalSettings({}), null);
});

test('Infisical values replace env, empty values included; missing keys fall back', async () => {
  const site = fakeInfisical({ PHONE: '9000000000', OUTLET: '' });
  const env = { ...settingsEnv(), OUTLET: 'old', OTHER: 'kept' };
  const result = await loadConfig(['PHONE', 'OUTLET', 'OTHER'], {
    env,
    fetchImpl: site.fetchImpl,
    log: () => {},
  });
  result.stop();
  assert.equal(env.PHONE, '9000000000');
  assert.equal(env.OUTLET, '');
  assert.equal(env.OTHER, 'kept');
  assert.equal(site.calls[0], 'https://infisical.test/api/v1/auth/universal-auth/login');
});

test('a changed value triggers onChange once; unrelated keys do not', async () => {
  const site = fakeInfisical({ PHONE: '' });
  let changes = 0;
  const result = await loadConfig(['PHONE'], {
    env: settingsEnv(),
    fetchImpl: site.fetchImpl,
    intervalMs: 10,
    onChange: () => changes++,
    log: () => {},
  });
  site.set({ PHONE: '', UNRELATED: 'x' });
  await new Promise((r) => setTimeout(r, 40));
  assert.equal(changes, 0);
  site.set({ PHONE: '9000000000' });
  await new Promise((r) => setTimeout(r, 60));
  result.stop();
  assert.equal(changes, 1);
});

test('startup fails loudly when Infisical rejects the identity', async () => {
  const site = fakeInfisical({});
  await assert.rejects(
    loadConfig(['PHONE'], {
      env: { ...settingsEnv(), INFISICAL_CLIENT_SECRET: 'wrong' },
      fetchImpl: site.fetchImpl,
    }),
    /login failed/,
  );
});
