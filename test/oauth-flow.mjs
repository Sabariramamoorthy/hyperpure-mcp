// Manual end-to-end check of the OAuth flow against a running server:
//   BASE=http://127.0.0.1:9310 OWNER_KEY=... node test/oauth-flow.mjs
import { createHash, randomBytes } from 'node:crypto';

const base = process.env.BASE || 'http://127.0.0.1:9310';
const redirectUri = 'https://claude.ai/api/mcp/auth_callback';
const step = (name, ok, detail = '') => {
  console.log(`${ok ? 'PASS' : 'FAIL'} ${name}${detail ? ` — ${detail}` : ''}`);
  if (!ok) process.exitCode = 1;
};
const form = (data) => new URLSearchParams(data).toString();

const prm = await fetch(`${base}/.well-known/oauth-protected-resource/mcp`).then((r) => r.json());
step('protected resource metadata', prm.authorization_servers?.length > 0, prm.resource);
const asm = await fetch(`${base}/.well-known/oauth-authorization-server`).then((r) => r.json());
step('authorization server metadata', Boolean(asm.registration_endpoint && asm.token_endpoint));

const unauth = await fetch(`${base}/mcp`, { method: 'POST' });
step(
  'mcp without token is 401 with resource metadata',
  unauth.status === 401 && /resource_metadata/.test(unauth.headers.get('www-authenticate') || ''),
);

const client = await fetch(`${base}/register`, {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({
    client_name: 'Flow test',
    redirect_uris: [redirectUri],
    token_endpoint_auth_method: 'none',
    grant_types: ['authorization_code', 'refresh_token'],
    response_types: ['code'],
  }),
}).then((r) => r.json());
step('dynamic client registration', Boolean(client.client_id));

const verifier = randomBytes(32).toString('base64url');
const challenge = createHash('sha256').update(verifier).digest('base64url');
const authorizeUrl = `${base}/authorize?${form({ response_type: 'code', client_id: client.client_id, redirect_uri: redirectUri, code_challenge: challenge, code_challenge_method: 'S256', state: 'xyz', resource: `${new URL(prm.resource).origin}/mcp`, scope: 'hyperpure' })}`;
const page = await fetch(authorizeUrl).then((r) => r.text());
const request = page
  .match(/name="request" value="([^"]+)"/)?.[1]
  ?.replace(/&#(\d+);/g, (_, c) => String.fromCharCode(c));
step('consent page rendered', Boolean(request));

const wrong = await fetch(`${base}/oauth/approve`, {
  method: 'POST',
  redirect: 'manual',
  headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
  body: form({ request, key: 'wrong', decision: 'approve' }),
});
step('wrong owner key rejected', wrong.status === 401);

const approved = await fetch(`${base}/oauth/approve`, {
  method: 'POST',
  redirect: 'manual',
  headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
  body: form({ request, key: process.env.OWNER_KEY, decision: 'approve' }),
});
const location = new URL(approved.headers.get('location') || 'about:blank');
const code = location.searchParams.get('code');
step(
  'approval redirects with code and state',
  approved.status === 302 && Boolean(code) && location.searchParams.get('state') === 'xyz',
);

const badPkce = await fetch(`${base}/token`, {
  method: 'POST',
  headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
  body: form({
    grant_type: 'authorization_code',
    code,
    code_verifier: 'x'.repeat(43),
    client_id: client.client_id,
    redirect_uri: redirectUri,
  }),
});
step('wrong PKCE verifier rejected', badPkce.status === 400);

const tokens = await fetch(`${base}/token`, {
  method: 'POST',
  headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
  body: form({
    grant_type: 'authorization_code',
    code,
    code_verifier: verifier,
    client_id: client.client_id,
    redirect_uri: redirectUri,
  }),
}).then((r) => r.json());
step(
  'token exchange',
  Boolean(tokens.access_token && tokens.refresh_token),
  JSON.stringify(tokens.error || ''),
);

const reuse = await fetch(`${base}/token`, {
  method: 'POST',
  headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
  body: form({
    grant_type: 'authorization_code',
    code,
    code_verifier: verifier,
    client_id: client.client_id,
    redirect_uri: redirectUri,
  }),
});
step('authorization code cannot be reused', reuse.status === 400);

const list = await fetch(`${base}/mcp`, {
  method: 'POST',
  headers: {
    Authorization: `Bearer ${tokens.access_token}`,
    'Content-Type': 'application/json',
    Accept: 'application/json, text/event-stream',
  },
  body: JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'tools/list', params: {} }),
}).then((r) => r.json());
step(
  'mcp tools/list with OAuth token',
  list.result?.tools?.length > 0,
  list.result?.tools?.map((t) => t.name).join(', '),
);

const refreshed = await fetch(`${base}/token`, {
  method: 'POST',
  headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
  body: form({
    grant_type: 'refresh_token',
    refresh_token: tokens.refresh_token,
    client_id: client.client_id,
  }),
}).then((r) => r.json());
step(
  'refresh token rotation',
  Boolean(refreshed.access_token) && refreshed.refresh_token !== tokens.refresh_token,
);
const oldRefresh = await fetch(`${base}/token`, {
  method: 'POST',
  headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
  body: form({
    grant_type: 'refresh_token',
    refresh_token: tokens.refresh_token,
    client_id: client.client_id,
  }),
});
step('used refresh token is rejected', oldRefresh.status === 400);
