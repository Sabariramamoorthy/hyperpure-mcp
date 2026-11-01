import { createHmac } from 'node:crypto';
import express from 'express';
import {
  InvalidGrantError,
  InvalidTokenError,
} from '@modelcontextprotocol/sdk/server/auth/errors.js';
import { digest, sameSecret, token } from './core.js';

const ACCESS_TTL_S = 60 * 60;
const REFRESH_TTL_S = 90 * 24 * 60 * 60;
const CODE_TTL_MS = 5 * 60_000;
const REQUEST_TTL_MS = 10 * 60_000;
const now = () => Math.floor(Date.now() / 1000);
const escape = (value) => String(value ?? '').replace(/[&<>"']/g, (c) => `&#${c.charCodeAt(0)};`);

/**
 * OAuth 2.1 authorization server for a single owner, for MCP clients that cannot send a fixed
 * bearer header (ChatGPT, Claude web/desktop custom connectors). The owner approves each client
 * once with OWNER_KEY (the /owner unlock key). The static MCP_TOKEN keeps working for
 * header-capable clients.
 */
export class OwnerOAuthProvider {
  constructor({ store, ownerKey, staticToken, resource }) {
    this.store = store;
    this.ownerKey = ownerKey;
    this.staticToken = staticToken;
    this.resource = resource;
    this.signingKey = digest(`oauth-request:${staticToken}`);
    this.codes = new Map();
    this.failures = [];
  }

  async load() {
    this.state = await this.store.read('oauth', { clients: {}, tokens: {} });
  }

  async save() {
    const t = now();
    for (const [key, entry] of Object.entries(this.state.tokens))
      if (entry.expiresAt < t) delete this.state.tokens[key];
    await this.store.write('oauth', this.state);
  }

  get clientsStore() {
    return {
      getClient: async (clientId) => this.state.clients[clientId],
      registerClient: async (client) => {
        this.state.clients[client.client_id] = client;
        await this.save();
        return client;
      },
    };
  }

  sign(payload) {
    const body = Buffer.from(JSON.stringify(payload)).toString('base64url');
    return `${body}.${createHmac('sha256', this.signingKey).update(body).digest('base64url')}`;
  }

  unsign(value) {
    const [body, signature] = String(value || '').split('.');
    if (!body || !signature) return null;
    const expected = createHmac('sha256', this.signingKey).update(body).digest('base64url');
    if (!sameSecret(signature, expected)) return null;
    const payload = JSON.parse(Buffer.from(body, 'base64url').toString());
    return payload.exp > Date.now() ? payload : null;
  }

  async authorize(client, params, res) {
    const request = this.sign({
      clientId: client.client_id,
      redirectUri: params.redirectUri,
      state: params.state,
      codeChallenge: params.codeChallenge,
      scopes: params.scopes || [],
      resource: params.resource?.href,
      exp: Date.now() + REQUEST_TTL_MS,
    });
    res
      .status(200)
      .type('html')
      .send(this.page({ client, redirectUri: params.redirectUri, request }));
  }

  page({ client, redirectUri, request, error }) {
    const app = client?.client_name || 'An MCP client';
    const host = redirectUri ? new URL(redirectUri).host : '';
    return `<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Connect to Hyperpure MCP</title>
<style>
:root{color-scheme:light dark;--bg:#f5f6f4;--surface:#fff;--text:#1b1f1c;--muted:#5b635d;--border:#d9ddd8;--primary:#1f7a3a;--primary-text:#fff;--error:#b42318;--focus:#2563eb}
@media (prefers-color-scheme:dark){:root{--bg:#111412;--surface:#1a1e1b;--text:#e9ece9;--muted:#a3aba5;--border:#2e352f;--primary:#3fa35c;--primary-text:#0b130d;--error:#f97066;--focus:#60a5fa}}
*{box-sizing:border-box}body{margin:0;min-height:100vh;display:grid;place-items:center;padding:24px 16px;background:var(--bg);color:var(--text);font:15px/1.5 system-ui,-apple-system,"Segoe UI",Roboto,sans-serif}
main{width:100%;max-width:420px;background:var(--surface);border:1px solid var(--border);border-radius:12px;padding:28px}
h1{font-size:20px;margin:0 0 8px}p{margin:0 0 16px;color:var(--muted)}strong{color:var(--text)}
label{display:block;font-weight:600;margin:0 0 6px}input{width:100%;height:44px;padding:0 12px;border:1px solid var(--border);border-radius:8px;background:var(--bg);color:var(--text);font:inherit}
input:focus-visible,button:focus-visible{outline:2px solid var(--focus);outline-offset:2px}
.hint{font-size:13px;margin:6px 0 20px}.error{color:var(--error);font-size:14px;margin:0 0 16px}
.actions{display:flex;gap:12px;flex-wrap:wrap}button{height:44px;padding:0 18px;border-radius:8px;font:inherit;font-weight:600;cursor:pointer}
.primary{flex:1;background:var(--primary);color:var(--primary-text);border:0}.secondary{background:transparent;color:var(--text);border:1px solid var(--border)}
</style></head><body><main>
<h1>Connect to Hyperpure MCP</h1>
<p><strong>${escape(app)}</strong>${host ? ` (${escape(host)})` : ''} wants to search products, prepare the cart and read orders and invoices for this Hyperpure account. It cannot pay or submit orders.</p>
${error ? `<p class="error" role="alert">${escape(error)}</p>` : ''}
<form method="post" action="/oauth/approve">
<input type="hidden" name="request" value="${escape(request)}">
<label for="key">Owner key</label>
<input id="key" name="key" type="password" autocomplete="current-password" required autofocus>
<p class="hint">The same owner key that unlocks the /owner page (OWNER_KEY).</p>
<div class="actions"><button class="primary" type="submit" name="decision" value="approve">Allow access</button>
<button class="secondary" type="submit" name="decision" value="deny" formnovalidate>Deny</button></div>
</form></main></body></html>`;
  }

  /** POST /oauth/approve: the owner's answer to the consent page. */
  approvalRouter() {
    const router = express.Router();
    router.post(
      '/oauth/approve',
      express.urlencoded({ extended: false, limit: '8kb' }),
      async (req, res) => {
        const request = this.unsign(req.body.request);
        const client = request && this.state.clients[request.clientId];
        if (!request || !client || !(client.redirect_uris || []).includes(request.redirectUri))
          return res
            .status(400)
            .type('text')
            .send('This sign-in request expired. Start connecting again from your app.');
        const back = (params) => {
          const url = new URL(request.redirectUri);
          for (const [k, v] of Object.entries(params))
            if (v !== undefined) url.searchParams.set(k, v);
          res.redirect(302, url.href);
        };
        if (req.body.decision === 'deny')
          return back({ error: 'access_denied', state: request.state });
        const t = Date.now();
        this.failures = this.failures.filter((f) => t - f < 10 * 60_000);
        if (this.failures.length >= 10)
          return res
            .status(429)
            .type('html')
            .send(
              this.page({
                client,
                redirectUri: request.redirectUri,
                request: req.body.request,
                error: 'Too many attempts. Wait 10 minutes and try again.',
              }),
            );
        if (!this.ownerKey || !sameSecret(req.body.key, this.ownerKey)) {
          this.failures.push(t);
          return res
            .status(401)
            .type('html')
            .send(
              this.page({
                client,
                redirectUri: request.redirectUri,
                request: req.body.request,
                error: 'That owner key is not correct.',
              }),
            );
        }
        const code = token();
        this.codes.set(code, { ...request, expiresAt: t + CODE_TTL_MS });
        back({ code, state: request.state });
      },
    );
    return router;
  }

  async challengeForAuthorizationCode(client, code) {
    const entry = this.codes.get(code);
    if (!entry || entry.clientId !== client.client_id)
      throw new InvalidGrantError('Invalid authorization code');
    return entry.codeChallenge;
  }

  async exchangeAuthorizationCode(client, code, _verifier, redirectUri) {
    const entry = this.codes.get(code);
    this.codes.delete(code);
    if (!entry || entry.clientId !== client.client_id || entry.expiresAt < Date.now())
      throw new InvalidGrantError('Invalid or expired authorization code');
    if (redirectUri && redirectUri !== entry.redirectUri)
      throw new InvalidGrantError('redirect_uri does not match the authorization request');
    return this.issue(client.client_id, entry.scopes, entry.resource);
  }

  async exchangeRefreshToken(client, refreshToken) {
    const key = digest(refreshToken);
    const entry = this.state.tokens[key];
    if (
      !entry ||
      entry.type !== 'refresh' ||
      entry.clientId !== client.client_id ||
      entry.expiresAt < now()
    )
      throw new InvalidGrantError('Invalid or expired refresh token');
    delete this.state.tokens[key];
    return this.issue(client.client_id, entry.scopes, entry.resource);
  }

  async issue(clientId, scopes, resource) {
    const access = token(),
      refresh = token(),
      t = now();
    this.state.tokens[digest(access)] = {
      type: 'access',
      clientId,
      scopes,
      resource,
      expiresAt: t + ACCESS_TTL_S,
    };
    this.state.tokens[digest(refresh)] = {
      type: 'refresh',
      clientId,
      scopes,
      resource,
      expiresAt: t + REFRESH_TTL_S,
    };
    await this.save();
    return {
      access_token: access,
      token_type: 'bearer',
      expires_in: ACCESS_TTL_S,
      refresh_token: refresh,
      ...(scopes.length ? { scope: scopes.join(' ') } : {}),
    };
  }

  async verifyAccessToken(accessToken) {
    if (this.staticToken && sameSecret(accessToken, this.staticToken))
      return {
        token: accessToken,
        clientId: 'static-token',
        scopes: [],
        expiresAt: now() + ACCESS_TTL_S,
      };
    const entry = this.state.tokens[digest(accessToken)];
    if (!entry || entry.type !== 'access' || entry.expiresAt < now())
      throw new InvalidTokenError('Invalid or expired access token');
    const origin = new URL(this.resource).origin;
    const ours = [origin, `${origin}/`, `${origin}/mcp`, `${origin}/mcp/`];
    if (entry.resource && !ours.includes(entry.resource))
      throw new InvalidTokenError('Token was issued for a different server');
    return {
      token: accessToken,
      clientId: entry.clientId,
      scopes: entry.scopes,
      expiresAt: entry.expiresAt,
      ...(entry.resource ? { resource: new URL(entry.resource) } : {}),
    };
  }

  async revokeToken(client, { token: value }) {
    const key = digest(value);
    if (this.state.tokens[key]?.clientId === client.client_id) {
      delete this.state.tokens[key];
      await this.save();
    }
  }
}
