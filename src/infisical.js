import { createHash } from 'node:crypto';

// Runtime configuration from Infisical, read with a universal-auth machine identity that can only
// see this server's project. Values present in Infisical (even empty) replace process.env; keys
// missing there fall back to process.env, so local `.env` runs work without Infisical.

const TIMEOUT_MS = 15_000;
const WATCH_INTERVAL_MS = 60_000;

export function infisicalSettings(env = process.env) {
  const settings = {
    url: (env.INFISICAL_URL || '').replace(/\/$/, ''),
    clientId: env.INFISICAL_CLIENT_ID,
    clientSecret: env.INFISICAL_CLIENT_SECRET,
    projectId: env.INFISICAL_PROJECT_ID,
    environment: env.INFISICAL_ENVIRONMENT || 'prod',
    secretPath: env.INFISICAL_SECRET_PATH || '/',
  };
  return settings.url && settings.clientId && settings.clientSecret && settings.projectId
    ? settings
    : null;
}

export async function fetchSecrets(settings, fetchImpl = fetch) {
  const login = await fetchImpl(`${settings.url}/api/v1/auth/universal-auth/login`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ clientId: settings.clientId, clientSecret: settings.clientSecret }),
    signal: AbortSignal.timeout(TIMEOUT_MS),
  });
  if (!login.ok) throw Error(`Infisical login failed (HTTP ${login.status})`);
  const { accessToken } = await login.json();
  const query = new URLSearchParams({
    workspaceId: settings.projectId,
    environment: settings.environment,
    secretPath: settings.secretPath,
  });
  const response = await fetchImpl(`${settings.url}/api/v3/secrets/raw?${query}`, {
    headers: { Authorization: `Bearer ${accessToken}` },
    signal: AbortSignal.timeout(TIMEOUT_MS),
  });
  if (!response.ok) throw Error(`Infisical secrets read failed (HTTP ${response.status})`);
  const { secrets = [] } = await response.json();
  return Object.fromEntries(secrets.map((s) => [s.secretKey, s.secretValue ?? '']));
}

const fingerprint = (secrets, keys) =>
  createHash('sha256')
    .update(JSON.stringify(keys.map((k) => [k, secrets[k] ?? null])))
    .digest('hex');

/**
 * Loads `keys` from Infisical into `env`, then re-reads every minute and calls `onChange` once
 * when any of them changes (default: SIGTERM, so the container restarts with the new values).
 * Startup fails loudly if Infisical is configured but unreachable; later read errors are logged
 * and the current values stay in use.
 */
export async function loadConfig(
  keys,
  {
    env = process.env,
    fetchImpl = fetch,
    intervalMs = WATCH_INTERVAL_MS,
    onChange = () => process.kill(process.pid, 'SIGTERM'),
    log = (event) => console.log(JSON.stringify(event)),
  } = {},
) {
  const settings = infisicalSettings(env);
  if (!settings) return { source: 'env', stop: () => {} };
  const secrets = await fetchSecrets(settings, fetchImpl);
  for (const key of keys) if (Object.hasOwn(secrets, key)) env[key] = secrets[key];
  const loaded = fingerprint(secrets, keys);
  log({
    event: 'config_loaded',
    source: 'infisical',
    keys: keys.filter((k) => Object.hasOwn(secrets, k)),
  });
  const timer = setInterval(async () => {
    try {
      const next = await fetchSecrets(settings, fetchImpl);
      if (fingerprint(next, keys) !== loaded) {
        clearInterval(timer);
        log({ event: 'config_changed', source: 'infisical', action: 'restart' });
        onChange();
      }
    } catch (error) {
      log({ event: 'config_refresh_failed', source: 'infisical', message: error.message });
    }
  }, intervalMs);
  timer.unref();
  return { source: 'infisical', stop: () => clearInterval(timer) };
}
