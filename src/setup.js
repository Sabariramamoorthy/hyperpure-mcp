import { mkdir, writeFile, unlink, access } from 'node:fs/promises';
import { resolve, join } from 'node:path';
import { token } from './core.js';

const normalize = (value) =>
  String(value || '')
    .replace(/\s+/g, ' ')
    .trim();
const bindingOf = (name, address) => ({
  selector: '[class*="Header_headerAddressInfo"]',
  text: `${name}: ${address}`,
  parts: [name, address],
});

/** Writes the expected-outlet binding from OUTLET_NAME / OUTLET_ADDRESS when both are set. */
export async function bindingFromEnv(store, env = process.env) {
  const name = normalize(env.OUTLET_NAME).replace(/:$/, ''),
    address = normalize(env.OUTLET_ADDRESS);
  if (!name || !address) return null;
  const binding = bindingOf(name, address);
  await store.write('binding', binding);
  return binding;
}

export async function configure({
  directory = process.cwd(),
  origin,
  mobile,
  outletName,
  outletAddress,
  dataDir,
}) {
  const url = new URL(origin);
  if (
    url.protocol !== 'https:' ||
    url.username ||
    url.password ||
    url.pathname !== '/' ||
    url.search ||
    url.hash
  )
    throw Error('Use an HTTPS origin without credentials, path, query or fragment.');
  if (!/^\d{10}$/.test(mobile || '')) throw Error('Enter a 10-digit Indian mobile number.');
  const name = normalize(outletName).replace(/:$/, ''),
    address = normalize(outletAddress);
  if (!name || !address) throw Error('The exact outlet name and address are required.');
  const root = resolve(directory),
    data = resolve(root, dataDir || 'data'),
    secrets = join(root, '.secrets');
  const files = [
    join(root, '.env'),
    join(data, 'binding.json'),
    join(secrets, 'connection.json'),
    join(secrets, 'owner-access.txt'),
  ];
  for (const file of files) {
    try {
      await access(file);
    } catch (e) {
      if (e.code === 'ENOENT') continue;
      throw e;
    }
    throw Error('Configuration already exists. It was not overwritten.');
  }
  const mcpToken = token(),
    ownerKey = token();
  const env = {
    PUBLIC_ORIGIN: url.origin,
    HYPERPURE_MOBILE: mobile,
    DATA_DIR: data,
    MCP_TOKEN: mcpToken,
    OWNER_KEY: ownerKey,
  };
  const values = [
    Object.entries(env)
      .map(([k, v]) => `${k}='${v.replaceAll("'", "'\\''")}'`)
      .join('\n') + '\n',
    JSON.stringify(bindingOf(name, address), null, 2) + '\n',
    JSON.stringify(
      {
        mcpServers: {
          hyperpure: { url: url.origin + '/mcp', headers: { Authorization: 'Bearer ' + mcpToken } },
        },
      },
      null,
      2,
    ) + '\n',
    `Owner controls: ${url.origin}/owner\nOwner key: ${ownerKey}\n`,
  ];
  // Node env files are not shell scripts; refuse characters requiring shell-style escaping.
  if (Object.values(env).some((v) => /[\r\n']/.test(v)))
    throw Error('Configuration values cannot contain quotes or line breaks.');
  await mkdir(root, { recursive: true, mode: 0o700 });
  await mkdir(data, { recursive: true, mode: 0o700 });
  await mkdir(secrets, { recursive: true, mode: 0o700 });
  const created = [];
  try {
    for (let i = 0; i < files.length; i++) {
      await writeFile(files[i], values[i], { flag: 'wx', mode: 0o600 });
      created.push(files[i]);
    }
  } catch (e) {
    await Promise.all(created.map((file) => unlink(file).catch(() => {})));
    throw e;
  }
  return { origin: url.origin, dataDir: data, files };
}
