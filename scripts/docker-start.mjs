// Container entrypoint: writes the expected-outlet binding from OUTLET_NAME / OUTLET_ADDRESS
// (the same shape `npm run configure` produces), then starts the server.
import { mkdir, writeFile } from 'node:fs/promises';

const normalize = (value) =>
  String(value || '')
    .replace(/\s+/g, ' ')
    .trim();
const dataDir = process.env.DATA_DIR || '/data';
const name = normalize(process.env.OUTLET_NAME).replace(/:$/, '');
const address = normalize(process.env.OUTLET_ADDRESS);

await mkdir(dataDir, { recursive: true, mode: 0o700 });
if (name && address) {
  await writeFile(
    `${dataDir}/binding.json`,
    JSON.stringify(
      {
        selector: '[class*="Header_headerAddressInfo"]',
        text: `${name}: ${address}`,
        parts: [name, address],
      },
      null,
      2,
    ) + '\n',
    { mode: 0o600 },
  );
} else {
  console.log(JSON.stringify({ event: 'binding_missing', hint: 'Set OUTLET_NAME and OUTLET_ADDRESS' }));
}

await import('../src/server.js');
