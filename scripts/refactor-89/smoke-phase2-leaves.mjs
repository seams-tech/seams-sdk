import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { fileURLToPath, pathToFileURL } from 'node:url';
import path from 'node:path';

const scriptDirectory = path.dirname(fileURLToPath(import.meta.url));
const repositoryRoot = path.resolve(scriptDirectory, '..', '..');

function hex(bytes) {
  return Buffer.from(bytes).toString('hex');
}

async function loadLeaf(directory, moduleName) {
  const packageDirectory = path.join(repositoryRoot, 'wasm', directory, 'pkg');
  const module = await import(pathToFileURL(path.join(packageDirectory, `${moduleName}.js`)));
  const bytes = await readFile(path.join(packageDirectory, `${moduleName}_bg.wasm`));
  await module.default({ module_or_path: bytes });
  return module;
}

function eip1559Vector() {
  return {
    chainId: 11155111,
    nonce: '7',
    maxPriorityFeePerGas: '1500000000',
    maxFeePerGas: '3000000000',
    gasLimit: '21000',
    to: `0x${'22'.repeat(20)}`,
    value: '12345',
    data: '0x',
    accessList: [],
  };
}

function coseP256Generator() {
  const x = Buffer.from('6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296', 'hex');
  const y = Buffer.from('4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5', 'hex');
  return Uint8Array.from([
    0xa5,
    0x01,
    0x02,
    0x03,
    0x26,
    0x20,
    0x01,
    0x21,
    0x58,
    0x20,
    ...x,
    0x22,
    0x58,
    0x20,
    ...y,
  ]);
}

async function smokeTransactionCodec() {
  const module = await loadLeaf('evm_transaction_codec', 'evm_transaction_codec');
  const tx = eip1559Vector();
  assert.equal(
    hex(module.compute_eip1559_tx_hash(tx)),
    'ec562eae017388b8e451182e6919ee681b63a9d8f9fe1d34009e8e58ab4f9366',
  );
  const signature = Uint8Array.from([
    ...new Uint8Array(32).fill(0x11),
    ...new Uint8Array(32).fill(0x22),
    1,
  ]);
  assert.equal(
    hex(module.encode_eip1559_signed_tx_from_signature65(tx, signature)),
    '02f86f83aa36a7078459682f0084b2d05e0082520894222222222222222222222222222222222222222282303980c001a01111111111111111111111111111111111111111111111111111111111111111a02222222222222222222222222222222222222222222222222222222222222222',
  );
}

async function smokeWebauthnP256() {
  const module = await loadLeaf('webauthn_p256', 'webauthn_p256');
  const challenge = new Uint8Array(32).fill(7);
  const clientData = new TextEncoder().encode(
    JSON.stringify({
      type: 'webauthn.get',
      challenge: Buffer.from(challenge).toString('base64url'),
      origin: 'https://example.localhost',
    }),
  );
  const packed = module.build_webauthn_p256_signature(
    challenge,
    Uint8Array.from([9, 9, 9, 9]),
    clientData,
    Uint8Array.from([0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x02]),
    new Uint8Array(32).fill(0x11),
    new Uint8Array(32).fill(0x22),
  );
  assert.equal(packed.length, 1 + 4 + clientData.length + 128);
  assert.equal(packed[0], 0x02);

  const decoded = module.decode_cose_p256_public_key(coseP256Generator());
  assert.equal(
    hex(decoded),
    '6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c2964fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5',
  );
}

await smokeTransactionCodec();
await smokeWebauthnP256();
process.stdout.write('Phase 2 leaf Wasm smoke passed.\n');
