#!/usr/bin/env node
import crypto from 'node:crypto';

function usage() {
  console.log(`Generate Shamir 3-pass key material for signing-session seal routes.

Usage:
  pnpm -C apps/web-server signing-session-seal:keygen [--key-version <value>] [--prime-bits <bits>] [--json]

Options:
  --key-version <value>  Key version tag used by server/client config
  --prime-bits <bits>    Prime size in bits (default: 2048)
  --json                 Print JSON only
  -h, --help             Show this help
`);
}

function parsePositiveInt(raw, fallback) {
  const parsed = Number(raw);
  if (!Number.isFinite(parsed)) return fallback;
  const int = Math.floor(parsed);
  return int > 2 ? int : fallback;
}

function parseArgs(argv) {
  const today = new Date().toISOString().slice(0, 10);
  const out = {
    keyVersion: `kek-s-${today}`,
    primeBits: 2048,
    json: false,
  };

  for (let i = 0; i < argv.length; i += 1) {
    const arg = String(argv[i] || '').trim();
    if (!arg) continue;
    if (arg === '--') continue;
    if (arg === '-h' || arg === '--help') {
      usage();
      process.exit(0);
    }
    if (arg === '--json') {
      out.json = true;
      continue;
    }
    if (arg === '--key-version') {
      const value = String(argv[i + 1] || '').trim();
      if (!value) throw new Error('--key-version requires a non-empty value');
      out.keyVersion = value;
      i += 1;
      continue;
    }
    if (arg.startsWith('--key-version=')) {
      const value = arg.slice('--key-version='.length).trim();
      if (!value) throw new Error('--key-version requires a non-empty value');
      out.keyVersion = value;
      continue;
    }
    if (arg === '--prime-bits') {
      out.primeBits = parsePositiveInt(argv[i + 1], out.primeBits);
      i += 1;
      continue;
    }
    if (arg.startsWith('--prime-bits=')) {
      out.primeBits = parsePositiveInt(arg.slice('--prime-bits='.length), out.primeBits);
      continue;
    }
    throw new Error(`Unknown argument: ${arg}`);
  }

  return out;
}

function gcd(a, b) {
  let x = a < 0n ? -a : a;
  let y = b < 0n ? -b : b;
  while (y !== 0n) {
    const t = x % y;
    x = y;
    y = t;
  }
  return x;
}

function modInverse(a, modulus) {
  let t = 0n;
  let nextT = 1n;
  let r = modulus;
  let nextR = a % modulus;

  while (nextR !== 0n) {
    const q = r / nextR;
    const tempT = t - q * nextT;
    t = nextT;
    nextT = tempT;
    const tempR = r - q * nextR;
    r = nextR;
    nextR = tempR;
  }

  if (r !== 1n) {
    throw new Error('modInverse: value is not invertible');
  }
  if (t < 0n) t += modulus;
  return t;
}

function bigintToBase64Url(value) {
  if (value <= 0n) throw new Error('Expected bigint > 0');
  let hex = value.toString(16);
  if (hex.length % 2 === 1) hex = `0${hex}`;
  return Buffer.from(hex, 'hex').toString('base64url');
}

function randomBigIntBelow(limit) {
  if (limit <= 1n) return 0n;
  const bitLength = limit.toString(2).length;
  const byteLength = Math.ceil(bitLength / 8);
  while (true) {
    const candidate = BigInt(`0x${crypto.randomBytes(byteLength).toString('hex')}`);
    if (candidate < limit) return candidate;
  }
}

function pickServerEncryptExponent(phi) {
  const preferred = 65_537n;
  if (preferred < phi && gcd(preferred, phi) === 1n) {
    return preferred;
  }

  // Choose random odd exponents until one is coprime with phi.
  while (true) {
    const candidate = 3n + randomBigIntBelow(phi - 3n);
    const oddCandidate = candidate % 2n === 0n ? candidate + 1n : candidate;
    if (oddCandidate >= phi) continue;
    if (gcd(oddCandidate, phi) === 1n) return oddCandidate;
  }
}

function generateShamir3PassKeyMaterial({ keyVersion, primeBits }) {
  const prime = crypto.generatePrimeSync(primeBits, { bigint: true });
  const phi = prime - 1n;
  const serverEncryptExponent = pickServerEncryptExponent(phi);
  const serverDecryptExponent = modInverse(serverEncryptExponent, phi);

  return {
    keyVersion,
    shamirPrimeB64u: bigintToBase64Url(prime),
    serverEncryptExponentB64u: bigintToBase64Url(serverEncryptExponent),
    serverDecryptExponentB64u: bigintToBase64Url(serverDecryptExponent),
    primeBits,
  };
}

function printEnvBlocks(material) {
  const {
    keyVersion,
    shamirPrimeB64u,
    serverEncryptExponentB64u,
    serverDecryptExponentB64u,
    primeBits,
  } = material;

  console.log(`# Generated Shamir 3-pass key material (${primeBits}-bit prime)\n`);

  console.log('# Relay server / worker env');
  console.log('SIGNING_SESSION_SEAL_ENABLED=1');
  console.log(`SIGNING_SESSION_SEAL_KEY_VERSION=${keyVersion}`);
  console.log(`SIGNING_SESSION_SHAMIR_P_B64U=${shamirPrimeB64u}`);
  console.log(`SIGNING_SESSION_SEAL_E_S_B64U=${serverEncryptExponentB64u}`);
  console.log(`SIGNING_SESSION_SEAL_D_S_B64U=${serverDecryptExponentB64u}`);
  console.log('');

  console.log('# Client env (sealed_refresh_v1)');
  console.log('VITE_SIGNING_SESSION_PERSISTENCE_MODE=sealed_refresh_v1');
  console.log(`VITE_SIGNING_SESSION_SEAL_KEY_VERSION=${keyVersion}`);
  console.log(`VITE_SIGNING_SESSION_SHAMIR_P_B64U=${shamirPrimeB64u}`);
}

async function main() {
  const args = parseArgs(process.argv.slice(2));
  const material = generateShamir3PassKeyMaterial({
    keyVersion: args.keyVersion,
    primeBits: args.primeBits,
  });

  if (args.json) {
    console.log(JSON.stringify(material, null, 2));
    return;
  }

  printEnvBlocks(material);
}

main().catch((error) => {
  console.error(`[signing-session-seal:keygen] ${error instanceof Error ? error.message : String(error)}`);
  process.exit(1);
});
