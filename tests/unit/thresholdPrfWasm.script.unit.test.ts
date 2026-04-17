import { expect, test } from '@playwright/test';
import { readFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  parseSigningRootSecretShareWireV1,
  type SigningRootSecretShareWirePair,
} from '../../server/src/core/ThresholdService/signingRootSecretShareWires';
import {
  deriveEcdsaHssYRelayerFromSigningRootSecretShares,
  deriveEd25519HssServerInputsFromSigningRootSecretShares,
} from '../../server/src/core/ThresholdService/thresholdPrfWasm';

type ThresholdPrfFixtureShare = {
  readonly id: number;
  readonly wire_hex: string;
};

type ThresholdPrfFixtureVector = {
  readonly purpose: string;
  readonly context_hex: string;
  readonly shares: readonly ThresholdPrfFixtureShare[];
  readonly direct_output_hex: string;
};

type ThresholdPrfFixtureCorpus = {
  readonly vectors: readonly ThresholdPrfFixtureVector[];
};

const __dirname = dirname(fileURLToPath(import.meta.url));
const FIXTURE_PATH = resolve(__dirname, '../../crates/threshold-prf/fixtures/protocol-v1.json');

function hexToBytes(hex: string): Uint8Array {
  return new Uint8Array(Buffer.from(hex, 'hex'));
}

function bytesToHex(bytes: Uint8Array): string {
  return Buffer.from(bytes).toString('hex');
}

function hexToBase64Url(hex: string): string {
  return Buffer.from(hex, 'hex').toString('base64url');
}

function loadCorpus(): ThresholdPrfFixtureCorpus {
  return JSON.parse(readFileSync(FIXTURE_PATH, 'utf8')) as ThresholdPrfFixtureCorpus;
}

function vectorForPurpose(purpose: string): ThresholdPrfFixtureVector {
  const vector = loadCorpus().vectors.find((candidate) => candidate.purpose === purpose);
  if (!vector) throw new Error(`missing threshold-prf fixture vector for ${purpose}`);
  return vector;
}

function fixtureSharePair(vector: ThresholdPrfFixtureVector): SigningRootSecretShareWirePair {
  const first = parseSigningRootSecretShareWireV1(hexToBytes(vector.shares[0].wire_hex));
  const second = parseSigningRootSecretShareWireV1(hexToBytes(vector.shares[1].wire_hex));
  if (!first.ok) throw new Error(first.message);
  if (!second.ok) throw new Error(second.message);
  return [first.value, second.value] as const;
}

test('threshold-prf WASM derives ECDSA HSS y_relayer from committed signing-root share vectors', async () => {
  const vector = vectorForPurpose('ecdsa-hss/y_relayer');

  const yRelayer = await deriveEcdsaHssYRelayerFromSigningRootSecretShares({
    shareWires: fixtureSharePair(vector),
    context: {
      signingRootId: 'project-alpha:dev',
      nearAccountId: 'alice.near',
      keyPurpose: 'wallet',
      keyVersion: 'v1',
    },
  });

  expect(bytesToHex(yRelayer)).toBe(vector.direct_output_hex);
});

test('threshold-prf WASM derives Ed25519 HSS relayer inputs from committed signing-root share vectors', async () => {
  const yVector = vectorForPurpose('ed25519-hss/y_relayer');
  const tauVector = vectorForPurpose('ed25519-hss/tau_relayer');

  const serverInputs = await deriveEd25519HssServerInputsFromSigningRootSecretShares({
    shareWires: fixtureSharePair(yVector),
    context: {
      signingRootId: 'project-alpha:dev',
      nearAccountId: 'alice.near',
      keyPurpose: 'wallet',
      keyVersion: 'v1',
      participantIds: [1, 2],
      derivationVersion: 1,
    },
  });

  expect(serverInputs.contextBindingB64u).toBe(hexToBase64Url(yVector.context_hex));
  expect(serverInputs.yRelayerB64u).toBe(hexToBase64Url(yVector.direct_output_hex));
  expect(serverInputs.tauRelayerB64u).toBe(hexToBase64Url(tauVector.direct_output_hex));
});
