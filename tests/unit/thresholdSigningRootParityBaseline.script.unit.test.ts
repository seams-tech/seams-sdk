import { expect, test } from '@playwright/test';
import { deriveEcdsaHssYRelayerFromSigningRootSecretShares } from '../../server/src/core/ThresholdService/thresholdPrfWasm';
import {
  parseSigningRootSecretShareWireV1,
  type SigningRootSecretShareWirePair,
} from '../../server/src/core/ThresholdService/signingRootSecretShareWires';

const BASELINE_ECDSA_HSS_CONTEXT = {
  signingRootId: 'project-alpha:dev',
  nearAccountId: 'alice.near',
  keyPurpose: 'wallet',
  keyVersion: 'v1',
} as const;

const BASELINE_ECDSA_HSS_SHARE_1_WIRE_HEX =
  '011ba5f9c2f4003d409a9358a20b40b37eb32a28daacc5676a468b64a203c1e303';
const BASELINE_ECDSA_HSS_SHARE_2_WIRE_HEX =
  '021bb9834016ae79b9a815f68d1f456b35acb1b5631dd04e1cab9f640852aaed0d';
const BASELINE_ECDSA_HSS_Y_RELAYER_HEX =
  'ad502d0d27c9ee5a34b924d1f28e2e7bcc8f4756c07cc8335268e1d99b2c1ef3';

function hexToBytes(hex: string): Uint8Array {
  return new Uint8Array(Buffer.from(hex, 'hex'));
}

function bytesToHex(bytes: Uint8Array): string {
  return Buffer.from(bytes).toString('hex');
}

function parseBaselineSharePair(): SigningRootSecretShareWirePair {
  const first = parseSigningRootSecretShareWireV1(hexToBytes(BASELINE_ECDSA_HSS_SHARE_1_WIRE_HEX));
  const second = parseSigningRootSecretShareWireV1(hexToBytes(BASELINE_ECDSA_HSS_SHARE_2_WIRE_HEX));
  if (!first.ok) throw new Error(first.message);
  if (!second.ok) throw new Error(second.message);
  return [first.value, second.value] as const;
}

test('current ECDSA signing-root derivation baseline is pinned for self-host migration compatibility', async () => {
  const yRelayer = await deriveEcdsaHssYRelayerFromSigningRootSecretShares({
    shareWires: parseBaselineSharePair(),
    context: BASELINE_ECDSA_HSS_CONTEXT,
  });

  expect(bytesToHex(yRelayer)).toBe(BASELINE_ECDSA_HSS_Y_RELAYER_HEX);
  yRelayer.fill(0);
});
