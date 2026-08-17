import { expect, test } from '@playwright/test';
import { captureLinkedDeviceOwnerCustodyHoldV1 } from '../../packages/sdk-web/src/SeamsWeb/operations/devices/deviceLinkingOwnerCustody';
import { base64UrlDecode } from '../../packages/shared-ts/src/utils/base64';
import {
  passkeyCustodyEnvelope,
  rawPasskeyFactor,
  CREDENTIAL_ID_B64U,
  OTHER_WALLET_ID,
  RP_ID,
  WALLET_ID,
} from './helpers/passkeyCustodyEnvelope.fixtures';

/**
 * Device 1 holds the factor secret that opens the wallet custody envelope
 * across a network wait, so the two ways that goes wrong are holding it for an
 * envelope it does not open, and leaving it in memory afterwards. These own
 * both.
 */
const PRF_FIRST_B64U = 'F2gjmLHjMV2Xrfs2Z4A-Wa-HNdXVcZ0JvVowpZ-EdYg';

function capture(overrides: Record<string, unknown> = {}) {
  return captureLinkedDeviceOwnerCustodyHoldV1({
    walletId: WALLET_ID,
    rpId: RP_ID,
    existingEnvelope: passkeyCustodyEnvelope(),
    ownerAssertion: {
      rawId: CREDENTIAL_ID_B64U,
      clientExtensionResults: { prf: { results: { first: PRF_FIRST_B64U } } },
    },
    ...overrides,
  } as never);
}

test('holds the PRF the approval already produced, and releases it exactly once', async () => {
  const hold = capture();
  const seen: Uint8Array[] = [];
  const sealed = await hold.sealOnceV1(async (material) => {
    seen.push(material.existingFactorSecret);
    expect([...material.existingFactorSecret]).toEqual([...base64UrlDecode(PRF_FIRST_B64U)]);
    expect(String(material.existingEnvelope.walletId)).toBe(WALLET_ID);
    return 'sealed';
  });
  expect(sealed).toBe('sealed');
  // The seal has consumed it, so it must not still be readable.
  expect([...(seen[0] ?? new Uint8Array([1]))].every((byte) => byte === 0)).toBe(true);
  // A second release would seal an all-zero seed, so it is refused outright.
  await expect(hold.sealOnceV1(async () => 'again')).rejects.toThrow('already released');
  // Discarding after a completed seal is not an error; the caller cannot know.
  expect(() => hold.discardV1()).not.toThrow();
});

test('wipes the secret when the seal throws, and when nothing seals at all', async () => {
  const failing = capture();
  let heldDuringSeal: Uint8Array | null = null;
  await expect(
    failing.sealOnceV1(async (material) => {
      heldDuringSeal = material.existingFactorSecret;
      throw new Error('worker refused the seal');
    }),
  ).rejects.toThrow('worker refused the seal');
  expect([...(heldDuringSeal ?? new Uint8Array([1]))].every((byte) => byte === 0)).toBe(true);

  // The abandoned-flow path: approval happened, no recipient ever arrived.
  const discarded = capture();
  discarded.discardV1();
  await expect(discarded.sealOnceV1(async () => 'unreachable')).rejects.toThrow('already released');
});

test('refuses material that does not belong together', async () => {
  const mismatches: Array<[string, Record<string, unknown>]> = [
    ['another wallet', { existingEnvelope: passkeyCustodyEnvelope({ walletId: OTHER_WALLET_ID }) }],
    [
      'another credential',
      {
        existingEnvelope: passkeyCustodyEnvelope({
          factor: rawPasskeyFactor({ credentialIdB64u: 'Y3JlZGVudGlhbC1vdGhlcg' }),
        }),
      },
    ],
    [
      'another relying party',
      {
        existingEnvelope: passkeyCustodyEnvelope({
          factor: rawPasskeyFactor({ rpId: 'attacker.example.localhost' }),
        }),
      },
    ],
    [
      'an assertion without PRF',
      { ownerAssertion: { rawId: CREDENTIAL_ID_B64U, clientExtensionResults: {} } },
    ],
  ];
  for (const [label, override] of mismatches) {
    expect(() => capture(override), label).toThrow();
  }
  // The unmodified capture still succeeds, so the refusals above are about the
  // mismatch and not a fixture that never captures.
  expect(() => capture()).not.toThrow();
});
