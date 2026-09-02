import { expect, test } from '@playwright/test';
import {
  parseCommittedSignerPackageSetDigestB64u,
  parseCommittedSignerPackageSetV1,
} from '../../packages/shared-ts/src/device-linking/committedSignerPackages';
import { parseActivateInstalledAuthorityResultV1 } from '../../packages/shared-ts/src/device-linking/parsers';
import {
  buildOrdinaryEd25519ActivationReceiptFixture,
  buildOrdinaryEd25519ClientMaterialFixture,
  buildOrdinaryMaterialActivationFixture,
} from './helpers/ordinarySignerMaterialReservation.fixtures';

test('committed signer package sets reject non-canonical family branches', () => {
  expect(() =>
    parseCommittedSignerPackageSetV1({
      kind: 'committed_signer_package_set_v1',
      keyFamilies: ['ecdsa_secp256k1', 'ed25519'],
    }),
  ).toThrow(/canonical family order/);
});

test('committed signer package digest parser enforces a canonical digest', () => {
  expect(() => parseCommittedSignerPackageSetDigestB64u('invalid')).toThrow(
    /digest must be canonical base64url/,
  );
});

test('committed Ed25519 packages require exact participant evidence and receipt bindings', () => {
  const materialActivation = buildOrdinaryMaterialActivationFixture('committed-package');
  const clientMaterial = buildOrdinaryEd25519ClientMaterialFixture('committed-package');
  const activationReceipt = buildOrdinaryEd25519ActivationReceiptFixture(
    'committed-package',
    materialActivation,
  );
  const packageValue = {
    kind: 'committed_ed25519_signer_package_v1' as const,
    materialActivation,
    participantIds: [1, 2] as const,
    activationReceipt,
    deriver_a_client_package: clientMaterial.deriver_a_client_package,
    deriver_b_client_package: clientMaterial.deriver_b_client_package,
  };
  expect(
    parseCommittedSignerPackageSetV1({
      kind: 'committed_signer_package_set_v1',
      keyFamilies: ['ed25519'],
      ed25519: packageValue,
    }),
  ).toMatchObject({ ed25519: { participantIds: [1, 2] } });
  const otherActivation = buildOrdinaryMaterialActivationFixture('other-committed-package');
  expect(() =>
    parseCommittedSignerPackageSetV1({
      kind: 'committed_signer_package_set_v1',
      keyFamilies: ['ed25519'],
      ed25519: {
        ...packageValue,
        activationReceipt: buildOrdinaryEd25519ActivationReceiptFixture(
          'committed-package',
          otherActivation,
        ),
      },
    }),
  ).toThrow(/activation receipt does not match material/);
  expect(() =>
    parseCommittedSignerPackageSetV1({
      kind: 'committed_signer_package_set_v1',
      keyFamilies: ['ed25519'],
      ed25519: { ...packageValue, participantIds: [1] },
    }),
  ).toThrow(/participant_ids must contain exactly two values/);
});

test('activation responses reject non-canonical result branches', () => {
  expect(() =>
    parseActivateInstalledAuthorityResultV1({
      kind: 'pending_local_install',
      authorityId: 'wallet-authority:test',
      reason: { kind: 'wallet_session_issuance_pending', extra: true },
    }),
  ).toThrow(/not part of ActivationRetryReasonV1/);
});
