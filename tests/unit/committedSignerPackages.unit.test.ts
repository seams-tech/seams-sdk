import { expect, test } from '@playwright/test';
import {
  parseCommittedSignerPackageSetDigestB64u,
  parseCommittedSignerPackageSetV1,
} from '../../packages/shared-ts/src/device-linking/committedSignerPackages';
import { parseActivateInstalledAuthorityResultV1 } from '../../packages/shared-ts/src/device-linking/parsers';

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

test('activation responses reject non-canonical result branches', () => {
  expect(() =>
    parseActivateInstalledAuthorityResultV1({
      kind: 'pending_local_install',
      authorityId: 'wallet-authority:test',
      reason: { kind: 'wallet_session_issuance_pending', extra: true },
    }),
  ).toThrow(/not part of ActivationRetryReasonV1/);
});
