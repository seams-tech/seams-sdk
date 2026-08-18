import { expect, test } from '@playwright/test';
import { parseOpaqueOwnerWalletSessionBinding } from '../../packages/wallet-server/src/authorization/service';
import { buildPasskeyWalletAuthAuthority } from '../../packages/shared-ts/src/utils/walletAuthAuthority';
import { ROUTER_AB_ED25519_NORMAL_SIGNING_STATE_KIND } from '../../packages/shared-ts/src/utils/signingSessionSeal';

/**
 * Owner Wallet Sessions name the key manifest their key set was registered
 * against. Registration is the only place that manifest is verified, and the
 * signer record is the only place it is kept — so a binding that reaches the
 * parser without one cannot say what the session's authority covers.
 *
 * These own the fail-closed half of that. A binding persisted before the field
 * existed must not narrow into a valid owner session, because an absent
 * manifest would otherwise read as "any manifest".
 */
const ED25519_BINDING = {
  kind: 'opaque_owner_wallet_session_binding_v1',
  curve: 'ed25519',
  walletId: 'wallet-manifest.testnet',
  thresholdSessionId: 'threshold-session-ed25519',
  authorizationId: 'wsa_manifest',
  walletSessionId: 'ws_manifest',
  quotaId: 'quota_manifest',
  relayerKeyId: 'relayer-1',
  participantIds: [1, 2],
  thresholdExpiresAtMs: 1_900_000_000_000,
  subjectId: 'wallet-manifest.testnet',
  keyManifestDigestB64u: 'Lcwi4R-zFWWooZJB2zonKJtBMlynySPIjt55tietXWE',
  nearAccountId: 'wallet-manifest.testnet',
  nearEd25519SigningKeyId: 'near-key-1',
  authority: buildPasskeyWalletAuthAuthority({
    walletId: 'wallet-manifest.testnet',
    rpId: 'example.test',
    credentialIdB64u: 'credential-manifest',
  }),
  runtimePolicyScope: {
    orgId: 'org-manifest',
    projectId: 'project-manifest',
    envId: 'env-manifest',
    signingRootVersion: '1',
  },
  routerAbNormalSigning: {
    kind: ROUTER_AB_ED25519_NORMAL_SIGNING_STATE_KIND,
    signingWorkerId: 'signing-worker-1',
  },
} as const;

test('refuses an owner binding that names no key manifest', () => {
  const { keyManifestDigestB64u: _omitted, ...withoutManifest } = ED25519_BINDING;
  expect(parseOpaqueOwnerWalletSessionBinding(withoutManifest)).toBeNull();
});

test('refuses an owner binding whose key manifest is not a digest', () => {
  // Not merely absent: a value that is present but not a canonical 32-byte
  // digest is the shape a truncated or re-encoded record would take.
  expect(
    parseOpaqueOwnerWalletSessionBinding({ ...ED25519_BINDING, keyManifestDigestB64u: '' }),
  ).toBeNull();
  expect(
    parseOpaqueOwnerWalletSessionBinding({
      ...ED25519_BINDING,
      keyManifestDigestB64u: 'Lcwi4R-zFWWooZJB2zonKJtBMlynySPIjt55tietXW',
    }),
  ).toBeNull();
});

test('carries the key manifest through a stored owner binding', () => {
  const parsed = parseOpaqueOwnerWalletSessionBinding(JSON.stringify(ED25519_BINDING));
  expect(parsed?.keyManifestDigestB64u).toBe(ED25519_BINDING.keyManifestDigestB64u);
});
