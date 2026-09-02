import {
  buildEvmFamilyWalletKeyRecord,
  buildOwnerPasskeySigningLaneRecord,
  parseWalletKeyVersion,
} from '../../../packages/shared-ts/src/signing-lanes/recordParsers';
import { requireEvmFamilySigningKeySlotId } from '../../../packages/shared-ts/src/signing-lanes/evmFamilySigningKeySlotId';
import {
  parseLaneShareEpoch,
  parseSigningLaneId,
  parseWalletKeyId,
} from '../../../packages/shared-ts/src/signing-lanes/ids';
import {
  buildOwnerLaneParticipantContinuityV1,
  computeOwnerLaneParticipantBindingDigestV1,
  parseWalletSignerId,
} from '../../../packages/shared-ts/src/signing-lanes/ownerContinuity';
import { parseSecp256k1CompressedPublicKeyB64u } from '../../../packages/shared-ts/src/passkey-custody/primitives';
import { base64UrlEncode } from '../../../packages/shared-ts/src/utils/base64';
import { parseDigestB64u } from '../../../packages/shared-ts/src/utils/canonicalPrimitives';
import {
  parseMpcMaterialActivationRef,
  parseMpcSigningWorkerRef,
  parseWalletAuthMethodId,
  parseWalletId,
} from '../../../packages/shared-ts/src/utils/domainIds';
import type { OwnerWalletExecutionEvidence } from '../../../packages/wallet-server/src/router/domains/signingOperations/walletExecutionAdmission';

function parsed<T>(
  result:
    | { readonly ok: true; readonly value: T }
    | { readonly ok: false; readonly error: { readonly message: string } },
): T {
  if (result.ok) return result.value;
  throw new Error(result.error.message);
}

export async function buildOwnerWalletExecutionEvidenceFixture(): Promise<OwnerWalletExecutionEvidence> {
  const walletId = parsed(parseWalletId('wallet-authorization'));
  const walletKeyId = parsed(parseWalletKeyId('wallet-key:evm:authorization'));
  const digestB64u = parseDigestB64u(base64UrlEncode(new Uint8Array(32).fill(7)));
  const signingWorkerId = parsed(parseMpcSigningWorkerRef('worker:wallet-authorization'));
  const ownerParticipantContinuity = buildOwnerLaneParticipantContinuityV1({
    signerId: parseWalletSignerId('ecdsa:eip155:1'),
    participantIds: [1, 2],
    signingWorkerId,
    custodyKeyManifestDigestB64u: digestB64u,
    sourceIdentityDigestB64u: digestB64u,
  });
  const participantBindingDigestB64u = await computeOwnerLaneParticipantBindingDigestV1(
    ownerParticipantContinuity,
  );
  const materialActivation = parsed(
    parseMpcMaterialActivationRef({
      kind: 'mpc_material_activation_ref',
      activationId: 'activation:wallet-authorization',
      capability: 'capability-evm',
      materialOwner: walletId,
      keyBinding: 'key-binding:wallet-authorization',
      lifecycleBinding: 'lifecycle:wallet-authorization',
      signingWorker: signingWorkerId,
    }),
  );
  const walletKey = buildEvmFamilyWalletKeyRecord({
    walletId,
    walletKeyId,
    walletKeyVersion: parseWalletKeyVersion('wallet-key-version:1'),
    evmFamilySigningKeySlotId: requireEvmFamilySigningKeySlotId(
      'wallet-key:evm-family:wallet-authorization:root:version-1',
    ),
    thresholdPublicKey33B64u: parseSecp256k1CompressedPublicKeyB64u(
      base64UrlEncode(Uint8Array.from([2, ...new Uint8Array(32).fill(9)])),
    ),
    evmAddress: '0x1111111111111111111111111111111111111111',
    lifecycle: { state: 'active', activatedAtMs: 1_900_000_000_000 },
  });
  const lane = buildOwnerPasskeySigningLaneRecord({
    walletId,
    walletKeyId,
    laneId: parsed(parseSigningLaneId('lane:owner-passkey:wallet-authorization')),
    laneShareEpoch: parsed(parseLaneShareEpoch('lane-share-epoch:1')),
    participantBindingDigestB64u,
    walletAuthMethodId: parsed(
      parseWalletAuthMethodId('passkey:wallet.example.test:credential-owner'),
    ),
    ownerParticipantContinuity,
    lifecycle: {
      state: 'active',
      revocationEpoch: 1,
      activatedAtMs: 1_900_000_000_000,
      activationReceiptDigestB64u: digestB64u,
    },
  });
  return {
    walletId,
    walletKey,
    lane,
    materialActivation,
    expectedMaterialActivation: materialActivation,
    verifiedLaneParticipantBindingDigestB64u: lane.participantBindingDigestB64u,
    verifiedActivationReceiptDigestB64u: digestB64u,
  };
}
