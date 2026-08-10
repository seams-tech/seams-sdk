import { buildEvmFamilyWalletKeyRecord } from '../../../packages/shared-ts/src/signing-lanes/recordParsers';
import { buildOwnerPasskeySigningLaneRecord } from '../../../packages/shared-ts/src/signing-lanes/recordParsers';
import { requireEvmFamilySigningKeySlotId } from '../../../packages/shared-ts/src/signing-lanes/evmFamilySigningKeySlotId';
import {
  parseLaneShareEpoch,
  parseSigningLaneId,
  parseWalletKeyId,
} from '../../../packages/shared-ts/src/signing-lanes/ids';
import {
  buildLaneHolderCustodyIdentityV1,
  buildSigningWorkerRecipientIdentityV1,
  parseHpkePublicKeyB64u,
  parseLaneCustodyBindingDigestB64u,
  parseLaneHolderCustodyBindingId,
  parseLaneHolderParticipantId,
  parseSigningWorkerParticipantId,
  parseSigningWorkerRecipientKeyDigestB64u,
  parseSigningWorkerRecipientKeyId,
} from '../../../packages/shared-ts/src/signing-lanes/participants';
import {
  buildLaneHolderParticipantRecordWithDigestV1,
  buildSigningWorkerParticipantRecordWithDigestV1,
} from '../../../packages/shared-ts/src/signing-lanes/participantDigest';
import { parseSecp256k1CompressedPublicKeyB64u } from '../../../packages/shared-ts/src/passkey-custody/primitives';
import { base64UrlEncode } from '../../../packages/shared-ts/src/utils/base64';
import { parseDigestB64u } from '../../../packages/shared-ts/src/utils/canonicalPrimitives';
import {
  parseMpcMaterialActivationRef,
  parseWalletId,
} from '../../../packages/shared-ts/src/utils/domainIds';
import type { OwnerWalletExecutionEvidence } from '../../../packages/sdk-server-ts/src/router/domains/signingOperations/walletExecutionAdmission';

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
  const hpkePublicKeyB64u = parsed(
    parseHpkePublicKeyB64u(base64UrlEncode(new Uint8Array(32).fill(8))),
  );
  const hpkePublicKeyDigestB64u = parsed(parseSigningWorkerRecipientKeyDigestB64u(digestB64u));
  const holderParticipant = await buildLaneHolderParticipantRecordWithDigestV1({
    participantId: parsed(parseLaneHolderParticipantId('holder:wallet-authorization')),
    custody: buildLaneHolderCustodyIdentityV1({
      custodyBindingId: parsed(parseLaneHolderCustodyBindingId('custody:wallet-authorization')),
      custodyBindingDigestB64u: parsed(parseLaneCustodyBindingDigestB64u(digestB64u)),
    }),
    hpkePublicKeyB64u,
    hpkePublicKeyDigestB64u,
  });
  const serverParticipant = await buildSigningWorkerParticipantRecordWithDigestV1({
    participantId: parsed(parseSigningWorkerParticipantId('worker:wallet-authorization')),
    recipient: buildSigningWorkerRecipientIdentityV1({
      recipientKeyId: parsed(parseSigningWorkerRecipientKeyId('recipient:wallet-authorization')),
      hpkePublicKeyB64u,
      hpkePublicKeyDigestB64u,
    }),
  });
  const materialActivation = parsed(
    parseMpcMaterialActivationRef({
      kind: 'mpc_material_activation_ref',
      activationId: 'activation:wallet-authorization',
      capability: 'capability-evm',
      materialOwner: walletId,
      keyBinding: 'key-binding:wallet-authorization',
      lifecycleBinding: 'lifecycle:wallet-authorization',
      signingWorker: serverParticipant.participantId,
    }),
  );
  const walletKey = buildEvmFamilyWalletKeyRecord({
    walletId,
    walletKeyId,
    walletKeyVersion: 'wallet-key-version:1',
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
    participantBindingDigestB64u: serverParticipant.participantBindingDigestB64u,
    holderParticipant,
    serverParticipant,
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
