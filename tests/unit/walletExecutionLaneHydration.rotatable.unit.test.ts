import { expect, test } from '@playwright/test';
import { hydrateRotatableWalletExecutionLaneV1 } from '../../packages/sdk-web/src/core/signingEngine/session/lanes/walletExecutionLaneHydration';
import {
  buildLaneHolderCustodyIdentityV1,
  buildSigningWorkerRecipientIdentityV1,
  parseHpkePublicKeyB64u,
  parseLaneHolderCustodyBindingId,
  parseLaneHolderParticipantId,
  parseLaneCustodyBindingDigestB64u,
  parseLaneParticipantBindingDigestB64u,
  parseSigningWorkerParticipantId,
  parseSigningWorkerRecipientKeyId,
  parseSigningWorkerRecipientKeyDigestB64u,
} from '../../packages/shared-ts/src/signing-lanes/participants';
import {
  buildLaneHolderParticipantRecordWithDigestV1,
  buildSigningWorkerParticipantRecordWithDigestV1,
  computeLaneParticipantSetBindingDigestV1,
} from '../../packages/shared-ts/src/signing-lanes/participantDigest';
import { parseMpcMaterialActivationRef } from '../../packages/shared-ts/src/utils/domainIds';
import { base64UrlEncode } from '../../packages/shared-ts/src/utils/base64';

const DIGEST_B64U = base64UrlEncode(new Uint8Array(32).fill(7));
const HOLDER_KEY_B64U = base64UrlEncode(new Uint8Array(32).fill(8));
const SUBSTITUTED_HOLDER_KEY_B64U = base64UrlEncode(new Uint8Array(32).fill(9));

function value<T>(
  result:
    | { readonly ok: true; readonly value: T }
    | { readonly ok: false; readonly error: { readonly message: string } },
): T {
  if (result.ok) return result.value;
  throw new Error(result.error.message);
}

async function participantFixture() {
  const holderParticipant = await buildLaneHolderParticipantRecordWithDigestV1({
    participantId: value(parseLaneHolderParticipantId('holder:rotatable')),
    custody: buildLaneHolderCustodyIdentityV1({
      custodyBindingId: value(parseLaneHolderCustodyBindingId('custody:rotatable')),
      custodyBindingDigestB64u: value(parseLaneCustodyBindingDigestB64u(DIGEST_B64U)),
    }),
    hpkePublicKeyB64u: value(parseHpkePublicKeyB64u(HOLDER_KEY_B64U)),
    hpkePublicKeyDigestB64u: value(parseSigningWorkerRecipientKeyDigestB64u(DIGEST_B64U)),
  });
  const signingWorkerParticipant = await buildSigningWorkerParticipantRecordWithDigestV1({
    participantId: value(parseSigningWorkerParticipantId('worker:rotatable')),
    recipient: buildSigningWorkerRecipientIdentityV1({
      recipientKeyId: value(parseSigningWorkerRecipientKeyId('recipient:rotatable')),
      hpkePublicKeyB64u: value(parseHpkePublicKeyB64u(HOLDER_KEY_B64U)),
      hpkePublicKeyDigestB64u: value(parseSigningWorkerRecipientKeyDigestB64u(DIGEST_B64U)),
    }),
  });
  const participantBindingDigestB64u = await computeLaneParticipantSetBindingDigestV1({
    holderParticipant,
    signingWorkerParticipant,
  });
  return { holderParticipant, signingWorkerParticipant, participantBindingDigestB64u };
}

function materialActivation() {
  return value(
    parseMpcMaterialActivationRef({
      kind: 'mpc_material_activation_ref',
      activationId: 'activation:rotatable',
      capability: 'capability:rotatable',
      materialOwner: 'wallet:rotatable',
      keyBinding: 'key-binding:rotatable',
      lifecycleBinding: 'lifecycle:rotatable',
      signingWorker: 'worker:rotatable',
    }),
  );
}

test.describe('R102 rotatable lane participant-set hydration', () => {
  test('accepts distinct verified participant digests bound by the aggregate', async () => {
    const participants = await participantFixture();
    const walletKey = {
      kind: 'wallet_key_record_v1',
      keyFamily: 'ed25519',
      walletId: 'wallet:rotatable',
      walletKeyId: 'wallet-key:rotatable',
      walletKeyVersion: 'version:1',
      nearEd25519SigningKeyId: 'near-signing-key:rotatable',
      keyCreationSignerSlot: 1,
      registeredPublicKeyB64u: base64UrlEncode(new Uint8Array(32).fill(6)),
      lifecycle: { state: 'active', activatedAtMs: 1 },
    };
    const lane = {
      kind: 'signing_lane_reference_v1',
      walletId: walletKey.walletId,
      walletKeyId: walletKey.walletKeyId,
      laneId: 'lane:rotatable',
      laneKind: 'linked_device',
      laneShareEpoch: 'epoch:1',
      participantBindingDigestB64u: participants.participantBindingDigestB64u,
      holderParticipant: participants.holderParticipant,
      serverParticipant: participants.signingWorkerParticipant,
      lifecycle: {
        state: 'active',
        revocationEpoch: 1,
        activatedAtMs: 2,
        activationReceiptDigestB64u: DIGEST_B64U,
      },
      linkedDeviceId: 'device:rotatable',
    };

    const result = await hydrateRotatableWalletExecutionLaneV1({
      walletKey,
      lane,
      keyFamily: 'ed25519',
      laneShareEpoch: 'epoch:1',
      materialActivation: materialActivation(),
      participantBindingDigestB64u: value(
        parseLaneParticipantBindingDigestB64u(participants.participantBindingDigestB64u),
      ),
    });
    expect(result.kind).toBe('active_rotatable_wallet_execution_lane_v1');
    expect(participants.holderParticipant.participantBindingDigestB64u).not.toBe(
      participants.participantBindingDigestB64u,
    );
    expect(participants.signingWorkerParticipant.participantBindingDigestB64u).not.toBe(
      participants.participantBindingDigestB64u,
    );
  });

  test('refuses a participant substitution even when the lane aggregate is unchanged', async () => {
    const participants = await participantFixture();
    const substitutedHolder = await buildLaneHolderParticipantRecordWithDigestV1({
      participantId: participants.holderParticipant.participantId,
      custody: buildLaneHolderCustodyIdentityV1({
        custodyBindingId: participants.holderParticipant.custodyBindingId,
        custodyBindingDigestB64u: participants.holderParticipant.custodyBindingDigestB64u,
      }),
      hpkePublicKeyB64u: value(parseHpkePublicKeyB64u(SUBSTITUTED_HOLDER_KEY_B64U)),
      hpkePublicKeyDigestB64u: participants.holderParticipant.hpkePublicKeyDigestB64u,
    });
    const walletKey = {
      kind: 'wallet_key_record_v1',
      keyFamily: 'ed25519',
      walletId: 'wallet:rotatable',
      walletKeyId: 'wallet-key:rotatable',
      walletKeyVersion: 'version:1',
      nearEd25519SigningKeyId: 'near-signing-key:rotatable',
      keyCreationSignerSlot: 1,
      registeredPublicKeyB64u: base64UrlEncode(new Uint8Array(32).fill(6)),
      lifecycle: { state: 'active', activatedAtMs: 1 },
    };
    const lane = {
      kind: 'signing_lane_reference_v1',
      walletId: walletKey.walletId,
      walletKeyId: walletKey.walletKeyId,
      laneId: 'lane:rotatable',
      laneKind: 'linked_device',
      laneShareEpoch: 'epoch:1',
      participantBindingDigestB64u: participants.participantBindingDigestB64u,
      holderParticipant: substitutedHolder,
      serverParticipant: participants.signingWorkerParticipant,
      lifecycle: {
        state: 'active',
        revocationEpoch: 1,
        activatedAtMs: 2,
        activationReceiptDigestB64u: DIGEST_B64U,
      },
      linkedDeviceId: 'device:rotatable',
    };

    const result = await hydrateRotatableWalletExecutionLaneV1({
      walletKey,
      lane,
      keyFamily: 'ed25519',
      laneShareEpoch: 'epoch:1',
      materialActivation: materialActivation(),
      participantBindingDigestB64u: value(
        parseLaneParticipantBindingDigestB64u(participants.participantBindingDigestB64u),
      ),
    });
    expect(result).toMatchObject({
      kind: 'wallet_execution_lane_refused_v1',
      reason: 'participant_binding_mismatch',
    });
  });
});
