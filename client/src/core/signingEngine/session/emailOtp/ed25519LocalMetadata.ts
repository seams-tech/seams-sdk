import { inferNearChainIdKey } from '@/core/accountData/near/accountRefs';
import {
  storeNearThresholdKeyMaterial,
  type NearKeyMaterialDeps,
} from '@/core/accountData/near/keyMaterial';
import { buildNearProfileId } from '@/core/accountData/near/profileId';
import type { AccountId } from '@/core/types/accountIds';
import type { AccountKeyMaterialStorePort } from '@/core/indexedDB/accountKeyMaterial';
import {
  SIGNER_MATERIAL_FINGERPRINT_METADATA_KEY,
  type ActivateAccountSignerInput,
  type ActivateAccountSignerResult,
} from '@/core/indexedDB/accountSignerLifecycle';
import type { UpsertChainAccountInput, UpsertProfileInput } from '@/core/indexedDB';
import { buildThresholdEd25519Participants2pV1 } from '@shared/threshold/participants';
import { EMAIL_OTP_CHANNEL } from '@shared/utils/emailOtpDomain';
import { SIGNER_AUTH_METHODS, SIGNER_KINDS, SIGNER_SOURCES } from '@shared/utils/signerDomain';

type EmailOtpThresholdEd25519LocalMetadataClientPort = NearKeyMaterialDeps['clientDB'] & {
  upsertProfile(input: UpsertProfileInput): Promise<unknown>;
  upsertChainAccount(input: UpsertChainAccountInput): Promise<unknown>;
  activateAccountSigner(input: ActivateAccountSignerInput): Promise<ActivateAccountSignerResult>;
};

export type PersistEmailOtpThresholdEd25519LocalMetadataDeps =
  AccountKeyMaterialStorePort & EmailOtpThresholdEd25519LocalMetadataClientPort;

export type PersistEmailOtpThresholdEd25519LocalMetadataArgs = {
  nearAccountId: AccountId;
  rpId: string;
  relayerUrl: string;
  publicKey: string;
  relayerKeyId: string;
  keyVersion: string;
  participantIds: number[];
};

function buildEmailOtpThresholdEd25519SignerMaterialFingerprint(
  args: PersistEmailOtpThresholdEd25519LocalMetadataArgs,
): string {
  return JSON.stringify({
    kind: SIGNER_KINDS.thresholdEd25519,
    authMethod: SIGNER_AUTH_METHODS.emailOtp,
    publicKey: args.publicKey,
    relayerKeyId: args.relayerKeyId,
    keyVersion: args.keyVersion,
    rpId: args.rpId,
    participantIds: args.participantIds,
  });
}

export async function persistEmailOtpThresholdEd25519LocalMetadata(
  deps: PersistEmailOtpThresholdEd25519LocalMetadataDeps,
  args: PersistEmailOtpThresholdEd25519LocalMetadataArgs,
): Promise<void> {
  const profileId = buildNearProfileId(args.nearAccountId);
  const chainIdKey = inferNearChainIdKey(args.nearAccountId);
  const accountAddress = String(args.nearAccountId);
  const signerId = `threshold-ed25519:${args.relayerKeyId}`;
  const signerMaterialFingerprint = buildEmailOtpThresholdEd25519SignerMaterialFingerprint(args);
  const clientDB = deps;

  await clientDB.upsertProfile({
    profileId,
    defaultSignerSlot: 1,
  });
  await clientDB.upsertChainAccount({
    profileId,
    chainIdKey,
    accountAddress,
    accountModel: 'near-native',
    isPrimary: true,
  });

  const activation = await clientDB.activateAccountSigner({
    account: {
      profileId,
      chainIdKey,
      accountAddress,
      accountModel: 'near-native',
    },
    signer: {
      signerId,
      signerType: 'threshold',
      signerKind: SIGNER_KINDS.thresholdEd25519,
      signerAuthMethod: SIGNER_AUTH_METHODS.emailOtp,
      signerSource: SIGNER_SOURCES.emailOtpRegistration,
      metadata: {
        operationalPublicKey: args.publicKey,
        relayerKeyId: args.relayerKeyId,
        keyVersion: args.keyVersion,
        rpId: args.rpId,
        participantIds: args.participantIds,
        source: EMAIL_OTP_CHANNEL,
        [SIGNER_MATERIAL_FINGERPRINT_METADATA_KEY]: signerMaterialFingerprint,
      },
    },
    activationPolicy: {
      mode: 'reuse_existing',
      signerId,
      materialFingerprint: signerMaterialFingerprint,
    },
    mutation: { routeThroughOutbox: false },
  });
  const signerSlot = activation.signerSlot;
  await clientDB.upsertProfile({
    profileId,
    defaultSignerSlot: signerSlot,
  });

  await storeNearThresholdKeyMaterial(
    {
      clientDB,
      keyMaterialStore: deps,
    },
    {
      nearAccountId: args.nearAccountId,
      signerSlot,
      signerId,
      publicKey: args.publicKey,
      relayerKeyId: args.relayerKeyId,
      keyVersion: args.keyVersion,
      participants: buildThresholdEd25519Participants2pV1({
        clientParticipantId: args.participantIds[0] ?? null,
        relayerParticipantId: args.participantIds[1] ?? null,
        relayerKeyId: args.relayerKeyId,
        relayerUrl: args.relayerUrl,
        clientShareDerivation: 'prf_first_v1',
      }),
      timestamp: Date.now(),
    },
  );
}
