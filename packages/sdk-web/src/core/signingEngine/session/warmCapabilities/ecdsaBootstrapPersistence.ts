import type {
  AccountSignerRecord,
  UpsertProfileInput,
} from '@/core/indexedDB/passkeyClientDB.types';
import {
  normalizeIndexedDbAccountAddress,
  toIndexedDbChainTargetKey,
} from '@/core/indexedDB/normalization';
import type { ThresholdEcdsaSessionBootstrapResult } from '../../threshold/ecdsa/activation';
import {
  thresholdEcdsaChainTargetFromChainFamily,
  type ThresholdEcdsaChainTarget,
} from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import { toWalletId, type WalletId } from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import type { ActivateAccountSignerInput } from '@/core/indexedDB/accountSignerLifecycle';
import { SIGNER_AUTH_METHODS, SIGNER_KINDS, SIGNER_SOURCES } from '@shared/utils/signerDomain';
import { resolveThresholdSigningRootBindingFromRecord } from '../identity/evmFamilyEcdsaIdentity';

export type ThresholdEcdsaBootstrapStorePort = {
  upsertProfile: (input: UpsertProfileInput) => Promise<unknown>;
  activateAccountSigner: (input: ActivateAccountSignerInput) => Promise<{
    signer: AccountSignerRecord;
    signerSlot: number;
  }>;
};

export type ThresholdEcdsaBootstrapSignerAuth =
  | {
      authMethod: typeof SIGNER_AUTH_METHODS.passkey;
      signerSource: typeof SIGNER_SOURCES.passkeyRegistration;
    }
  | {
      authMethod: typeof SIGNER_AUTH_METHODS.emailOtp;
      signerSource: typeof SIGNER_SOURCES.emailOtpRegistration;
    };

function resolveBootstrapTargetChainIdKey(args: {
  chainTarget: ThresholdEcdsaChainTarget;
  bootstrap: ThresholdEcdsaSessionBootstrapResult;
}): string {
  const keygenChainId = Number(args.bootstrap.keygen.chainId);
  if (Number.isFinite(keygenChainId) && keygenChainId > 0) {
    return toIndexedDbChainTargetKey(
      thresholdEcdsaChainTargetFromChainFamily({
        chain: args.chainTarget.kind,
        chainId: Math.floor(keygenChainId),
        networkSlug: args.chainTarget.networkSlug,
      }),
    );
  }
  return toIndexedDbChainTargetKey(args.chainTarget);
}

function requireBootstrapString(value: unknown, field: string): string {
  const normalized = String(value || '').trim();
  if (!normalized) {
    throw new Error(`[SigningEngine] threshold-ecdsa bootstrap missing ${field}`);
  }
  return normalized;
}

function requireConsistentBootstrapString(args: {
  primary: unknown;
  secondary: unknown;
  field: string;
}): string {
  const primary = String(args.primary || '').trim();
  const secondary = String(args.secondary || '').trim();
  if (primary && secondary && primary !== secondary) {
    throw new Error(`[SigningEngine] threshold-ecdsa bootstrap ${args.field} mismatch`);
  }
  return requireBootstrapString(primary || secondary, args.field);
}

function requireParticipantIds(value: unknown): number[] {
  if (!Array.isArray(value) || value.length === 0) {
    throw new Error('[SigningEngine] threshold-ecdsa bootstrap missing participantIds');
  }
  return value.map((participantId) => {
    const normalized = Number(participantId);
    if (!Number.isSafeInteger(normalized) || normalized <= 0) {
      throw new Error(
        '[SigningEngine] threshold-ecdsa bootstrap participantIds must be positive integers',
      );
    }
    return normalized;
  });
}

function roleLocalDurableMaterialRefFromBootstrap(
  binding: ThresholdEcdsaSessionBootstrapResult['thresholdEcdsaKeyRef']['backendBinding'],
): string | null {
  if (!binding) return null;
  switch (binding.materialKind) {
    case 'role_local_worker_handle':
      return binding.roleLocalMaterialHandle.durableMaterialRef;
    case 'role_local_durable_sealed_ref':
      return binding.durableMaterialRef;
    case 'email_otp_worker_handle':
    case 'role_local_durable_public_anchor':
    case 'role_local_ready_state_blob':
    case 'metadata_only':
      return null;
  }
}

function ecdsaBootstrapSignerActivation(args: {
  walletId: WalletId;
  chainTarget: ThresholdEcdsaChainTarget;
  bootstrap: ThresholdEcdsaSessionBootstrapResult;
  signerAuth: ThresholdEcdsaBootstrapSignerAuth;
}): ActivateAccountSignerInput {
  const keyRef = args.bootstrap.thresholdEcdsaKeyRef;
  const keygen = args.bootstrap.keygen;
  const keyHandle = requireConsistentBootstrapString({
    primary: keyRef.keyHandle,
    secondary: keygen.keyHandle,
    field: 'keyHandle',
  });
  const ecdsaThresholdKeyId = requireConsistentBootstrapString({
    primary: keyRef.ecdsaThresholdKeyId,
    secondary: keygen.ecdsaThresholdKeyId,
    field: 'ecdsaThresholdKeyId',
  });
  const ecdsaRoleLocalReadyRecord = keyRef.backendBinding?.ecdsaRoleLocalReadyRecord;
  const ecdsaRoleLocalPublicFacts =
    keyRef.backendBinding?.materialKind === 'role_local_worker_handle'
      ? keyRef.backendBinding.publicFacts
      : ecdsaRoleLocalReadyRecord?.publicFacts;
  if (!ecdsaRoleLocalPublicFacts) {
    throw new Error(
      '[SigningEngine] threshold-ecdsa bootstrap did not provide role-local public facts',
    );
  }
  const signingRootBinding = resolveThresholdSigningRootBindingFromRecord({
    record: {
      signingRootId: ecdsaRoleLocalPublicFacts.signingRootId,
      signingRootVersion: ecdsaRoleLocalPublicFacts.signingRootVersion,
    },
  });
  const signingRootId = String(signingRootBinding.signingRootId);
  const signingRootVersion = String(signingRootBinding.signingRootVersion);
  const thresholdOwnerAddress = normalizeIndexedDbAccountAddress(keygen.ethereumAddress);
  if (!thresholdOwnerAddress) {
    throw new Error(
      '[SigningEngine] threshold-ecdsa bootstrap did not provide a threshold owner address',
    );
  }
  const thresholdEcdsaPublicKeyB64u = requireConsistentBootstrapString({
    primary: keyRef.thresholdEcdsaPublicKeyB64u,
    secondary: keygen.thresholdEcdsaPublicKeyB64u,
    field: 'thresholdEcdsaPublicKeyB64u',
  });
  const relayerKeyId = requireBootstrapString(keygen.relayerKeyId, 'relayerKeyId');
  const relayerVerifyingShareB64u = requireBootstrapString(
    keygen.relayerVerifyingShareB64u,
    'relayerVerifyingShareB64u',
  );
  const participantIds = requireParticipantIds(keyRef.participantIds || keygen.participantIds);
  const evmFamilySigningKeySlotId = requireBootstrapString(
    keygen.evmFamilySigningKeySlotId,
    'evmFamilySigningKeySlotId',
  );
  const chainIdKey = resolveBootstrapTargetChainIdKey({
    chainTarget: args.chainTarget,
    bootstrap: args.bootstrap,
  });
  const roleLocalDurableMaterialRef = roleLocalDurableMaterialRefFromBootstrap(
    keyRef.backendBinding,
  );
  const metadata: Record<string, unknown> = {
    accountModel: 'threshold-ecdsa',
    accountAddress: thresholdOwnerAddress,
    ownerAddress: thresholdOwnerAddress,
    thresholdOwnerAddress,
    keyScope: 'evm-family',
    keyHandle,
    walletId: args.walletId,
    evmFamilySigningKeySlotId,
    ecdsaThresholdKeyId,
    signingRootId,
    signingRootVersion,
    relayerKeyId,
    relayerVerifyingShareB64u,
    thresholdEcdsaPublicKeyB64u,
    participantIds,
    publicCapability: ecdsaRoleLocalPublicFacts.publicCapability,
    ecdsaRoleLocalPublicFacts,
    chainTarget: args.chainTarget,
    targetMembership: {
      targetKey: chainIdKey,
      chainTarget: args.chainTarget,
    },
    sharedEvmFamilyKey: {
      walletId: args.walletId,
      evmFamilySigningKeySlotId,
      keyScope: 'evm-family',
      keyHandle,
      ecdsaThresholdKeyId,
      signingRootId,
      signingRootVersion,
      participantIds,
      thresholdOwnerAddress,
      thresholdEcdsaPublicKeyB64u,
    },
    chainId: args.chainTarget.chainId,
  };
  if (roleLocalDurableMaterialRef) {
    metadata.roleLocalDurableMaterialRef = roleLocalDurableMaterialRef;
  }

  return {
    account: {
      profileId: args.walletId,
      chainIdKey,
      accountAddress: thresholdOwnerAddress,
      accountModel: 'threshold-ecdsa',
    },
    signer: {
      signerId: thresholdOwnerAddress,
      signerType: 'threshold',
      signerKind: SIGNER_KINDS.thresholdEcdsa,
      signerAuthMethod: args.signerAuth.authMethod,
      signerSource: args.signerAuth.signerSource,
      metadata,
    },
    activationPolicy: { mode: 'allocate_next_free' },
    preferredSlot: 1,
    selectAsActive: false,
    mutation: { routeThroughOutbox: false },
  };
}

export async function persistThresholdEcdsaBootstrapForWalletTarget(args: {
  bootstrapStore: ThresholdEcdsaBootstrapStorePort;
  walletId: WalletId;
  chainTarget: ThresholdEcdsaChainTarget;
  bootstrap: ThresholdEcdsaSessionBootstrapResult;
  signerAuth: ThresholdEcdsaBootstrapSignerAuth;
}): Promise<void> {
  const walletId = toWalletId(args.walletId);
  await args.bootstrapStore.upsertProfile({
    profileId: walletId,
  });
  await args.bootstrapStore.activateAccountSigner(
    ecdsaBootstrapSignerActivation({
      walletId,
      chainTarget: args.chainTarget,
      bootstrap: args.bootstrap,
      signerAuth: args.signerAuth,
    }),
  );
}
