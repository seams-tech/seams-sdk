import type {
  AccountSignerRecord,
  UpsertProfileInput,
} from '@/core/indexedDB/passkeyClientDB.types';
import {
  normalizeIndexedDbAccountAddress,
  toIndexedDbChainTargetKey,
} from '@/core/indexedDB/normalization';
import type { ThresholdEcdsaSessionBootstrapResult } from '../../threshold/ecdsa/activation';
import type { ThresholdEcdsaChainTarget } from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import { toWalletId, type WalletId } from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import type { ActivateAccountSignerInput } from '@/core/indexedDB/accountSignerLifecycle';
import { SIGNER_AUTH_METHODS, SIGNER_KINDS, SIGNER_SOURCES } from '@shared/utils/signerDomain';
import { resolveThresholdSigningRootBindingFromRecord } from '../identity/evmFamilyEcdsaIdentity';
import type { EcdsaRoleLocalPersistedMaterialRef } from '../keyMaterialBrands';

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

function roleLocalMaterialRefFromBootstrap(
  binding: ThresholdEcdsaSessionBootstrapResult['thresholdEcdsaKeyRef']['backendBinding'],
): EcdsaRoleLocalPersistedMaterialRef | null {
  if (!binding) return null;
  switch (binding.materialKind) {
    case 'role_local_worker_handle':
      return binding.roleLocalMaterialRef;
    case 'role_local_durable_sealed_ref':
      return binding.roleLocalMaterialRef;
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
  const keyHandle = keyRef.keyHandle;
  const ecdsaThresholdKeyId = keyRef.ecdsaThresholdKeyId;
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
  const thresholdOwnerAddress = normalizeIndexedDbAccountAddress(keyRef.ethereumAddress);
  if (!thresholdOwnerAddress) {
    throw new Error(
      '[SigningEngine] threshold-ecdsa bootstrap did not provide a threshold owner address',
    );
  }
  const thresholdEcdsaPublicKeyB64u = keyRef.thresholdEcdsaPublicKeyB64u;
  const relayerKeyId = keyRef.backendBinding.relayerKeyId;
  const relayerVerifyingShareB64u = keyRef.relayerVerifyingShareB64u;
  const participantIds = keyRef.participantIds;
  const chainIdKey = toIndexedDbChainTargetKey(args.chainTarget);
  const roleLocalMaterialRef = roleLocalMaterialRefFromBootstrap(keyRef.backendBinding);
  const metadata: Record<string, unknown> = {
    accountModel: 'threshold-ecdsa',
    accountAddress: thresholdOwnerAddress,
    ownerAddress: thresholdOwnerAddress,
    thresholdOwnerAddress,
    keyScope: 'evm-family',
    keyHandle,
    walletId: args.walletId,
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
  if (roleLocalMaterialRef) {
    metadata.roleLocalMaterialRef = roleLocalMaterialRef;
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
