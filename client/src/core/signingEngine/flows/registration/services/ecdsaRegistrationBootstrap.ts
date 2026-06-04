import {
  buildWebAuthnPrfFirstSecretSourceFromParts,
  type EcdsaPreparePublicFacts,
  type EcdsaRoleLocalPendingStateBlob,
  type FinalizeEcdsaClientBootstrapOutput,
  type SignerCryptoPort,
} from '@/core/platform';
import {
  toWalletId,
  type ThresholdEcdsaChainTarget,
} from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import { toRpId } from '@/core/signingEngine/session/identity/evmFamilyEcdsaIdentity';
import {
  toEcdsaHssSigningRootId,
  toEcdsaHssSigningRootVersion,
  toEcdsaHssThresholdKeyId,
} from '@/core/signingEngine/session/identity/emailOtpHssIdentity';
import type {
  WalletRegistrationEcdsaClientBootstrap,
  WalletRegistrationEcdsaHssRespondBootstrap,
  WalletRegistrationEcdsaPrepareContext,
} from '@/core/rpcClients/relayer/walletRegistration';
import type { WorkerOperationContext } from '@/core/signingEngine/workerManager/executeWorkerOperation';
import type {
  EmailOtpWalletRegistrationEcdsaPrepareHandlePayload,
} from '@/core/signingEngine/workerManager/workerTypes';

export type PasskeyWalletRegistrationEcdsaPreparedClientBootstrap = {
  materialSource: 'passkey_prf_first';
  clientBootstrap: WalletRegistrationEcdsaClientBootstrap;
  pendingStateBlob: EcdsaRoleLocalPendingStateBlob;
  preparePublicFacts: EcdsaPreparePublicFacts;
  passkeyPrfFirstB64u: string;
  credentialIdB64u: string;
};

export type EmailOtpWalletRegistrationEcdsaPreparedClientBootstrap = {
  materialSource: 'email_otp_worker_handle';
  clientBootstrap: WalletRegistrationEcdsaClientBootstrap;
  pendingStateBlob: EcdsaRoleLocalPendingStateBlob;
  preparePublicFacts: EcdsaPreparePublicFacts;
  passkeyPrfFirstB64u?: never;
};

export type WalletRegistrationEcdsaPreparedClientBootstrap =
  | PasskeyWalletRegistrationEcdsaPreparedClientBootstrap
  | EmailOtpWalletRegistrationEcdsaPreparedClientBootstrap;

export type PreparePasskeyWalletRegistrationEcdsaClientBootstrapInput = {
  prepare: WalletRegistrationEcdsaPrepareContext;
  chainTarget: ThresholdEcdsaChainTarget;
  passkeyPrfFirstB64u: string;
  credentialIdB64u: string;
};

export type PrepareEmailOtpWalletRegistrationEcdsaClientBootstrapInput = {
  prepare: WalletRegistrationEcdsaPrepareContext;
  chainTarget: ThresholdEcdsaChainTarget;
  clientRootShareHandle: EmailOtpWalletRegistrationEcdsaPrepareHandlePayload;
};

export type FinalizeWalletRegistrationEcdsaClientBootstrapInput = {
  preparedClientBootstrap: WalletRegistrationEcdsaPreparedClientBootstrap;
  bootstrap: WalletRegistrationEcdsaHssRespondBootstrap;
};

export type EcdsaRegistrationBootstrapService = {
  preparePasskeyClientBootstrap(
    input: PreparePasskeyWalletRegistrationEcdsaClientBootstrapInput,
  ): Promise<PasskeyWalletRegistrationEcdsaPreparedClientBootstrap>;
  prepareEmailOtpClientBootstrap(
    input: PrepareEmailOtpWalletRegistrationEcdsaClientBootstrapInput,
  ): Promise<EmailOtpWalletRegistrationEcdsaPreparedClientBootstrap>;
  finalizeClientBootstrap(
    input: FinalizeWalletRegistrationEcdsaClientBootstrapInput,
  ): Promise<FinalizeEcdsaClientBootstrapOutput>;
};

export function createEcdsaRegistrationBootstrapService(deps: {
  signerCrypto: Pick<
    SignerCryptoPort,
    'prepareEcdsaClientBootstrap' | 'finalizeEcdsaClientBootstrap'
  >;
  emailOtpWorker: WorkerOperationContext;
}): EcdsaRegistrationBootstrapService {
  return {
    preparePasskeyClientBootstrap: (input) => preparePasskeyClientBootstrap(deps, input),
    prepareEmailOtpClientBootstrap: (input) => prepareEmailOtpClientBootstrap(deps, input),
    finalizeClientBootstrap: (input) => finalizeClientBootstrap(deps, input),
  };
}

async function preparePasskeyClientBootstrap(
  deps: {
    signerCrypto: Pick<SignerCryptoPort, 'prepareEcdsaClientBootstrap'>;
  },
  args: PreparePasskeyWalletRegistrationEcdsaClientBootstrapInput,
): Promise<PasskeyWalletRegistrationEcdsaPreparedClientBootstrap> {
  const prepared = await deps.signerCrypto.prepareEcdsaClientBootstrap({
    kind: 'prepare_ecdsa_client_bootstrap_v1',
    algorithm: 'ecdsa_hss_secp256k1_role_local_v1',
    context: {
      walletId: toWalletId(args.prepare.walletId),
      rpId: toRpId(args.prepare.rpId),
      chainTarget: args.chainTarget,
      ecdsaThresholdKeyId: toEcdsaHssThresholdKeyId(args.prepare.ecdsaThresholdKeyId),
      signingRootId: toEcdsaHssSigningRootId(args.prepare.signingRootId),
      signingRootVersion: toEcdsaHssSigningRootVersion(args.prepare.signingRootVersion),
      keyPurpose: 'evm-signing',
      keyVersion: 'v1',
    },
    participants: {
      clientParticipantId: 1,
      relayerParticipantId: 2,
      participantIds: [1, 2],
    },
    secretSource: buildWebAuthnPrfFirstSecretSourceFromParts({
      prfFirstB64u: args.passkeyPrfFirstB64u,
      rpId: toRpId(args.prepare.rpId),
      credentialIdB64u: args.credentialIdB64u,
    }),
  });
  if (!prepared.ok) {
    throw new Error(prepared.message);
  }
  const serverVisibleClientBootstrap: WalletRegistrationEcdsaClientBootstrap = {
    ...args.prepare,
    hssClientSharePublicKey33B64u: prepared.value.clientBootstrap.hssClientSharePublicKey33B64u,
    clientShareRetryCounter: prepared.value.clientBootstrap.clientShareRetryCounter,
    contextBinding32B64u: prepared.value.clientBootstrap.contextBinding32B64u,
  };
  return {
    materialSource: 'passkey_prf_first',
    clientBootstrap: serverVisibleClientBootstrap,
    pendingStateBlob: prepared.value.pendingStateBlob,
    preparePublicFacts: prepared.value.publicFacts,
    passkeyPrfFirstB64u: args.passkeyPrfFirstB64u,
    credentialIdB64u: args.credentialIdB64u,
  };
}

async function prepareEmailOtpClientBootstrap(
  deps: {
    emailOtpWorker: WorkerOperationContext;
  },
  args: PrepareEmailOtpWalletRegistrationEcdsaClientBootstrapInput,
): Promise<EmailOtpWalletRegistrationEcdsaPreparedClientBootstrap> {
  const result = await deps.emailOtpWorker.requestWorkerOperation({
    kind: 'emailOtp',
    request: {
      type: 'prepareWalletRegistrationEcdsaPreparedClientBootstrapFromEmailOtpHandle',
      timeoutMs: 60_000,
      payload: {
        prepare: args.prepare,
        clientRootShareHandle: args.clientRootShareHandle,
        chainTarget: args.chainTarget,
      },
    },
  });
  return {
    materialSource: 'email_otp_worker_handle',
    clientBootstrap: result.clientBootstrap,
    pendingStateBlob: result.pendingStateBlob,
    preparePublicFacts: result.preparePublicFacts,
  };
}

async function finalizeClientBootstrap(
  deps: {
    signerCrypto: Pick<SignerCryptoPort, 'finalizeEcdsaClientBootstrap'>;
  },
  args: FinalizeWalletRegistrationEcdsaClientBootstrapInput,
): Promise<FinalizeEcdsaClientBootstrapOutput> {
  const finalized = await deps.signerCrypto.finalizeEcdsaClientBootstrap({
    kind: 'finalize_ecdsa_client_bootstrap_v1',
    pendingStateBlob: args.preparedClientBootstrap.pendingStateBlob,
    relayerPublicIdentity: {
      relayerKeyId: args.bootstrap.relayerKeyId,
      relayerPublicKey33B64u: args.bootstrap.publicIdentity.relayerPublicKey33B64u,
      groupPublicKey33B64u: args.bootstrap.publicIdentity.groupPublicKey33B64u,
      ethereumAddress: args.bootstrap.publicIdentity.ethereumAddress as `0x${string}`,
    },
  });
  if (!finalized.ok) {
    throw new Error(finalized.message);
  }
  return finalized.value;
}
