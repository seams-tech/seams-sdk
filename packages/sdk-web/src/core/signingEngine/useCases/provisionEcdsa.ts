import {
  buildEmailOtpWorkerSessionSecretSource,
  buildWebAuthnPrfFirstSecretSource,
  type AuthenticatorPort,
  type AuthenticatorResult,
  type BootstrapEcdsaSessionRouteInput,
  type BootstrapEcdsaSessionRouteOutput,
  type ClockPort,
  type CredentialIdB64u,
  type DurableRecordStore,
  type EcdsaBootstrapSecretSource,
  type EcdsaProvisioningFailureCode,
  type EcdsaRelayerClient,
  type EcdsaRoleLocalAuthMethod,
  type EcdsaRoleLocalReadyRecord,
  type EmailOtpWorkerIssuedSessionHandle,
  type LoadEcdsaRoleLocalReadyRecordInput,
  type PrepareEcdsaClientBootstrapOutput,
  type RelayerKeyId,
  type RequiredPrfAuthenticatorSuccess,
  type SignerCryptoPort,
} from '@/core/platform';
import {
  buildEcdsaRoleLocalEmailOtpAuthMethod,
  buildEcdsaRoleLocalPasskeyAuthMethod,
  buildEcdsaRoleLocalPublicFacts,
  buildEcdsaRoleLocalReadyRecord,
} from '../session/persistence/ecdsaRoleLocalRecords';
import {
  thresholdEcdsaChainTargetsEqual,
  type ThresholdEcdsaChainTarget,
  type WalletId,
} from '../interfaces/ecdsaChainTarget';
import type { RpId } from '../session/identity/evmFamilyEcdsaIdentity';
import type {
  EcdsaThresholdKeyId,
} from '../session/identity/emailOtpHssIdentity';
import {
  toEcdsaHssSigningRootId,
  toEcdsaHssSigningRootVersion,
} from '../session/identity/emailOtpHssIdentity';
import type { ThresholdRuntimePolicyScope } from '../threshold/sessionPolicy';
import { signingRootScopeFromRuntimePolicyScope } from '@shared/threshold/signingRootScope';
import { assertNeverUseCase, useCaseFailure, type UseCaseFailure } from './lifecycle';

export type ProvisionEcdsaDeps = {
  authenticator: Pick<AuthenticatorPort, 'run'>;
  signerCrypto: Pick<
    SignerCryptoPort,
    'prepareEcdsaClientBootstrap' | 'finalizeEcdsaClientBootstrap'
  >;
  storage: Pick<
    DurableRecordStore,
    'loadEcdsaRoleLocalReadyRecord' | 'persistEcdsaRoleLocalReadyRecord'
  >;
  relayer: Pick<EcdsaRelayerClient, 'bootstrapEcdsaSession'>;
  clock: Pick<ClockPort, 'nowMs'>;
};

export type ProvisionEcdsaEmailOtpHandle = Extract<
  EmailOtpWorkerIssuedSessionHandle,
  { action: 'threshold_ecdsa_bootstrap' }
>;

export type ProvisionEcdsaAuthMethod =
  | {
      kind: 'passkey';
      credentialIdB64u: CredentialIdB64u;
      challengeB64u: string;
      handle?: never;
    }
  | {
      kind: 'email_otp';
      handle: ProvisionEcdsaEmailOtpHandle;
      credentialIdB64u?: never;
      challengeB64u?: never;
    };

export type ProvisionEcdsaRouteFacts = {
  relayerKeyId: RelayerKeyId;
  requestId: string;
  sessionId: string;
  signingGrantId: string;
  ttlMs: number;
  remainingUses: number;
  sessionKind: 'jwt';
  auth: BootstrapEcdsaSessionRouteInput['auth'];
  runtimePolicyScope: ThresholdRuntimePolicyScope;
};

export type ProvisionEcdsaInput = {
  walletId: WalletId;
  rpId: RpId;
  chainTarget: ThresholdEcdsaChainTarget;
  keyHandle: string;
  ecdsaThresholdKeyId: EcdsaThresholdKeyId;
  participantIds: readonly [1, 2];
  authMethod: ProvisionEcdsaAuthMethod;
  route: ProvisionEcdsaRouteFacts;
};

export type ProvisionEcdsaSuccess = {
  ok: true;
  record: EcdsaRoleLocalReadyRecord;
  value?: never;
};

export type ProvisionEcdsaFailure = UseCaseFailure<EcdsaProvisioningFailureCode>;

export type ProvisionEcdsaResult = ProvisionEcdsaSuccess | ProvisionEcdsaFailure;

export type ProvisionEcdsaUseCase = {
  provision(input: ProvisionEcdsaInput): Promise<ProvisionEcdsaResult>;
};

export function createProvisionEcdsaUseCase(deps: ProvisionEcdsaDeps): ProvisionEcdsaUseCase {
  return {
    provision: (input) => provisionEcdsa(deps, input),
  };
}

function failure(input: {
  code: EcdsaProvisioningFailureCode;
  source: ProvisionEcdsaFailure['source'];
  message: string;
  retryable: boolean;
  cause?: unknown;
}): ProvisionEcdsaFailure {
  return useCaseFailure(input);
}

function signerFailure(input: {
  failure: 'command' | 'invocation';
  message: string;
}): ProvisionEcdsaFailure {
  switch (input.failure) {
    case 'command':
      return failure({
        code: 'signer_crypto_command_failed',
        source: 'signer_crypto',
        message: input.message,
        retryable: false,
      });
    case 'invocation':
      return failure({
        code: 'signer_crypto_invocation_failed',
        source: 'signer_crypto',
        message: input.message,
        retryable: true,
      });
    default:
      return assertNeverUseCase(input.failure);
  }
}

function isProvisionEcdsaFailure(
  result: EcdsaBootstrapSecretSource | ProvisionEcdsaFailure,
): result is ProvisionEcdsaFailure {
  return 'ok' in result && result.ok === false;
}

function authenticatorFailureRetryable(
  result: Extract<AuthenticatorResult, { ok: false }>,
): boolean {
  switch (result.code) {
    case 'unavailable':
    case 'platform_error':
      return true;
    case 'cancelled':
    case 'not_allowed':
    case 'prf_unavailable':
    case 'invalid_credential':
      return false;
    default:
      return assertNeverUseCase(result.code);
  }
}

function isRequiredPrfGetSuccess(
  result: AuthenticatorResult,
): result is Extract<RequiredPrfAuthenticatorSuccess, { operation: 'get_passkey' }> {
  return (
    result.ok === true &&
    result.operation === 'get_passkey' &&
    result.requirePrfFirst === true &&
    result.prf.kind === 'required'
  );
}

function sameString(left: unknown, right: unknown): boolean {
  return String(left || '').trim() === String(right || '').trim();
}

type ProvisionEcdsaSigningRoot = {
  signingRootId: ReturnType<typeof toEcdsaHssSigningRootId>;
  signingRootVersion: ReturnType<typeof toEcdsaHssSigningRootVersion>;
};

function signingRootFromProvisionInput(input: ProvisionEcdsaInput): ProvisionEcdsaSigningRoot {
  const signingRoot = signingRootScopeFromRuntimePolicyScope(input.route.runtimePolicyScope);
  return {
    signingRootId: toEcdsaHssSigningRootId(signingRoot.signingRootId),
    signingRootVersion: toEcdsaHssSigningRootVersion(signingRoot.signingRootVersion),
  };
}

function validateEmailOtpHandle(input: ProvisionEcdsaInput): ProvisionEcdsaFailure | null {
  if (input.authMethod.kind !== 'email_otp') return null;
  const handle = input.authMethod.handle;
  if (
    !sameString(handle.walletId, input.walletId) ||
    !sameString(handle.rpId, input.rpId) ||
    !sameString(handle.action, 'threshold_ecdsa_bootstrap') ||
    !thresholdEcdsaChainTargetsEqual(handle.chainTarget, input.chainTarget)
  ) {
    return failure({
      code: 'invalid_state',
      source: 'domain',
      message: 'Email OTP ECDSA provisioning handle does not match the requested lane',
      retryable: false,
    });
  }
  return null;
}

function storageAuthMethodFromInput(input: ProvisionEcdsaInput): EcdsaRoleLocalAuthMethod {
  switch (input.authMethod.kind) {
    case 'passkey':
      return buildEcdsaRoleLocalPasskeyAuthMethod({
        credentialIdB64u: input.authMethod.credentialIdB64u,
        rpId: input.rpId,
      });
    case 'email_otp':
      return buildEcdsaRoleLocalEmailOtpAuthMethod({
        authSubjectId: input.authMethod.handle.authSubjectId,
      });
    default:
      return assertNeverUseCase(input.authMethod);
  }
}

function storageKeyFactsFromInput(
  input: ProvisionEcdsaInput,
  authMethod: EcdsaRoleLocalAuthMethod,
  signingRoot: ProvisionEcdsaSigningRoot,
): LoadEcdsaRoleLocalReadyRecordInput {
  return {
    walletId: input.walletId,
    rpId: input.rpId,
    chainTarget: input.chainTarget,
    keyHandle: input.keyHandle,
    ecdsaThresholdKeyId: input.ecdsaThresholdKeyId,
    signingRootId: signingRoot.signingRootId,
    signingRootVersion: signingRoot.signingRootVersion,
    participantIds: input.participantIds,
    authMethod,
  };
}

async function secretSourceFromInput(
  deps: ProvisionEcdsaDeps,
  input: ProvisionEcdsaInput,
): Promise<EcdsaBootstrapSecretSource | ProvisionEcdsaFailure> {
  switch (input.authMethod.kind) {
    case 'passkey': {
      const result = await deps.authenticator.run({
        kind: 'get_passkey',
        rpId: input.rpId,
        credentialIdB64u: input.authMethod.credentialIdB64u,
        challengeB64u: input.authMethod.challengeB64u,
        requirePrfFirst: true,
      });
      if (!result.ok) {
        return failure({
          code: 'authenticator_failed',
          source: 'authenticator',
          message: result.message,
          retryable: authenticatorFailureRetryable(result),
        });
      }
      if (!isRequiredPrfGetSuccess(result)) {
        return failure({
          code: 'invalid_state',
          source: 'authenticator',
          message: 'Passkey provisioning requires PRF.first from a get-passkey assertion',
          retryable: false,
        });
      }
      return buildWebAuthnPrfFirstSecretSource(result);
    }
    case 'email_otp':
      return buildEmailOtpWorkerSessionSecretSource(input.authMethod.handle);
    default:
      return assertNeverUseCase(input.authMethod);
  }
}

function routeInputFromPrepared(args: {
  input: ProvisionEcdsaInput;
  prepared: PrepareEcdsaClientBootstrapOutput;
}): BootstrapEcdsaSessionRouteInput {
  return {
    kind: 'bootstrap_ecdsa_session_route_v1',
    walletId: args.input.walletId,
    rpId: args.input.rpId,
    chainTarget: args.input.chainTarget,
    keyScope: 'evm-family',
    ecdsaThresholdKeyId: args.input.ecdsaThresholdKeyId,
    relayerKeyId: args.input.route.relayerKeyId,
    requestId: args.input.route.requestId,
    sessionId: args.input.route.sessionId,
    signingGrantId: args.input.route.signingGrantId,
    ttlMs: args.input.route.ttlMs,
    remainingUses: args.input.route.remainingUses,
    sessionKind: args.input.route.sessionKind,
    participantIds: args.input.participantIds,
    auth: args.input.route.auth,
    clientBootstrap: args.prepared.clientBootstrap,
    preparePublicFacts: args.prepared.publicFacts,
    runtimePolicyScope: args.input.route.runtimePolicyScope,
  };
}

function validateRelayerOutput(args: {
  input: ProvisionEcdsaInput;
  output: BootstrapEcdsaSessionRouteOutput;
}): ProvisionEcdsaFailure | null {
  const output = args.output;
  const input = args.input;
  if (
    !sameString(output.walletId, input.walletId) ||
    !sameString(output.rpId, input.rpId) ||
    !sameString(output.ecdsaThresholdKeyId, input.ecdsaThresholdKeyId) ||
    !sameString(output.keyHandle, input.keyHandle) ||
    !sameString(output.relayerPublicIdentity.relayerKeyId, input.route.relayerKeyId) ||
    output.participantIds[0] !== 1 ||
    output.participantIds[1] !== 2
  ) {
    return failure({
      code: 'invalid_state',
      source: 'relayer',
      message: 'ECDSA relayer bootstrap output does not match the provisioning request',
      retryable: false,
    });
  }
  return null;
}

export async function provisionEcdsa(
  deps: ProvisionEcdsaDeps,
  input: ProvisionEcdsaInput,
): Promise<ProvisionEcdsaResult> {
  const handleFailure = validateEmailOtpHandle(input);
  if (handleFailure) return handleFailure;

  const signingRoot = signingRootFromProvisionInput(input);
  const authMethod = storageAuthMethodFromInput(input);
  const storageKeyFacts = storageKeyFactsFromInput(input, authMethod, signingRoot);

  const loaded = await deps.storage.loadEcdsaRoleLocalReadyRecord(storageKeyFacts);
  if (!loaded.ok) {
    return failure({
      code: 'storage_failed',
      source: 'storage',
      message: loaded.message,
      retryable: true,
    });
  }
  switch (loaded.value.kind) {
    case 'found':
      return { ok: true, record: loaded.value.record };
    case 'not_found':
    case 'reauth_required':
      break;
    case 'malformed':
      return failure({
        code: 'invalid_state',
        source: 'storage',
        message: loaded.value.message,
        retryable: false,
      });
    default:
      return assertNeverUseCase(loaded.value);
  }

  const secretSource = await secretSourceFromInput(deps, input);
  if (isProvisionEcdsaFailure(secretSource)) return secretSource;

  const prepared = await deps.signerCrypto.prepareEcdsaClientBootstrap({
    kind: 'prepare_ecdsa_client_bootstrap_v1',
    algorithm: 'ecdsa_hss_secp256k1_role_local_v1',
    context: {
      walletId: input.walletId,
      rpId: input.rpId,
      chainTarget: input.chainTarget,
      ecdsaThresholdKeyId: input.ecdsaThresholdKeyId,
      signingRootId: signingRoot.signingRootId,
      signingRootVersion: signingRoot.signingRootVersion,
      keyPurpose: 'evm-signing',
      keyVersion: 'v1',
    },
    participants: {
      clientParticipantId: 1,
      relayerParticipantId: 2,
      participantIds: input.participantIds,
    },
    secretSource,
  });
  if (!prepared.ok) {
    return signerFailure({ failure: prepared.failure, message: prepared.message });
  }

  const relayer = await deps.relayer.bootstrapEcdsaSession(
    routeInputFromPrepared({ input, prepared: prepared.value }),
  );
  if (!relayer.ok) {
    return failure({
      code: 'relayer_failed',
      source: 'relayer',
      message: relayer.message,
      retryable: relayer.retryable,
    });
  }
  const relayerMismatch = validateRelayerOutput({ input, output: relayer.value });
  if (relayerMismatch) return relayerMismatch;

  const finalized = await deps.signerCrypto.finalizeEcdsaClientBootstrap({
    kind: 'finalize_ecdsa_client_bootstrap_v1',
    pendingStateBlob: prepared.value.pendingStateBlob,
    relayerPublicIdentity: relayer.value.relayerPublicIdentity,
  });
  if (!finalized.ok) {
    return signerFailure({ failure: finalized.failure, message: finalized.message });
  }

  const publicFacts = buildEcdsaRoleLocalPublicFacts({
    walletId: input.walletId,
    rpId: input.rpId,
    chainTarget: input.chainTarget,
    keyHandle: relayer.value.keyHandle,
    ecdsaThresholdKeyId: input.ecdsaThresholdKeyId,
    signingRootId: signingRoot.signingRootId,
    signingRootVersion: signingRoot.signingRootVersion,
    clientParticipantId: 1,
    relayerParticipantId: 2,
    participantIds: input.participantIds,
    contextBinding32B64u: finalized.value.publicFacts.contextBinding32B64u,
    hssClientSharePublicKey33B64u: finalized.value.publicFacts.hssClientSharePublicKey33B64u,
    relayerPublicKey33B64u: finalized.value.publicFacts.relayerPublicKey33B64u,
    groupPublicKey33B64u: finalized.value.publicFacts.groupPublicKey33B64u,
    ethereumAddress: finalized.value.publicFacts.ethereumAddress,
  });
  const record = buildEcdsaRoleLocalReadyRecord({
    stateBlob: finalized.value.stateBlob,
    publicFacts,
    authMethod,
  });
  const persisted = await deps.storage.persistEcdsaRoleLocalReadyRecord({
    record,
    storageKeyFacts,
  });
  if (!persisted.ok) {
    return failure({
      code: 'storage_failed',
      source: 'storage',
      message: persisted.message,
      retryable: persisted.code === 'unavailable',
    });
  }
  return { ok: true, record };
}
