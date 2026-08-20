import type { AuthenticatorPort } from '@/core/platform';
import { SignedTransaction, type NearClient } from '@/core/rpcClients/near/NearClient';
import { fundImplicitNearAccountForTesting } from '@/core/rpcClients/relayer/walletRegistration';
import { buildNearTransactionSigningPayload } from '@/core/signingEngine/chains/near/payloads';
import {
  buildThresholdEd25519NearTxUnsignedBorshWasm,
  decodeThresholdEd25519SignedNearTxBorshWasm,
  finalizeThresholdEd25519NearTxFromSignatureWasm,
} from '@/core/signingEngine/chains/near/nearSignerWasm';
import type { WorkerOperationContext } from '@/core/signingEngine/workerManager/executeWorkerOperation';
import {
  buildNearNonceLane,
  nonceLeaseToRef,
  type NearFundingRequest,
  type NearTransactionReadiness,
  type NonceCoordinator,
} from '@/core/signingEngine/nonce/NonceCoordinator';
import type { NonceLeaseRef } from '@/core/signingEngine/interfaces/nonceLease';
import {
  SigningOperationIntent,
  SigningSessionIds,
  type SigningOperationId,
} from '@/core/signingEngine/session/operationState/types';
import {
  resolveActiveLinkedDeviceExecutionBundleV1,
  resolveLinkedDeviceExecutionBundleV1,
  linkedDeviceExecutionEvidence,
} from '@/core/indexedDB/seamsWalletDB/linkedDeviceExecutionEvidenceStore';
import { linkedDeviceWalletSessions } from '@/core/indexedDB/seamsWalletDB/linkedDeviceWalletSessionStore';
import { laneSealedHolderMaterialRepository } from '@/core/indexedDB/seamsWalletDB/laneHolderMaterialStore';
import type {
  ActiveLinkedDeviceExecutionBundleV1,
  ActiveLinkedDeviceExecutionChildV1,
} from '@/core/signingEngine/session/lanes/linkedDeviceExecutionBundle';
import { executeLinkedDeviceEd25519NormalSigningV1 } from '@/core/signingEngine/flows/signNear/shared/linkedDeviceEd25519NormalSigning';
import { createDeviceLinkingKeyMaterialPortV1 } from './deviceLinkingWorkerChannels';
import type { TransactionInputWasm } from '@/core/types/actions';
import type { SignTransactionResult, SeamsChainConfig } from '@/core/types/seams';
import {
  parseThresholdEd25519NearTransaction,
  thresholdEd25519NearTransactionOperationFingerprint,
  thresholdEd25519NearTransactionPlanningOperationFingerprint,
} from '@shared/threshold/ed25519OperationFingerprint';
import { routerAbNormalSigningActionFingerprint } from '@/core/rpcClients/relayer/routerAbNormalSigning';
import { base64UrlDecode, base64UrlEncode } from '@shared/utils/base64';
import { base58Encode } from '@shared/utils/base58';
import { secureRandomBase64Url } from '@shared/utils/secureRandomId';
import type { WalletId } from '@shared/utils/domainIds';
import { parseDigestB64u } from '@shared/utils/canonicalPrimitives';
import type { EvmFamilySigningDeps } from '@/core/signingEngine/interfaces/operationDeps';
import type {
  WalletSessionRef,
  ThresholdEcdsaChainTarget,
} from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import type { TempoSigningRequest } from '@/core/signingEngine/chains/tempo/tempoSigning.types';
import type { EvmSigningRequest } from '@/core/signingEngine/chains/evm/evmSigning.types';
import type { TempoSignedResult } from '@/core/signingEngine/chains/tempo/tempoAdapter';
import type { EvmSignedResult } from '@/core/signingEngine/chains/evm/evmAdapter';
import type { ConfirmationConfig, RpcCallPayload } from '@/core/types/signer-worker';
import { toAccountId } from '@/core/types/accountIds';
import type { SigningFlowEvent } from '@/core/types/sdkSentEvents';
import {
  computeSigningOperationFingerprint,
  parseSigningOperationFingerprintDigest,
} from '@/core/signingEngine/session/planning/operationFingerprint';
import { executeEvmFamilyTransactionSigning } from '@/core/signingEngine/flows/signEvmFamily/transactionExecutor';
import { executeLinkedDeviceEcdsaNormalSigningV1 } from '@/core/signingEngine/flows/signEvmFamily/shared/linkedDeviceEcdsaNormalSigning';
import { resolveNearNetwork } from '@/core/config/chains';
import type {
  DeviceLinkingHolderSigningMaterialHandleV1,
  DeviceLinkingHolderSigningMaterialPortV1,
} from '@/core/signingEngine/session/lanes/linkedDevicePorts';
import type { LinkedDeviceEnrollmentId } from '@shared/signing-lanes/ids';
import type {
  DeviceLinkingPersistedHolderSigningMaterialChildV1,
  DeviceLinkingEmailOtpFactorReleaseHolderSigningMaterialBatchInputV1,
  DeviceLinkingLiveKeyMaterialPortV1,
  LinkedDeviceEd25519OwnerRestoreV1,
  LinkedDeviceEcdsaOwnerRestoreV1,
  LinkedDeviceSigningSessionActivationV1,
} from './deviceLinkingPorts';
import {
  authenticateLinkedDeviceLocalPresenceV1,
  type LinkedDeviceEmailOtpFactorAuthorizationV1,
} from '@/core/signingEngine/session/lanes/linkedDeviceLocalPresence';
import {
  computeLinkedDeviceTargetPreparationDigestV1,
  computeLinkedDeviceWalletSessionRenewalIntentDigestV1,
  linkedDeviceWalletSessionRenewalAuthorizedOperationIdV1,
} from '@shared/device-linking/digests';
import type { UiConfirmRuntimeBridgePort } from '@/core/signingEngine/uiConfirm/uiConfirm.types';
import {
  buildSigningConfirmationAuthParams,
  confirmationConfigForSigningAuthPlan,
} from '@/core/signingEngine/flows/shared/signingConfirmation';
import { confirmSigningOperation } from '@/core/signingEngine/stepUpConfirmation/confirmOperation';
import { SigningAuthPlanKind } from '@/core/signingEngine/stepUpConfirmation/types';
import {
  parseLinkedDeviceWalletSessionDeliveryV1,
  parseLinkedDeviceEmailOtpFactorReleaseEnvelopeV1,
  type LinkedDeviceLocalPresenceAssertionV1,
  type LinkedDeviceEmailOtpFactorReleaseEnvelopeV1,
  type LinkedDeviceWalletSessionDeliveryV1,
} from '@shared/device-linking';
import {
  buildRelayerJsonPostRequestInit,
  normalizeRelayerBaseUrl,
} from '@/core/rpcClients/relayer/relayerHttp';
import type { PasskeyMpcSessionPort } from '@/core/signingEngine/uiConfirm/uiConfirm.types';
import type { WarmSessionSealTransportInput } from '@/core/types/secure-confirm-worker';
import {
  SIGNING_SESSION_SEAL_ALG,
  SIGNING_SESSION_SEAL_GROUP_ID,
} from '@shared/utils/signingSessionSeal';
import { parseSigningSessionSealKeyVersion } from '@/core/signingEngine/session/keyMaterialBrands';
import { WALLET_EMAIL_OTP_UNLOCK_OPERATION } from '@shared/utils/emailOtpDomain';

type LinkedDeviceWarmSigningSessionBaseV1 = {
  readonly kind: 'linked_device_warm_signing_session_v1';
  readonly walletId: WalletId;
  readonly bundle: ActiveLinkedDeviceExecutionBundleV1;
  readonly handles: readonly DeviceLinkingHolderSigningMaterialHandleV1[];
  readonly ed25519OwnerRestore: LinkedDeviceEd25519OwnerRestoreV1;
  readonly ecdsaOwnerRestore: LinkedDeviceEcdsaOwnerRestoreV1;
};

export type LinkedDeviceWarmSigningSessionV1 = LinkedDeviceWarmSigningSessionBaseV1 &
  (
    | {
        readonly holderMaterialOwnership: 'owned_port';
        readonly holderMaterial: ReturnType<typeof createDeviceLinkingKeyMaterialPortV1>;
      }
    | {
        readonly holderMaterialOwnership: 'shared_port';
        readonly holderMaterial: DeviceLinkingLiveKeyMaterialPortV1;
      }
  );

type LinkedDeviceWarmMaterialPortV1 = Pick<
  PasskeyMpcSessionPort,
  | 'putWarmSessionMaterial'
  | 'sealAndPersistWarmSessionMaterial'
  | 'rehydrateWarmSessionMaterial'
  | 'claimWarmSessionMaterial'
>;

type LinkedDeviceSealTransportV1 = Extract<
  WarmSessionSealTransportInput,
  { readonly curve: 'linked_device' }
>;

export type LinkedDeviceEmailOtpWarmSigningActivationV1 = Extract<
  LinkedDeviceSigningSessionActivationV1,
  { readonly kind: 'target_email_otp_activation' }
>;

type LinkedDeviceWarmSigningActivationV1 =
  | Extract<
      LinkedDeviceSigningSessionActivationV1,
      { readonly kind: 'target_passkey_creation' | 'verified_owner_unlock' }
    >
  | (Extract<
      LinkedDeviceSigningSessionActivationV1,
      { readonly kind: 'existing_target_passkey' }
    > & { readonly authenticator: AuthenticatorPort });

type LinkedDeviceWarmSigningActivationV1WithEmail =
  | LinkedDeviceWarmSigningActivationV1
  | LinkedDeviceEmailOtpWarmSigningActivationV1;

function zeroizeLiveBytes(value: Uint8Array): void {
  if (value.byteLength > 0) value.fill(0);
}

function requireLinkedDevicePasskeyCredentialIdV1(
  bundle: ActiveLinkedDeviceExecutionBundleV1,
): string {
  const registration = bundle.targetCredentialRegistration;
  if (registration.targetFactor.kind !== 'passkey_prf') {
    throw new Error('linked-device Passkey credential crossed an Email OTP target boundary');
  }
  const webauthnRegistration = registration.webauthnRegistration;
  if (!webauthnRegistration) {
    throw new Error('linked-device Passkey registration is missing WebAuthn evidence');
  }
  return webauthnRegistration.credentialIdB64u;
}

function linkedDeviceWalletAuthMethodV1(
  bundle: ActiveLinkedDeviceExecutionBundleV1,
): 'passkey' | 'email_otp' {
  switch (bundle.targetCredentialRegistration.targetFactor.kind) {
    case 'passkey_prf':
      return 'passkey';
    case 'email_otp':
      return 'email_otp';
    default:
      bundle.targetCredentialRegistration.targetFactor satisfies never;
      throw new Error('linked-device target factor is unsupported');
  }
}

function assertLinkedDeviceEmailOtpActivationV1(input: {
  readonly bundle: ActiveLinkedDeviceExecutionBundleV1;
  readonly activation: LinkedDeviceEmailOtpWarmSigningActivationV1;
}): void {
  const nowMs = Date.now();
  const registration = input.bundle.targetCredentialRegistration;
  const preparation = input.bundle.targetPreparation;
  if (
    registration.targetFactor.kind !== 'email_otp' ||
    preparation.targetFactor.kind !== 'email_otp' ||
    preparation.ownerEnrollment.kind !== 'linked_device_email_otp_owner_enrollment_v1'
  ) {
    throw new Error('linked-device Email OTP activation crossed a Passkey target boundary');
  }
  const grant = registration.emailOtpVerificationGrant;
  if (!grant) {
    throw new Error('linked-device Email OTP registration is missing its verification grant');
  }
  if (
    grant.grantId !== input.activation.verificationGrant.grantId ||
    grant.grantToken !== input.activation.verificationGrant.grantToken ||
    grant.challengeId !== input.activation.verificationGrant.challengeId ||
    grant.linkSessionId !== input.bundle.linkSessionId ||
    grant.walletId !== input.bundle.walletId ||
    grant.enrollmentId !== input.bundle.enrollmentId ||
    grant.deviceId !== input.bundle.deviceId ||
    grant.linkSessionId !== input.activation.verificationGrant.linkSessionId ||
    grant.walletId !== input.activation.verificationGrant.walletId ||
    grant.enrollmentId !== input.activation.verificationGrant.enrollmentId ||
    grant.deviceId !== input.activation.verificationGrant.deviceId ||
    grant.targetPreparationDigestB64u !==
      input.activation.verificationGrant.targetPreparationDigestB64u ||
    grant.baseWalletAuthMethodId !== preparation.ownerEnrollment.baseWalletAuthMethodId ||
    grant.baseWalletAuthMethodId !== input.activation.verificationGrant.baseWalletAuthMethodId ||
    grant.linkedOwnerAuthMethodId !== input.activation.verificationGrant.linkedOwnerAuthMethodId ||
    grant.authorityDigestB64u !== input.activation.verificationGrant.authorityDigestB64u ||
    grant.issuedAtMs !== input.activation.verificationGrant.issuedAtMs ||
    grant.expiresAtMs !== input.activation.verificationGrant.expiresAtMs ||
    grant.issuedAtMs > nowMs ||
    grant.expiresAtMs <= nowMs ||
    grant.expiresAtMs > preparation.ownerEnrollment.expiresAtMs ||
    grant.expiresAtMs > preparation.expiresAtMs
  ) {
    throw new Error('linked-device Email OTP activation authority changed');
  }
  if (
    input.activation.resealedCustodyEnvelope.walletId !== input.bundle.walletId ||
    input.activation.factorRelease.challengeId !== grant.challengeId ||
    input.activation.resealedCustodyEnvelope.factor.enrollmentId !==
      input.activation.factorRelease.enrollmentId ||
    input.activation.resealedCustodyEnvelope.factor.enrollmentSealKeyVersion !==
      input.activation.factorRelease.enrollmentSealKeyVersion
  ) {
    throw new Error('linked-device Email OTP custody envelope has an invalid factor binding');
  }
}

export type ActiveLinkedDeviceCurveSigningContextV1<TFamily extends 'ed25519' | 'ecdsa_secp256k1'> =
  {
    readonly bundle: ActiveLinkedDeviceExecutionBundleV1;
    readonly child: Extract<ActiveLinkedDeviceExecutionChildV1, { readonly keyFamily: TFamily }>;
    readonly walletSession: Extract<
      Awaited<ReturnType<typeof linkedDeviceWalletSessions.readTokenForWalletKeyV1>>,
      { readonly kind: 'found' }
    >;
    readonly holderMaterial: DeviceLinkingHolderSigningMaterialPortV1;
    readonly holderHandle: Extract<
      DeviceLinkingHolderSigningMaterialHandleV1,
      { readonly keyFamily: TFamily }
    >;
  };

const LINKED_NEAR_ACCESS_KEY_POLL_DELAYS_MS = [
  120, 180, 250, 350, 500, 700, 1_000, 1_000, 1_500, 1_500, 2_000,
] as const;

function delayLinkedNearAccessKeyPoll(delayMs: number): Promise<void> {
  return new Promise((resolve) => {
    setTimeout(resolve, delayMs);
  });
}

function assertLinkedNearFundingRequest(args: {
  readonly request: NearFundingRequest;
  readonly walletId: WalletId;
  readonly nearAccountId: string;
  readonly nearPublicKeyStr: string;
  readonly operationId: SigningOperationId;
  readonly operationFingerprint: string;
}): void {
  const operation = args.request.operation;
  if (
    String(args.request.subject.walletId) !== String(args.walletId) ||
    String(args.request.subject.nearAccountId) !== args.nearAccountId ||
    args.request.subject.nearPublicKeyStr !== args.nearPublicKeyStr ||
    String(operation.operationId) !== String(args.operationId) ||
    String(operation.operationFingerprint) !== args.operationFingerprint ||
    operation.intent !== SigningOperationIntent.TransactionSign ||
    operation.accountId !== args.nearAccountId ||
    args.request.signatureUses !== 1
  ) {
    throw new Error('linked-device NEAR funding request does not match the signing operation');
  }
}

async function reserveLinkedNearContextAfterFunding(args: {
  readonly request: NearFundingRequest;
  readonly chains: readonly SeamsChainConfig[];
  readonly nonceCoordinator: NonceCoordinator;
  readonly nearClient: NearClient;
}): Promise<Extract<NearTransactionReadiness, { readonly kind: 'context_ready' }>> {
  const lane = buildNearNonceLane({
    chains: args.chains,
    walletId: String(args.request.subject.walletId),
    nearAccountId: String(args.request.subject.nearAccountId),
    nearPublicKeyStr: args.request.subject.nearPublicKeyStr,
  });
  let latestError: unknown;
  for (const delayMs of LINKED_NEAR_ACCESS_KEY_POLL_DELAYS_MS) {
    try {
      const reserved = await args.nonceCoordinator.reserveNearContext({
        lane,
        operation: args.request.operation,
        count: args.request.signatureUses,
        nearClient: args.nearClient,
      });
      return {
        kind: 'context_ready',
        transactionContext: reserved.context,
        nonceLeases: reserved.leases.map(nonceLeaseToRef),
      };
    } catch (error: unknown) {
      latestError = error;
      await delayLinkedNearAccessKeyPoll(delayMs);
    }
  }
  try {
    const reserved = await args.nonceCoordinator.reserveNearContext({
      lane,
      operation: args.request.operation,
      count: args.request.signatureUses,
      nearClient: args.nearClient,
    });
    return {
      kind: 'context_ready',
      transactionContext: reserved.context,
      nonceLeases: reserved.leases.map(nonceLeaseToRef),
    };
  } catch (error: unknown) {
    latestError = error;
  }
  throw latestError instanceof Error
    ? latestError
    : new Error('Funded linked-device NEAR access key did not become available');
}

async function resolveLinkedNearTransactionReadiness(args: {
  readonly readiness: NearTransactionReadiness;
  readonly walletId: WalletId;
  readonly nearAccountId: string;
  readonly nearPublicKeyStr: string;
  readonly operationId: SigningOperationId;
  readonly operationFingerprint: string;
  readonly walletSessionToken: string;
  readonly relayServerUrl: string;
  readonly chains: readonly SeamsChainConfig[];
  readonly nonceCoordinator: NonceCoordinator;
  readonly nearClient: NearClient;
}): Promise<Extract<NearTransactionReadiness, { readonly kind: 'context_ready' }>> {
  switch (args.readiness.kind) {
    case 'context_ready':
      return args.readiness;
    case 'funding_required': {
      assertLinkedNearFundingRequest({
        request: args.readiness.request,
        walletId: args.walletId,
        nearAccountId: args.nearAccountId,
        nearPublicKeyStr: args.nearPublicKeyStr,
        operationId: args.operationId,
        operationFingerprint: args.operationFingerprint,
      });
      const funded = await fundImplicitNearAccountForTesting({
        relayerUrl: args.relayServerUrl,
        walletId: args.walletId,
        nearAccountId: args.nearAccountId,
        nearPublicKeyStr: args.nearPublicKeyStr,
        walletSessionToken: args.walletSessionToken,
      });
      if (!funded.ok) {
        throw new Error(
          funded.message || funded.code || 'Failed to fund linked-device NEAR account',
        );
      }
      return await reserveLinkedNearContextAfterFunding({
        request: args.readiness.request,
        chains: args.chains,
        nonceCoordinator: args.nonceCoordinator,
        nearClient: args.nearClient,
      });
    }
    default:
      args.readiness satisfies never;
      throw new Error('Unsupported linked-device NEAR transaction readiness');
  }
}

function requireWarmHandle<TFamily extends 'ed25519' | 'ecdsa_secp256k1'>(
  session: LinkedDeviceWarmSigningSessionV1,
  keyFamily: TFamily,
): Extract<DeviceLinkingHolderSigningMaterialHandleV1, { readonly keyFamily: TFamily }> {
  const matches = session.handles.filter(
    (
      handle,
    ): handle is Extract<
      DeviceLinkingHolderSigningMaterialHandleV1,
      { readonly keyFamily: TFamily }
    > => handle.keyFamily === keyFamily,
  );
  if (matches.length !== 1 || !matches[0]) {
    throw new Error(`linked-device ${keyFamily} warm holder material is unavailable`);
  }
  return matches[0];
}

function linkedDeviceSealTransportV1(input: {
  readonly bundle: ActiveLinkedDeviceExecutionBundleV1;
  readonly delivery: LinkedDeviceWalletSessionDeliveryV1;
  readonly relayServerUrl: string;
}): LinkedDeviceSealTransportV1 {
  const token = input.delivery.orderedTokens[0];
  if (!token) throw new Error('linked-device Wallet Session has no signing token');
  const credentialIdB64u = requireLinkedDevicePasskeyCredentialIdV1(input.bundle);
  return {
    curve: 'linked_device',
    authMethod: 'passkey',
    walletId: String(input.bundle.walletId),
    relayerUrl: input.relayServerUrl,
    walletSessionToken: token.walletSessionJwt,
    enrollmentId: String(input.bundle.enrollmentId),
    deviceId: String(input.bundle.deviceId),
    credentialIdB64u,
  };
}

function linkedDeviceWarmMaterialClaimTargetV1(
  bundle: ActiveLinkedDeviceExecutionBundleV1,
): Parameters<PasskeyMpcSessionPort['claimWarmSessionMaterial']>[0] {
  const child = bundle.orderedExecutions[0];
  if (!child) throw new Error('linked-device execution bundle has no signing lane');
  const thresholdSessionId = String(bundle.walletSessionId);
  if (child.keyFamily === 'ed25519') {
    return {
      thresholdSessionId,
      purpose: { curve: 'ed25519', materialActivation: child.materialActivation },
      consume: false,
    };
  }
  const target = child.job.targetCapability.orderedThresholdSessions[0];
  if (!target) throw new Error('linked-device ECDSA lane has no threshold target');
  return {
    purpose: {
      curve: 'ecdsa',
      thresholdSessionId,
      chainTarget: target.chainTarget,
    },
    consume: false,
  };
}

async function openLinkedDeviceHolderHandlesV1(input: {
  readonly bundle: ActiveLinkedDeviceExecutionBundleV1;
  readonly factorSecret: Uint8Array;
  readonly holderMaterial: ReturnType<typeof createDeviceLinkingKeyMaterialPortV1>;
}): Promise<readonly DeviceLinkingHolderSigningMaterialHandleV1[]> {
  const handles: DeviceLinkingHolderSigningMaterialHandleV1[] = [];
  for (const child of input.bundle.orderedExecutions) {
    const holderRecord = await laneSealedHolderMaterialRepository.get(child.holderRecordLookup);
    if (!holderRecord) throw new Error('linked-device sealed holder material is unavailable');
    const holderFactorSecret = input.factorSecret.slice();
    try {
      const handle = await input.holderMaterial.openPersistedHolderSigningMaterialV1({
        factorSecret: holderFactorSecret.buffer,
        job: child.job,
        protocolCommitReceipt: child.protocolCommitReceipt,
        materialActivation: child.materialActivation,
        holderRecord,
      });
      if (handle.keyFamily !== child.keyFamily) {
        throw new Error('linked-device holder material changed its active curve');
      }
      handles.push(handle);
    } finally {
      // The worker owns the transferred copy after postMessage; this also
      // covers validation failures before transfer.
      zeroizeLiveBytes(holderFactorSecret);
    }
  }
  return handles;
}

async function discardLinkedDeviceHolderHandlesV1(input: {
  readonly holderMaterial: DeviceLinkingLiveKeyMaterialPortV1;
  readonly handles: readonly DeviceLinkingHolderSigningMaterialHandleV1[];
}): Promise<void> {
  for (const handle of input.handles) {
    await input.holderMaterial.discardHolderSigningMaterialV1({ handle });
  }
}

async function openInitialLinkedDeviceEmailOtpWarmSessionV1(input: {
  readonly bundle: ActiveLinkedDeviceExecutionBundleV1;
  readonly activation: LinkedDeviceEmailOtpWarmSigningActivationV1;
  readonly relayServerUrl: string;
}): Promise<LinkedDeviceWarmSigningSessionV1> {
  const orderedChildren: DeviceLinkingPersistedHolderSigningMaterialChildV1[] = [];
  for (const child of input.bundle.orderedExecutions) {
    const holderRecord = await laneSealedHolderMaterialRepository.get(child.holderRecordLookup);
    if (!holderRecord) throw new Error('linked-device sealed holder material is unavailable');
    orderedChildren.push({
      job: child.job,
      protocolCommitReceipt: child.protocolCommitReceipt,
      materialActivation: child.materialActivation,
      holderRecord,
    });
  }
  const first = orderedChildren[0];
  if (!first) throw new Error('linked-device execution bundle has no signing lane');
  const opened =
    await input.activation.holderMaterial.openPersistedEmailOtpHolderSigningMaterialsV1({
      keyMaterial: input.activation.keyMaterial,
      walletId: input.bundle.walletId,
      linkSessionId: input.bundle.linkSessionId,
      enrollmentId: input.bundle.enrollmentId,
      deviceId: input.bundle.deviceId,
      targetPreparationDigestB64u: await computeLinkedDeviceTargetPreparationDigestV1(
        input.bundle.targetPreparation,
      ),
      resealedCustodyEnvelope: input.activation.resealedCustodyEnvelope,
      relayServerUrl: input.relayServerUrl,
      ed25519OwnerActivation: input.bundle.ed25519OwnerActivation,
      ecdsaOwnerActivation: input.bundle.ecdsaOwnerActivation,
      orderedChildren: [first, ...orderedChildren.slice(1)],
    });
  const handles = opened.handles;
  try {
    return {
      kind: 'linked_device_warm_signing_session_v1',
      walletId: input.bundle.walletId,
      bundle: input.bundle,
      holderMaterialOwnership: 'shared_port',
      holderMaterial: input.activation.holderMaterial,
      handles,
      ed25519OwnerRestore: opened.ed25519OwnerRestore,
      ecdsaOwnerRestore: opened.ecdsaOwnerRestore,
    };
  } catch (error: unknown) {
    await discardLinkedDeviceHolderHandlesV1({
      holderMaterial: input.activation.holderMaterial,
      handles,
    });
    throw error;
  }
}

async function sealLinkedDeviceWarmMaterialV1(input: {
  readonly bundle: ActiveLinkedDeviceExecutionBundleV1;
  readonly delivery: LinkedDeviceWalletSessionDeliveryV1;
  readonly factorSecret: Uint8Array;
  readonly relayServerUrl: string;
  readonly warmMaterial: LinkedDeviceWarmMaterialPortV1;
}): Promise<void> {
  const thresholdSessionId = String(input.bundle.walletSessionId);
  await input.warmMaterial.putWarmSessionMaterial({
    thresholdSessionId,
    prfFirstB64u: base64UrlEncode(input.factorSecret),
    expiresAtMs: input.bundle.expiresAtMs,
    remainingUses: input.bundle.remainingUses,
  });
  const sealed = await input.warmMaterial.sealAndPersistWarmSessionMaterial({
    thresholdSessionId,
    transport: linkedDeviceSealTransportV1(input),
  });
  if (!sealed.ok) {
    throw new Error(`linked-device sealed refresh failed (${sealed.code}): ${sealed.message}`);
  }
  await linkedDeviceWalletSessions.putSealedRefreshV1({
    kind: 'linked_device_sealed_refresh_material_v1',
    algorithm: SIGNING_SESSION_SEAL_ALG,
    groupId: SIGNING_SESSION_SEAL_GROUP_ID,
    walletId: String(input.bundle.walletId),
    enrollmentId: input.bundle.enrollmentId,
    deviceId: String(input.bundle.deviceId),
    walletSessionId: String(input.bundle.walletSessionId),
    credentialIdB64u: requireLinkedDevicePasskeyCredentialIdV1(input.bundle),
    sealedSecretB64u: sealed.sealedSecretB64u,
    keyVersion: sealed.keyVersion ?? null,
    issuedAtMs: input.bundle.issuedAtMs,
    expiresAtMs: sealed.expiresAtMs,
    remainingUses: sealed.remainingUses,
  });
}

async function readLinkedDeviceRenewalResponseBody(response: Response): Promise<unknown> {
  try {
    return await response.json();
  } catch {
    return null;
  }
}

function linkedDeviceRenewalErrorMessage(body: unknown, status: number): string {
  if (body && typeof body === 'object' && !Array.isArray(body)) {
    const message = Reflect.get(body, 'message');
    if (typeof message === 'string' && message.trim()) return message;
  }
  return `linked-device signing session renewal failed with HTTP ${status}`;
}

async function renewLinkedDeviceWalletSessionV1(input: {
  readonly relayServerUrl: string;
  readonly bundle: ActiveLinkedDeviceExecutionBundleV1;
  readonly keyFamily: ActiveLinkedDeviceExecutionChildV1['keyFamily'];
  readonly localPresenceAssertion:
    | LinkedDeviceLocalPresenceAssertionV1
    | LinkedDeviceEmailOtpFactorAuthorizationV1;
}): Promise<LinkedDeviceWalletSessionDeliveryV1> {
  const path = `/wallet/device-linking/v1/sessions/${encodeURIComponent(
    String(input.bundle.linkSessionId),
  )}/wallet-session-renew`;
  const response = await fetch(
    `${normalizeRelayerBaseUrl(input.relayServerUrl)}${path}`,
    buildRelayerJsonPostRequestInit({
      body: {
        keyFamily: input.keyFamily,
        localPresenceAssertion: input.localPresenceAssertion,
      },
    }),
  );
  const body = await readLinkedDeviceRenewalResponseBody(response);
  if (!response.ok) {
    throw new Error(linkedDeviceRenewalErrorMessage(body, response.status));
  }
  return parseLinkedDeviceWalletSessionDeliveryV1(body);
}

function linkedDeviceEmailOtpFactorReleaseErrorMessage(body: unknown, status: number): string {
  if (body && typeof body === 'object' && !Array.isArray(body)) {
    const message = Reflect.get(body, 'message');
    if (typeof message === 'string' && message.trim()) return message;
  }
  return `linked-device Email OTP factor release failed with HTTP ${status}`;
}

function parseLinkedDeviceEmailOtpFactorReleaseResponseV1(
  value: unknown,
): LinkedDeviceEmailOtpFactorReleaseEnvelopeV1 {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) {
    throw new Error('linked-device Email OTP factor release response is invalid');
  }
  const ok = Reflect.get(value, 'ok');
  if (ok !== undefined && ok !== true) {
    throw new Error('linked-device Email OTP factor release response was refused');
  }
  if (ok === undefined) return parseLinkedDeviceEmailOtpFactorReleaseEnvelopeV1(value);
  return parseLinkedDeviceEmailOtpFactorReleaseEnvelopeV1({
    kind: Reflect.get(value, 'kind'),
    challengeId: Reflect.get(value, 'challengeId'),
    enrollmentId: Reflect.get(value, 'enrollmentId'),
    enrollmentSealKeyVersion: Reflect.get(value, 'enrollmentSealKeyVersion'),
    serverEphemeralPublicKey65B64u: Reflect.get(value, 'serverEphemeralPublicKey65B64u'),
    nonce12B64u: Reflect.get(value, 'nonce12B64u'),
    ciphertextB64u: Reflect.get(value, 'ciphertextB64u'),
  });
}

async function requestLinkedDeviceEmailOtpFactorReleaseV1(input: {
  readonly relayServerUrl: string;
  readonly walletId: WalletId;
  readonly challengeId: string;
  readonly otpCode: string;
  readonly workerPublicKey65B64u: string;
}): Promise<LinkedDeviceEmailOtpFactorReleaseEnvelopeV1> {
  const response = await fetch(
    `${normalizeRelayerBaseUrl(input.relayServerUrl)}/wallet/email-otp/factor-release`,
    {
      ...buildRelayerJsonPostRequestInit({
        body: {
          walletId: String(input.walletId),
          kind: 'email_otp',
          challengeId: input.challengeId,
          otpCode: input.otpCode,
          operation: WALLET_EMAIL_OTP_UNLOCK_OPERATION,
          workerEphemeralPublicKey65B64u: input.workerPublicKey65B64u,
        },
      }),
      credentials: 'include',
    },
  );
  const body = await readLinkedDeviceRenewalResponseBody(response);
  if (!response.ok) {
    throw new Error(linkedDeviceEmailOtpFactorReleaseErrorMessage(body, response.status));
  }
  return parseLinkedDeviceEmailOtpFactorReleaseResponseV1(body);
}

function linkedSessionExpiredErrorV1(): Error {
  return new Error('linked-session-expired');
}

async function requireUnchangedActiveLinkedDeviceBundleV1(
  expected: ActiveLinkedDeviceExecutionBundleV1,
): Promise<ActiveLinkedDeviceExecutionBundleV1> {
  const resolved = await resolveActiveLinkedDeviceExecutionBundleV1({
    enrollmentId: expected.enrollmentId,
    nowMs: Date.now(),
    evidenceRepository: linkedDeviceExecutionEvidence,
    walletSessionRepository: linkedDeviceWalletSessions,
  });
  if (resolved.kind === 'expired' || resolved.kind === 'missing') {
    throw linkedSessionExpiredErrorV1();
  }
  if (resolved.kind !== 'found') {
    throw new Error(`linked-device execution bundle is ${resolved.kind}`);
  }
  const current = resolved.bundle;
  if (
    current.walletId !== expected.walletId ||
    current.linkSessionId !== expected.linkSessionId ||
    current.enrollmentId !== expected.enrollmentId ||
    current.deviceId !== expected.deviceId ||
    current.authorizationId !== expected.authorizationId ||
    current.walletSessionId !== expected.walletSessionId ||
    current.quotaId !== expected.quotaId ||
    current.keyManifestDigestB64u !== expected.keyManifestDigestB64u ||
    current.aggregateReceiptDigestB64u !== expected.aggregateReceiptDigestB64u ||
    current.revocationEpoch !== expected.revocationEpoch ||
    current.expiresAtMs !== expected.expiresAtMs
  ) {
    throw new Error('linked-device active Wallet Session binding changed during Email OTP unlock');
  }
  return current;
}

export async function openLinkedDeviceEmailOtpWarmSigningSessionV1(input: {
  readonly walletId: WalletId;
  readonly relayServerUrl: string;
  readonly challengeId: string;
  readonly otpCode: string;
}): Promise<LinkedDeviceWarmSigningSessionV1 | null> {
  const nowMs = Date.now();
  const stored = await linkedDeviceWalletSessions.readUniqueForWalletV1({
    walletId: String(input.walletId),
  });
  if (stored.kind === 'missing') return null;
  if (stored.kind === 'expired') throw linkedSessionExpiredErrorV1();
  if (stored.kind !== 'found') {
    throw new Error(`linked-device Wallet Session is ${stored.kind}`);
  }
  if (stored.delivery.expiresAtMs <= nowMs) throw linkedSessionExpiredErrorV1();
  const resolved = await resolveActiveLinkedDeviceExecutionBundleV1({
    enrollmentId: stored.delivery.enrollmentId,
    nowMs,
    evidenceRepository: linkedDeviceExecutionEvidence,
    walletSessionRepository: linkedDeviceWalletSessions,
  });
  if (resolved.kind === 'expired') throw linkedSessionExpiredErrorV1();
  if (resolved.kind !== 'found') {
    throw new Error(`linked-device execution bundle is ${resolved.kind}`);
  }
  const bundle = resolved.bundle;
  if (
    bundle.walletId !== input.walletId ||
    bundle.enrollmentId !== stored.delivery.enrollmentId ||
    bundle.deviceId !== stored.delivery.deviceId ||
    bundle.walletSessionId !== stored.delivery.walletSessionId
  ) {
    throw new Error('linked-device Wallet Session binding changed');
  }
  if (
    bundle.targetPreparation.targetFactor.kind !== 'email_otp' ||
    bundle.targetPreparation.ownerEnrollment.kind !== 'linked_device_email_otp_owner_enrollment_v1'
  ) {
    return null;
  }
  if (!input.challengeId.trim() || !input.otpCode.trim()) {
    throw new Error('linked-device Email OTP challenge and code are required');
  }

  const holderMaterial = createDeviceLinkingKeyMaterialPortV1();
  try {
    const keyMaterial = await holderMaterial.createBootstrapKeyMaterialV1();
    const factorRelease = await requestLinkedDeviceEmailOtpFactorReleaseV1({
      relayServerUrl: input.relayServerUrl,
      walletId: bundle.walletId,
      challengeId: input.challengeId,
      otpCode: input.otpCode,
      workerPublicKey65B64u: keyMaterial.emailOtpReleasePublicKey65B64u,
    });
    const activeBundle = await requireUnchangedActiveLinkedDeviceBundleV1(bundle);
    const orderedChildren: DeviceLinkingEmailOtpFactorReleaseHolderSigningMaterialBatchInputV1['orderedChildren'][number][] =
      [];
    for (const child of activeBundle.orderedExecutions) {
      const holderRecord = await laneSealedHolderMaterialRepository.get(child.holderRecordLookup);
      if (!holderRecord) throw new Error('linked-device sealed holder material is unavailable');
      orderedChildren.push({
        job: child.job,
        protocolCommitReceipt: child.protocolCommitReceipt,
        materialActivation: child.materialActivation,
        holderRecord,
      });
    }
    const first = orderedChildren[0];
    if (!first) throw new Error('linked-device execution bundle has no signing lane');
    const handles =
      await holderMaterial.openPersistedEmailOtpHolderSigningMaterialsFromFactorReleaseV1({
        keyMaterial: keyMaterial.handle,
        walletId: activeBundle.walletId,
        enrollmentId: activeBundle.enrollmentId,
        expectedChallengeId: input.challengeId,
        factorRelease,
        orderedChildren: [first, ...orderedChildren.slice(1)],
      });
    await requireUnchangedActiveLinkedDeviceBundleV1(activeBundle);
    return {
      kind: 'linked_device_warm_signing_session_v1',
      walletId: activeBundle.walletId,
      bundle: activeBundle,
      holderMaterialOwnership: 'owned_port',
      holderMaterial,
      handles,
      ed25519OwnerRestore: { kind: 'absent' },
      ecdsaOwnerRestore: { kind: 'absent' },
    };
  } catch (error) {
    holderMaterial.close();
    throw error;
  }
}

export async function openLinkedDeviceWarmSigningSessionV1(input: {
  readonly walletId: WalletId;
  readonly enrollmentId: LinkedDeviceEnrollmentId;
  readonly relayServerUrl: string;
  readonly warmMaterial: LinkedDeviceWarmMaterialPortV1;
  readonly activation: LinkedDeviceWarmSigningActivationV1WithEmail;
}): Promise<LinkedDeviceWarmSigningSessionV1> {
  const nowMs = Date.now();
  const resolved = await resolveLinkedDeviceExecutionBundleV1({
    enrollmentId: input.enrollmentId,
    evidenceRepository: linkedDeviceExecutionEvidence,
    walletSessionRepository: linkedDeviceWalletSessions,
  });
  if (resolved.kind !== 'found') {
    throw new Error(`linked-device execution bundle is ${resolved.kind} during unlock`);
  }
  if (resolved.bundle.walletId !== input.walletId) {
    throw new Error('linked-device execution bundle changed its wallet identity');
  }
  const child = resolved.bundle.orderedExecutions[0];
  if (!child) throw new Error('linked-device execution bundle has no signing lane');
  let delivery: LinkedDeviceWalletSessionDeliveryV1;
  let factorSecret: Uint8Array | null = null;
  let holderMaterial: ReturnType<typeof createDeviceLinkingKeyMaterialPortV1> | null = null;
  try {
    switch (input.activation.kind) {
      case 'target_email_otp_activation': {
        assertLinkedDeviceEmailOtpActivationV1({
          bundle: resolved.bundle,
          activation: input.activation,
        });
        const stored = await linkedDeviceWalletSessions.readActiveForEnrollmentV1({
          enrollmentId: resolved.bundle.enrollmentId,
          nowMs,
        });
        if (
          stored.kind !== 'found' ||
          stored.delivery.walletId !== resolved.bundle.walletId ||
          stored.delivery.enrollmentId !== resolved.bundle.enrollmentId ||
          stored.delivery.deviceId !== resolved.bundle.deviceId ||
          stored.delivery.walletSessionId !== resolved.bundle.walletSessionId
        ) {
          throw new Error('linked-device initial Email OTP Wallet Session is unavailable');
        }
        return await openInitialLinkedDeviceEmailOtpWarmSessionV1({
          bundle: resolved.bundle,
          activation: input.activation,
          relayServerUrl: input.relayServerUrl,
        });
      }
      case 'target_passkey_creation':
      case 'verified_owner_unlock': {
        // Creation and owner unlock already verified this passkey. Reuse that
        // ceremony's PRF instead of asking the authenticator a second time.
        const stored = await linkedDeviceWalletSessions.readActiveForEnrollmentV1({
          enrollmentId: resolved.bundle.enrollmentId,
          nowMs,
        });
        if (stored.kind !== 'found') {
          throw new Error(`linked-device initial Wallet Session is ${stored.kind}`);
        }
        if (
          stored.delivery.walletId !== resolved.bundle.walletId ||
          stored.delivery.enrollmentId !== resolved.bundle.enrollmentId ||
          stored.delivery.deviceId !== resolved.bundle.deviceId ||
          stored.delivery.walletSessionId !== resolved.bundle.walletSessionId
        ) {
          throw new Error('linked-device initial Wallet Session binding changed');
        }
        delivery = stored.delivery;
        factorSecret = input.activation.factorSecret.slice();
        if (factorSecret.byteLength !== 32) {
          throw new Error('linked-device target passkey creation PRF output must be 32 bytes');
        }
        break;
      }
      case 'existing_target_passkey': {
        const authorizedOperationId = linkedDeviceWalletSessionRenewalAuthorizedOperationIdV1();
        const intentDigestB64u = await computeLinkedDeviceWalletSessionRenewalIntentDigestV1({
          authorizationId: resolved.bundle.authorizationId,
          walletSessionId: resolved.bundle.walletSessionId,
          quotaId: resolved.bundle.quotaId,
          deviceId: resolved.bundle.deviceId,
          enrollmentId: resolved.bundle.enrollmentId,
        });
        const authentication = await authenticateLinkedDeviceLocalPresenceV1({
          authenticator: input.activation.authenticator,
          bundle: resolved.bundle,
          child,
          authorizedOperationId,
          intentDigestB64u,
          issuedAtMs: nowMs,
          expiresAtMs: nowMs + 60_000,
        });
        if (authentication.factor !== 'passkey_prf') {
          throw new Error('linked-device Passkey activation crossed an Email OTP target boundary');
        }
        factorSecret = authentication.factorSecret;
        delivery = await renewLinkedDeviceWalletSessionV1({
          relayServerUrl: input.relayServerUrl,
          bundle: resolved.bundle,
          keyFamily: child.keyFamily,
          localPresenceAssertion: authentication.localPresenceAssertion,
        });
        await linkedDeviceWalletSessions.replaceExactRenewedDeliveryV1(delivery);
        break;
      }
      default:
        input.activation satisfies never;
        throw new Error('linked-device signing activation is unsupported');
    }
    if (!factorSecret) throw new Error('linked-device factor secret is unavailable');
    const renewed = await resolveActiveLinkedDeviceExecutionBundleV1({
      enrollmentId: resolved.bundle.enrollmentId,
      nowMs: Date.now(),
      evidenceRepository: linkedDeviceExecutionEvidence,
      walletSessionRepository: linkedDeviceWalletSessions,
    });
    if (renewed.kind !== 'found' || renewed.bundle.enrollmentId !== resolved.bundle.enrollmentId) {
      throw new Error('linked-device execution bundle is unavailable after unlock');
    }
    holderMaterial = createDeviceLinkingKeyMaterialPortV1();
    await sealLinkedDeviceWarmMaterialV1({
      bundle: renewed.bundle,
      delivery,
      factorSecret,
      relayServerUrl: input.relayServerUrl,
      warmMaterial: input.warmMaterial,
    });
    const handles = await openLinkedDeviceHolderHandlesV1({
      bundle: renewed.bundle,
      factorSecret,
      holderMaterial,
    });
    return {
      kind: 'linked_device_warm_signing_session_v1',
      walletId: renewed.bundle.walletId,
      bundle: renewed.bundle,
      holderMaterialOwnership: 'owned_port',
      holderMaterial,
      handles,
      ed25519OwnerRestore: { kind: 'absent' },
      ecdsaOwnerRestore: { kind: 'absent' },
    };
  } catch (error) {
    holderMaterial?.close();
    throw error;
  } finally {
    if (factorSecret) zeroizeLiveBytes(factorSecret);
  }
}

export async function restoreLinkedDeviceWarmSigningSessionV1(input: {
  readonly walletId: WalletId;
  readonly relayServerUrl: string;
  readonly warmMaterial: LinkedDeviceWarmMaterialPortV1;
}): Promise<LinkedDeviceWarmSigningSessionV1 | null> {
  const nowMs = Date.now();
  const stored = await linkedDeviceWalletSessions.readUniqueActiveSealedRefreshForWalletV1({
    walletId: String(input.walletId),
    nowMs,
  });
  if (stored.kind !== 'found') return null;
  const resolved = await resolveActiveLinkedDeviceExecutionBundleV1({
    enrollmentId: stored.sealedRefresh.enrollmentId,
    nowMs,
    evidenceRepository: linkedDeviceExecutionEvidence,
    walletSessionRepository: linkedDeviceWalletSessions,
  });
  if (resolved.kind !== 'found') return null;
  if (resolved.bundle.walletId !== input.walletId) {
    throw new Error('linked-device sealed refresh changed its wallet identity');
  }
  const credentialIdB64u = requireLinkedDevicePasskeyCredentialIdV1(resolved.bundle);
  if (
    stored.sealedRefresh.enrollmentId !== resolved.bundle.enrollmentId ||
    stored.sealedRefresh.walletSessionId !== resolved.bundle.walletSessionId ||
    stored.sealedRefresh.credentialIdB64u !== credentialIdB64u
  ) {
    throw new Error('linked-device sealed refresh binding changed');
  }
  const transport = linkedDeviceSealTransportV1({
    bundle: resolved.bundle,
    delivery: stored.delivery,
    relayServerUrl: input.relayServerUrl,
  });
  const rehydrated = await input.warmMaterial.rehydrateWarmSessionMaterial({
    thresholdSessionId: String(resolved.bundle.walletSessionId),
    sealedSecretB64u: stored.sealedRefresh.sealedSecretB64u,
    ...(stored.sealedRefresh.keyVersion
      ? {
          signingSessionSealKeyVersion: parseSigningSessionSealKeyVersion(
            stored.sealedRefresh.keyVersion,
          ),
        }
      : {}),
    expiresAtMs: stored.sealedRefresh.expiresAtMs,
    remainingUses: stored.sealedRefresh.remainingUses,
    transport,
  });
  if (!rehydrated.ok) return null;
  const claimed = await input.warmMaterial.claimWarmSessionMaterial(
    linkedDeviceWarmMaterialClaimTargetV1(resolved.bundle),
  );
  if (!claimed.ok) return null;
  const factorSecret = base64UrlDecode(claimed.prfFirstB64u);
  if (factorSecret.length !== 32) {
    zeroizeLiveBytes(factorSecret);
    throw new Error('linked-device rehydrated factor secret must be 32 bytes');
  }
  const holderMaterial = createDeviceLinkingKeyMaterialPortV1();
  try {
    const handles = await openLinkedDeviceHolderHandlesV1({
      bundle: resolved.bundle,
      factorSecret,
      holderMaterial,
    });
    return {
      kind: 'linked_device_warm_signing_session_v1',
      walletId: resolved.bundle.walletId,
      bundle: resolved.bundle,
      holderMaterialOwnership: 'owned_port',
      holderMaterial,
      handles,
      ed25519OwnerRestore: { kind: 'absent' },
      ecdsaOwnerRestore: { kind: 'absent' },
    };
  } catch (error) {
    holderMaterial.close();
    throw error;
  } finally {
    zeroizeLiveBytes(factorSecret);
  }
}

export function closeLinkedDeviceWarmSigningSessionV1(
  session: LinkedDeviceWarmSigningSessionV1,
): void {
  switch (session.holderMaterialOwnership) {
    case 'owned_port':
      session.holderMaterial.close();
      return;
    case 'shared_port':
      void discardLinkedDeviceHolderHandlesV1({
        holderMaterial: session.holderMaterial,
        handles: session.handles,
      });
      return;
    default:
      session satisfies never;
  }
}

function requireEvmAddress(value: string): `0x${string}` {
  if (!/^0x[0-9a-fA-F]{40}$/.test(value)) {
    throw new Error('linked-device ECDSA address is invalid');
  }
  return `0x${value.slice(2)}`;
}

export async function resolveActiveLinkedDeviceCurveSigningContextV1<
  TFamily extends 'ed25519' | 'ecdsa_secp256k1',
>(input: {
  readonly walletId: WalletId | string;
  readonly keyFamily: TFamily;
  readonly warmSession: LinkedDeviceWarmSigningSessionV1;
}): Promise<ActiveLinkedDeviceCurveSigningContextV1<TFamily> | null> {
  const resolved = await resolveActiveLinkedDeviceExecutionBundleV1({
    enrollmentId: input.warmSession.bundle.enrollmentId,
    nowMs: Date.now(),
    evidenceRepository: linkedDeviceExecutionEvidence,
    walletSessionRepository: linkedDeviceWalletSessions,
  });
  if (resolved.kind !== 'found') return null;
  if (
    resolved.bundle.enrollmentId !== input.warmSession.bundle.enrollmentId ||
    resolved.bundle.walletSessionId !== input.warmSession.bundle.walletSessionId ||
    resolved.bundle.walletId !== input.warmSession.walletId ||
    String(resolved.bundle.walletId) !== String(input.walletId)
  ) {
    throw new Error('linked-device warm signing session is stale');
  }
  const matches = resolved.bundle.orderedExecutions.filter(
    (candidate): candidate is Extract<ActiveLinkedDeviceExecutionChildV1, { keyFamily: TFamily }> =>
      candidate.keyFamily === input.keyFamily,
  );
  if (matches.length !== 1 || !matches[0]) {
    throw new Error(`linked-device ${input.keyFamily} execution is missing or ambiguous`);
  }
  const child = matches[0];
  const walletSession = await linkedDeviceWalletSessions.readTokenForWalletKeyV1({
    enrollmentId: resolved.bundle.enrollmentId,
    walletKeyId: child.walletKeyId,
    keyFamily: input.keyFamily,
    nowMs: Date.now(),
  });
  if (walletSession.kind !== 'found') {
    throw new Error(`linked-device ${input.keyFamily} Wallet Session token is unavailable`);
  }
  return {
    bundle: resolved.bundle,
    child,
    walletSession,
    holderMaterial: input.warmSession.holderMaterial,
    holderHandle: requireWarmHandle(input.warmSession, input.keyFamily),
  };
}

export async function signLinkedDeviceNearTransactionV1(input: {
  readonly walletId: WalletId;
  readonly nearAccountId: string;
  readonly transaction: TransactionInputWasm;
  readonly authenticator: AuthenticatorPort;
  readonly warmSession: LinkedDeviceWarmSigningSessionV1;
  readonly relayServerUrl: string;
  readonly chains: readonly SeamsChainConfig[];
  readonly nonceCoordinator: NonceCoordinator;
  readonly nearClient: NearClient;
  readonly touchConfirm: UiConfirmRuntimeBridgePort;
  readonly rpcCall: RpcCallPayload;
  readonly confirmationConfigOverride?: Partial<ConfirmationConfig>;
  readonly title?: string;
  readonly body?: string;
  readonly workerCtx: WorkerOperationContext;
}): Promise<SignTransactionResult | null> {
  const linked = await resolveActiveLinkedDeviceCurveSigningContextV1({
    walletId: input.walletId,
    keyFamily: 'ed25519',
    warmSession: input.warmSession,
  });
  if (!linked) return null;
  {
    const publicKey = `ed25519:${base58Encode(
      base64UrlDecode(linked.child.walletKey.registeredPublicKeyB64u),
    )}`;
    const { txSigningRequest, confirmationTransaction } = buildNearTransactionSigningPayload({
      nearAccountId: input.nearAccountId,
      transaction: input.transaction,
    });
    const parsedTransaction = parseThresholdEd25519NearTransaction(
      txSigningRequest,
      'linkedDevice.txSigningRequest',
    );
    const nearNetworkId = resolveNearNetwork(input.chains);
    const relayerKeyId = String(linked.child.job.targetSigningWorker.recipientKeyId);
    const operationId: SigningOperationId = SigningSessionIds.signingOperation(
      `linked-near:${secureRandomBase64Url(24, 'linked NEAR operation')}`,
    );
    const planningOperationFingerprint = SigningSessionIds.signingOperationFingerprint(
      await thresholdEd25519NearTransactionPlanningOperationFingerprint({
        nearAccountId: input.nearAccountId,
        nearNetworkId,
        relayerKeyId,
        signerPublicKey: publicKey,
        transactions: [parsedTransaction],
      }),
    );
    const operation = {
      operationId,
      operationFingerprint: planningOperationFingerprint,
      intent: SigningOperationIntent.TransactionSign,
      accountId: input.nearAccountId,
    };
    const confirmationAuthPlan = {
      kind: SigningAuthPlanKind.WarmSession,
      method: linkedDeviceWalletAuthMethodV1(linked.bundle),
      accountId: String(input.walletId),
      intent: 'transaction_sign' as const,
      curve: 'ed25519' as const,
      thresholdSessionId: String(linked.bundle.walletSessionId),
      retention: null,
      expiresAtMs: linked.bundle.expiresAtMs,
      remainingUses: 1,
    };
    const confirmation = await confirmSigningOperation({
      runtime: input.touchConfirm,
      request: {
        ctx: { touchConfirm: input.touchConfirm },
        sessionId: String(operationId),
        chain: 'near',
        kind: 'transaction',
        ...buildSigningConfirmationAuthParams({ signingAuthPlan: confirmationAuthPlan }),
        walletId: String(input.walletId),
        txSigningRequests: [confirmationTransaction],
        rpcCall: input.rpcCall,
        nearPublicKeyStr: publicKey,
        nearFundingRequest: {
          subject: {
            walletId: input.walletId,
            nearAccountId: toAccountId(input.nearAccountId),
            nearPublicKeyStr: publicKey,
          },
          operation,
          signatureUses: 1,
        },
        confirmationConfigOverride: confirmationConfigForSigningAuthPlan({
          signingAuthPlan: confirmationAuthPlan,
          override: input.confirmationConfigOverride,
        }),
        ...(input.title ? { title: input.title } : {}),
        ...(input.body ? { body: input.body } : {}),
      },
    });
    const confirmedReadiness = await resolveLinkedNearTransactionReadiness({
      readiness: confirmation.readiness,
      walletId: input.walletId,
      nearAccountId: input.nearAccountId,
      nearPublicKeyStr: publicKey,
      operationId,
      operationFingerprint: planningOperationFingerprint,
      walletSessionToken: linked.walletSession.token.walletSessionJwt,
      relayServerUrl: input.relayServerUrl,
      chains: input.chains,
      nonceCoordinator: input.nonceCoordinator,
      nearClient: input.nearClient,
    });
    const nonceLease = confirmedReadiness.nonceLeases[0];
    if (!nonceLease) throw new Error('linked-device NEAR nonce reservation is missing');
    try {
      const unsigned = await buildThresholdEd25519NearTxUnsignedBorshWasm({
        txSigningRequest,
        transactionContext: confirmedReadiness.transactionContext,
        workerCtx: input.workerCtx,
      });
      const operationFingerprint = SigningSessionIds.signingOperationFingerprint(
        await thresholdEd25519NearTransactionOperationFingerprint({
          nearAccountId: input.nearAccountId,
          nearNetworkId,
          relayerKeyId,
          signerPublicKey: publicKey,
          transactions: [parsedTransaction],
          unsignedTransactionBorshB64u: unsigned.unsignedTransactionBorshB64u,
          signingDigestB64u: unsigned.signingDigestB64u,
        }),
      );
      const result = await executeLinkedDeviceEd25519NormalSigningV1({
        relayServerUrl: input.relayServerUrl,
        authenticator: input.authenticator,
        holderMaterial: linked.holderMaterial,
        holderHandle: linked.holderHandle,
        bundle: linked.bundle,
        child: linked.child,
        walletSession: linked.walletSession,
        issuedAtMs: Date.now(),
        request: {
          kind: 'near_transaction',
          requestId: String(operationId),
          operationId,
          operationFingerprint,
          expiresAtMs: Math.min(linked.bundle.expiresAtMs, Date.now() + 60_000),
          displayDigestB64u: parseSigningOperationFingerprintDigest(planningOperationFingerprint),
          nearAccountId: input.nearAccountId,
          nearNetworkId,
          transactions: [
            {
              receiverId: parsedTransaction.receiverId,
              actionFingerprint: await routerAbNormalSigningActionFingerprint(
                parsedTransaction.actions,
              ),
            },
          ],
          unsignedTransactionBorshB64u: unsigned.unsignedTransactionBorshB64u,
          expectedSigningDigestB64u: parseDigestB64u(unsigned.signingDigestB64u),
        },
      });
      const finalized = await finalizeThresholdEd25519NearTxFromSignatureWasm({
        unsignedTransactionBorshB64u: unsigned.unsignedTransactionBorshB64u,
        signingDigestB64u: unsigned.signingDigestB64u,
        signatureB64u: result.signatureB64u,
        expectedNearAccountId: input.nearAccountId,
        expectedSignerPublicKey: publicKey,
        workerCtx: input.workerCtx,
      });
      const decoded = await decodeThresholdEd25519SignedNearTxBorshWasm({
        signedTransactionBorshB64u: finalized.signedTransactionBorshB64u,
        workerCtx: input.workerCtx,
      });
      await markLinkedNearNonceLeaseSigned(input.nonceCoordinator, nonceLease);
      return {
        signedTransaction: new SignedTransaction({
          transaction: decoded.signedTransaction.transaction,
          signature: decoded.signedTransaction.signature,
          borsh_bytes: Array.from(decoded.signedTransaction.borshBytes),
          nonceLease,
        }),
        nearAccountId: input.nearAccountId,
        nonceLease,
        logs: ['NEAR transaction signed by the active linked device'],
      };
    } catch (error) {
      await releaseLinkedNearNonceLease(input.nonceCoordinator, nonceLease);
      throw error;
    }
  }
}

async function markLinkedNearNonceLeaseSigned(
  nonceCoordinator: NonceCoordinator,
  nonceLease: NonceLeaseRef,
): Promise<void> {
  await nonceCoordinator.markSigned({
    leaseId: nonceLease.leaseId,
    operationId: nonceLease.operationId,
    operationFingerprint: nonceLease.operationFingerprint,
  });
}

async function releaseLinkedNearNonceLease(
  nonceCoordinator: NonceCoordinator,
  nonceLease: NonceLeaseRef,
): Promise<void> {
  await nonceCoordinator.release({
    leaseId: nonceLease.leaseId,
    operationId: nonceLease.operationId,
    operationFingerprint: nonceLease.operationFingerprint,
    reason: 'signing_failed',
  });
}

export async function signLinkedDeviceEvmFamilyV1(input: {
  readonly deps: EvmFamilySigningDeps;
  readonly authenticator: AuthenticatorPort;
  readonly warmSession: LinkedDeviceWarmSigningSessionV1;
  readonly walletSession: WalletSessionRef;
  readonly request: TempoSigningRequest | EvmSigningRequest;
  readonly chainTarget: ThresholdEcdsaChainTarget;
  readonly confirmationConfigOverride?: Partial<ConfirmationConfig>;
  readonly shouldAbort?: () => boolean;
  readonly onEvent?: (event: SigningFlowEvent) => void;
}): Promise<TempoSignedResult | EvmSignedResult | null> {
  if (input.request.senderSignatureAlgorithm !== 'secp256k1') return null;
  const linked = await resolveActiveLinkedDeviceCurveSigningContextV1({
    walletId: input.walletSession.walletId,
    keyFamily: 'ecdsa_secp256k1',
    warmSession: input.warmSession,
  });
  if (!linked) return null;
  {
    const operationId = SigningSessionIds.signingOperation(
      `linked-evm:${secureRandomBase64Url(24, 'linked EVM-family operation')}`,
    );
    const operationFingerprint = SigningSessionIds.signingOperationFingerprint(
      await computeSigningOperationFingerprint({
        kind: `evm-family:${input.chainTarget.kind}`,
        payload: {
          walletId: input.walletSession.walletId,
          chainTarget: input.chainTarget,
          request: input.request,
        },
      }),
    );
    const signingOperation = {
      operationId,
      operationFingerprint,
      intent: SigningOperationIntent.TransactionSign,
    };
    const workerCtx = input.deps.getSignerWorkerContext();
    const flowArgs = {
      ctx: input.deps.touchConfirm.getContext(),
      touchConfirm: input.deps.touchConfirm,
      workerCtx,
      walletId: String(input.walletSession.walletId),
      request: input.request,
      engines: {},
      signingOperation,
      ...(input.confirmationConfigOverride
        ? { confirmationConfigOverride: input.confirmationConfigOverride }
        : {}),
      ...(input.shouldAbort ? { shouldAbort: input.shouldAbort } : {}),
      ...(input.onEvent ? { onEvent: input.onEvent } : {}),
      authorization: {
        kind: 'linked_device' as const,
        confirmationAuthPlan: {
          kind: 'warmSession' as const,
          method: linkedDeviceWalletAuthMethodV1(linked.bundle),
          accountId: String(input.walletSession.walletId),
          intent: 'transaction_sign' as const,
          curve: 'ecdsa' as const,
          thresholdSessionId: String(linked.bundle.walletSessionId),
          retention: null,
          expiresAtMs: linked.bundle.expiresAtMs,
          remainingUses: 1,
        },
        sign: async (request: {
          readonly requestId: string;
          readonly operationId: string;
          readonly operationDigests: Parameters<
            typeof executeLinkedDeviceEcdsaNormalSigningV1
          >[0]['request']['operationDigests'];
          readonly signingDigest32: Uint8Array;
        }): Promise<Uint8Array> => {
          const result = await executeLinkedDeviceEcdsaNormalSigningV1({
            relayServerUrl: String(input.deps.seamsWebConfigs.network.relayer?.url || ''),
            authenticator: input.authenticator,
            holderHandle: linked.holderHandle,
            workerCtx,
            bundle: linked.bundle,
            child: linked.child,
            walletSession: linked.walletSession,
            issuedAtMs: Date.now(),
            request: {
              ...request,
              expiresAtMs: Math.min(linked.bundle.expiresAtMs, Date.now() + 60_000),
            },
          });
          return result.signature65;
        },
      },
    };
    return await executeEvmFamilyTransactionSigning({
      deps: input.deps,
      walletId: String(input.walletSession.walletId),
      request: input.request,
      chainTarget: input.chainTarget,
      flowArgs,
      nonceOperation: {
        ...signingOperation,
        accountId: String(input.walletSession.walletId),
      },
      thresholdEcdsaState: {
        kind: 'prepared',
        thresholdOwnerAddress: requireEvmAddress(linked.child.walletKey.evmAddress),
      },
      onConfirmationDisplayed: () => undefined,
      thresholdEcdsaStepUp: { kind: 'not_required' },
      retryWithFreshEmailOtpAuth: async () => null,
    });
  }
}
