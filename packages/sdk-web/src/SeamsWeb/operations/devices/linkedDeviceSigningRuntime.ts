import type { AuthenticatorPort } from '@/core/platform';
import { SignedTransaction } from '@/core/rpcClients/near/NearClient';
import { buildNearTransactionSigningPayload } from '@/core/signingEngine/chains/near/payloads';
import {
  buildThresholdEd25519NearTxUnsignedBorshWasm,
  decodeThresholdEd25519SignedNearTxBorshWasm,
  finalizeThresholdEd25519NearTxFromSignatureWasm,
} from '@/core/signingEngine/chains/near/nearSignerWasm';
import type { WorkerOperationContext } from '@/core/signingEngine/workerManager/executeWorkerOperation';
import type { NonceCoordinator } from '@/core/signingEngine/nonce/NonceCoordinator';
import type { NonceLeaseRef } from '@/core/signingEngine/interfaces/nonceLease';
import {
  SigningOperationIntent,
  SigningSessionIds,
  type SigningOperationId,
} from '@/core/signingEngine/session/operationState/types';
import {
  resolveUniqueActiveLinkedDeviceExecutionBundleV1,
  resolveUniqueLinkedDeviceExecutionBundleV1,
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
import type { DeviceLinkingHolderSigningMaterialHandleV1 } from '@/core/signingEngine/session/lanes/linkedDevicePorts';
import { authenticateLinkedDeviceLocalPresenceV1 } from '@/core/signingEngine/session/lanes/linkedDeviceLocalPresence';
import {
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
  type LinkedDeviceLocalPresenceAssertionV1,
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

export type LinkedDeviceWarmSigningSessionV1 = {
  readonly kind: 'linked_device_warm_signing_session_v1';
  readonly walletId: WalletId;
  readonly bundle: ActiveLinkedDeviceExecutionBundleV1;
  readonly holderMaterial: ReturnType<typeof createDeviceLinkingKeyMaterialPortV1>;
  readonly handles: readonly DeviceLinkingHolderSigningMaterialHandleV1[];
};

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

export type ActiveLinkedDeviceCurveSigningContextV1<TFamily extends 'ed25519' | 'ecdsa_secp256k1'> =
  {
    readonly bundle: ActiveLinkedDeviceExecutionBundleV1;
    readonly child: Extract<ActiveLinkedDeviceExecutionChildV1, { readonly keyFamily: TFamily }>;
    readonly walletSession: Extract<
      Awaited<ReturnType<typeof linkedDeviceWalletSessions.readTokenForWalletKeyV1>>,
      { readonly kind: 'found' }
    >;
    readonly holderMaterial: ReturnType<typeof createDeviceLinkingKeyMaterialPortV1>;
    readonly holderHandle: Extract<
      DeviceLinkingHolderSigningMaterialHandleV1,
      { readonly keyFamily: TFamily }
    >;
  };

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
  return {
    curve: 'linked_device',
    authMethod: 'passkey',
    walletId: String(input.bundle.walletId),
    relayerUrl: input.relayServerUrl,
    walletSessionToken: token.walletSessionJwt,
    enrollmentId: String(input.bundle.enrollmentId),
    deviceId: String(input.bundle.deviceId),
    credentialIdB64u:
      input.bundle.targetCredentialRegistration.webauthnRegistration.credentialIdB64u,
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
    const handle = await input.holderMaterial.openPersistedHolderSigningMaterialV1({
      factorSecret: input.factorSecret.slice().buffer,
      job: child.job,
      protocolCommitReceipt: child.protocolCommitReceipt,
      materialActivation: child.materialActivation,
      holderRecord,
    });
    if (handle.keyFamily !== child.keyFamily) {
      throw new Error('linked-device holder material changed its active curve');
    }
    handles.push(handle);
  }
  return handles;
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
    enrollmentId: String(input.bundle.enrollmentId),
    deviceId: String(input.bundle.deviceId),
    walletSessionId: String(input.bundle.walletSessionId),
    credentialIdB64u:
      input.bundle.targetCredentialRegistration.webauthnRegistration.credentialIdB64u,
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
  readonly localPresenceAssertion: LinkedDeviceLocalPresenceAssertionV1;
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

export async function openLinkedDeviceWarmSigningSessionV1(input: {
  readonly walletId: WalletId;
  readonly authenticator: AuthenticatorPort;
  readonly relayServerUrl: string;
  readonly warmMaterial: LinkedDeviceWarmMaterialPortV1;
}): Promise<LinkedDeviceWarmSigningSessionV1> {
  const nowMs = Date.now();
  const resolved = await resolveUniqueLinkedDeviceExecutionBundleV1({
    walletId: String(input.walletId),
    evidenceRepository: linkedDeviceExecutionEvidence,
    walletSessionRepository: linkedDeviceWalletSessions,
  });
  if (resolved.kind !== 'found') {
    throw new Error('linked-device execution bundle is unavailable during unlock');
  }
  const child = resolved.bundle.orderedExecutions[0];
  if (!child) throw new Error('linked-device execution bundle has no signing lane');
  const authorizedOperationId = linkedDeviceWalletSessionRenewalAuthorizedOperationIdV1();
  const intentDigestB64u = await computeLinkedDeviceWalletSessionRenewalIntentDigestV1({
    authorizationId: resolved.bundle.authorizationId,
    walletSessionId: resolved.bundle.walletSessionId,
    quotaId: resolved.bundle.quotaId,
    deviceId: resolved.bundle.deviceId,
    enrollmentId: resolved.bundle.enrollmentId,
  });
  const authentication = await authenticateLinkedDeviceLocalPresenceV1({
    authenticator: input.authenticator,
    bundle: resolved.bundle,
    child,
    authorizedOperationId,
    intentDigestB64u,
    issuedAtMs: nowMs,
    expiresAtMs: nowMs + 60_000,
  });
  const holderMaterial = createDeviceLinkingKeyMaterialPortV1();
  try {
    const renewedDelivery = await renewLinkedDeviceWalletSessionV1({
      relayServerUrl: input.relayServerUrl,
      bundle: resolved.bundle,
      keyFamily: child.keyFamily,
      localPresenceAssertion: authentication.localPresenceAssertion,
    });
    await linkedDeviceWalletSessions.replaceExactRenewedDeliveryV1(renewedDelivery);
    const renewed = await resolveUniqueActiveLinkedDeviceExecutionBundleV1({
      walletId: String(input.walletId),
      nowMs: Date.now(),
      evidenceRepository: linkedDeviceExecutionEvidence,
      walletSessionRepository: linkedDeviceWalletSessions,
    });
    if (renewed.kind !== 'found' || renewed.bundle.enrollmentId !== resolved.bundle.enrollmentId) {
      throw new Error('linked-device execution bundle is unavailable after unlock');
    }
    await sealLinkedDeviceWarmMaterialV1({
      bundle: renewed.bundle,
      delivery: renewedDelivery,
      factorSecret: authentication.factorSecret,
      relayServerUrl: input.relayServerUrl,
      warmMaterial: input.warmMaterial,
    });
    const handles = await openLinkedDeviceHolderHandlesV1({
      bundle: renewed.bundle,
      factorSecret: authentication.factorSecret,
      holderMaterial,
    });
    return {
      kind: 'linked_device_warm_signing_session_v1',
      walletId: renewed.bundle.walletId,
      bundle: renewed.bundle,
      holderMaterial,
      handles,
    };
  } catch (error) {
    holderMaterial.close();
    throw error;
  } finally {
    authentication.factorSecret.fill(0);
  }
}

export async function restoreLinkedDeviceWarmSigningSessionV1(input: {
  readonly walletId: WalletId;
  readonly relayServerUrl: string;
  readonly warmMaterial: LinkedDeviceWarmMaterialPortV1;
}): Promise<LinkedDeviceWarmSigningSessionV1 | null> {
  const resolved = await resolveUniqueActiveLinkedDeviceExecutionBundleV1({
    walletId: String(input.walletId),
    nowMs: Date.now(),
    evidenceRepository: linkedDeviceExecutionEvidence,
    walletSessionRepository: linkedDeviceWalletSessions,
  });
  if (resolved.kind !== 'found') return null;
  const stored = await linkedDeviceWalletSessions.readActiveSealedRefreshV1({
    enrollmentId: resolved.bundle.enrollmentId,
    nowMs: Date.now(),
  });
  if (stored.kind !== 'found') return null;
  const credentialIdB64u =
    resolved.bundle.targetCredentialRegistration.webauthnRegistration.credentialIdB64u;
  if (
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
    factorSecret.fill(0);
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
      holderMaterial,
      handles,
    };
  } catch (error) {
    holderMaterial.close();
    throw error;
  } finally {
    factorSecret.fill(0);
  }
}

export function closeLinkedDeviceWarmSigningSessionV1(
  session: LinkedDeviceWarmSigningSessionV1,
): void {
  session.holderMaterial.close();
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
  const resolved = await resolveUniqueActiveLinkedDeviceExecutionBundleV1({
    walletId: String(input.walletId),
    nowMs: Date.now(),
    evidenceRepository: linkedDeviceExecutionEvidence,
    walletSessionRepository: linkedDeviceWalletSessions,
  });
  if (resolved.kind !== 'found') return null;
  if (
    resolved.bundle.enrollmentId !== input.warmSession.bundle.enrollmentId ||
    resolved.bundle.walletSessionId !== input.warmSession.bundle.walletSessionId ||
    resolved.bundle.walletId !== input.warmSession.walletId
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
      method: 'passkey' as const,
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
    if (confirmation.readiness.kind !== 'context_ready') {
      throw new Error('linked-device NEAR transaction context is unavailable');
    }
    const nonceLease = confirmation.readiness.nonceLeases[0];
    if (!nonceLease) throw new Error('linked-device NEAR nonce reservation is missing');
    try {
      const unsigned = await buildThresholdEd25519NearTxUnsignedBorshWasm({
        txSigningRequest,
        transactionContext: confirmation.readiness.transactionContext,
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
          method: 'passkey' as const,
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
