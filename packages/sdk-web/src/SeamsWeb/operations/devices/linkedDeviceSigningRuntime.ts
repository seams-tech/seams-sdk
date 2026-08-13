import type { AuthenticatorPort } from '@/core/platform';
import type { NearClient } from '@/core/rpcClients/near/NearClient';
import { SignedTransaction } from '@/core/rpcClients/near/NearClient';
import { buildNearTransactionSigningPayload } from '@/core/signingEngine/chains/near/payloads';
import {
  buildThresholdEd25519NearTxUnsignedBorshWasm,
  decodeThresholdEd25519SignedNearTxBorshWasm,
  finalizeThresholdEd25519NearTxFromSignatureWasm,
} from '@/core/signingEngine/chains/near/nearSignerWasm';
import type { WorkerOperationContext } from '@/core/signingEngine/workerManager/executeWorkerOperation';
import { buildNearNonceLane } from '@/core/signingEngine/nonce/nearNonceLaneIdentity';
import {
  nonceLeaseToRef,
  type NonceCoordinator,
} from '@/core/signingEngine/nonce/NonceCoordinator';
import {
  SigningOperationIntent,
  SigningSessionIds,
  type SigningOperationId,
} from '@/core/signingEngine/session/operationState/types';
import {
  resolveUniqueActiveLinkedDeviceExecutionBundleV1,
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
import { base64UrlDecode } from '@shared/utils/base64';
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
import type { ConfirmationConfig } from '@/core/types/signer-worker';
import type { SigningFlowEvent } from '@/core/types/sdkSentEvents';
import {
  computeSigningOperationFingerprint,
  parseSigningOperationFingerprintDigest,
} from '@/core/signingEngine/session/planning/operationFingerprint';
import { executeEvmFamilyTransactionSigning } from '@/core/signingEngine/flows/signEvmFamily/transactionExecutor';
import { executeLinkedDeviceEcdsaNormalSigningV1 } from '@/core/signingEngine/flows/signEvmFamily/shared/linkedDeviceEcdsaNormalSigning';
import { resolveNearNetwork } from '@/core/config/chains';

export type ActiveLinkedDeviceCurveSigningContextV1<TFamily extends 'ed25519' | 'ecdsa_secp256k1'> =
  {
    readonly bundle: ActiveLinkedDeviceExecutionBundleV1;
    readonly child: Extract<ActiveLinkedDeviceExecutionChildV1, { readonly keyFamily: TFamily }>;
    readonly walletSession: Extract<
      Awaited<ReturnType<typeof linkedDeviceWalletSessions.readTokenForWalletKeyV1>>,
      { readonly kind: 'found' }
    >;
    readonly holderMaterial: ReturnType<typeof createDeviceLinkingKeyMaterialPortV1>;
  };

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
}): Promise<ActiveLinkedDeviceCurveSigningContextV1<TFamily> | null> {
  const resolved = await resolveUniqueActiveLinkedDeviceExecutionBundleV1({
    walletId: String(input.walletId),
    nowMs: Date.now(),
    evidenceRepository: linkedDeviceExecutionEvidence,
    walletSessionRepository: linkedDeviceWalletSessions,
  });
  if (resolved.kind !== 'found') return null;
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
    holderMaterial: createDeviceLinkingKeyMaterialPortV1(),
  };
}

export async function signLinkedDeviceNearTransactionV1(input: {
  readonly walletId: WalletId;
  readonly nearAccountId: string;
  readonly transaction: TransactionInputWasm;
  readonly authenticator: AuthenticatorPort;
  readonly relayServerUrl: string;
  readonly chains: readonly SeamsChainConfig[];
  readonly nonceCoordinator: NonceCoordinator;
  readonly nearClient: NearClient;
  readonly workerCtx: WorkerOperationContext;
}): Promise<SignTransactionResult | null> {
  const linked = await resolveActiveLinkedDeviceCurveSigningContextV1({
    walletId: input.walletId,
    keyFamily: 'ed25519',
  });
  if (!linked) return null;
  try {
    const publicKey = `ed25519:${base58Encode(
      base64UrlDecode(linked.child.walletKey.registeredPublicKeyB64u),
    )}`;
    const { txSigningRequest } = buildNearTransactionSigningPayload({
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
    await input.nonceCoordinator.recoverDurableLeases({ walletId: String(input.walletId) });
    const reserved = await input.nonceCoordinator.reserveNearContext({
      lane: buildNearNonceLane({
        chains: input.chains,
        walletId: String(input.walletId),
        nearAccountId: input.nearAccountId,
        nearPublicKeyStr: publicKey,
      }),
      operation,
      count: 1,
      nearClient: input.nearClient,
    });
    const lease = reserved.leases[0];
    if (!lease) throw new Error('linked-device NEAR nonce reservation is missing');
    try {
      const unsigned = await buildThresholdEd25519NearTxUnsignedBorshWasm({
        txSigningRequest,
        transactionContext: reserved.context,
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
        holderRepository: laneSealedHolderMaterialRepository,
        holderMaterial: linked.holderMaterial,
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
          displayDigestB64u: parseSigningOperationFingerprintDigest(
            planningOperationFingerprint,
          ),
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
      await input.nonceCoordinator.markSigned({
        leaseId: lease.leaseId,
        operationId: lease.operationId,
        operationFingerprint: lease.operationFingerprint,
      });
      const nonceLease = nonceLeaseToRef(lease);
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
      await input.nonceCoordinator.release({
        leaseId: lease.leaseId,
        operationId: lease.operationId,
        operationFingerprint: lease.operationFingerprint,
        reason: 'signing_failed',
      });
      throw error;
    }
  } finally {
    linked.holderMaterial.close();
  }
}

export async function signLinkedDeviceEvmFamilyV1(input: {
  readonly deps: EvmFamilySigningDeps;
  readonly authenticator: AuthenticatorPort;
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
  });
  if (!linked) return null;
  try {
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
            holderRepository: laneSealedHolderMaterialRepository,
            holderMaterial: linked.holderMaterial,
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
  } finally {
    linked.holderMaterial.close();
  }
}
