import type { AccountId } from '@/core/types/accountIds';
import type { TransactionInputWasm } from '@/core/types/actions';
import type { DelegateActionInput } from '@/core/types/delegate';
import type { onProgressEvents } from '@/core/types/sdkSentEvents';
import type {
  ConfirmationConfig,
  RpcCallPayload,
  SignerMode,
  WasmSignedDelegate,
} from '@/core/types/signer-worker';
import type { SignTransactionResult } from '@/core/types/tatchi';
import type { TempoSecp256k1SigningRequest, TempoSigningRequest } from '../../chainAdaptors/tempo/types';
import type { TempoSignedResult } from '../../chainAdaptors/tempo/tempoAdapter';
import type { ThresholdEcdsaSecp256k1KeyRef } from '../../orchestration/types';
import {
  signDelegateAction as signDelegateActionValue,
  signNEP413Message as signNEP413MessageValue,
  signTransactionsWithActions as signTransactionsWithActionsValue,
  type NearSigningApiDeps,
} from '../signing/nearSigning';
import { signTempo as signTempoValue, type TempoSigningDeps } from '../signing/tempoSigning';
import type { ManagerConvenienceDeps } from '../bootstrap/orchestrationDependencyFactory';
import { withThresholdEcdsaSignInFlightGate } from '../thresholdLifecycle/thresholdEcdsaSignInFlightGate';

export type SigningActionsSurfaceDeps = {
  nearSigningDeps: NearSigningApiDeps;
  tempoSigningDeps: TempoSigningDeps;
  getManagerConvenienceDeps: () => ManagerConvenienceDeps;
  thresholdEcdsaSignInFlightByAccount: Set<string>;
};

export type SigningActionsSurface = {
  signTransactionsWithActions(args: {
    transactions: TransactionInputWasm[];
    rpcCall: RpcCallPayload;
    deviceNumber?: number;
    signerMode: SignerMode;
    confirmationConfigOverride?: Partial<ConfirmationConfig>;
    title?: string;
    body?: string;
    onEvent?: (update: onProgressEvents) => void;
    sessionId?: string;
  }): Promise<SignTransactionResult[]>;
  signDelegateAction(args: {
    delegate: DelegateActionInput;
    rpcCall: RpcCallPayload;
    deviceNumber?: number;
    signerMode: SignerMode;
    confirmationConfigOverride?: Partial<ConfirmationConfig>;
    title?: string;
    body?: string;
    onEvent?: (update: onProgressEvents) => void;
  }): Promise<{
    signedDelegate: WasmSignedDelegate;
    hash: string;
    nearAccountId: AccountId;
    logs?: string[];
  }>;
  signNEP413Message(payload: {
    message: string;
    recipient: string;
    nonce: string;
    state: string | null;
    accountId: AccountId;
    signerMode: SignerMode;
    deviceNumber?: number;
    title?: string;
    body?: string;
    confirmationConfigOverride?: Partial<ConfirmationConfig>;
  }): Promise<{
    success: boolean;
    accountId: string;
    publicKey: string;
    signature: string;
    state?: string;
    error?: string;
  }>;
  signTempo(args: {
    nearAccountId: string;
    request: TempoSigningRequest;
    confirmationConfigOverride?: Partial<ConfirmationConfig>;
    thresholdEcdsaKeyRef?: ThresholdEcdsaSecp256k1KeyRef;
    shouldAbort?: () => boolean;
    onEvent?: (event: {
      step: number;
      phase: string;
      status: 'progress' | 'success' | 'error';
      message?: string;
      data?: unknown;
    }) => void;
  }): Promise<TempoSignedResult>;
  signTempoWithThresholdEcdsa(args: {
    nearAccountId: string;
    request: TempoSecp256k1SigningRequest;
    thresholdEcdsaKeyRef: ThresholdEcdsaSecp256k1KeyRef;
    confirmationConfigOverride?: Partial<ConfirmationConfig>;
  }): Promise<TempoSignedResult>;
};

export function createSigningActionsSurface(
  deps: SigningActionsSurfaceDeps,
): SigningActionsSurface {
  return {
    async signTransactionsWithActions(args): Promise<SignTransactionResult[]> {
      return await signTransactionsWithActionsValue(deps.nearSigningDeps, args);
    },
    async signDelegateAction(args): Promise<{
      signedDelegate: WasmSignedDelegate;
      hash: string;
      nearAccountId: AccountId;
      logs?: string[];
    }> {
      return await signDelegateActionValue(deps.nearSigningDeps, args);
    },
    async signNEP413Message(payload): Promise<{
      success: boolean;
      accountId: string;
      publicKey: string;
      signature: string;
      state?: string;
      error?: string;
    }> {
      return await signNEP413MessageValue(deps.nearSigningDeps, payload);
    },
    async signTempo(args): Promise<TempoSignedResult> {
      return await withThresholdEcdsaSignInFlightGate({
        inFlightByAccount: deps.thresholdEcdsaSignInFlightByAccount,
        nearAccountId: args.nearAccountId,
        enabled: args.request.senderSignatureAlgorithm === 'secp256k1',
        task: async () => await signTempoValue(deps.tempoSigningDeps, args),
      });
    },
    async signTempoWithThresholdEcdsa(args): Promise<TempoSignedResult> {
      if (args.request.senderSignatureAlgorithm !== 'secp256k1') {
        throw new Error(
          '[WebAuthnManager] signTempoWithThresholdEcdsa requires senderSignatureAlgorithm=secp256k1',
        );
      }

      return await deps.getManagerConvenienceDeps().signTempo({
        nearAccountId: args.nearAccountId,
        request: args.request,
        thresholdEcdsaKeyRef: args.thresholdEcdsaKeyRef,
        confirmationConfigOverride: args.confirmationConfigOverride,
      });
    },
  };
}
