import type { AccountId } from '@/core/types/accountIds';
import type { ThresholdEcdsaSecp256k1KeyRef } from '@/core/signing/orchestration/types';
import type { WorkerOperationContext } from '@/core/signing/workers/operations/executeSignerWorkerOperation';
import type {
  ThresholdIndexedDbPort,
  ThresholdPrfFirstCachePort,
  ThresholdWebAuthnPromptPort,
} from '@/core/signing/threshold/webauthn';
import type { keygenThresholdEcdsaLite } from '@/core/signing/threshold/workflows/keygenThresholdEcdsaLite';
import type { connectThresholdEcdsaSessionLite } from '@/core/signing/threshold/workflows/connectThresholdEcdsaSessionLite';

export type ThresholdEcdsaActivationChain = 'evm' | 'tempo';

export type ThresholdEcdsaKeygenLiteResult = Awaited<ReturnType<typeof keygenThresholdEcdsaLite>>;
export type ThresholdEcdsaSessionLiteResult = Awaited<
  ReturnType<typeof connectThresholdEcdsaSessionLite>
>;
export type ThresholdEcdsaKeygenLiteSuccess = ThresholdEcdsaKeygenLiteResult & { ok: true };
export type ThresholdEcdsaSessionLiteSuccess = ThresholdEcdsaSessionLiteResult & { ok: true };

export type ThresholdEcdsaSessionBootstrapResult = {
  thresholdEcdsaKeyRef: ThresholdEcdsaSecp256k1KeyRef;
  keygen: ThresholdEcdsaKeygenLiteSuccess;
  session: ThresholdEcdsaSessionLiteSuccess;
};

export type ActivateThresholdEcdsaSessionLiteDeps = {
  indexedDB: ThresholdIndexedDbPort;
  touchIdPrompt: ThresholdWebAuthnPromptPort;
  prfFirstCache: ThresholdPrfFirstCachePort;
  workerCtx: WorkerOperationContext;
  getOrCreateActiveSigningSessionId: (nearAccountId: AccountId) => string;
};

export type ActivateThresholdEcdsaSessionLiteRequest = {
  nearAccountId: AccountId | string;
  relayerUrl: string;
  participantIds?: number[];
  sessionKind?: 'jwt' | 'cookie';
  ttlMs?: number;
  remainingUses?: number;
};
