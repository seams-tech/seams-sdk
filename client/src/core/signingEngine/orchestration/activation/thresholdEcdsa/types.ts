import type { AccountId } from '@/core/types/accountIds';
import type { ThresholdEcdsaSecp256k1KeyRef } from '@/core/signingEngine/interfaces/signing';
import type { WorkerOperationContext } from '@/core/signingEngine/workerManager/executeWorkerOperation';
import type {
  ThresholdIndexedDbPort,
  ThresholdPrfFirstCachePort,
  ThresholdWebAuthnPromptPort,
} from '@/core/signingEngine/threshold/webauthn';
import type { keygenEcdsa } from '@/core/signingEngine/threshold/workflows/keygenEcdsa';
import type { connectEcdsaSession } from '@/core/signingEngine/threshold/workflows/connectEcdsaSession';

export type ThresholdEcdsaActivationChain = 'evm' | 'tempo';

export type EcdsaKeygenResult = Awaited<ReturnType<typeof keygenEcdsa>>;
export type EcdsaSessionResult = Awaited<
  ReturnType<typeof connectEcdsaSession>
>;
export type EcdsaKeygenSuccess = EcdsaKeygenResult & { ok: true };
export type EcdsaSessionSuccess = EcdsaSessionResult & { ok: true };

export type ThresholdEcdsaSessionBootstrapResult = {
  thresholdEcdsaKeyRef: ThresholdEcdsaSecp256k1KeyRef;
  keygen: EcdsaKeygenSuccess;
  session: EcdsaSessionSuccess;
};

export type ActivateEcdsaSessionDeps = {
  indexedDB: ThresholdIndexedDbPort;
  touchIdPrompt: ThresholdWebAuthnPromptPort;
  prfFirstCache: ThresholdPrfFirstCachePort;
  workerCtx: WorkerOperationContext;
  getOrCreateActiveSigningSessionId: (nearAccountId: AccountId) => string;
};

export type ActivateEcdsaSessionRequest = {
  nearAccountId: AccountId | string;
  relayerUrl: string;
  participantIds?: number[];
  sessionKind?: 'jwt' | 'cookie';
  ttlMs?: number;
  remainingUses?: number;
};
