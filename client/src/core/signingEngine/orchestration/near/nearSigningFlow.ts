import { NearAdapter } from '@/core/signingEngine/chainAdaptors/near/nearAdapter';
import type {
  NearEd25519SignRequest,
  NearIntentResult,
  NearEd25519SignOutput,
  NearSigningRequest,
} from '@/core/signingEngine/interfaces/near';
import type { SignerMap } from '@/core/signingEngine/interfaces/signing';
import { executeSigningIntent } from '@/core/signingEngine/orchestration/executeSigningIntent';
import {
  NearEd25519Engine,
  NEAR_ED25519_KEY_REF,
  type NearEd25519OperationHandlers,
  type NearEd25519KeyRef,
} from '@/core/signingEngine/signers/algorithms/ed25519';
import { signTransactionsWithActions } from './transactionsFlow';
import { signDelegateAction } from './delegateFlow';
import { signNep413Message } from './nep413Flow';

export async function signNearWithSecureConfirm<TRequest extends NearSigningRequest>(
  request: TRequest,
): Promise<NearIntentResult<TRequest>> {
  const adapter = new NearAdapter();
  const intent = await adapter.buildIntent(request);
  const handlers: NearEd25519OperationHandlers = {
    signTransactionsWithActions,
    signDelegateAction,
    signNep413Message,
  };
  const engines: SignerMap<NearEd25519SignRequest, NearEd25519KeyRef, NearEd25519SignOutput> = {
    ed25519: new NearEd25519Engine(handlers),
  };

  return await executeSigningIntent({
    intent,
    engines,
    resolveSignInput: async (
      signReq: NearEd25519SignRequest,
    ): Promise<{ signReq: NearEd25519SignRequest; keyRef: NearEd25519KeyRef }> => ({
      signReq,
      keyRef: NEAR_ED25519_KEY_REF,
    }),
  }) as NearIntentResult<TRequest>;
}
