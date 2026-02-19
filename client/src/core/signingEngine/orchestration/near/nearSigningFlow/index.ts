import { NearAdapter } from '@/core/signingEngine/chainAdaptors/near/nearAdapter';
import type {
  NearEd25519ExecutionRequest,
  NearEd25519IntentSignRequest,
  NearIntentResult,
  NearEd25519SignOutput,
  NearSigningRequest,
} from '@/core/signingEngine/interfaces/near';
import type { SignerMap } from '@/core/signingEngine/interfaces/signing';
import { executeSigningIntent } from '@/core/signingEngine/orchestration/executeSigningIntent';
import {
  NearEd25519Engine,
  NEAR_ED25519_KEY_REF,
  type NearEd25519KeyRef,
} from '@/core/signingEngine/signers/algorithms/ed25519';
import { signTransactionsWithActions } from '../transactionsFlow';
import { signDelegateAction } from '../delegateFlow';
import { signNep413Message } from '../nep413Flow';

function resolveNearExecutionRequest(
  request: NearEd25519IntentSignRequest,
): NearEd25519ExecutionRequest {
  if (request.kind === 'near-transactions-with-actions') {
    return {
      kind: 'near-transactions-with-actions',
      algorithm: 'ed25519',
      execute: async () => await signTransactionsWithActions(request.payload),
    };
  }

  if (request.kind === 'near-delegate-action') {
    return {
      kind: 'near-delegate-action',
      algorithm: 'ed25519',
      execute: async () => await signDelegateAction(request.payload),
    };
  }

  if (request.kind === 'near-nep413-message') {
    return {
      kind: 'near-nep413-message',
      algorithm: 'ed25519',
      execute: async () => await signNep413Message(request.payload),
    };
  }

  const _exhaustive: never = request;
  return _exhaustive;
}

export async function signNearWithSecureConfirm<TRequest extends NearSigningRequest>(
  request: TRequest,
): Promise<NearIntentResult<TRequest>> {
  const adapter = new NearAdapter();
  const intent = await adapter.buildIntent(request);
  const engines: SignerMap<
    NearEd25519ExecutionRequest,
    NearEd25519KeyRef,
    NearEd25519SignOutput
  > = {
    ed25519: new NearEd25519Engine(),
  };

  return await executeSigningIntent({
    intent,
    engines,
    resolveSignInput: async (
      signReq: NearEd25519IntentSignRequest,
    ): Promise<{ signReq: NearEd25519ExecutionRequest; keyRef: NearEd25519KeyRef }> => ({
      signReq: resolveNearExecutionRequest(signReq),
      keyRef: NEAR_ED25519_KEY_REF,
    }),
  }) as NearIntentResult<TRequest>;
}
