import { NearAdapter } from '@/core/signingEngine/chainAdaptors/near/nearAdapter';
import type {
  NearEd25519SignRequest,
  NearIntentResult,
  NearEd25519SignOutput,
  NearSigningRequest,
} from '@/core/signingEngine/interfaces/near';
import {
  NearEd25519Engine,
  type NearEd25519OperationHandlers,
} from '@/core/signingEngine/signers/algorithms/ed25519';
import { signTransactionsWithActions } from './transactionsFlow';
import { signDelegateAction } from './delegateFlow';
import { signNep413Message } from './nep413Flow';

export async function signNearWithTouchConfirm<TRequest extends NearSigningRequest>(
  request: TRequest,
): Promise<NearIntentResult<TRequest>> {
  const adapter = new NearAdapter();
  const intent = await adapter.buildIntent(request);
  const handlers: NearEd25519OperationHandlers = {
    signTransactionsWithActions,
    signDelegateAction,
    signNep413Message,
  };
  const engine = new NearEd25519Engine(handlers);
  const signatures: NearEd25519SignOutput[] = [];
  for (const signReq of intent.signRequests) {
    signatures.push(await engine.sign(signReq));
  }

  return (await intent.finalize(signatures)) as NearIntentResult<TRequest>;
}
