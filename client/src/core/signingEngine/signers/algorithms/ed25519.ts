import type { Signer } from '../../interfaces/signing';
import type {
  NearDelegateActionPayload,
  NearEd25519SignRequest,
  NearEd25519SignOutput,
  NearNep413Payload,
  NearTransactionsWithActionsPayload,
} from '../../interfaces/near';

export type NearEd25519KeyRef = {
  type: 'near-ed25519-runtime';
};

export const NEAR_ED25519_KEY_REF: NearEd25519KeyRef = {
  type: 'near-ed25519-runtime',
};

export type NearEd25519OperationHandlers = {
  signTransactionsWithActions: (
    payload: NearTransactionsWithActionsPayload,
  ) => Promise<Extract<NearEd25519SignOutput, { kind: 'near-transactions-with-actions' }>['result']>;
  signDelegateAction: (
    payload: NearDelegateActionPayload,
  ) => Promise<Extract<NearEd25519SignOutput, { kind: 'near-delegate-action' }>['result']>;
  signNep413Message: (
    payload: NearNep413Payload,
  ) => Promise<Extract<NearEd25519SignOutput, { kind: 'near-nep413-message' }>['result']>;
};

export class NearEd25519Engine implements Signer<
  NearEd25519SignRequest,
  NearEd25519KeyRef,
  NearEd25519SignOutput
> {

  readonly algorithm = 'ed25519' as const;

  constructor(private readonly handlers: NearEd25519OperationHandlers) {}

  async sign(
    req: NearEd25519SignRequest,
    keyRef: NearEd25519KeyRef,
  ): Promise<NearEd25519SignOutput> {
    if (keyRef.type !== 'near-ed25519-runtime') {
      throw new Error('[NearEd25519Engine] keyRef must be near-ed25519-runtime');
    }

    if (req.kind === 'near-transactions-with-actions') {
      return {
        kind: 'near-transactions-with-actions',
        result: await this.handlers.signTransactionsWithActions(req.payload),
      };
    }

    if (req.kind === 'near-delegate-action') {
      return {
        kind: 'near-delegate-action',
        result: await this.handlers.signDelegateAction(req.payload),
      };
    }

    if (req.kind === 'near-nep413-message') {
      return {
        kind: 'near-nep413-message',
        result: await this.handlers.signNep413Message(req.payload),
      };
    }

    const _exhaustive: never = req;
    return _exhaustive;
  }
}
