import type { Signer } from '../../interfaces/signing';
import type {
  NearEd25519ExecutionRequest,
  NearEd25519SignOutput,
} from '../../interfaces/near';

export type NearEd25519KeyRef = {
  type: 'near-ed25519-runtime';
};

export const NEAR_ED25519_KEY_REF: NearEd25519KeyRef = {
  type: 'near-ed25519-runtime',
};

export class NearEd25519Engine implements Signer<
  NearEd25519ExecutionRequest,
  NearEd25519KeyRef,
  NearEd25519SignOutput
> {

  readonly algorithm = 'ed25519' as const;

  async sign(
    req: NearEd25519ExecutionRequest,
    keyRef: NearEd25519KeyRef,
  ): Promise<NearEd25519SignOutput> {
    if (keyRef.type !== 'near-ed25519-runtime') {
      throw new Error('[NearEd25519Engine] keyRef must be near-ed25519-runtime');
    }

    if (req.kind === 'near-transactions-with-actions') {
      return {
        kind: 'near-transactions-with-actions',
        result: await req.execute(),
      };
    }

    if (req.kind === 'near-delegate-action') {
      return {
        kind: 'near-delegate-action',
        result: await req.execute(),
      };
    }

    if (req.kind === 'near-nep413-message') {
      return {
        kind: 'near-nep413-message',
        result: await req.execute(),
      };
    }

    const _exhaustive: never = req;
    return _exhaustive;
  }
}
