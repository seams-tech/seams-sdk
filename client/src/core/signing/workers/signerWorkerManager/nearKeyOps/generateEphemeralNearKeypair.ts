import { ensureEd25519Prefix } from '@shared/utils/validation';
import {
  WorkerRequestType,
  WorkerResponseType,
} from '@/core/types/signer-worker';
import type { SignerWorkerManagerContext } from '..';

export async function generateEphemeralNearKeypair(args: {
  ctx: SignerWorkerManagerContext;
}): Promise<{
  publicKey: string;
  privateKey: string;
}> {
  const response = await args.ctx.requestWorkerOperation({
    kind: 'nearSigner',
    request: {
      type: WorkerRequestType.GenerateEphemeralNearKeypair,
      payload: {},
    },
  });

  if (response.type !== WorkerResponseType.GenerateEphemeralNearKeypairSuccess) {
    throw new Error('Worker failed to generate ephemeral NEAR keypair');
  }

  const publicKey = ensureEd25519Prefix(String((response.payload as { publicKey?: unknown }).publicKey || '').trim());
  const privateKey = ensureEd25519Prefix(String((response.payload as { privateKey?: unknown }).privateKey || '').trim());
  if (!publicKey || !privateKey) {
    throw new Error('Worker returned invalid ephemeral NEAR keypair');
  }

  return { publicKey, privateKey };
}
