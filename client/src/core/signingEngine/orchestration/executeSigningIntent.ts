import type { SignerMap, SigningIntent } from '../interfaces/signing';

export async function executeSigningIntent<
  Result,
  PendingRequest extends { algorithm: string },
  SignRequestType extends { algorithm: string },
  Signed,
  ResolvedSignInput extends { signReq: SignRequestType; keyRef: unknown },
>(args: {
  intent: SigningIntent<unknown, Result, PendingRequest, Signed>;
  engines: SignerMap<SignRequestType, ResolvedSignInput['keyRef'], Signed>;
  resolveSignInput: (req: PendingRequest) => Promise<ResolvedSignInput>;
}): Promise<Result> {

  const signatures: Signed[] = [];

  for (const pendingReq of args.intent.signRequests) {

    const { signReq, keyRef } = await args.resolveSignInput(pendingReq);
    const algorithm = signReq.algorithm as SignRequestType['algorithm'] & string;
    const engine = args.engines[algorithm];

    if (!engine) {
      throw new Error(`[chains] missing engine for algorithm: ${signReq.algorithm}`);
    }
    signatures.push(await engine.sign(signReq, keyRef));
  }

  return await args.intent.finalize(signatures);
}
