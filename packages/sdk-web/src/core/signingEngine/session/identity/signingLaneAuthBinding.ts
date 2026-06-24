import type { RpId } from './evmFamilyEcdsaIdentity';

export type SigningLaneAuthBinding =
  | {
      kind: 'passkey';
      rpId: RpId;
      credentialIdB64u: string;
      providerSubjectId?: never;
    }
  | {
      kind: 'email_otp';
      providerSubjectId: string;
      rpId?: never;
      credentialIdB64u?: never;
    };

export function signingLaneAuthMethod(auth: SigningLaneAuthBinding): 'passkey' | 'email_otp' {
  switch (auth.kind) {
    case 'passkey':
      return 'passkey';
    case 'email_otp':
      return 'email_otp';
  }
  auth satisfies never;
  throw new Error('[SigningSession] unsupported signing lane auth binding');
}
