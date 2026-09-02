import type { WalletRecoveryTargetV1 } from './walletRecoveryTarget';
import { parseWebAuthnRpId } from '../utils/domainIds';

const parsedRpId = parseWebAuthnRpId('wallet.example.localhost');
if (!parsedRpId.ok) throw new Error(parsedRpId.error.message);

const passkeyTarget: WalletRecoveryTargetV1 = {
  kind: 'passkey',
  rpId: parsedRpId.value,
};

const googleTarget: WalletRecoveryTargetV1 = {
  kind: 'google_email_otp',
  googleProvider: 'google',
};

// @ts-expect-error Passkey recovery requires an RP ID.
const passkeyWithoutRp: WalletRecoveryTargetV1 = { kind: 'passkey' };

// @ts-expect-error Google recovery cannot carry Passkey RP state.
const googleWithRp: WalletRecoveryTargetV1 = {
  kind: 'google_email_otp',
  googleProvider: 'google',
  rpId: parsedRpId.value,
};

const unsupportedProvider: WalletRecoveryTargetV1 = {
  kind: 'google_email_otp',
  // @ts-expect-error Google recovery accepts only the Google provider.
  googleProvider: 'email',
};

void passkeyTarget;
void googleTarget;
void passkeyWithoutRp;
void googleWithRp;
void unsupportedProvider;
