import { toAccountId, type AccountId } from '@/core/types/accountIds';
import type {
  WebAuthnAuthenticationCredential,
  WebAuthnRegistrationCredential,
} from '@/core/types/webauthn';
import { getPrfResultsFromCredential } from '../../signers/webauthn/credentials/credentialExtensions';
import type { NearSigningKeyOps } from '../../interfaces/nearKeyOps';
import { THRESHOLD_ED25519_WRAP_KEY_SALT_B64U } from '../../threshold/ed25519WrapKeySalt';

export type ThresholdEd25519LifecycleDeps = {
  signingKeyOps: Pick<
    NearSigningKeyOps,
    'deriveThresholdEd25519ClientVerifyingShare' | 'deriveThresholdEd25519BootstrapPackage'
  >;
  createSessionId: (prefix: string) => string;
};

export type DeriveThresholdEd25519ClientVerifyingShareResult = {
  success: boolean;
  nearAccountId: string;
  clientVerifyingShareB64u: string;
  error?: string;
};

export type DeriveThresholdEd25519BootstrapPackageResult =
  | {
      success: true;
      nearAccountId: string;
      keyVersion: string;
      recoveryExportCapable: true;
      clientParticipantId: number;
      relayerParticipantId: number;
      publicKey: string;
      recoveryPublicKey: string;
      clientVerifyingShareB64u: string;
      relayerSigningShareB64u: string;
      relayerVerifyingShareB64u: string;
    }
  | {
      success: false;
      nearAccountId: string;
      keyVersion: string;
      error?: string;
    };

function requirePrfFirstB64uFromCredential(
  credential: WebAuthnRegistrationCredential | WebAuthnAuthenticationCredential,
): string {
  const value = getPrfResultsFromCredential(credential).first;
  if (!value) {
    throw new Error('Missing PRF.first output from credential (requires a PRF-enabled passkey)');
  }
  return value;
}

export async function deriveThresholdEd25519ClientVerifyingShareFromCredential(
  deps: ThresholdEd25519LifecycleDeps,
  args: {
    credential: WebAuthnRegistrationCredential | WebAuthnAuthenticationCredential;
    nearAccountId: AccountId | string;
  },
): Promise<DeriveThresholdEd25519ClientVerifyingShareResult> {
  const nearAccountId = toAccountId(args.nearAccountId);
  try {
    const prfFirstB64u = requirePrfFirstB64uFromCredential(args.credential);
    const sessionId = deps.createSessionId('threshold-client-share');
    return await deps.signingKeyOps.deriveThresholdEd25519ClientVerifyingShare({
      sessionId,
      nearAccountId,
      prfFirstB64u,
      wrapKeySalt: THRESHOLD_ED25519_WRAP_KEY_SALT_B64U,
    });
  } catch (error: unknown) {
    const message = String((error as { message?: unknown })?.message ?? error);
    return {
      success: false,
      nearAccountId,
      clientVerifyingShareB64u: '',
      error: message,
    };
  }
}

export async function deriveThresholdEd25519BootstrapPackageFromCredential(
  deps: ThresholdEd25519LifecycleDeps,
  args: {
    credential: WebAuthnRegistrationCredential | WebAuthnAuthenticationCredential;
    nearAccountId: AccountId | string;
    rpId?: string;
    keyVersion: string;
    recoveryServerShareB64u?: string;
  },
): Promise<DeriveThresholdEd25519BootstrapPackageResult> {
  const nearAccountId = toAccountId(args.nearAccountId);
  const rpId = String(args.rpId || '').trim();
  const keyVersion = String(args.keyVersion || '').trim();
  const recoveryServerShareB64u = String(args.recoveryServerShareB64u || '').trim();
  try {
    const prfFirstB64u = requirePrfFirstB64uFromCredential(args.credential);
    const sessionId = deps.createSessionId('threshold-bootstrap-ed25519-enrollment');
    return await deps.signingKeyOps.deriveThresholdEd25519BootstrapPackage({
      sessionId,
      nearAccountId,
      ...(rpId ? { rpId } : {}),
      keyVersion,
      prfFirstB64u,
      ...(recoveryServerShareB64u ? { recoveryServerShareB64u } : {}),
    });
  } catch (error: unknown) {
    const message = String((error as { message?: unknown })?.message ?? error);
    return {
      success: false,
      nearAccountId,
      keyVersion,
      error: message,
    };
  }
}
