import type { WalletAuthMethodId } from '@shared/utils/domainIds';
import {
  type AddAuthMethodIntentV1,
  type AddSignerIntentV1,
  type RegistrationAuthority,
  type WebAuthnRpId,
  type WalletId,
  type WalletAuthMethodRevocationProof,
} from '@shared/utils/registrationIntent';
import {
  buildEmailOtpWalletAuthAuthority,
  buildPasskeyWalletAuthAuthority,
  type EmailOtpWalletAuthAuthority,
  type WalletAuthAuthority,
} from '@shared/utils/walletAuthAuthority';
import type {
  StoredWalletAddAuthMethodCeremony,
  StoredWalletAddSignerCeremony,
} from '../../../../core/RegistrationCeremonyStore';
import type {
  WalletAddAuthMethodStartRequest,
  WalletAddSignerStartRequest,
  WalletRegistrationFinalizeAuthMethod,
} from '../../../../core/registrationContracts';
import type {
  WalletAuthMethodRecord,
  WalletAuthMethodStore,
  WalletAuthMethodV2Store,
} from '../../../../core/d1WalletAuthMethodStore';
import { webAuthnCredentialIdB64uFromCredential } from '../../../auth/webAuthnCredentialCodecs';
import { sha256HexUtf8 } from '@shared/utils/digests';
import type { DigestB64u } from '@shared/utils/canonicalPrimitives';
import {
  EMAIL_OTP_CHANNEL,
  WALLET_EMAIL_OTP_ACTIONS,
  WALLET_EMAIL_OTP_TRANSACTION_SIGN_OPERATION,
} from '@shared/utils/emailOtpDomain';
import type { EmailOtpWalletEnrollmentRecord } from '../../../../core/EmailOtpStores';
import type {
  EmailOtpExistingChallengeVerifyInput,
  EmailOtpExistingChallengeVerifyResult,
} from '../emailOtp/d1EmailOtpChallengeVerifier';
import { hashEmailOtpOperationBinding } from '../../../domains/emailOtp/emailOtpSessionRouteHelpers';
import { walletAuthAuthorityRef } from '@shared/utils/walletAuthAuthority';

type StartWalletAddSignerInput = WalletAddSignerStartRequest;
type StartWalletAddAuthMethodInput = WalletAddAuthMethodStartRequest;

export type D1AddSignerExistingAuthResolution =
  | {
      readonly ok: true;
      readonly auth: StoredWalletAddSignerCeremony['auth'];
    }
  | {
      readonly ok: false;
      readonly code: string;
      readonly message: string;
    };

export type D1AddAuthMethodExistingAuthResolution =
  | {
      readonly ok: true;
      readonly auth: StoredWalletAddAuthMethodCeremony['auth'];
    }
  | {
      readonly ok: false;
      readonly code: string;
      readonly message: string;
    };

export function walletRegistrationFinalizeAuthMethodFromAuthority(
  authority: RegistrationAuthority,
): WalletRegistrationFinalizeAuthMethod {
  switch (authority.kind) {
    case 'passkey':
      return {
        kind: 'passkey',
        credentialIdB64u: authority.credentialIdB64u,
        credentialPublicKeyB64u: authority.credentialPublicKeyB64u,
      };
    case 'email_otp':
      return {
        kind: 'email_otp',
        registrationAuthorityId: authority.registrationAuthorityId,
      };
  }
  return unreachableRegistrationAuthority(authority);
}

export function walletAuthAuthorityFromRegistrationAuthority(
  authority: RegistrationAuthority,
): WalletAuthAuthority {
  switch (authority.kind) {
    case 'passkey':
      return buildPasskeyWalletAuthAuthority({
        walletId: authority.walletId,
        rpId: authority.rpId,
        credentialIdB64u: authority.credentialIdB64u,
      });
    case 'email_otp':
      return buildEmailOtpWalletAuthAuthority({
        walletId: authority.walletId,
        provider: authority.proofKind === 'google_sso_registration' ? 'google' : 'email',
        providerUserId: authority.providerSubject,
        emailHashHex: authority.emailHashHex,
      });
  }
  return unreachableRegistrationAuthority(authority);
}

export function walletAuthMethodRecordFromRegistrationAuthority(input: {
  readonly authority: RegistrationAuthority;
  readonly now: number;
}): WalletAuthMethodRecord {
  switch (input.authority.kind) {
    case 'passkey':
      return {
        version: 'wallet_auth_method_v1',
        kind: 'passkey',
        status: 'active',
        walletId: input.authority.walletId,
        rpId: input.authority.rpId,
        credentialIdB64u: input.authority.credentialIdB64u,
        credentialPublicKeyB64u: input.authority.credentialPublicKeyB64u,
        counter: input.authority.counter,
        createdAtMs: input.now,
        updatedAtMs: input.now,
      };
    case 'email_otp':
      return {
        version: 'wallet_auth_method_v1',
        kind: 'email_otp',
        status: 'active',
        walletId: input.authority.walletId,
        emailHashHex: input.authority.emailHashHex,
        registrationAuthorityId: input.authority.registrationAuthorityId,
        createdAtMs: input.now,
        updatedAtMs: input.now,
      };
  }
  return unreachableRegistrationAuthority(input.authority);
}

export function activeWalletAuthMethodRecord(record: WalletAuthMethodRecord): boolean {
  return record.status === 'active';
}

function unreachableRegistrationAuthority(value: never): never {
  throw new Error(`Unhandled registration authority kind: ${String(value)}`);
}

export type D1LinkedDeviceFreshRevokeProofV1 = WalletAuthMethodRevocationProof;

export type D1FreshRevokeWebAuthnVerifierV1 = (input: {
  readonly userId: string;
  readonly rpId: WebAuthnRpId;
  readonly expectedChallenge: string;
  readonly webauthn_authentication: unknown;
  readonly expected_origin: string;
}) => Promise<{
  readonly success: boolean;
  readonly verified: boolean;
  readonly message?: string;
}>;

export async function verifyD1LinkedDeviceFreshRevokeProofV1(input: {
  readonly walletId: WalletId;
  readonly orgId: string;
  readonly targetWalletAuthMethodId: WalletAuthMethodId;
  readonly proof: D1LinkedDeviceFreshRevokeProofV1;
  readonly expectedOrigin: string;
  readonly verifiedAtMs: number;
  readonly operationFingerprintDigest: DigestB64u;
  readonly walletAuthMethodStore: Pick<WalletAuthMethodV2Store, 'getPasskeyV2' | 'getEmailOtpV2'>;
  readonly verifyWebAuthnAuthenticationLite: D1FreshRevokeWebAuthnVerifierV1;
  readonly verifyEmailOtpExisting?: (
    input: EmailOtpExistingChallengeVerifyInput,
  ) => Promise<EmailOtpExistingChallengeVerifyResult>;
  readonly readEmailOtpEnrollment?: (
    walletId: string,
  ) => Promise<EmailOtpWalletEnrollmentRecord | null>;
  readonly resolveEmailOtpAuthority?: (input: {
    readonly walletId: string;
    readonly providerUserId: string;
  }) => Promise<
    | { readonly ok: true; readonly authority: EmailOtpWalletAuthAuthority }
    | { readonly ok: false; readonly code: string; readonly message: string }
  >;
}): Promise<
  | {
      readonly kind: 'authorized';
      readonly walletAuthMethodId: WalletAuthMethodId;
      readonly verifiedAtMs: number;
    }
  | {
      readonly kind: 'denied';
      readonly code: 'unauthorized' | 'invalid';
      readonly message: string;
    }
> {
  if (input.proof.kind === 'email_otp') {
    if (
      !input.verifyEmailOtpExisting ||
      !input.readEmailOtpEnrollment ||
      !input.resolveEmailOtpAuthority
    ) {
      return {
        kind: 'denied',
        code: 'invalid',
        message: 'Email OTP revocation proof is not configured',
      };
    }
    const enrollment = await input.readEmailOtpEnrollment(String(input.walletId));
    if (
      !enrollment ||
      enrollment.walletId !== String(input.walletId) ||
      enrollment.orgId !== input.orgId
    ) {
      return {
        kind: 'denied',
        code: 'unauthorized',
        message: 'Email OTP enrollment is not active for this wallet',
      };
    }
    const emailHashHex = await sha256HexUtf8(enrollment.verifiedEmail);
    const sourceMethod = await input.walletAuthMethodStore.getEmailOtpV2({
      walletId: String(input.walletId),
      emailHashHex,
    });
    if (
      !sourceMethod ||
      sourceMethod.kind !== 'email_otp' ||
      sourceMethod.status !== 'active' ||
      sourceMethod.walletId !== input.walletId ||
      sourceMethod.walletAuthMethodId === input.targetWalletAuthMethodId
    ) {
      return {
        kind: 'denied',
        code: 'unauthorized',
        message: 'Fresh revocation proof is not from a different active wallet method',
      };
    }
    const authority = await input.resolveEmailOtpAuthority({
      walletId: String(input.walletId),
      providerUserId: enrollment.providerUserId,
    });
    if (
      !authority.ok ||
      authority.authority.walletId !== input.walletId ||
      authority.authority.verifier.emailHashHex !== emailHashHex
    ) {
      return {
        kind: 'denied',
        code: 'unauthorized',
        message: 'Fresh Email OTP revocation authority is not active for this wallet',
      };
    }
    const expectedBindingDigest = await hashEmailOtpOperationBinding({
      walletId: String(input.walletId),
      providerUserId: enrollment.providerUserId,
      orgId: input.orgId,
      operation: WALLET_EMAIL_OTP_TRANSACTION_SIGN_OPERATION,
      requestOrigin: input.expectedOrigin,
      audience: input.expectedOrigin,
      authorityRef: await walletAuthAuthorityRef({ authority: authority.authority }),
      operationFingerprintDigest: String(input.operationFingerprintDigest),
    });
    if (expectedBindingDigest !== input.proof.ownerProofBindingDigest) {
      return {
        kind: 'denied',
        code: 'unauthorized',
        message: 'Fresh Email OTP proof is bound to another revoke operation',
      };
    }
    const verified = await input.verifyEmailOtpExisting({
      userId: enrollment.providerUserId,
      walletId: String(input.walletId),
      orgId: input.orgId,
      challengeId: input.proof.challengeId,
      otpCode: input.proof.otpCode,
      otpChannel: EMAIL_OTP_CHANNEL,
      ownerProofBindingDigest: input.proof.ownerProofBindingDigest,
      action: WALLET_EMAIL_OTP_ACTIONS.login,
      operation: WALLET_EMAIL_OTP_TRANSACTION_SIGN_OPERATION,
    });
    if (!verified.ok) {
      return {
        kind: 'denied',
        code: 'unauthorized',
        message: verified.message,
      };
    }
    return {
      kind: 'authorized',
      walletAuthMethodId: sourceMethod.walletAuthMethodId,
      verifiedAtMs: input.verifiedAtMs,
    };
  }
  if (input.proof.kind !== 'webauthn_assertion') {
    return {
      kind: 'denied',
      code: 'invalid',
      message: 'Email OTP revocation proof must use its exact operation verifier',
    };
  }
  const credentialId = webAuthnCredentialIdB64uFromCredential(input.proof.credential);
  if (!credentialId.ok) {
    return {
      kind: 'denied',
      code: 'invalid',
      message: credentialId.message,
    };
  }
  const sourceMethod = await input.walletAuthMethodStore.getPasskeyV2({
    rpId: input.proof.rpId,
    credentialIdB64u: credentialId.credentialIdB64u,
  });
  if (
    !sourceMethod ||
    sourceMethod.kind !== 'passkey' ||
    sourceMethod.status !== 'active' ||
    sourceMethod.walletId !== input.walletId ||
    sourceMethod.walletAuthMethodId === input.targetWalletAuthMethodId
  ) {
    return {
      kind: 'denied',
      code: 'unauthorized',
      message: 'Fresh revocation proof is not from a different active wallet method',
    };
  }
  const verified = await input.verifyWebAuthnAuthenticationLite({
    userId: String(input.walletId),
    rpId: input.proof.rpId,
    expectedChallenge: String(input.operationFingerprintDigest),
    webauthn_authentication: input.proof.credential,
    expected_origin: input.expectedOrigin,
  });
  if (input.proof.expectedChallengeDigestB64u !== String(input.operationFingerprintDigest)) {
    return {
      kind: 'denied',
      code: 'unauthorized',
      message: 'Fresh WebAuthn revocation proof is bound to another revoke operation',
    };
  }
  if (!verified.success || !verified.verified) {
    return {
      kind: 'denied',
      code: 'unauthorized',
      message: verified.message || 'Fresh WebAuthn revocation proof is invalid',
    };
  }
  return {
    kind: 'authorized',
    walletAuthMethodId: sourceMethod.walletAuthMethodId,
    verifiedAtMs: input.verifiedAtMs,
  };
}

export async function resolveD1AddSignerExistingAuth(input: {
  readonly auth: StartWalletAddSignerInput['auth'];
  readonly walletId: WalletId;
  readonly intent: AddSignerIntentV1;
  readonly walletAuthMethodStore: Pick<WalletAuthMethodStore, 'getPasskey'>;
  readonly nowMs: number;
}): Promise<D1AddSignerExistingAuthResolution> {
  const authorization = await resolveD1WebAuthnExistingWalletAuth({
    credential: input.auth.credential,
    rpId: input.auth.rpId,
    walletId: input.walletId,
    walletAuthMethodStore: input.walletAuthMethodStore,
  });
  if (!authorization.ok) return authorization;
  return {
    ok: true,
    auth: {
      kind: 'webauthn_assertion',
      rpId: input.auth.rpId,
      credentialIdB64u: authorization.credentialIdB64u,
    },
  };
}

export async function resolveD1AddAuthMethodExistingAuth(input: {
  readonly auth: StartWalletAddAuthMethodInput['auth'];
  readonly walletId: WalletId;
  readonly intent: AddAuthMethodIntentV1;
  readonly walletAuthMethodStore: Pick<WalletAuthMethodStore, 'getPasskey'>;
  readonly nowMs: number;
}): Promise<D1AddAuthMethodExistingAuthResolution> {
  if (input.auth.kind === 'email_otp') {
    return {
      ok: false,
      code: 'unsupported',
      message: 'Email OTP add-auth authorization requires the wallet auth service boundary',
    };
  }
  if (input.auth.kind === 'wallet_session') {
    /* R103: wallet-session authorization is resolved against active wallet
       methods in the wallet auth service boundary, not here. */
    return {
      ok: false,
      code: 'unsupported',
      message: 'Wallet Session add-auth authorization requires the wallet auth service boundary',
    };
  }

  const authorization = await resolveD1WebAuthnExistingWalletAuth({
    credential: input.auth.credential,
    rpId: input.auth.rpId,
    walletId: input.walletId,
    walletAuthMethodStore: input.walletAuthMethodStore,
  });
  if (!authorization.ok) return authorization;
  return {
    ok: true,
    auth: {
      kind: 'webauthn_assertion',
      rpId: input.auth.rpId,
      credentialIdB64u: authorization.credentialIdB64u,
    },
  };
}

export function d1HostIsWithinWebAuthnRpId(host: string, rpId: string): boolean {
  const normalizedHost = host.toLowerCase();
  const normalizedRpId = rpId.toLowerCase();
  if (!normalizedHost || !normalizedRpId) return false;
  const env = typeof process !== 'undefined' ? process.env : {};
  if (
    (env.NO_CADDY === '1' || env.VITE_NO_CADDY === '1') &&
    (normalizedHost === 'localhost' || normalizedHost === '127.0.0.1') &&
    normalizedRpId.endsWith('.localhost')
  ) {
    return true;
  }
  return normalizedHost === normalizedRpId || normalizedHost.endsWith(`.${normalizedRpId}`);
}

async function resolveD1WebAuthnExistingWalletAuth(input: {
  readonly credential: unknown;
  readonly rpId: WebAuthnRpId;
  readonly walletId: WalletId;
  readonly walletAuthMethodStore: Pick<WalletAuthMethodStore, 'getPasskey'>;
}): Promise<
  | { readonly ok: true; readonly credentialIdB64u: string }
  | { readonly ok: false; readonly code: string; readonly message: string }
> {
  const credentialId = webAuthnCredentialIdB64uFromCredential(input.credential);
  if (!credentialId.ok) return credentialId;
  const authorizationMethod = await input.walletAuthMethodStore.getPasskey({
    rpId: input.rpId,
    credentialIdB64u: credentialId.credentialIdB64u,
  });
  if (
    !authorizationMethod ||
    authorizationMethod.kind !== 'passkey' ||
    authorizationMethod.walletId !== input.walletId ||
    authorizationMethod.status !== 'active'
  ) {
    return {
      ok: false,
      code: 'unauthorized',
      message: 'WebAuthn authorization credential is not active for this wallet',
    };
  }
  return { ok: true, credentialIdB64u: credentialId.credentialIdB64u };
}
