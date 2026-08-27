import { buildLinkedDeviceTargetPreparationV1 } from '../../../packages/shared-ts/src/device-linking/parsers';
import type { LinkedDeviceTargetPreparationV1 } from '../../../packages/shared-ts/src/device-linking/contracts';
import {
  parseLinkedDeviceEnrollmentId,
  parseLinkedDeviceId,
  parseLinkDeviceSessionId,
  parseWalletKeyId,
} from '../../../packages/shared-ts/src/signing-lanes/ids';
import {
  parseWalletAuthMethodId,
  parseWalletId,
  parseWebAuthnRpId,
  parseVerifiedEmailAddress,
} from '../../../packages/shared-ts/src/utils/domainIds';
import { parseDigestB64u } from '../../../packages/shared-ts/src/utils/canonicalPrimitives';

function required<T>(
  result:
    | { readonly ok: true; readonly value: T }
    | { readonly ok: false; readonly error: { readonly message: string } },
): T {
  if (result.ok) return result.value;
  throw new Error(result.error.message);
}

const LINK_SESSION_ID = required(parseLinkDeviceSessionId('link-session:target-preparation-test'));
const WALLET_ID = required(parseWalletId('wallet:target-preparation-test'));
const ENROLLMENT_ID = required(parseLinkedDeviceEnrollmentId('enrollment:target-preparation-test'));
const DEVICE_ID = required(parseLinkedDeviceId('device:target-preparation-test'));
const WALLET_KEY_ID = required(parseWalletKeyId('wallet-key:target-preparation-test'));
const RP_ID = required(parseWebAuthnRpId('wallet.example.test'));
const TARGET_EMAIL = required(parseVerifiedEmailAddress('owner@example.test'));
const PASSKEY_CONFIGURATION_DIGEST = parseDigestB64u('-_FGSvFbB5YyBu0DYdUOH-clwdy5pelU3m_l9jzbsZ0');

function recipientRequirement(): {
  readonly kind: 'ordinary_signer_material_recipient_requirement_v1';
  readonly walletKeyId: typeof WALLET_KEY_ID;
  readonly keyFamily: 'ed25519';
} {
  return {
    kind: 'ordinary_signer_material_recipient_requirement_v1',
    walletKeyId: WALLET_KEY_ID,
    keyFamily: 'ed25519',
  };
}

function isPasskeyPreparation(
  value: LinkedDeviceTargetPreparationV1,
): value is Extract<
  LinkedDeviceTargetPreparationV1,
  { readonly targetFactor: { readonly kind: 'passkey_prf' } }
> {
  return value.targetFactor.kind === 'passkey_prf' && value.passkeyCreationOptions !== undefined;
}

function isEmailOtpPreparation(
  value: LinkedDeviceTargetPreparationV1,
): value is Extract<
  LinkedDeviceTargetPreparationV1,
  { readonly targetFactor: { readonly kind: 'email_otp' } }
> {
  return value.targetFactor.kind === 'email_otp' && value.passkeyCreationOptions === undefined;
}

export function buildPasskeyTargetPreparationFixtureV1(): Extract<
  LinkedDeviceTargetPreparationV1,
  { readonly targetFactor: { readonly kind: 'passkey_prf' } }
> {
  const walletAuthMethodId = required(
    parseWalletAuthMethodId('passkey:wallet.example.test:target-preparation-test'),
  );
  const preparation = buildLinkedDeviceTargetPreparationV1({
    linkSessionId: LINK_SESSION_ID,
    walletId: WALLET_ID,
    enrollmentId: ENROLLMENT_ID,
    deviceId: DEVICE_ID,
    walletAuthMethodId,
    ed25519ExportRoot: null,
    targetFactor: { kind: 'passkey_prf' },
    passkeyConfigurationDigestB64u: PASSKEY_CONFIGURATION_DIGEST,
    passkeyCreationOptions: {
      kind: 'webauthn_add_auth_method_registration_v1',
      walletAuthMethodId,
      challengeId: 'target-preparation-challenge-id',
      challengeB64u: 'target-preparation-challenge',
      rpId: RP_ID,
      user: {
        idB64u: 'dGFyZ2V0LXByZXBhcmF0aW9u',
        name: String(WALLET_ID),
        displayName: String(WALLET_ID),
      },
      pubKeyCredParams: [
        { type: 'public-key', alg: -7 },
        { type: 'public-key', alg: -257 },
      ],
      authenticatorSelection: {
        residentKey: 'required',
        userVerification: 'preferred',
      },
      timeoutMs: 60_000,
      attestation: 'none',
      extensions: {
        prf: {
          eval: {
            firstB64u: 'target-preparation-first-salt',
            secondB64u: 'target-preparation-second-salt',
          },
        },
      },
      excludeCredentials: [],
    },
    ordinarySignerMaterialRecipientRequirements: [recipientRequirement()],
    issuedAtMs: 1_000,
    expiresAtMs: 2_000,
  });
  if (!isPasskeyPreparation(preparation)) {
    throw new Error('passkey target preparation fixture has the wrong factor');
  }
  return preparation;
}

export function buildEmailOtpTargetPreparationFixtureV1(): Extract<
  LinkedDeviceTargetPreparationV1,
  { readonly targetFactor: { readonly kind: 'email_otp' } }
> {
  const walletAuthMethodId = required(
    parseWalletAuthMethodId('email_otp:wallet:target-preparation-test'),
  );
  const baseWalletAuthMethodId = required(
    parseWalletAuthMethodId('email_otp:wallet:target-preparation-base'),
  );
  const preparation = buildLinkedDeviceTargetPreparationV1({
    linkSessionId: LINK_SESSION_ID,
    walletId: WALLET_ID,
    enrollmentId: ENROLLMENT_ID,
    deviceId: DEVICE_ID,
    walletAuthMethodId,
    ed25519ExportRoot: null,
    targetFactor: { kind: 'email_otp' },
    targetEmail: TARGET_EMAIL,
    enrollment: { kind: 'existing_enrollment' },
    baseWalletAuthMethodId,
    ordinarySignerMaterialRecipientRequirements: [recipientRequirement()],
    issuedAtMs: 1_000,
    expiresAtMs: 2_000,
  });
  if (!isEmailOtpPreparation(preparation)) {
    throw new Error('Email OTP target preparation fixture has the wrong factor');
  }
  return preparation;
}
