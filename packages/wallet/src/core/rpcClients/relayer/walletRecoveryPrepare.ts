import { buildRelayerJsonPostRequestInit, normalizeRelayerBaseUrl } from './relayerHttp';
import {
  parseDigestField,
  parseEnvelopeCiphertextB64u,
  parseEnvelopeNonceB64u,
  parseUnixMs,
  rejectUnknownFields,
  requireRecord,
  type EnvelopeCiphertextB64u,
  type EnvelopeNonceB64u,
} from '@shared/passkey-custody';
import {
  parseWalletRecoveryEnvelopeEntry,
  type WalletRecoveryEnvelopeEntry,
} from '@shared/wallet-recovery';
import type { DigestB64u } from '@shared/utils';
import { parseRouterAbMpcMaterialActivationRef } from '@shared/utils/routerAbNormalSigningIdentity';
import type {
  RouterAbEd25519YaoApplicationBindingFactsV1,
  RouterAbEd25519YaoBytes32V1,
  RouterAbEd25519YaoLifecycleScopeV1,
} from '@shared/utils/routerAbEd25519Yao';
import {
  parseRouterAbEcdsaDerivationPublicCapabilityV1,
  parseRouterAbEcdsaRegistrationActivationReceiptV1,
  type RouterAbEcdsaRegistrationActivationReceiptV1,
  type RouterAbEcdsaDerivationPublicCapabilityV1,
} from '@shared/utils/routerAbEcdsaDerivation';
import {
  parseWalletRecoveryEcdsaPossessionChallengeV1,
  type WalletRecoveryEcdsaPossessionChallengeV1,
} from '@shared/wallet-recovery/walletRecoveryEcdsaPossession';
import {
  parseEcdsaServerGeneration,
  type EcdsaServerGeneration,
} from '@shared/utils/ecdsaCapabilityActivation';
import {
  normalizeRuntimePolicyScope,
  type RuntimePolicyScope,
} from '@shared/threshold/signingRootScope';
import {
  parseWebAuthnCredentialIdB64u,
  parseWebAuthnRpId,
  parseWalletAuthMethodId,
  parseWalletAuthorityId,
  parseWalletRecoveryOperationId,
  parseWalletId,
  type WalletId,
  type WebAuthnCredentialIdB64u,
  type WebAuthnRpId,
  type WalletAuthMethodId,
  type WalletAuthorityId,
  type WalletRecoveryOperationId,
} from '@shared/utils/domainIds';
import { parseDeviceId, type DeviceId } from '@shared/authorization/capabilityKinds';
import { base64UrlDecode, base64UrlEncode } from '@shared/utils/encoders';
import {
  PASSKEY_PRF_FIRST_SALT_V1,
  PASSKEY_PRF_SECOND_SALT_V1,
} from '@shared/utils/signingSessionSeal';
import {
  ecdsaClientRootPublicKey33B64uFromString,
  parseSdkEcdsaDerivationSigningRootId,
  parseSdkEcdsaDerivationSigningRootVersion,
  parseSdkEcdsaDerivationThresholdKeyId,
  type EcdsaClientRootPublicKey33B64u,
  type EcdsaThresholdKeyId,
  type SigningRootId,
  type SigningRootVersion,
} from '@shared/threshold/ecdsaDerivationRoleLocalBootstrap';
import type { ThresholdEcdsaChainTarget } from '@/core/platform/types';
import { requireEvmFamilySigningKeySlotId } from '@shared/signing-lanes';
import {
  parseRecoveryCodeReservationId,
  type RecoveryCodeReservationId,
} from '@shared/wallet-recovery/recoveryCodeReservation';
import {
  parseWalletRecoveryTargetV1,
  type WalletRecoveryTargetV1,
} from '@shared/wallet-recovery/walletRecoveryTarget';

/**
 * Preparing an admitted wallet recovery.
 *
 * The response is ciphertext: a wrapped manifest KEK and the entry ciphertexts
 * it opens. The code never leaves this call, and the server cannot open what
 * it returns — it only matched a derived identifier against stored wraps.
 *
 * Unknown and malformed codes remain generic. A consumed code has a durable
 * locator tombstone and receives the distinct `consumed` result used by the
 * recovery menu.
 *
 * `conflict` is the exception worth distinguishing, because it is the one
 * failure where the same code is still worth trying again.
 */

const WALLET_RECOVERY_PREPARE_PATH = '/wallets/recovery/prepare';

export type WalletRecoveryPreparationKeyManifestEntry =
  | {
      readonly kind: 'near_ed25519';
      readonly keySetId: `near_ed25519:${string}`;
      readonly signerId: string;
      readonly nearAccountId: string;
      readonly recordedKeyManifestDigestB64u: DigestB64u;
      readonly recoveryBasis: WalletRecoveryPreparationNearRecoveryBasis;
    }
  | {
      readonly kind: 'evm_family_ecdsa';
      readonly keySetId: `evm_family_ecdsa:${string}`;
      readonly keyHandle: string;
      readonly evmFamilySigningKeySlotId: string;
      readonly recordedKeyManifestDigestB64u: DigestB64u;
      readonly recoveryBasis: WalletRecoveryPreparationEcdsaRecoveryBasis;
    };

export type WalletRecoveryPreparationNearRecoveryBasis = {
  readonly capabilityKind: 'registration' | 'recovery';
  readonly activeCapabilityBinding: RouterAbEd25519YaoBytes32V1;
  readonly scope: RouterAbEd25519YaoLifecycleScopeV1;
  readonly applicationBinding: RouterAbEd25519YaoApplicationBindingFactsV1;
  readonly participantIds: readonly [number, number];
  readonly registeredPublicKey: RouterAbEd25519YaoBytes32V1;
  readonly runtimePolicyScope: RuntimePolicyScope;
  readonly activationTranscript: RouterAbEd25519YaoBytes32V1;
  readonly activationStateEpoch: number;
  readonly signingWorkerVerifyingShare: RouterAbEd25519YaoBytes32V1;
};

export type WalletRecoveryPreparationEcdsaRecoveryBasis = {
  readonly publicCapability: RouterAbEcdsaDerivationPublicCapabilityV1;
  readonly activationReceipt: RouterAbEcdsaRegistrationActivationReceiptV1;
  readonly serverGeneration: EcdsaServerGeneration;
  readonly clientRootPublicKey33B64u: EcdsaClientRootPublicKey33B64u;
  readonly chainTargets: readonly [ThresholdEcdsaChainTarget, ...ThresholdEcdsaChainTarget[]];
  readonly ecdsaThresholdKeyId: EcdsaThresholdKeyId;
  readonly signingRootId: SigningRootId;
  readonly signingRootVersion: SigningRootVersion;
  readonly runtimePolicyScope: RuntimePolicyScope;
  readonly participantIds: readonly [1, 2];
  readonly possessionChallenge: WalletRecoveryEcdsaPossessionChallengeV1;
};

export type WalletCustodyUnlockKeyManifestEntry =
  | {
      readonly kind: 'near_ed25519';
      readonly keySetId: `near_ed25519:${string}`;
      readonly signerId: string;
      readonly nearAccountId: string;
      readonly nearEd25519SigningKeyId: string;
      readonly signerSlot: number;
      readonly registeredPublicKeyB64u: string;
      readonly recordedKeyManifestDigestB64u: DigestB64u;
      readonly activeCapabilityBinding: readonly number[];
    }
  | {
      readonly kind: 'evm_family_ecdsa';
      readonly keySetId: `evm_family_ecdsa:${string}`;
      readonly keyHandle: string;
      readonly evmFamilySigningKeySlotId: string;
      readonly recordedKeyManifestDigestB64u: DigestB64u;
      readonly clientRootPublicKey33B64u: EcdsaClientRootPublicKey33B64u;
      readonly applicationBindingDigestB64u: DigestB64u;
      readonly chainTargetKeys: readonly string[];
    };

export type WalletCustodyUnlockKeyManifest = {
  readonly version: 'wallet_custody_unlock_key_manifest_v1';
  readonly walletId: string;
  readonly entries: readonly WalletCustodyUnlockKeyManifestEntry[];
};

export type WalletRecoveryPreparationKeyManifest = {
  readonly version: 'wallet_recovery_preparation_key_manifest_v1';
  readonly walletId: string;
  readonly entries: readonly WalletRecoveryPreparationKeyManifestEntry[];
};

export type WalletRecoveryRegistrationCredentialDescriptor = {
  readonly type: 'public-key';
  readonly id: WebAuthnCredentialIdB64u;
};

export type WalletRecoveryRegistrationOptions = {
  readonly kind: 'webauthn_recovery_registration_v1';
  readonly challengeId: string;
  readonly challengeB64u: string;
  readonly replacementId: string;
  readonly walletAuthMethodId: WalletAuthMethodId;
  readonly rpId: WebAuthnRpId;
  readonly user: {
    readonly idB64u: string;
    readonly name: string;
    readonly displayName: string;
  };
  readonly pubKeyCredParams: readonly [
    { readonly type: 'public-key'; readonly alg: -7 },
    { readonly type: 'public-key'; readonly alg: -257 },
  ];
  readonly authenticatorSelection: {
    readonly residentKey: 'required';
    readonly userVerification: 'preferred';
  };
  readonly timeoutMs: number;
  readonly attestation: 'none';
  readonly extensions: {
    readonly prf: {
      readonly eval: {
        readonly firstB64u: string;
        readonly secondB64u: string;
      };
    };
  };
  readonly excludeCredentials: readonly WalletRecoveryRegistrationCredentialDescriptor[];
};

export type WalletRecoveryAttemptFailure =
  | { readonly kind: 'refused' }
  | { readonly kind: 'retryable_conflict' }
  | { readonly kind: 'transport_uncertain' };

export type WalletRecoveryPrepareResult =
  | (WalletRecoveryPrepareResultCommon & {
      readonly target: Extract<WalletRecoveryTargetV1, { readonly kind: 'passkey' }>;
      readonly registration: WalletRecoveryRegistrationOptions;
    })
  | (WalletRecoveryPrepareResultCommon & {
      readonly target: Extract<WalletRecoveryTargetV1, { readonly kind: 'google_email_otp' }>;
      readonly registration?: never;
    })
  | WalletRecoveryAttemptFailure
  | { readonly kind: 'consumed' };

type WalletRecoveryPrepareResultCommon = {
  readonly kind: 'prepared';
  readonly walletId: WalletId;
  readonly recoveryOperationId: WalletRecoveryOperationId;
  readonly targetDeviceId: DeviceId;
  readonly targetAuthorityId: WalletAuthorityId;
  readonly targetWalletAuthMethodId: WalletAuthMethodId;
  readonly wrap: {
    readonly nonceB64u: EnvelopeNonceB64u;
    readonly wrappedManifestKekB64u: EnvelopeCiphertextB64u;
    readonly aadHashB64u: DigestB64u;
  };
  readonly entries: readonly [WalletRecoveryEnvelopeEntry];
  readonly keyManifest: WalletRecoveryPreparationKeyManifest;
  readonly reservationId: RecoveryCodeReservationId;
  readonly reservationExpiresAtMs: number;
  readonly storeVersion: string;
};

export type PreparedWalletRecovery = Extract<
  WalletRecoveryPrepareResult,
  { readonly kind: 'prepared' }
>;

/**
 * Builds the only recovery-custody wire accepted by the ceremony WASM.
 *
 * The recovery key id and code are absent. Rust derives the id from the code
 * bytes supplied through the worker's separate secret field, so serialized
 * custody can contain only the reserved wrap and the wallet's single seed
 * entry.
 */
export function buildWalletRecoveryCeremonyCustodyJson(args: {
  readonly walletId: string;
  readonly prepared: PreparedWalletRecovery;
}): string {
  const walletId = parseWalletId(args.walletId);
  if (!walletId.ok) throw new Error(`wallet recovery ${walletId.error.message}`);
  return JSON.stringify({
    walletId: String(walletId.value),
    wrap: args.prepared.wrap,
    entry: args.prepared.entries[0],
  });
}

export async function prepareWalletRecoveryWithCode(args: {
  readonly relayUrl: string;
  readonly target: WalletRecoveryTargetV1;
  readonly recoveryCodeB64u: string;
  readonly reservationId: RecoveryCodeReservationId;
  readonly fetchImpl?: typeof fetch;
}): Promise<WalletRecoveryPrepareResult> {
  const requested = await requestWalletRecoveryPrepare(args);
  if (!requested.ok) return { kind: requested.kind };
  return await parseWalletRecoveryPrepareResponse({
    response: requested.response,
    target: args.target,
    reservationId: args.reservationId,
  });
}

async function requestWalletRecoveryPrepare(args: {
  readonly relayUrl: string;
  readonly target: WalletRecoveryTargetV1;
  readonly recoveryCodeB64u: string;
  readonly reservationId: RecoveryCodeReservationId;
  readonly fetchImpl?: typeof fetch;
}): Promise<
  | { readonly ok: true; readonly response: Response }
  | { readonly ok: false; readonly kind: 'transport_uncertain' }
> {
  const url = `${normalizeRelayerBaseUrl(args.relayUrl)}${WALLET_RECOVERY_PREPARE_PATH}`;
  const doFetch = args.fetchImpl || fetch;

  try {
    const response = await doFetch(
      url,
      buildRelayerJsonPostRequestInit({
        body: {
          recoveryCodeB64u: args.recoveryCodeB64u,
          reservationId: args.reservationId,
          target: args.target,
        },
      }),
    );
    return { ok: true, response };
  } catch {
    return { ok: false, kind: 'transport_uncertain' };
  }
}

async function parseWalletRecoveryPrepareResponse(args: {
  readonly response: Response;
  readonly target: WalletRecoveryTargetV1;
  readonly reservationId: RecoveryCodeReservationId;
}): Promise<WalletRecoveryPrepareResult> {
  const response = args.response;
  const bodyUnknown: unknown = await response.json().catch(() => ({}));
  const body = isRecord(bodyUnknown) ? bodyUnknown : {};
  if (response.status === 200 && body.ok === true) {
    try {
      rejectUnknownFields(
        body,
        [
          'ok',
          'walletId',
          'target',
          'recoveryOperationId',
          'targetDeviceId',
          'targetAuthorityId',
          'targetWalletAuthMethodId',
          'wrap',
          'entries',
          'keyManifest',
          'registration',
          'reservationId',
          'reservationExpiresAtMs',
          'storeVersion',
        ],
        'walletRecoveryPrepare',
      );
      const wrap = parsePreparedRecoveryWrap(body.wrap);
      const entries = parsePreparedRecoveryEntries(body.entries);
      const walletIdResult = parseWalletId(body.walletId);
      if (!walletIdResult.ok) throw new Error('walletRecoveryPrepare.walletId is invalid');
      const walletId = walletIdResult.value;
      const target = parseWalletRecoveryTargetV1(body.target);
      if (!recoveryTargetsMatch(target, args.target)) {
        throw new Error('wallet recovery preparation changed the recovery target');
      }
      const recoveryOperationId = parseWalletRecoveryOperationId(body.recoveryOperationId);
      const targetDeviceId = parseDeviceId(body.targetDeviceId);
      const targetAuthorityId = parseWalletAuthorityId(body.targetAuthorityId);
      const targetWalletAuthMethodId = parseWalletAuthMethodId(body.targetWalletAuthMethodId);
      if (
        !recoveryOperationId.ok ||
        !targetDeviceId.ok ||
        !targetAuthorityId.ok ||
        !targetWalletAuthMethodId.ok
      ) {
        throw new Error('wallet recovery preparation target identity is invalid');
      }
      const keyManifest = parseWalletRecoveryPreparationKeyManifest(body.keyManifest, walletId);
      const reservationId = parseRecoveryCodeReservationId(body.reservationId);
      const reservationExpiresAtMs = parseUnixMs(
        body.reservationExpiresAtMs,
        'walletRecoveryPrepare.reservationExpiresAtMs',
      );
      const storeVersion = requireResponseString(body.storeVersion, 'storeVersion');
      if (reservationId !== args.reservationId) {
        throw new Error('wallet recovery preparation changed the reservation identity');
      }
      const common = {
        kind: 'prepared' as const,
        walletId,
        recoveryOperationId: recoveryOperationId.value,
        targetDeviceId: targetDeviceId.value,
        targetAuthorityId: targetAuthorityId.value,
        targetWalletAuthMethodId: targetWalletAuthMethodId.value,
        wrap,
        entries,
        keyManifest,
        reservationId,
        reservationExpiresAtMs,
        storeVersion,
      };
      switch (target.kind) {
        case 'passkey': {
          const registration = parseWalletRecoveryRegistrationOptions(
            body.registration,
            String(walletId),
            target.rpId,
          );
          if (registration.walletAuthMethodId !== targetWalletAuthMethodId.value) {
            throw new Error('wallet recovery registration changed the target auth method');
          }
          return { ...common, target, registration };
        }
        case 'google_email_otp':
          if (Object.prototype.hasOwnProperty.call(body, 'registration')) {
            throw new Error('Google Email OTP recovery cannot carry passkey registration');
          }
          return { ...common, target };
        default:
          return assertNeverRecoveryTarget(target);
      }
    } catch {
      return { kind: 'transport_uncertain' };
    }
  }

  if (response.status === 409) {
    return { kind: 'retryable_conflict' };
  }
  if (response.status === 401 && body.code === 'recovery_code_used') {
    return { kind: 'consumed' };
  }
  if (response.status === 401 || response.status === 400) {
    return { kind: 'refused' };
  }
  return { kind: 'transport_uncertain' };
}

function parseWalletRecoveryRegistrationOptions(
  raw: unknown,
  expectedWalletId: string,
  expectedRpId: WebAuthnRpId,
): WalletRecoveryRegistrationOptions {
  const registration = requireRecord(raw, 'walletRecoveryPrepare.registration');
  rejectUnknownFields(
    registration,
    [
      'kind',
      'challengeId',
      'challengeB64u',
      'replacementId',
      'walletAuthMethodId',
      'rpId',
      'user',
      'pubKeyCredParams',
      'authenticatorSelection',
      'timeoutMs',
      'attestation',
      'extensions',
      'excludeCredentials',
    ],
    'walletRecoveryPrepare.registration',
  );
  if (registration.kind !== 'webauthn_recovery_registration_v1') {
    throw new Error('walletRecoveryPrepare.registration kind is invalid');
  }
  const challengeId = requireResponseString(registration.challengeId, 'registration.challengeId');
  const challengeB64u = requireCanonicalBytesB64u(
    registration.challengeB64u,
    32,
    'registration.challengeB64u',
  );
  const replacementId = requireResponseString(
    registration.replacementId,
    'registration.replacementId',
  );
  const walletAuthMethodId = parseWalletAuthMethodId(registration.walletAuthMethodId);
  if (!walletAuthMethodId.ok) {
    throw new Error('walletRecoveryPrepare.registration.walletAuthMethodId is invalid');
  }
  const rpIdResult = parseWebAuthnRpId(registration.rpId);
  if (!rpIdResult.ok) throw new Error('walletRecoveryPrepare.registration.rpId is invalid');
  if (rpIdResult.value !== expectedRpId) {
    throw new Error('walletRecoveryPrepare.registration changed the relying party');
  }

  const user = requireRecord(registration.user, 'walletRecoveryPrepare.registration.user');
  rejectUnknownFields(
    user,
    ['idB64u', 'name', 'displayName'],
    'walletRecoveryPrepare.registration.user',
  );
  const expectedUserIdB64u = base64UrlEncode(new TextEncoder().encode(expectedWalletId));
  const idB64u = requireCanonicalNonEmptyB64u(user.idB64u, 'registration.user.idB64u');
  if (idB64u !== expectedUserIdB64u) {
    throw new Error('walletRecoveryPrepare.registration user is bound to another wallet');
  }
  const name = requireResponseString(user.name, 'registration.user.name');
  const displayName = requireResponseString(user.displayName, 'registration.user.displayName');
  if (name !== expectedWalletId || displayName !== expectedWalletId) {
    throw new Error('walletRecoveryPrepare.registration user labels changed the wallet identity');
  }

  const pubKeyCredParams = parseRecoveryPublicKeyParameters(registration.pubKeyCredParams);
  const authenticatorSelection = parseRecoveryAuthenticatorSelection(
    registration.authenticatorSelection,
  );
  const timeoutMs = Number(registration.timeoutMs);
  if (!Number.isSafeInteger(timeoutMs) || timeoutMs <= 0) {
    throw new Error('walletRecoveryPrepare.registration.timeoutMs is invalid');
  }
  if (registration.attestation !== 'none') {
    throw new Error('walletRecoveryPrepare.registration.attestation is invalid');
  }
  const extensions = parseRecoveryPrfExtensions(registration.extensions);
  const excludeCredentials = parseRecoveryExcludeCredentials(registration.excludeCredentials);
  return {
    kind: 'webauthn_recovery_registration_v1',
    challengeId,
    challengeB64u,
    replacementId,
    walletAuthMethodId: walletAuthMethodId.value,
    rpId: rpIdResult.value,
    user: { idB64u, name, displayName },
    pubKeyCredParams,
    authenticatorSelection,
    timeoutMs,
    attestation: 'none',
    extensions,
    excludeCredentials,
  };
}

function parseRecoveryPrfExtensions(raw: unknown): WalletRecoveryRegistrationOptions['extensions'] {
  const extensions = requireRecord(raw, 'walletRecoveryPrepare.registration.extensions');
  rejectUnknownFields(extensions, ['prf'], 'walletRecoveryPrepare.registration.extensions');
  const prf = requireRecord(extensions.prf, 'walletRecoveryPrepare.registration.extensions.prf');
  rejectUnknownFields(prf, ['eval'], 'walletRecoveryPrepare.registration.extensions.prf');
  const evaluation = requireRecord(
    prf.eval,
    'walletRecoveryPrepare.registration.extensions.prf.eval',
  );
  rejectUnknownFields(
    evaluation,
    ['firstB64u', 'secondB64u'],
    'walletRecoveryPrepare.registration.extensions.prf.eval',
  );
  const firstB64u = requireCanonicalBytesB64u(
    evaluation.firstB64u,
    PASSKEY_PRF_FIRST_SALT_V1.length,
    'registration.extensions.prf.eval.firstB64u',
  );
  const secondB64u = requireCanonicalBytesB64u(
    evaluation.secondB64u,
    PASSKEY_PRF_SECOND_SALT_V1.length,
    'registration.extensions.prf.eval.secondB64u',
  );
  if (
    firstB64u !== base64UrlEncode(PASSKEY_PRF_FIRST_SALT_V1) ||
    secondB64u !== base64UrlEncode(PASSKEY_PRF_SECOND_SALT_V1)
  ) {
    throw new Error('walletRecoveryPrepare.registration PRF salts are unsupported');
  }
  return { prf: { eval: { firstB64u, secondB64u } } };
}

function parseRecoveryPublicKeyParameters(
  raw: unknown,
): WalletRecoveryRegistrationOptions['pubKeyCredParams'] {
  if (!Array.isArray(raw) || raw.length !== 2) {
    throw new Error('walletRecoveryPrepare.registration.pubKeyCredParams is invalid');
  }
  const first = requireRecord(raw[0], 'walletRecoveryPrepare.registration.pubKeyCredParams[0]');
  const second = requireRecord(raw[1], 'walletRecoveryPrepare.registration.pubKeyCredParams[1]');
  rejectUnknownFields(
    first,
    ['type', 'alg'],
    'walletRecoveryPrepare.registration.pubKeyCredParams[0]',
  );
  rejectUnknownFields(
    second,
    ['type', 'alg'],
    'walletRecoveryPrepare.registration.pubKeyCredParams[1]',
  );
  if (first.type !== 'public-key' || first.alg !== -7) {
    throw new Error('walletRecoveryPrepare.registration.pubKeyCredParams[0] is invalid');
  }
  if (second.type !== 'public-key' || second.alg !== -257) {
    throw new Error('walletRecoveryPrepare.registration.pubKeyCredParams[1] is invalid');
  }
  return [
    { type: 'public-key', alg: -7 },
    { type: 'public-key', alg: -257 },
  ];
}

function parseRecoveryAuthenticatorSelection(
  raw: unknown,
): WalletRecoveryRegistrationOptions['authenticatorSelection'] {
  const selection = requireRecord(raw, 'walletRecoveryPrepare.registration.authenticatorSelection');
  rejectUnknownFields(
    selection,
    ['residentKey', 'userVerification'],
    'walletRecoveryPrepare.registration.authenticatorSelection',
  );
  if (selection.residentKey !== 'required' || selection.userVerification !== 'preferred') {
    throw new Error('walletRecoveryPrepare.registration.authenticatorSelection is invalid');
  }
  return { residentKey: 'required', userVerification: 'preferred' };
}

function parseRecoveryExcludeCredentials(
  raw: unknown,
): readonly WalletRecoveryRegistrationCredentialDescriptor[] {
  if (!Array.isArray(raw)) {
    throw new Error('walletRecoveryPrepare.registration.excludeCredentials is invalid');
  }
  return raw.map((entry, index) => {
    const descriptor = requireRecord(
      entry,
      `walletRecoveryPrepare.registration.excludeCredentials[${index}]`,
    );
    rejectUnknownFields(
      descriptor,
      ['type', 'id'],
      `walletRecoveryPrepare.registration.excludeCredentials[${index}]`,
    );
    if (descriptor.type !== 'public-key') {
      throw new Error('walletRecoveryPrepare.registration.excludeCredentials type is invalid');
    }
    const parsedId = parseWebAuthnCredentialIdB64u(descriptor.id);
    if (!parsedId.ok) {
      throw new Error('walletRecoveryPrepare.registration.excludeCredentials id is invalid');
    }
    requireCanonicalNonEmptyB64u(parsedId.value, 'registration.excludeCredentials.id');
    return {
      type: 'public-key',
      id: parsedId.value,
    };
  });
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function recoveryTargetsMatch(
  left: WalletRecoveryTargetV1,
  right: WalletRecoveryTargetV1,
): boolean {
  if (left.kind !== right.kind) return false;
  switch (left.kind) {
    case 'passkey':
      return right.kind === 'passkey' && left.rpId === right.rpId;
    case 'google_email_otp':
      return right.kind === 'google_email_otp' && left.googleProvider === right.googleProvider;
    default:
      return assertNeverRecoveryTarget(left);
  }
}

function assertNeverRecoveryTarget(value: never): never {
  throw new Error(`unsupported wallet recovery target: ${String(value)}`);
}

const PREPARED_WRAP_FIELDS = ['nonceB64u', 'wrappedManifestKekB64u', 'aadHashB64u'] as const;

function parsePreparedRecoveryWrap(raw: unknown): {
  readonly nonceB64u: EnvelopeNonceB64u;
  readonly wrappedManifestKekB64u: EnvelopeCiphertextB64u;
  readonly aadHashB64u: DigestB64u;
} {
  const wrap = requireRecord(raw, 'walletRecoveryPrepare.wrap');
  rejectUnknownFields(wrap, PREPARED_WRAP_FIELDS, 'walletRecoveryPrepare.wrap');
  return {
    nonceB64u: parseEnvelopeNonceB64u(wrap.nonceB64u, 'walletRecoveryPrepare.wrap.nonceB64u'),
    wrappedManifestKekB64u: parseEnvelopeCiphertextB64u(
      wrap.wrappedManifestKekB64u,
      'walletRecoveryPrepare.wrap.wrappedManifestKekB64u',
    ),
    aadHashB64u: parseDigestField(wrap.aadHashB64u, 'walletRecoveryPrepare.wrap.aadHashB64u'),
  };
}

function parsePreparedRecoveryEntries(raw: unknown): readonly [WalletRecoveryEnvelopeEntry] {
  if (!Array.isArray(raw) || raw.length !== 1) {
    throw new Error('walletRecoveryPrepare.entries must contain exactly one custody seed');
  }
  return [parseWalletRecoveryEnvelopeEntry(raw[0], 'walletRecoveryPrepare.entries[0]')];
}

function requireResponseString(raw: unknown, field: string): string {
  if (typeof raw !== 'string' || !raw.trim()) {
    throw new Error(`walletRecoveryPrepare.${field} must be a non-empty string`);
  }
  return raw.trim();
}

export function parseWalletRecoveryPreparationKeyManifest(
  raw: unknown,
  expectedWalletId: string,
): WalletRecoveryPreparationKeyManifest {
  const manifest = requireRecord(raw, 'walletRecoveryPrepare.keyManifest');
  rejectUnknownFields(
    manifest,
    ['version', 'walletId', 'entries'],
    'walletRecoveryPrepare.keyManifest',
  );
  if (manifest.version !== 'wallet_recovery_preparation_key_manifest_v1') {
    throw new Error('walletRecoveryPrepare.keyManifest version is invalid');
  }
  const walletId = requireResponseString(manifest.walletId, 'keyManifest.walletId');
  if (walletId !== expectedWalletId) {
    throw new Error('walletRecoveryPrepare.keyManifest changed the wallet identity');
  }
  if (!Array.isArray(manifest.entries) || manifest.entries.length === 0) {
    throw new Error('walletRecoveryPrepare.keyManifest must contain a key set');
  }
  const entries = manifest.entries.map((entry) =>
    parseWalletRecoveryPreparationKeyManifestEntry(entry, walletId),
  );
  const keySetIds = new Set(entries.map((entry) => entry.keySetId));
  if (keySetIds.size !== entries.length) {
    throw new Error('walletRecoveryPrepare.keyManifest contains duplicate key sets');
  }
  return {
    version: 'wallet_recovery_preparation_key_manifest_v1',
    walletId,
    entries,
  };
}

export function parseWalletCustodyUnlockKeyManifest(
  raw: unknown,
  expectedWalletId: string,
): WalletCustodyUnlockKeyManifest {
  const manifest = requireRecord(raw, 'walletCustodyUnlock.keyManifest');
  rejectUnknownFields(
    manifest,
    ['version', 'walletId', 'entries'],
    'walletCustodyUnlock.keyManifest',
  );
  if (manifest.version !== 'wallet_custody_unlock_key_manifest_v1') {
    throw new Error('walletCustodyUnlock.keyManifest version is invalid');
  }
  const walletId = requireResponseString(manifest.walletId, 'walletCustodyUnlock.walletId');
  if (walletId !== expectedWalletId) {
    throw new Error('walletCustodyUnlock.keyManifest changed the wallet identity');
  }
  if (!Array.isArray(manifest.entries) || manifest.entries.length === 0) {
    throw new Error('walletCustodyUnlock.keyManifest must contain a key set');
  }
  const entries = manifest.entries.map(parseWalletCustodyUnlockKeyManifestEntry);
  const keySetIds = new Set(entries.map((entry) => entry.keySetId));
  if (keySetIds.size !== entries.length) {
    throw new Error('walletCustodyUnlock.keyManifest contains duplicate key sets');
  }
  return {
    version: 'wallet_custody_unlock_key_manifest_v1',
    walletId,
    entries,
  };
}

function parseWalletCustodyUnlockKeyManifestEntry(
  raw: unknown,
): WalletCustodyUnlockKeyManifestEntry {
  const entry = requireRecord(raw, 'walletCustodyUnlock.keyManifest.entries[]');
  switch (entry.kind) {
    case 'near_ed25519': {
      rejectUnknownFields(
        entry,
        [
          'kind',
          'keySetId',
          'signerId',
          'nearAccountId',
          'nearEd25519SigningKeyId',
          'signerSlot',
          'registeredPublicKeyB64u',
          'recordedKeyManifestDigestB64u',
          'activeCapabilityBinding',
        ],
        'walletCustodyUnlock.keyManifest.entries[].near_ed25519',
      );
      const signerId = requireResponseString(entry.signerId, 'walletCustodyUnlock.signerId');
      const suppliedKeySetId = requireResponseString(
        entry.keySetId,
        'walletCustodyUnlock.keySetId',
      );
      const keySetId = `near_ed25519:${signerId}` as const;
      if (suppliedKeySetId !== keySetId) {
        throw new Error('walletCustodyUnlock NEAR key-set identity is inconsistent');
      }
      const signerSlot = Number(entry.signerSlot);
      if (!Number.isSafeInteger(signerSlot) || signerSlot <= 0) {
        throw new Error('walletCustodyUnlock NEAR signer slot is invalid');
      }
      return {
        kind: 'near_ed25519',
        keySetId,
        signerId,
        nearAccountId: requireResponseString(
          entry.nearAccountId,
          'walletCustodyUnlock.nearAccountId',
        ),
        nearEd25519SigningKeyId: requireResponseString(
          entry.nearEd25519SigningKeyId,
          'walletCustodyUnlock.nearEd25519SigningKeyId',
        ),
        signerSlot,
        registeredPublicKeyB64u: requireCanonicalBytesB64u(
          entry.registeredPublicKeyB64u,
          32,
          'walletCustodyUnlock.registeredPublicKeyB64u',
        ),
        recordedKeyManifestDigestB64u: parseDigestField(
          entry.recordedKeyManifestDigestB64u,
          'walletCustodyUnlock.recordedKeyManifestDigestB64u',
        ),
        activeCapabilityBinding: requireByteArray(
          entry.activeCapabilityBinding,
          32,
          'walletCustodyUnlock.activeCapabilityBinding',
        ),
      };
    }
    case 'evm_family_ecdsa': {
      rejectUnknownFields(
        entry,
        [
          'kind',
          'keySetId',
          'keyHandle',
          'evmFamilySigningKeySlotId',
          'recordedKeyManifestDigestB64u',
          'clientRootPublicKey33B64u',
          'applicationBindingDigestB64u',
          'chainTargetKeys',
        ],
        'walletCustodyUnlock.keyManifest.entries[].evm_family_ecdsa',
      );
      const keyHandle = requireResponseString(entry.keyHandle, 'walletCustodyUnlock.keyHandle');
      const suppliedKeySetId = requireResponseString(
        entry.keySetId,
        'walletCustodyUnlock.keySetId',
      );
      const keySetId = `evm_family_ecdsa:${keyHandle}` as const;
      if (suppliedKeySetId !== keySetId) {
        throw new Error('walletCustodyUnlock ECDSA key-set identity is inconsistent');
      }
      if (!Array.isArray(entry.chainTargetKeys) || entry.chainTargetKeys.length === 0) {
        throw new Error('walletCustodyUnlock ECDSA key set has no chain targets');
      }
      return {
        kind: 'evm_family_ecdsa',
        keySetId,
        keyHandle,
        evmFamilySigningKeySlotId: requireEvmFamilySigningKeySlotId(
          entry.evmFamilySigningKeySlotId,
        ),
        recordedKeyManifestDigestB64u: parseDigestField(
          entry.recordedKeyManifestDigestB64u,
          'walletCustodyUnlock.recordedKeyManifestDigestB64u',
        ),
        clientRootPublicKey33B64u: ecdsaClientRootPublicKey33B64uFromString(
          requireResponseString(
            entry.clientRootPublicKey33B64u,
            'walletCustodyUnlock.clientRootPublicKey33B64u',
          ),
        ),
        applicationBindingDigestB64u: parseDigestField(
          entry.applicationBindingDigestB64u,
          'walletCustodyUnlock.applicationBindingDigestB64u',
        ),
        chainTargetKeys: entry.chainTargetKeys.map((value) =>
          requireResponseString(value, 'walletCustodyUnlock.chainTargetKeys[]'),
        ),
      };
    }
    default:
      throw new Error('walletCustodyUnlock key-manifest entry kind is invalid');
  }
}

function parseWalletRecoveryPreparationKeyManifestEntry(
  raw: unknown,
  expectedWalletId: string,
): WalletRecoveryPreparationKeyManifestEntry {
  const entry = requireRecord(raw, 'walletRecoveryPrepare.keyManifest.entries[]');
  switch (entry.kind) {
    case 'near_ed25519': {
      rejectUnknownFields(
        entry,
        [
          'kind',
          'keySetId',
          'signerId',
          'nearAccountId',
          'recordedKeyManifestDigestB64u',
          'recoveryBasis',
        ],
        'walletRecoveryPrepare.keyManifest.entries[].near_ed25519',
      );
      const signerId = requireResponseString(entry.signerId, 'keyManifest.entries[].signerId');
      const suppliedKeySetId = requireResponseString(
        entry.keySetId,
        'keyManifest.entries[].keySetId',
      );
      const keySetId = `near_ed25519:${signerId}` as const;
      if (suppliedKeySetId !== keySetId) {
        throw new Error('walletRecoveryPrepare NEAR key-set identity is inconsistent');
      }
      const nearAccountId = requireResponseString(
        entry.nearAccountId,
        'keyManifest.entries[].nearAccountId',
      );
      const recoveryBasis = parseWalletRecoveryPreparationNearRecoveryBasis(
        entry.recoveryBasis,
        expectedWalletId,
      );
      return {
        kind: 'near_ed25519',
        keySetId,
        signerId,
        nearAccountId,
        recordedKeyManifestDigestB64u: parseDigestField(
          entry.recordedKeyManifestDigestB64u,
          'walletRecoveryPrepare.keyManifest.entries[].recordedKeyManifestDigestB64u',
        ),
        recoveryBasis,
      };
    }
    case 'evm_family_ecdsa': {
      rejectUnknownFields(
        entry,
        [
          'kind',
          'keySetId',
          'keyHandle',
          'evmFamilySigningKeySlotId',
          'recordedKeyManifestDigestB64u',
          'recoveryBasis',
        ],
        'walletRecoveryPrepare.keyManifest.entries[].evm_family_ecdsa',
      );
      const keyHandle = requireResponseString(entry.keyHandle, 'keyManifest.entries[].keyHandle');
      const suppliedKeySetId = requireResponseString(
        entry.keySetId,
        'keyManifest.entries[].keySetId',
      );
      const keySetId = `evm_family_ecdsa:${keyHandle}` as const;
      if (suppliedKeySetId !== keySetId) {
        throw new Error('walletRecoveryPrepare ECDSA key-set identity is inconsistent');
      }
      const recoveryBasis = parseWalletRecoveryPreparationEcdsaRecoveryBasis(
        entry.recoveryBasis,
        expectedWalletId,
      );
      return {
        kind: 'evm_family_ecdsa',
        keySetId,
        keyHandle,
        evmFamilySigningKeySlotId: requireEvmFamilySigningKeySlotId(
          entry.evmFamilySigningKeySlotId,
        ),
        recordedKeyManifestDigestB64u: parseDigestField(
          entry.recordedKeyManifestDigestB64u,
          'walletRecoveryPrepare.keyManifest.entries[].recordedKeyManifestDigestB64u',
        ),
        recoveryBasis,
      };
    }
    default:
      throw new Error('walletRecoveryPrepare key-manifest entry kind is invalid');
  }
}

function parseWalletRecoveryPreparationNearRecoveryBasis(
  raw: unknown,
  expectedWalletId: string,
): WalletRecoveryPreparationNearRecoveryBasis {
  const basis = requireRecord(raw, 'walletRecoveryPrepare.keyManifest.entries[].recoveryBasis');
  rejectUnknownFields(
    basis,
    [
      'capabilityKind',
      'activeCapabilityBinding',
      'scope',
      'applicationBinding',
      'participantIds',
      'registeredPublicKey',
      'runtimePolicyScope',
      'activationTranscript',
      'activationStateEpoch',
      'signingWorkerVerifyingShare',
    ],
    'walletRecoveryPrepare.keyManifest.entries[].recoveryBasis',
  );
  if (basis.capabilityKind !== 'registration' && basis.capabilityKind !== 'recovery') {
    throw new Error('walletRecoveryPrepare NEAR recovery capability kind is invalid');
  }
  const activeCapabilityBinding = requireByteArray(
    basis.activeCapabilityBinding,
    32,
    'NEAR recovery active capability binding',
  );
  const scope = parseWalletRecoveryNearLifecycleScope(basis.scope);
  const applicationBinding = parseWalletRecoveryNearApplicationBinding(basis.applicationBinding);
  const participantIds = requireParticipantPair(
    basis.participantIds,
    'NEAR recovery participant IDs',
  );
  const registeredPublicKey = requireByteArray(
    basis.registeredPublicKey,
    32,
    'NEAR recovery registered public key',
  );
  const runtimePolicyScope = parseWalletRecoveryRuntimePolicyScope(basis.runtimePolicyScope);
  const activationTranscript = requireByteArray(
    basis.activationTranscript,
    32,
    'NEAR recovery activation transcript',
  );
  const activationStateEpoch = Number(basis.activationStateEpoch);
  if (!Number.isSafeInteger(activationStateEpoch) || activationStateEpoch <= 0) {
    throw new Error('walletRecoveryPrepare NEAR recovery activation state epoch is invalid');
  }
  const signingWorkerVerifyingShare = requireByteArray(
    basis.signingWorkerVerifyingShare,
    32,
    'NEAR recovery signing-worker verifying share',
  );
  if (
    applicationBinding.wallet_id !== expectedWalletId ||
    scope.account_id !== expectedWalletId ||
    scope.root_share_epoch !== runtimePolicyScope.signingRootVersion
  ) {
    throw new Error('walletRecoveryPrepare NEAR recovery basis changed its wallet scope');
  }
  return {
    capabilityKind: basis.capabilityKind,
    activeCapabilityBinding,
    scope,
    applicationBinding,
    participantIds,
    registeredPublicKey,
    runtimePolicyScope,
    activationTranscript,
    activationStateEpoch,
    signingWorkerVerifyingShare,
  };
}

function parseWalletRecoveryPreparationEcdsaRecoveryBasis(
  raw: unknown,
  expectedWalletId: string,
): WalletRecoveryPreparationEcdsaRecoveryBasis {
  const basis = requireRecord(raw, 'walletRecoveryPrepare.keyManifest.entries[].recoveryBasis');
  rejectUnknownFields(
    basis,
    [
      'publicCapability',
      'activationReceipt',
      'serverGeneration',
      'clientRootPublicKey33B64u',
      'chainTargets',
      'ecdsaThresholdKeyId',
      'signingRootId',
      'signingRootVersion',
      'runtimePolicyScope',
      'participantIds',
      'possessionChallenge',
    ],
    'walletRecoveryPrepare.keyManifest.entries[].recoveryBasis',
  );
  const publicCapability = parseRouterAbEcdsaDerivationPublicCapabilityV1(basis.publicCapability);
  const activationReceipt = parseRouterAbEcdsaRegistrationActivationReceiptV1(
    basis.activationReceipt,
  );
  if (publicCapability.client_id !== expectedWalletId) {
    throw new Error('walletRecoveryPrepare ECDSA recovery capability changed the wallet scope');
  }
  const signingRootId = parseSdkEcdsaDerivationSigningRootId(basis.signingRootId);
  const signingRootVersion = parseSdkEcdsaDerivationSigningRootVersion(basis.signingRootVersion);
  const runtimePolicyScope = parseWalletRecoveryRuntimePolicyScope(basis.runtimePolicyScope);
  if (runtimePolicyScope.signingRootVersion !== signingRootVersion) {
    throw new Error('walletRecoveryPrepare ECDSA recovery scope changed the signing root');
  }
  const serverGeneration = parseEcdsaServerGeneration(basis.serverGeneration);
  if (String(activationReceipt.server_generation) !== String(serverGeneration)) {
    throw new Error('walletRecoveryPrepare ECDSA activation receipt changed server generation');
  }
  const possessionChallenge = parseWalletRecoveryEcdsaPossessionChallengeV1(
    basis.possessionChallenge,
  );
  if (
    possessionChallenge.walletId !== expectedWalletId ||
    possessionChallenge.expectedServerGeneration !== String(serverGeneration) ||
    possessionChallenge.derivationClientSharePublicKey33B64u !==
      publicCapability.public_identity.derivation_client_share_public_key33_b64u
  ) {
    throw new Error('walletRecoveryPrepare ECDSA possession challenge changed its capability');
  }
  return {
    publicCapability,
    activationReceipt,
    serverGeneration,
    clientRootPublicKey33B64u: ecdsaClientRootPublicKey33B64uFromString(
      requireResponseString(
        basis.clientRootPublicKey33B64u,
        'keyManifest.entries[].recoveryBasis.clientRootPublicKey33B64u',
      ),
    ),
    chainTargets: parseWalletRecoveryEcdsaChainTargets(basis.chainTargets),
    ecdsaThresholdKeyId: parseSdkEcdsaDerivationThresholdKeyId(basis.ecdsaThresholdKeyId),
    signingRootId,
    signingRootVersion,
    runtimePolicyScope,
    participantIds: parseWalletRecoveryEcdsaParticipantIds(basis.participantIds),
    possessionChallenge,
  };
}

function parseWalletRecoveryEcdsaChainTargets(
  raw: unknown,
): readonly [ThresholdEcdsaChainTarget, ...ThresholdEcdsaChainTarget[]] {
  if (!Array.isArray(raw) || raw.length === 0) {
    throw new Error('walletRecoveryPrepare ECDSA recovery chain targets are invalid');
  }
  const targets = raw.map((value, index) => parseWalletRecoveryEcdsaChainTarget(value, index));
  const keys = new Set(targets.map(walletRecoveryEcdsaChainTargetKey));
  if (keys.size !== targets.length) {
    throw new Error('walletRecoveryPrepare ECDSA recovery chain targets are duplicated');
  }
  const first = targets[0];
  if (!first) {
    throw new Error('walletRecoveryPrepare ECDSA recovery chain targets are invalid');
  }
  return [first, ...targets.slice(1)];
}

function parseWalletRecoveryEcdsaChainTarget(
  raw: unknown,
  index: number,
): ThresholdEcdsaChainTarget {
  const target = requireRecord(
    raw,
    `walletRecoveryPrepare.keyManifest.entries[].recoveryBasis.chainTargets[${index}]`,
  );
  rejectUnknownFields(
    target,
    ['kind', 'namespace', 'chainId', 'networkSlug'],
    `walletRecoveryPrepare ECDSA recovery chain target ${index}`,
  );
  const chainId = Number(target.chainId);
  if (!Number.isSafeInteger(chainId) || chainId <= 0) {
    throw new Error('walletRecoveryPrepare ECDSA recovery chain id is invalid');
  }
  const networkSlug =
    typeof target.networkSlug === 'string' && target.networkSlug.trim()
      ? target.networkSlug.trim()
      : null;
  if (target.kind === 'evm') {
    if (target.namespace !== 'eip155') {
      throw new Error('walletRecoveryPrepare ECDSA recovery EVM namespace is invalid');
    }
    return {
      kind: 'evm',
      namespace: 'eip155',
      chainId,
      networkSlug: networkSlug ?? `evm-${chainId}`,
    };
  }
  if (target.kind === 'tempo') {
    return {
      kind: 'tempo',
      chainId,
      networkSlug: networkSlug ?? `tempo-${chainId}`,
    };
  }
  throw new Error('walletRecoveryPrepare ECDSA recovery chain family is invalid');
}

function walletRecoveryEcdsaChainTargetKey(target: ThresholdEcdsaChainTarget): string {
  return target.kind === 'evm' ? `evm:eip155:${target.chainId}` : `tempo:${target.chainId}`;
}

function parseWalletRecoveryEcdsaParticipantIds(raw: unknown): readonly [1, 2] {
  if (!Array.isArray(raw) || raw.length !== 2 || raw[0] !== 1 || raw[1] !== 2) {
    throw new Error('walletRecoveryPrepare ECDSA recovery participant IDs are invalid');
  }
  return [1, 2];
}

function parseWalletRecoveryNearLifecycleScope(raw: unknown): RouterAbEd25519YaoLifecycleScopeV1 {
  const scope = requireRecord(
    raw,
    'walletRecoveryPrepare.keyManifest.entries[].recoveryBasis.scope',
  );
  rejectUnknownFields(
    scope,
    [
      'lifecycle_id',
      'root_share_epoch',
      'account_id',
      'threshold_session_id',
      'signer_set_id',
      'signing_worker_id',
      'material_activation',
    ],
    'walletRecoveryPrepare.keyManifest.entries[].recoveryBasis.scope',
  );
  return {
    lifecycle_id: requireResponseString(
      scope.lifecycle_id,
      'keyManifest.entries[].recoveryBasis.scope.lifecycle_id',
    ),
    root_share_epoch: requireResponseString(
      scope.root_share_epoch,
      'keyManifest.entries[].recoveryBasis.scope.root_share_epoch',
    ),
    account_id: requireResponseString(
      scope.account_id,
      'keyManifest.entries[].recoveryBasis.scope.account_id',
    ),
    threshold_session_id: requireResponseString(
      scope.threshold_session_id,
      'keyManifest.entries[].recoveryBasis.scope.threshold_session_id',
    ),
    signer_set_id: requireResponseString(
      scope.signer_set_id,
      'keyManifest.entries[].recoveryBasis.scope.signer_set_id',
    ),
    signing_worker_id: requireResponseString(
      scope.signing_worker_id,
      'keyManifest.entries[].recoveryBasis.scope.signing_worker_id',
    ),
    material_activation: parseRouterAbMpcMaterialActivationRef(scope.material_activation),
  };
}

function parseWalletRecoveryNearApplicationBinding(
  raw: unknown,
): RouterAbEd25519YaoApplicationBindingFactsV1 {
  const applicationBinding = requireRecord(
    raw,
    'walletRecoveryPrepare.keyManifest.entries[].recoveryBasis.applicationBinding',
  );
  rejectUnknownFields(
    applicationBinding,
    ['wallet_id', 'near_ed25519_signing_key_id', 'signing_root_id', 'key_creation_signer_slot'],
    'walletRecoveryPrepare.keyManifest.entries[].recoveryBasis.applicationBinding',
  );
  const keyCreationSignerSlot = Number(applicationBinding.key_creation_signer_slot);
  if (!Number.isSafeInteger(keyCreationSignerSlot) || keyCreationSignerSlot <= 0) {
    throw new Error('walletRecoveryPrepare NEAR recovery key-creation signer slot is invalid');
  }
  return {
    wallet_id: requireResponseString(
      applicationBinding.wallet_id,
      'keyManifest.entries[].recoveryBasis.applicationBinding.wallet_id',
    ),
    near_ed25519_signing_key_id: requireResponseString(
      applicationBinding.near_ed25519_signing_key_id,
      'keyManifest.entries[].recoveryBasis.applicationBinding.near_ed25519_signing_key_id',
    ),
    signing_root_id: requireResponseString(
      applicationBinding.signing_root_id,
      'keyManifest.entries[].recoveryBasis.applicationBinding.signing_root_id',
    ),
    key_creation_signer_slot: keyCreationSignerSlot,
  };
}

function parseWalletRecoveryRuntimePolicyScope(raw: unknown): RuntimePolicyScope {
  const scope = requireRecord(
    raw,
    'walletRecoveryPrepare.keyManifest.entries[].recoveryBasis.runtimePolicyScope',
  );
  rejectUnknownFields(
    scope,
    ['orgId', 'projectId', 'envId', 'signingRootVersion'],
    'walletRecoveryPrepare.keyManifest.entries[].recoveryBasis.runtimePolicyScope',
  );
  try {
    return normalizeRuntimePolicyScope(scope);
  } catch {
    throw new Error('walletRecoveryPrepare NEAR recovery runtime policy scope is invalid');
  }
}

function requireParticipantPair(raw: unknown, label: string): readonly [number, number] {
  if (
    !Array.isArray(raw) ||
    raw.length !== 2 ||
    !Number.isSafeInteger(raw[0]) ||
    !Number.isSafeInteger(raw[1]) ||
    Number(raw[0]) <= 0 ||
    Number(raw[1]) <= 0 ||
    Number(raw[0]) === Number(raw[1])
  ) {
    throw new Error(`walletRecoveryPrepare ${label} is invalid`);
  }
  return [Number(raw[0]), Number(raw[1])];
}

function requireCanonicalBytesB64u(raw: unknown, length: number, label: string): string {
  const value = requireResponseString(raw, label);
  const bytes = base64UrlDecode(value);
  if (bytes.length !== length || base64UrlEncode(bytes) !== value) {
    throw new Error(`walletRecoveryPrepare ${label} is invalid`);
  }
  return value;
}

function requireCanonicalNonEmptyB64u(raw: unknown, label: string): string {
  const value = requireResponseString(raw, label);
  const bytes = base64UrlDecode(value);
  if (bytes.length === 0 || base64UrlEncode(bytes) !== value) {
    throw new Error(`walletRecoveryPrepare ${label} is invalid`);
  }
  return value;
}

function requireByteArray(raw: unknown, length: number, label: string): readonly number[] {
  if (
    !Array.isArray(raw) ||
    raw.length !== length ||
    raw.some((value) => !Number.isInteger(value) || value < 0 || value > 255)
  ) {
    throw new Error(`walletRecoveryPrepare ${label} is invalid`);
  }
  return raw.map(Number);
}
