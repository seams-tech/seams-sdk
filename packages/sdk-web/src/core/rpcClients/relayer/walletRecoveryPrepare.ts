import {
  buildBearerAuthorizationHeader,
  buildRelayerJsonPostRequestInit,
  normalizeRelayerBaseUrl,
} from './relayerHttp';
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
import {
  parseWebAuthnCredentialIdB64u,
  parseWebAuthnRpId,
  parseWalletId,
  type WebAuthnCredentialIdB64u,
  type WebAuthnRpId,
} from '@shared/utils/domainIds';
import { base64UrlDecode, base64UrlEncode } from '@shared/utils/encoders';
import {
  PASSKEY_PRF_FIRST_SALT_V1,
  PASSKEY_PRF_SECOND_SALT_V1,
} from '@shared/utils/signingSessionSeal';
import {
  ecdsaClientRootPublicKey33B64uFromString,
  type EcdsaClientRootPublicKey33B64u,
} from '@shared/threshold/ecdsaDerivationRoleLocalBootstrap';
import { requireEvmFamilySigningKeySlotId } from '@shared/signing-lanes';

/**
 * Preparing an admitted wallet recovery.
 *
 * The response is ciphertext: a wrapped manifest KEK and the entry ciphertexts
 * it opens. The code never leaves this call, and the server cannot open what
 * it returns — it only matched a derived identifier against stored wraps.
 *
 * **`rejected` says nothing about why.** The server answers identically for an
 * unknown wallet, an unknown code, a spent code and a malformed one, so that
 * the route cannot be used to count how many of a user's ten codes remain.
 * This keeps that: no client-side guess at which case it was, however helpful
 * a "you already used this one" would be to show.
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

export type WalletRecoveryPrepareResult =
  | {
      readonly kind: 'prepared';
      readonly wrap: {
        readonly nonceB64u: EnvelopeNonceB64u;
        readonly wrappedManifestKekB64u: EnvelopeCiphertextB64u;
        readonly aadHashB64u: DigestB64u;
      };
      readonly entries: readonly [WalletRecoveryEnvelopeEntry];
      readonly keyManifest: WalletRecoveryPreparationKeyManifest;
      readonly registration: WalletRecoveryRegistrationOptions;
      readonly reservationId: string;
      readonly reservationExpiresAtMs: number;
      readonly storeVersion: string;
    }
  /** The code did not work. Deliberately without a reason. */
  | { readonly kind: 'rejected'; readonly message: string }
  /** Another attempt landed first; this code may still be good. */
  | { readonly kind: 'conflict'; readonly message: string }
  /** The wallet cannot currently produce a safe replacement registration. */
  | { readonly kind: 'unavailable'; readonly message: string }
  | { readonly kind: 'transport_failed'; readonly message: string };

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

export async function prepareWalletRecovery(args: {
  readonly relayUrl: string;
  readonly walletId: string;
  readonly sessionToken: string;
  readonly challengeId: string;
  readonly otpCode: string;
  /** Base64url of the decoded code. Not persisted, not logged. */
  readonly recoveryCode: string;
  readonly reservationId: string;
  readonly fetchImpl?: typeof fetch;
}): Promise<WalletRecoveryPrepareResult> {
  const url = `${normalizeRelayerBaseUrl(args.relayUrl)}${WALLET_RECOVERY_PREPARE_PATH}`;
  const doFetch = args.fetchImpl || fetch;

  let response: Response;
  try {
    response = await doFetch(
      url,
      buildRelayerJsonPostRequestInit({
        headers: buildBearerAuthorizationHeader({
          token: args.sessionToken,
          missingMessage: 'wallet recovery preparation requires an app session',
        }),
        body: {
          walletId: args.walletId,
          recoveryCode: args.recoveryCode,
          reservationId: args.reservationId,
          challengeId: args.challengeId,
          otpCode: args.otpCode,
        },
      }),
    );
  } catch (error: unknown) {
    return {
      kind: 'transport_failed',
      message: error instanceof Error ? error.message : 'recovery preparation request failed',
    };
  }

  const bodyUnknown: unknown = await response.json().catch(() => ({}));
  const body = isRecord(bodyUnknown) ? bodyUnknown : {};
  const message = typeof body.message === 'string' ? body.message : '';

  if (response.status === 200 && body.ok === true) {
    try {
      const wrap = parsePreparedRecoveryWrap(body.wrap);
      const entries = parsePreparedRecoveryEntries(body.entries);
      const keyManifest = parseWalletRecoveryPreparationKeyManifest(
        body.keyManifest,
        args.walletId,
      );
      const registration = parseWalletRecoveryRegistrationOptions(
        body.registration,
        args.walletId,
      );
      const reservationId = requireResponseString(body.reservationId, 'reservationId');
      const reservationExpiresAtMs = parseUnixMs(
        body.reservationExpiresAtMs,
        'walletRecoveryPrepare.reservationExpiresAtMs',
      );
      const storeVersion = requireResponseString(body.storeVersion, 'storeVersion');
      if (reservationId !== args.reservationId) {
        throw new Error('wallet recovery preparation changed the reservation identity');
      }
      return {
        kind: 'prepared',
        wrap,
        entries,
        keyManifest,
        registration,
        reservationId,
        reservationExpiresAtMs,
        storeVersion,
      };
    } catch {
      return {
        kind: 'transport_failed',
        message: 'recovery preparation returned an unusable payload',
      };
    }
  }

  if (response.status === 409) {
    if (
      body.code === 'recovery_manifest_unavailable' ||
      body.code === 'recovery_registration_unavailable'
    ) {
      return {
        kind: 'unavailable',
        message: message || 'wallet recovery is temporarily unavailable',
      };
    }
    return { kind: 'conflict', message: message || 'the recovery set changed; try again' };
  }
  if (response.status === 401 || response.status === 400) {
    return { kind: 'rejected', message: message || 'that recovery code cannot be used' };
  }
  return {
    kind: 'transport_failed',
    message: message || `recovery preparation failed (HTTP ${response.status})`,
  };
}

function parseWalletRecoveryRegistrationOptions(
  raw: unknown,
  expectedWalletId: string,
): WalletRecoveryRegistrationOptions {
  const registration = requireRecord(raw, 'walletRecoveryPrepare.registration');
  rejectUnknownFields(
    registration,
    [
      'kind',
      'challengeId',
      'challengeB64u',
      'replacementId',
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
  const challengeId = requireResponseString(
    registration.challengeId,
    'registration.challengeId',
  );
  const challengeB64u = requireCanonicalBytesB64u(
    registration.challengeB64u,
    32,
    'registration.challengeB64u',
  );
  const replacementId = requireResponseString(
    registration.replacementId,
    'registration.replacementId',
  );
  const rpIdResult = parseWebAuthnRpId(registration.rpId);
  if (!rpIdResult.ok) throw new Error('walletRecoveryPrepare.registration.rpId is invalid');

  const user = requireRecord(registration.user, 'walletRecoveryPrepare.registration.user');
  rejectUnknownFields(
    user,
    ['idB64u', 'name', 'displayName'],
    'walletRecoveryPrepare.registration.user',
  );
  const expectedUserIdB64u = base64UrlEncode(new TextEncoder().encode(expectedWalletId));
  const idB64u = requireCanonicalNonEmptyB64u(
    user.idB64u,
    'registration.user.idB64u',
  );
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

function parseRecoveryPrfExtensions(
  raw: unknown,
): WalletRecoveryRegistrationOptions['extensions'] {
  const extensions = requireRecord(raw, 'walletRecoveryPrepare.registration.extensions');
  rejectUnknownFields(
    extensions,
    ['prf'],
    'walletRecoveryPrepare.registration.extensions',
  );
  const prf = requireRecord(
    extensions.prf,
    'walletRecoveryPrepare.registration.extensions.prf',
  );
  rejectUnknownFields(
    prf,
    ['eval'],
    'walletRecoveryPrepare.registration.extensions.prf',
  );
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
  const selection = requireRecord(
    raw,
    'walletRecoveryPrepare.registration.authenticatorSelection',
  );
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
  const entries = manifest.entries.map(parseWalletRecoveryPreparationKeyManifestEntry);
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

function parseWalletRecoveryPreparationKeyManifestEntry(
  raw: unknown,
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
          'nearEd25519SigningKeyId',
          'signerSlot',
          'registeredPublicKeyB64u',
          'recordedKeyManifestDigestB64u',
          'activeCapabilityBinding',
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
      const signerSlot = Number(entry.signerSlot);
      if (!Number.isSafeInteger(signerSlot) || signerSlot <= 0) {
        throw new Error('walletRecoveryPrepare NEAR signer slot is invalid');
      }
      return {
        kind: 'near_ed25519',
        keySetId,
        signerId,
        nearAccountId: requireResponseString(
          entry.nearAccountId,
          'keyManifest.entries[].nearAccountId',
        ),
        nearEd25519SigningKeyId: requireResponseString(
          entry.nearEd25519SigningKeyId,
          'keyManifest.entries[].nearEd25519SigningKeyId',
        ),
        signerSlot,
        registeredPublicKeyB64u: requireCanonicalBytesB64u(
          entry.registeredPublicKeyB64u,
          32,
          'registered public key',
        ),
        recordedKeyManifestDigestB64u: parseDigestField(
          entry.recordedKeyManifestDigestB64u,
          'walletRecoveryPrepare.keyManifest.entries[].recordedKeyManifestDigestB64u',
        ),
        activeCapabilityBinding: requireByteArray(
          entry.activeCapabilityBinding,
          32,
          'active capability binding',
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
      if (!Array.isArray(entry.chainTargetKeys) || entry.chainTargetKeys.length === 0) {
        throw new Error('walletRecoveryPrepare ECDSA key set has no chain targets');
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
          'walletRecoveryPrepare.keyManifest.entries[].recordedKeyManifestDigestB64u',
        ),
        clientRootPublicKey33B64u: ecdsaClientRootPublicKey33B64uFromString(
          requireResponseString(
            entry.clientRootPublicKey33B64u,
            'keyManifest.entries[].clientRootPublicKey33B64u',
          ),
        ),
        applicationBindingDigestB64u: parseDigestField(
          entry.applicationBindingDigestB64u,
          'walletRecoveryPrepare.keyManifest.entries[].applicationBindingDigestB64u',
        ),
        chainTargetKeys: entry.chainTargetKeys.map((value) =>
          requireResponseString(value, 'keyManifest.entries[].chainTargetKeys[]'),
        ),
      };
    }
    default:
      throw new Error('walletRecoveryPrepare key-manifest entry kind is invalid');
  }
}

function requireCanonicalBytesB64u(
  raw: unknown,
  length: number,
  label: string,
): string {
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
