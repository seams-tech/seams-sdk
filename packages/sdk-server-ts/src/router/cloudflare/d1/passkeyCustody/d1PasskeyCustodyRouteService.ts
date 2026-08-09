import type {
  CloudflareD1PasskeyCustodyEnvelopeStore,
  PasskeyCustodyEnvelopeFactorLookupResult,
  WalletCustodyFactorRef,
  WalletCredentialActivityProjection,
} from './d1PasskeyCustodyEnvelopeStore';
import {
  handlePasskeyCustodyEnvelopeRetrieval,
  type PasskeyCustodyEnvelopeRetrievalRouteResponse,
} from '../../../domains/passkeyCustody/passkeyCustodyEnvelopeRetrievalRoute';
import type { PasskeyCustodyEnvelopeRetrievalRequest } from '../../../domains/passkeyCustody/passkeyCustodyEnvelopeRetrieval';
import type { WebAuthnAuthenticatorStore } from '../../../../core/WebAuthnAuthenticatorStore';
import type { CloudflareD1WebAuthnStore } from '../webauthn/d1WebAuthnStore';
import type { NormalizedLogger } from '../../../../core/logger';
import type { CloudflareD1WalletCustodyCommitStore } from './d1WalletCustodyCommitStore';
import {
  prepareWalletRecoveryWithCodeV1,
  type WalletRecoveryPreparationResult,
} from '../../../domains/passkeyCustody/walletRecoveryAttempt';
import {
  parsePasskeyEnvelopeId,
  parseWalletId,
  parseWebAuthnRpId,
  type WalletId,
} from '@shared/utils/domainIds';
import {
  parseWalletAuthAuthorityRef,
  type WalletAuthAuthorityRef,
} from '@shared/utils/walletAuthAuthority';
import { secureRandomBase64Url } from '@shared/utils/secureRandomId';
import { base64UrlEncode } from '@shared/utils/encoders';
import {
  PASSKEY_PRF_FIRST_SALT_V1,
  PASSKEY_PRF_SECOND_SALT_V1,
} from '@shared/utils/signingSessionSeal';
import {
  finalizeRecoveredWalletCredentialV1,
  resolveCommittedRecoveryReplayV1,
  type WalletRecoveryFinalizationResult,
} from '../../../domains/passkeyCustody/walletRecoveryFinalization';
import type { PasskeyCustodyEnvelopeRecord } from '@shared/passkey-custody';
import type { WebAuthnRecoveryRegistrationChallengeRecord } from '../webauthn/d1WebAuthnRecords';
import {
  rotateWalletRecoveryCodesV1,
  type WalletRecoveryRotationResult,
} from '../../../domains/passkeyCustody/walletRecoveryRotation';
import type { WalletRecoveryEnvelopeSetRecord } from '@shared/wallet-recovery/walletRecoveryEnvelopeSet';
import {
  buildWalletRecoveryBackupAcknowledgementV1,
  walletRecoveryBackupIsOutstanding,
} from '@shared/wallet-recovery/recoveryCodes';
import type { RecoveryCodeReservationId } from '@shared/wallet-recovery/recoveryCodeReservation';
import type { D1WalletStore } from '../../../../core/d1WalletStore';
import {
  projectWalletUnlockKeyManifestV1,
  projectWalletRecoveryPreparationKeyManifestV1,
  resolveWalletRecoveryKeyManifestV1,
  verifyWalletRecoveryKeyActivationsV1,
  type WalletUnlockKeyManifestV1,
  type WalletRecoveryPreparationKeyManifestV1,
} from '../../../domains/passkeyCustody/walletRecoveryKeyManifest';

/**
 * The custody envelope layer's way into the router.
 *
 * Everything below this file — the store, the retrieval gate, the revocation
 * admission, the wire mapping — was written, tested, and unreachable: nothing
 * in the running server constructed a store, so cold unlock could not be
 * implemented end to end no matter how complete the pieces were. This is the
 * seam that makes them reachable.
 *
 * It is a *port*, like everything else in the service bag, not the store
 * itself. Routes get a method they can call; the store, the authenticator
 * store, and the logger stay behind it. A route holding a D1 store directly
 * would make every future custody route depend on the storage shape, and the
 * bag's whole point is that they do not.
 */

/**
 * What a browser may send. Deliberately *not*
 * `PasskeyCustodyEnvelopeRetrievalRequest`.
 *
 * That type carries `expectedChallenge`, `userId` and `rpId` — the values the
 * assertion is checked against. On a public route a caller that supplies both
 * the assertion and what it must match has proved nothing, so those three are
 * not accepted here: they come from the challenge record the server issued and
 * stores, named by an opaque id.
 */
export type PasskeyCustodyEnvelopeRetrievalWireRequest = {
  readonly locator: PasskeyCustodyEnvelopeRetrievalRequest['locator'];
  /** Names the server-issued challenge; consumed once. */
  readonly challengeId: string;
  /**
   * The relying party's origin, taken from the request's `Origin` header.
   *
   * Frozen 2026-08-09 to the header with no body fallback. The sibling
   * WebAuthn service takes `expected_origin` from its caller because an app
   * server calls it; this route is browser-reachable, and there a value the
   * requester supplies is not evidence — it would let a caller name the
   * origin its own assertion is checked against.
   */
  readonly expectedOrigin: string;
  readonly webauthnAuthentication: PasskeyCustodyEnvelopeRetrievalRequest['webauthnAuthentication'];
};

export interface RouterApiPasskeyCustodyService {
  readVerifiedFactorCustody(request: {
    readonly walletId: WalletId;
    readonly factor: WalletCustodyFactorRef;
  }): Promise<
    | (Extract<PasskeyCustodyEnvelopeFactorLookupResult, { readonly kind: 'active' }> & {
        readonly keyManifest: WalletUnlockKeyManifestV1;
      })
    | Exclude<PasskeyCustodyEnvelopeFactorLookupResult, { readonly kind: 'active' }>
    | { readonly kind: 'manifest_unavailable'; readonly reason: string }
  >;
  /**
   * Fetch a wallet's custody envelope for a browser that has none locally.
   *
   * Returns the wire response rather than the domain result: the status a
   * failure earns is a decision, it is made once in the wire mapping, and a
   * second caller re-deciding it is how two clients come to disagree about
   * what "this credential no longer opens the wallet" means.
   */
  retrieveEnvelope(
    request: PasskeyCustodyEnvelopeRetrievalWireRequest,
  ): Promise<PasskeyCustodyEnvelopeRetrievalRouteResponse>;

  listWalletCredentials(request: {
    readonly walletId: WalletId;
  }): Promise<readonly WalletCredentialActivityProjection[]>;

  renameWalletCredential(request: {
    readonly walletId: WalletId;
    readonly envelopeId: string;
    readonly label?: string;
  }): Promise<
    | { readonly kind: 'updated'; readonly projection: WalletCredentialActivityProjection }
    | { readonly kind: 'missing' }
    | { readonly kind: 'conflict' }
    | { readonly kind: 'invalid_label'; readonly reason: string }
    | { readonly kind: 'invalid_envelope_id' }
  >;

  /** Holds one code after Refactor 90 admits fresh Email OTP evidence. */
  prepareRecovery(request: {
    readonly walletId: string;
    readonly recoveryCodeBytes: Uint8Array;
    readonly reservationId: RecoveryCodeReservationId;
    readonly authorityRef: WalletAuthAuthorityRef;
    readonly replacedCredentialIdB64u: string;
  }): Promise<WalletRecoveryRoutePreparationResult>;

  /**
   * Installs the credential a recovery enrolled and retires the old ones.
   *
   * Called after activation, with an envelope the client sealed under the new
   * credential. The server cannot verify that sealing because it never has the
   * seed. It derives the exact wallet manifest and queries durable activation
   * receipts before this method can consume the reserved code.
   */
  finalizeRecovery(request: {
    readonly walletId: string;
    readonly reservationId: RecoveryCodeReservationId;
    readonly challengeId: string;
    readonly replacementId: string;
    readonly replacedCredentialIdB64u: string;
    readonly webauthnRegistration: unknown;
    readonly expectedOrigin: string;
    readonly replacementEnvelope: PasskeyCustodyEnvelopeRecord;
  }): Promise<WalletRecoveryFinalizationResult>;

  /**
   * Records that the owner confirmed saving their recovery codes.
   *
   * Cosmetic by design: nothing consults it to decide whether a recovery may
   * proceed. It exists so the product can stop asking, and it must never mean
   * more than that — a user who acknowledged without saving has no codes, and
   * one who never acknowledged still has working ones.
   */
  acknowledgeRecoveryBackup(request: {
    readonly walletId: string;
  }): Promise<{ kind: 'acknowledged'; issuedAtMs: number } | { kind: 'no_recovery_set' }>;

  /**
   * Replaces the wallet's recovery codes with a freshly wrapped set.
   *
   * The wraps are built client-side from the same manifest KEK, so the server
   * swaps which codes unwrap it without ever holding the seed. The entries are
   * untouched by design.
   */
  rotateRecoveryCodes(request: {
    readonly walletId: string;
    readonly manifestKekWraps: WalletRecoveryEnvelopeSetRecord['manifestKekWraps'];
  }): Promise<WalletRecoveryRotationResult>;

  /**
   * How many codes remain and whether the owner has saved them.
   *
   * Counting is credential-gated. An unauthenticated caller learning how many
   * of ten codes are left gains an enumeration oracle; the wallet owner needs
   * the same count for the recovery settings screen.
   *
   * It returns counts, never identifiers: which codes remain is not something
   * even the owner's browser needs, and a list would be one leak away from
   * being useful to someone else.
   */
  readRecoveryStatus(request: { readonly walletId: string }): Promise<
    | {
        readonly kind: 'status';
        readonly activeCodeCount: number;
        readonly totalCodeCount: number;
        readonly issuedAtMs: number;
        readonly backupOutstanding: boolean;
      }
    | { readonly kind: 'no_recovery_set' }
  >;
}

/** How long a reservation may sit before another attempt may take the code. */
const RECOVERY_RESERVATION_TTL_MS = 5 * 60 * 1000;

export type WalletRecoveryRoutePreparationResult =
  | (Extract<WalletRecoveryPreparationResult, { readonly kind: 'prepared' }> & {
      readonly keyManifest: WalletRecoveryPreparationKeyManifestV1;
      readonly registration: WalletRecoveryRegistrationOptions;
      readonly authorityRef: WalletAuthAuthorityRef;
    })
  | Exclude<WalletRecoveryPreparationResult, { readonly kind: 'prepared' }>
  | { readonly kind: 'manifest_unavailable'; readonly reason: string }
  | { readonly kind: 'registration_unavailable'; readonly reason: string };

export type WalletRecoveryRegistrationOptions = {
  readonly kind: 'webauthn_recovery_registration_v1';
  readonly challengeId: string;
  readonly challengeB64u: string;
  readonly replacementId: string;
  readonly replacedCredentialIdB64u: string;
  readonly rpId: string;
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
  readonly excludeCredentials: readonly {
    readonly type: 'public-key';
    readonly id: string;
  }[];
};

export function createD1PasskeyCustodyRouteService(assembly: {
  readonly passkeyCustodyEnvelopes: CloudflareD1PasskeyCustodyEnvelopeStore;
  readonly walletCustodyCommits: CloudflareD1WalletCustodyCommitStore;
  readonly walletStore: D1WalletStore;
  readonly webAuthnStore: CloudflareD1WebAuthnStore;
  readonly logger: NormalizedLogger;
  /** Injected so the reservation window is testable without waiting. */
  readonly nowMs?: () => number;
}): RouterApiPasskeyCustodyService {
  const authenticatorStore = authenticatorStoreView(assembly.webAuthnStore);
  return {
    readVerifiedFactorCustody: async (request) => {
      const envelope = await assembly.passkeyCustodyEnvelopes.lookupEnvelopeForFactor(request);
      if (envelope.kind !== 'active') return envelope;
      try {
        const manifest = await resolveWalletRecoveryKeyManifestV1({
          registry: assembly.walletStore,
          walletId: request.walletId,
        });
        if (request.factor.kind === 'passkey') {
          await assembly.passkeyCustodyEnvelopes
            .recordWalletCredentialUse({
              walletId: request.walletId,
              envelopeId: envelope.envelope.envelopeId,
              usedAtMs: (assembly.nowMs ?? Date.now)(),
            })
            .catch(() => undefined);
        }
        return {
          ...envelope,
          keyManifest: projectWalletUnlockKeyManifestV1(manifest),
        };
      } catch (error: unknown) {
        return {
          kind: 'manifest_unavailable',
          reason:
            error instanceof Error
              ? error.message
              : 'wallet custody key manifest is unavailable',
        };
      }
    },
    listWalletCredentials: async (request) =>
      await assembly.passkeyCustodyEnvelopes.listWalletCredentialActivity(request.walletId),

    renameWalletCredential: async (request) => {
      const envelopeId = parsePasskeyEnvelopeId(request.envelopeId);
      if (!envelopeId.ok) return { kind: 'invalid_envelope_id' };
      const label = request.label === undefined ? undefined : String(request.label);
      return await assembly.passkeyCustodyEnvelopes.renameWalletCredential({
        walletId: request.walletId,
        envelopeId: envelopeId.value,
        ...(label === undefined ? {} : { label }),
        nowMs: (assembly.nowMs ?? Date.now)(),
      });
    },
    retrieveEnvelope: async (request) => {
      const challengeId = String(request.challengeId || '').trim();
      const expectedOrigin = String(request.expectedOrigin || '').trim();
      if (!challengeId || !expectedOrigin) {
        return {
          status: 400,
          body: {
            ok: false,
            code: 'challenge_required',
            message: 'custody retrieval needs a server-issued challenge and an origin',
          },
        };
      }

      /* Consumed, not read: a challenge that could be replayed would let one
         captured assertion fetch the envelope repeatedly. */
      const challenge = await assembly.webAuthnStore.consumeLoginChallenge(challengeId);
      if (!challenge) {
        return {
          status: 401,
          body: {
            ok: false,
            code: 'challenge_unknown',
            message: 'the challenge is unknown, expired, or already used',
          },
        };
      }

      const response = await handlePasskeyCustodyEnvelopeRetrieval({
        request: {
          locator: request.locator,
          /* From the issued challenge, never the request body. This is what
             makes the assertion evidence: the browser cannot choose the
             user, the relying party, or the bytes it signs over. */
          rpId: challenge.rpId as PasskeyCustodyEnvelopeRetrievalRequest['rpId'],
          userId: challenge.userId,
          expectedChallenge: challenge.challengeB64u,
          expectedOrigin,
          webauthnAuthentication: request.webauthnAuthentication,
        },
        envelopeStore: assembly.passkeyCustodyEnvelopes,
        authenticatorStore,
        logger: assembly.logger,
      });
      if (response.status === 200 && request.locator.factor.kind === 'passkey') {
        await assembly.passkeyCustodyEnvelopes
          .recordWalletCredentialUse({
            walletId: request.locator.walletId,
            envelopeId: request.locator.envelopeId,
            usedAtMs: (assembly.nowMs ?? Date.now)(),
          })
          .catch(() => undefined);
      }
      return response;
    },

    prepareRecovery: prepareRecoveryForRoute.bind(undefined, assembly),

    finalizeRecovery: finalizeRecoveryForRoute.bind(undefined, assembly),

    acknowledgeRecoveryBackup: async (request) => {
      const stored = await assembly.walletCustodyCommits.readRecoveryEnvelopeSet(
        request.walletId as WalletId,
      );
      /* The acknowledgement names the issuance it covers, so there has to be
         one. Acknowledging nothing would write a row that silences the prompt
         for codes that were never issued. */
      if (!stored) return { kind: 'no_recovery_set' };

      const issuedAtMs = Number(stored.record.issuedAtMs);
      await assembly.walletCustodyCommits.writeBackupAcknowledgement(
        buildWalletRecoveryBackupAcknowledgementV1({
          walletId: request.walletId,
          issuedAtMs,
          acknowledgedAtMs: (assembly.nowMs ?? Date.now)(),
        }),
      );
      return { kind: 'acknowledged', issuedAtMs };
    },

    readRecoveryStatus: async (request) => {
      const stored = await assembly.walletCustodyCommits.readRecoveryEnvelopeSet(
        request.walletId as WalletId,
      );
      if (!stored) return { kind: 'no_recovery_set' };

      const acknowledgement = await assembly.walletCustodyCommits.readBackupAcknowledgement(
        request.walletId as WalletId,
      );
      const issuedAtMs = Number(stored.record.issuedAtMs);
      return {
        kind: 'status',
        activeCodeCount: stored.record.manifestKekWraps.filter(
          (wrap) => wrap.lifecycle.state === 'active',
        ).length,
        /* Both counts, because "3 left" means something different out of ten
           than out of three, and a rotation changes which one the user is
           looking at. */
        totalCodeCount: stored.record.manifestKekWraps.length,
        issuedAtMs,
        backupOutstanding: walletRecoveryBackupIsOutstanding({
          setIssuedAtMs: issuedAtMs,
          acknowledgement,
        }),
      };
    },

    rotateRecoveryCodes: (request) =>
      rotateWalletRecoveryCodesV1({
        store: assembly.walletCustodyCommits,
        walletId: request.walletId as WalletId,
        manifestKekWraps: request.manifestKekWraps,
        nowMs: (assembly.nowMs ?? Date.now)(),
      }),
  };
}

async function prepareRecoveryForRoute(
  assembly: {
    readonly walletCustodyCommits: CloudflareD1WalletCustodyCommitStore;
    readonly walletStore: D1WalletStore;
    readonly webAuthnStore: CloudflareD1WebAuthnStore;
    readonly nowMs?: () => number;
  },
  request: {
    readonly walletId: string;
    readonly recoveryCodeBytes: Uint8Array;
    readonly reservationId: RecoveryCodeReservationId;
    readonly authorityRef: WalletAuthAuthorityRef;
    readonly replacedCredentialIdB64u: string;
  },
): Promise<WalletRecoveryRoutePreparationResult> {
  let walletId: WalletId;
  try {
    walletId = requireWalletId(request.walletId);
  } catch {
    return { kind: 'refused', reason: 'that recovery code cannot be used' };
  }
  const authorityRef = parseWalletAuthAuthorityRef(request.authorityRef);
  if (!authorityRef || String(authorityRef.walletId) !== String(walletId)) {
    return { kind: 'refused', reason: 'that recovery code cannot be used' };
  }
  const prepared = await prepareWalletRecoveryWithCodeV1({
    store: assembly.walletCustodyCommits,
    walletId,
    recoveryCodeBytes: request.recoveryCodeBytes,
    reservationId: request.reservationId,
    nowMs: (assembly.nowMs ?? Date.now)(),
    reservationTtlMs: RECOVERY_RESERVATION_TTL_MS,
  });
  if (prepared.kind !== 'prepared') return prepared;
  try {
    const manifest = await resolveWalletRecoveryKeyManifestV1({
      registry: assembly.walletStore,
      walletId,
    });
    const registration = await createWalletRecoveryRegistrationOptions({
      webAuthnStore: assembly.webAuthnStore,
      walletId,
      reservationId: request.reservationId,
      replacedCredentialIdB64u: request.replacedCredentialIdB64u,
      nowMs: (assembly.nowMs ?? Date.now)(),
    });
    if (registration.kind !== 'ready') {
      return { kind: 'registration_unavailable', reason: registration.reason };
    }
    return {
      ...prepared,
      keyManifest: projectWalletRecoveryPreparationKeyManifestV1(manifest),
      registration: registration.options,
      authorityRef,
    };
  } catch (error: unknown) {
    return {
      kind: 'manifest_unavailable',
      reason:
        error instanceof Error ? error.message : 'wallet recovery key manifest is unavailable',
    };
  }
}

async function createWalletRecoveryRegistrationOptions(input: {
  readonly webAuthnStore: CloudflareD1WebAuthnStore;
  readonly walletId: WalletId;
  readonly reservationId: RecoveryCodeReservationId;
  readonly replacedCredentialIdB64u: string;
  readonly nowMs: number;
}): Promise<
  | { readonly kind: 'ready'; readonly options: WalletRecoveryRegistrationOptions }
  | { readonly kind: 'unavailable'; readonly reason: string }
> {
  const selectedBinding = await input.webAuthnStore.readBindingByCredentialId(
    input.replacedCredentialIdB64u,
  );
  if (!selectedBinding || selectedBinding.userId !== String(input.walletId)) {
    return {
      kind: 'unavailable',
      reason: 'wallet recovery replacement credential is unavailable',
    };
  }
  const parsedRpId = parseWebAuthnRpId(selectedBinding.rpId);
  if (!parsedRpId.ok) {
    return { kind: 'unavailable', reason: 'wallet recovery relying party is invalid' };
  }
  const challengeId = secureRandomBase64Url(16, 'wallet recovery registration challenge id');
  const challengeB64u = secureRandomBase64Url(32, 'wallet recovery registration challenge');
  const replacementId = `wallet-recovery-replacement:${secureRandomBase64Url(
    18,
    'wallet recovery replacement id',
  )}`;
  const expiresAtMs = input.nowMs + RECOVERY_RESERVATION_TTL_MS;
  const record: WebAuthnRecoveryRegistrationChallengeRecord = {
    version: 'webauthn_recovery_registration_challenge_v1',
    challengeId,
    walletId: String(input.walletId),
    reservationId: String(input.reservationId),
    replacementId,
    replacedCredentialIdB64u: selectedBinding.credentialIdB64u,
    rpId: parsedRpId.value,
    challengeB64u,
    createdAtMs: input.nowMs,
    expiresAtMs,
  };
  await input.webAuthnStore.writeChallenge({
    challengeId,
    challengeKind: 'recovery_registration',
    record,
    createdAtMs: input.nowMs,
    expiresAtMs,
  });
  const bindings = await input.webAuthnStore.readBindingRows({
    userId: String(input.walletId),
    rpId: parsedRpId.value,
  });
  const excludeCredentials = bindings
    .filter((binding) => String(binding.rpId) === String(parsedRpId.value))
    .map((binding) => ({
      type: 'public-key' as const,
      id: String(binding.credentialIdB64u),
    }));
  return {
    kind: 'ready',
    options: {
      kind: 'webauthn_recovery_registration_v1',
      challengeId,
      challengeB64u,
      replacementId,
      replacedCredentialIdB64u: selectedBinding.credentialIdB64u,
      rpId: parsedRpId.value,
      user: {
        idB64u: base64UrlEncode(new TextEncoder().encode(String(input.walletId))),
        name: String(input.walletId),
        displayName: String(input.walletId),
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
            firstB64u: base64UrlEncode(PASSKEY_PRF_FIRST_SALT_V1),
            secondB64u: base64UrlEncode(PASSKEY_PRF_SECOND_SALT_V1),
          },
        },
      },
      excludeCredentials,
    },
  };
}

async function finalizeRecoveryForRoute(
  assembly: {
    readonly passkeyCustodyEnvelopes: CloudflareD1PasskeyCustodyEnvelopeStore;
    readonly walletCustodyCommits: CloudflareD1WalletCustodyCommitStore;
    readonly walletStore: D1WalletStore;
    readonly webAuthnStore: CloudflareD1WebAuthnStore;
    readonly nowMs?: () => number;
  },
  request: {
    readonly walletId: string;
    readonly reservationId: RecoveryCodeReservationId;
    readonly challengeId: string;
    readonly replacementId: string;
    readonly webauthnRegistration: unknown;
    readonly expectedOrigin: string;
    readonly replacementEnvelope: PasskeyCustodyEnvelopeRecord;
  },
): Promise<WalletRecoveryFinalizationResult> {
  let walletId: WalletId;
  try {
    walletId = requireWalletId(request.walletId);
  } catch {
    return { kind: 'refused', reason: 'wallet recovery identity is invalid' };
  }
  const challenge = await assembly.webAuthnStore.readRecoveryRegistrationChallenge(
    request.challengeId,
  );
  if (!challenge) {
    const replay = await resolveCommittedRecoveryReplayV1({
      envelopeStore: assembly.passkeyCustodyEnvelopes,
      walletCustodyCommits: assembly.walletCustodyCommits,
      walletId: request.walletId,
      reservationId: request.reservationId,
      replacementId: request.replacementId,
      replacementEnvelope: request.replacementEnvelope,
      webAuthnStore: assembly.webAuthnStore,
      walletStore: assembly.walletStore,
    });
    if (replay.kind === 'rejected') {
      return { kind: 'registration_rejected', reason: replay.reason };
    }
    return replay;
  }
  const activationVerification = await verifyWalletRecoveryKeyActivationsV1({
    registry: assembly.walletStore,
    walletId,
    recoveryCorrelationId: request.reservationId,
  });
  if (activationVerification.kind === 'refused') {
    const replay = await resolveCommittedRecoveryReplayV1({
      envelopeStore: assembly.passkeyCustodyEnvelopes,
      walletCustodyCommits: assembly.walletCustodyCommits,
      walletId: request.walletId,
      reservationId: request.reservationId,
      replacementId: request.replacementId,
      replacementEnvelope: request.replacementEnvelope,
      webAuthnStore: assembly.webAuthnStore,
      walletStore: assembly.walletStore,
    });
    if (replay.kind !== 'rejected') return replay;
    return activationVerification;
  }
  return await finalizeRecoveredWalletCredentialV1({
    envelopeStore: assembly.passkeyCustodyEnvelopes,
    walletCustodyCommits: assembly.walletCustodyCommits,
    walletId: request.walletId,
    reservationId: request.reservationId,
    challengeId: request.challengeId,
    replacementId: request.replacementId,
    replacedCredentialIdB64u: request.replacedCredentialIdB64u,
    webauthnRegistration: request.webauthnRegistration,
    expectedOrigin: request.expectedOrigin,
    webAuthnStore: assembly.webAuthnStore,
    walletStore: assembly.walletStore,
    replacementEnvelope: request.replacementEnvelope,
    activationVerification,
    nowMs: (assembly.nowMs ?? Date.now)(),
  });
}

function requireWalletId(value: unknown): WalletId {
  const parsed = parseWalletId(value);
  if (!parsed.ok) throw new Error('wallet ID is invalid');
  return parsed.value;
}

/**
 * The router's WebAuthn store, seen as the interface assertion verification
 * expects.
 *
 * The two shapes differ only in naming — both read and write the same
 * `WebAuthnAuthenticatorRecord` rows — so this adapts rather than duplicates.
 * Verifying against the router's own authenticators is the point: a separate
 * store would let a credential be active for registration and unknown to
 * custody, and the wallet would refuse a passkey the user just enrolled.
 */
function authenticatorStoreView(store: CloudflareD1WebAuthnStore): WebAuthnAuthenticatorStore {
  return {
    get: async (userId, credentialIdB64u) => {
      const record = await store.readAuthenticator({ userId, credentialIdB64u });
      if (!record) return null;
      /* The router row carries device info the verifier has no use for, and
         lacks the version tag the core record is discriminated by. The five
         fields verification actually reads are identical in both. */
      return {
        version: 'webauthn_authenticator_v1',
        credentialIdB64u: record.credentialIdB64u,
        credentialPublicKeyB64u: record.credentialPublicKeyB64u,
        counter: record.counter,
        createdAtMs: record.createdAtMs,
        updatedAtMs: record.updatedAtMs,
      };
    },
    /* Narrowed to the counter on purpose. A successful assertion may advance
       the signature counter and nothing else; a general write here could
       replace a credential's public key on the strength of an assertion that
       key just verified, which is a credential swap with extra steps. It also
       cannot create a row, so custody retrieval can never enroll a factor. */
    put: (userId, record) =>
      store.updateAuthenticatorCounter({
        userId,
        credentialIdB64u: record.credentialIdB64u,
        newCounter: record.counter,
        updatedAtMs: record.updatedAtMs,
      }),
    del: async () => {
      /* Deliberately not implemented rather than a silent no-op. The D1 store
         has no delete, and a `del` that resolved without removing anything
         would report a revoked credential as gone while it still verified
         assertions. Retrieval never calls this; anything that does is a bug
         that should surface here rather than as phantom access later. */
      throw new Error(
        'the router WebAuthn store cannot delete authenticators; revoke the custody envelope instead',
      );
    },
  };
}
