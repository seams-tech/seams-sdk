import type {
  CloudflareD1PasskeyCustodyEnvelopeStore,
  PasskeyCustodyEnvelopeFactorLookupResult,
  PasskeyCustodyEnvelopeLocator,
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
import type {
  CloudflareD1WalletCustodyCommitStore,
  WalletRecoveryCodeLocatorRecord,
} from './d1WalletCustodyCommitStore';
import {
  prepareWalletRecoveryWithCodeV1,
  type WalletRecoveryPreparationResult,
} from '../../../domains/passkeyCustody/walletRecoveryAttempt';
import {
  parsePasskeyEnvelopeId,
  parseWalletId,
  parseWebAuthnCredentialIdB64u,
  parseWebAuthnRpId,
  type WalletId,
  type WebAuthnRpId,
} from '@shared/utils/domainIds';
import {
  buildPasskeyWalletAuthAuthority,
  walletAuthAuthorityRef,
  type WalletAuthAuthorityRef,
} from '@shared/utils/walletAuthAuthority';
import {
  walletAuthMethodId,
  type WalletAuthMethodRecord,
} from '../../../../core/d1WalletAuthMethodStore';
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
import type {
  WalletRecoveryEnvelopeSetRecord,
  WalletRecoverySetRotationWireV1,
} from '@shared/wallet-recovery/walletRecoveryEnvelopeSet';
import { deriveRecoveryCodeLocatorV1FromBytes } from '@shared/wallet-recovery/recoveryCodeLocator';
import {
  buildWalletRecoveryBackupAcknowledgementV1,
  walletRecoveryBackupIsOutstanding,
} from '@shared/wallet-recovery/recoveryCodes';
import type { RecoveryCodeReservationId } from '@shared/wallet-recovery/recoveryCodeReservation';
import type {
  WalletRecoveryEcdsaPossessionChallengeV1,
  WalletRecoveryEcdsaPossessionProofV1,
} from '@shared/wallet-recovery/walletRecoveryEcdsaPossession';
import type { D1WalletStore } from '../../../../core/d1WalletStore';
import {
  projectWalletUnlockKeyManifestV1,
  projectWalletRecoveryPreparationKeyManifestV1,
  resolveWalletRecoveryKeyManifestV1,
  verifyWalletRecoveryKeyActivationsV1,
  buildWalletRecoveryEcdsaPossessionChallengesV1,
  type PreparedEd25519RecoveryAdmissionV1,
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
  /** Wallet and verified passkey identify the envelope; the server resolves its opaque id. */
  readonly locator: {
    readonly walletId: PasskeyCustodyEnvelopeLocator['walletId'];
    readonly factor: Extract<WalletCustodyFactorRef, { readonly kind: 'passkey' }>;
  };
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

  /** Reserves one recovery code while the replacement Passkey is created. */
  prepareRecovery(request: {
    readonly rpId: string;
    readonly origin: string;
    readonly recoveryCodeBytes: Uint8Array;
    readonly reservationId: RecoveryCodeReservationId;
  }): Promise<WalletRecoveryRoutePreparationResult>;

  readPreparedEd25519RecoveryAdmission(request: {
    readonly challengeId: string;
    readonly nowMs: number;
  }): Promise<PreparedEd25519RecoveryAdmissionV1 | null>;

  /**
   * Installs the credential a recovery enrolled and retires the old ones.
   *
   * Called after activation, with an envelope the client sealed under the new
   * credential. The server cannot verify that sealing because it never has the
   * seed. It derives the exact wallet manifest and queries durable activation
   * receipts before this method can consume the reserved code.
   */
  finalizeRecovery(request: {
    readonly walletId: WalletId;
    readonly reservationId: RecoveryCodeReservationId;
    readonly challengeId: string;
    readonly replacementId: string;
    readonly webauthnRegistration: unknown;
    readonly expectedOrigin: string;
    readonly replacementEnvelope: PasskeyCustodyEnvelopeRecord;
    readonly ecdsaMaterialPossessionProofs: readonly {
      readonly keySetId: string;
      readonly proof: WalletRecoveryEcdsaPossessionProofV1;
    }[];
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
   * The active factor opens the seed inside the custody worker and returns a
   * full replacement set. The server receives opaque wraps plus the freshly
   * sealed seed entry and CAS-replaces both the set and its backup ack.
   */
  rotateRecoveryCodes(request: {
    readonly walletId: string;
    readonly replacement: WalletRecoverySetRotationWireV1;
    readonly recoveryCodeLocators: readonly WalletRecoveryCodeLocatorRecord[];
    readonly expectedStoreVersion: string;
  }): Promise<WalletRecoveryRotationResult>;

  readRecoverySet(request: { readonly walletId: string }): Promise<
    | {
        readonly kind: 'ready';
        readonly record: WalletRecoveryEnvelopeSetRecord;
        readonly storeVersion: string;
      }
    | { readonly kind: 'no_recovery_set' }
  >;

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
        readonly storeVersion: string;
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
    })
  | Exclude<WalletRecoveryPreparationResult, { readonly kind: 'prepared' }>
  | { readonly kind: 'manifest_unavailable'; readonly reason: string }
  | { readonly kind: 'registration_unavailable'; readonly reason: string };

export type WalletRecoveryRegistrationOptions = {
  readonly kind: 'webauthn_recovery_registration_v1';
  readonly challengeId: string;
  readonly challengeB64u: string;
  readonly replacementId: string;
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
            error instanceof Error ? error.message : 'wallet custody key manifest is unavailable',
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

      const projections = await assembly.passkeyCustodyEnvelopes.listWalletCredentialActivity(
        request.locator.walletId,
      );
      const requestedFactor = request.locator.factor;
      const matchingProjections = projections.filter((entry) => {
        const factor = entry.index.factor;
        return (
          factor.kind === 'passkey' &&
          requestedFactor.kind === 'passkey' &&
          String(factor.rpId) === String(requestedFactor.rpId) &&
          String(factor.credentialIdB64u) === String(requestedFactor.credentialIdB64u)
        );
      });
      const projection =
        matchingProjections.find((entry) => entry.index.lifecycle.state === 'active') ??
        matchingProjections[0];
      if (!projection || projection.index.factor.kind !== 'passkey') {
        return {
          status: 404,
          body: {
            ok: false,
            code: 'envelope_missing',
            message: 'no custody envelope for this wallet and credential',
          },
        };
      }
      const locator: PasskeyCustodyEnvelopeRetrievalRequest['locator'] = {
        walletId: request.locator.walletId,
        envelopeId: projection.index.envelopeId,
        factor: {
          kind: 'passkey',
          rpId: projection.index.factor.rpId,
          credentialIdB64u: projection.index.factor.credentialIdB64u,
        },
      };
      const response = await handlePasskeyCustodyEnvelopeRetrieval({
        request: {
          locator,
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
            envelopeId: locator.envelopeId,
            usedAtMs: (assembly.nowMs ?? Date.now)(),
          })
          .catch(() => undefined);
      }
      return response;
    },

    prepareRecovery: prepareRecoveryForRoute.bind(undefined, assembly),
    readPreparedEd25519RecoveryAdmission: readPreparedEd25519RecoveryAdmission.bind(
      undefined,
      assembly,
    ),

    finalizeRecovery: finalizeRecoveryForRoute.bind(undefined, assembly),

    acknowledgeRecoveryBackup: async (request) => {
      const stored = await assembly.walletCustodyCommits.readRecoveryEnvelopeSet(
        requireWalletId(request.walletId),
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
        requireWalletId(request.walletId),
      );
      if (!stored) return { kind: 'no_recovery_set' };

      const acknowledgement = await assembly.walletCustodyCommits.readBackupAcknowledgement(
        requireWalletId(request.walletId),
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
        storeVersion: stored.storeVersion,
        backupOutstanding: walletRecoveryBackupIsOutstanding({
          setIssuedAtMs: issuedAtMs,
          acknowledgement,
        }),
      };
    },

    rotateRecoveryCodes: (request) =>
      rotateWalletRecoveryCodesV1({
        store: assembly.walletCustodyCommits,
        walletId: requireWalletId(request.walletId),
        replacement: request.replacement,
        recoveryCodeLocators: request.recoveryCodeLocators,
        expectedStoreVersion: request.expectedStoreVersion,
        nowMs: (assembly.nowMs ?? Date.now)(),
      }),
    readRecoverySet: async (request) => {
      const stored = await assembly.walletCustodyCommits.readRecoveryEnvelopeSet(
        requireWalletId(request.walletId),
      );
      return stored
        ? { kind: 'ready', record: stored.record, storeVersion: stored.storeVersion }
        : { kind: 'no_recovery_set' };
    },
  };
}

async function readPreparedEd25519RecoveryAdmission(
  assembly: {
    readonly walletCustodyCommits: CloudflareD1WalletCustodyCommitStore;
    readonly walletStore: D1WalletStore;
    readonly webAuthnStore: CloudflareD1WebAuthnStore;
  },
  request: {
    readonly challengeId: string;
    readonly nowMs: number;
  },
): Promise<PreparedEd25519RecoveryAdmissionV1 | null> {
  const challenge = await assembly.webAuthnStore.readRecoveryRegistrationChallenge(
    request.challengeId,
    request.nowMs,
  );
  if (!challenge) return null;
  const storedRecoverySet = await assembly.walletCustodyCommits.readRecoveryEnvelopeSet(
    challenge.walletId,
  );
  const hasActiveReservation = storedRecoverySet?.record.manifestKekWraps.some(
    (wrap) =>
      wrap.lifecycle.state === 'reserved' &&
      wrap.lifecycle.reservationId === challenge.reservationId &&
      wrap.lifecycle.reservationExpiresAtMs > request.nowMs,
  );
  if (!hasActiveReservation) return null;
  const manifest = await resolveWalletRecoveryKeyManifestV1({
    registry: assembly.walletStore,
    walletId: challenge.walletId,
  });
  return {
    kind: 'prepared_ed25519_recovery_admission_v1',
    walletId: challenge.walletId,
    reservationId: challenge.reservationId,
    entries: manifest.entries.filter(
      (
        entry,
      ): entry is Extract<(typeof manifest.entries)[number], { readonly kind: 'near_ed25519' }> =>
        entry.kind === 'near_ed25519',
    ),
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
    readonly rpId: string;
    readonly origin: string;
    readonly recoveryCodeBytes: Uint8Array;
    readonly reservationId: RecoveryCodeReservationId;
  },
): Promise<WalletRecoveryRoutePreparationResult> {
  const parsedRpId = parseWebAuthnRpId(request.rpId);
  if (!parsedRpId.ok || !request.origin.trim()) {
    return { kind: 'refused', reason: 'that recovery code cannot be used' };
  }
  let locator: Awaited<ReturnType<typeof deriveRecoveryCodeLocatorV1FromBytes>>;
  try {
    locator = await deriveRecoveryCodeLocatorV1FromBytes(request.recoveryCodeBytes);
  } catch {
    return { kind: 'refused', reason: 'that recovery code cannot be used' };
  }
  const located = await assembly.walletCustodyCommits.readRecoveryCodeLocator(locator);
  if (!located) return { kind: 'refused', reason: 'that recovery code cannot be used' };
  const walletId = located.walletId;
  const methods = await assembly.walletCustodyCommits.listWalletAuthMethods(walletId);
  const activeMethods = methods.filter((method) => method.status === 'active');
  const sourceMethod = activeMethods.length === 1 ? activeMethods[0] : undefined;
  if (!sourceMethod || sourceMethod.kind !== 'passkey' || sourceMethod.rpId !== parsedRpId.value) {
    return { kind: 'refused', reason: 'that recovery code cannot be used' };
  }
  const sourceBinding = await assembly.webAuthnStore.readBindingByCredential({
    rpId: String(sourceMethod.rpId),
    credentialIdB64u: sourceMethod.credentialIdB64u,
  });
  if (
    !sourceBinding ||
    sourceBinding.userId !== String(walletId) ||
    sourceBinding.rpId !== sourceMethod.rpId ||
    sourceBinding.credentialIdB64u !== sourceMethod.credentialIdB64u
  ) {
    return { kind: 'refused', reason: 'that recovery code cannot be used' };
  }
  const sourceAuthority = await walletAuthAuthorityRef({
    authority: buildPasskeyWalletAuthAuthority({
      walletId,
      rpId: sourceMethod.rpId,
      credentialIdB64u: sourceMethod.credentialIdB64u,
    }),
  });
  const prepared = await prepareWalletRecoveryWithCodeV1({
    store: assembly.walletCustodyCommits,
    walletId,
    expectedRecoveryKeyId: located.recoveryKeyId,
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
      origin: request.origin,
      rpId: parsedRpId.value,
      sourceMethod,
      sourceAuthorityDigestB64u: sourceAuthority.authorityDigest,
      expiresAtMs: prepared.reservationExpiresAtMs,
      nowMs: (assembly.nowMs ?? Date.now)(),
    });
    if (registration.kind !== 'ready') {
      return { kind: 'registration_unavailable', reason: registration.reason };
    }
    const possessionChallenges = await buildEcdsaPossessionChallenges({
      manifest,
      walletId,
      reservationId: request.reservationId,
      replacementId: registration.options.replacementId,
      sourceAuthorityDigestB64u: sourceAuthority.authorityDigest,
      challengeB64u: registration.options.challengeB64u,
      expiresAtMs: prepared.reservationExpiresAtMs,
    });
    return {
      ...prepared,
      keyManifest: projectWalletRecoveryPreparationKeyManifestV1(manifest, possessionChallenges),
      registration: registration.options,
    };
  } catch (error: unknown) {
    return {
      kind: 'manifest_unavailable',
      reason:
        error instanceof Error ? error.message : 'wallet recovery key manifest is unavailable',
    };
  }
}

export async function createWalletRecoveryRegistrationOptions(input: {
  readonly webAuthnStore: Pick<CloudflareD1WebAuthnStore, 'writeChallenge' | 'readBindingRows'>;
  readonly walletId: WalletId;
  readonly reservationId: RecoveryCodeReservationId;
  readonly origin: string;
  readonly rpId: WebAuthnRpId;
  readonly sourceMethod: Extract<WalletAuthMethodRecord, { readonly kind: 'passkey' }>;
  readonly sourceAuthorityDigestB64u: WalletAuthAuthorityRef['authorityDigest'];
  readonly expiresAtMs: number;
  readonly nowMs: number;
}): Promise<
  | { readonly kind: 'ready'; readonly options: WalletRecoveryRegistrationOptions }
  | { readonly kind: 'unavailable'; readonly reason: string }
> {
  const challengeId = secureRandomBase64Url(16, 'wallet recovery registration challenge id');
  const challengeB64u = secureRandomBase64Url(32, 'wallet recovery registration challenge');
  const replacementId = `wallet-recovery-replacement:${secureRandomBase64Url(
    18,
    'wallet recovery replacement id',
  )}`;
  const sourceCredentialIdB64u = parseWebAuthnCredentialIdB64u(input.sourceMethod.credentialIdB64u);
  if (!sourceCredentialIdB64u.ok) {
    return { kind: 'unavailable', reason: 'the source passkey credential id is invalid' };
  }
  const record: WebAuthnRecoveryRegistrationChallengeRecord = {
    version: 'webauthn_recovery_registration_challenge_v1',
    challengeId,
    walletId: input.walletId,
    reservationId: input.reservationId,
    origin: input.origin,
    rpId: input.rpId,
    replacementId,
    challengeB64u,
    sourceWalletAuthMethodId: walletAuthMethodId(input.sourceMethod),
    sourceCredentialIdB64u: sourceCredentialIdB64u.value,
    sourceAuthorityDigestB64u: input.sourceAuthorityDigestB64u,
    sourceAuthMethodUpdatedAtMs: input.sourceMethod.updatedAtMs,
    createdAtMs: input.nowMs,
    expiresAtMs: input.expiresAtMs,
  };
  await input.webAuthnStore.writeChallenge({
    challengeId,
    challengeKind: 'recovery_registration',
    record,
    createdAtMs: input.nowMs,
    expiresAtMs: input.expiresAtMs,
  });
  const bindings = await input.webAuthnStore.readBindingRows({
    userId: String(input.walletId),
    rpId: input.rpId,
  });
  const excludeCredentials = bindings
    .filter((binding) => String(binding.rpId) === String(input.rpId))
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
      rpId: input.rpId,
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
    readonly walletId: WalletId;
    readonly reservationId: RecoveryCodeReservationId;
    readonly challengeId: string;
    readonly replacementId: string;
    readonly webauthnRegistration: unknown;
    readonly expectedOrigin: string;
    readonly replacementEnvelope: PasskeyCustodyEnvelopeRecord;
    readonly ecdsaMaterialPossessionProofs: readonly {
      readonly keySetId: string;
      readonly proof: WalletRecoveryEcdsaPossessionProofV1;
    }[];
  },
): Promise<WalletRecoveryFinalizationResult> {
  return await finalizeRecoveredWalletCredentialV1({
    envelopeStore: assembly.passkeyCustodyEnvelopes,
    walletCustodyCommits: assembly.walletCustodyCommits,
    walletId: request.walletId,
    reservationId: request.reservationId,
    challengeId: request.challengeId,
    replacementId: request.replacementId,
    webauthnRegistration: request.webauthnRegistration,
    expectedOrigin: request.expectedOrigin,
    webAuthnStore: assembly.webAuthnStore,
    walletStore: assembly.walletStore,
    replacementEnvelope: request.replacementEnvelope,
    ecdsaMaterialPossessionProofs: request.ecdsaMaterialPossessionProofs,
    nowMs: (assembly.nowMs ?? Date.now)(),
  });
}

async function buildEcdsaPossessionChallenges(input: {
  readonly manifest: Awaited<ReturnType<typeof resolveWalletRecoveryKeyManifestV1>>;
  readonly walletId: WalletId;
  readonly reservationId: RecoveryCodeReservationId;
  readonly replacementId: string;
  readonly sourceAuthorityDigestB64u: WalletAuthAuthorityRef['authorityDigest'];
  readonly challengeB64u: string;
  readonly expiresAtMs: number;
}): Promise<ReadonlyMap<`evm_family_ecdsa:${string}`, WalletRecoveryEcdsaPossessionChallengeV1>> {
  return await buildWalletRecoveryEcdsaPossessionChallengesV1({
    manifest: input.manifest,
    walletId: input.walletId,
    reservationId: input.reservationId,
    replacementId: input.replacementId,
    sourceAuthorityDigestB64u: input.sourceAuthorityDigestB64u,
    challengeB64u: input.challengeB64u,
    expiresAtMs: input.expiresAtMs,
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
      /* The router row lacks the version tag the core record is discriminated
         by. Every other field, device metadata included, is identical in both. */
      return {
        version: 'webauthn_authenticator_v1',
        credentialIdB64u: record.credentialIdB64u,
        credentialPublicKeyB64u: record.credentialPublicKeyB64u,
        counter: record.counter,
        createdAtMs: record.createdAtMs,
        updatedAtMs: record.updatedAtMs,
        deviceInfo: record.deviceInfo,
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
