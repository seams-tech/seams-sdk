import type { CloudflareD1PasskeyCustodyEnvelopeStore } from './d1PasskeyCustodyEnvelopeStore';
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
  attemptWalletRecoveryWithCodeV1,
  type WalletRecoveryAttemptResult,
} from '../../../domains/passkeyCustody/walletRecoveryAttempt';
import type { WalletId } from '@shared/utils/domainIds';
import {
  promoteRecoveredWalletCredentialV1,
  type WalletRecoveryPromotionResult,
} from '../../../domains/passkeyCustody/walletRecoveryPromotion';
import type { PasskeyCustodyEnvelopeRecord } from '@shared/passkey-custody';
import {
  rotateWalletRecoveryCodesV1,
  type WalletRecoveryRotationResult,
} from '../../../domains/passkeyCustody/walletRecoveryRotation';
import type { WalletRecoveryEnvelopeSetRecord } from '@shared/wallet-recovery/walletRecoveryEnvelopeSet';
import {
  buildWalletRecoveryBackupAcknowledgementV1,
  walletRecoveryBackupIsOutstanding,
  type RecoveredKeySetOutcome,
} from '@shared/wallet-recovery/recoveryCodes';

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
   * The relying party's origin, from the caller.
   *
   * Matches the convention of the sibling WebAuthn service, which takes
   * `expected_origin` the same way. Worth revisiting for a browser-reachable
   * route: the sibling is called by an app server, and a value the requester
   * supplies is weaker evidence there. Left consistent rather than quietly
   * given a different origin policy than every other WebAuthn route.
   */
  readonly expectedOrigin: string;
  readonly webauthnAuthentication: PasskeyCustodyEnvelopeRetrievalRequest['webauthnAuthentication'];
};

export interface RouterApiPasskeyCustodyService {
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

  /**
   * Spends one recovery code and returns the wrapped payload.
   *
   * The code is the proof — it is 160 bits of randomness and the server can
   * only match its derived id against stored wraps. There is nothing else to
   * authenticate with: recovery exists precisely for the case where every
   * enrolled factor is gone.
   */
  spendRecoveryCode(request: {
    readonly walletId: string;
    readonly recoveryCodeBytes: Uint8Array;
    readonly reservationId: string;
  }): Promise<WalletRecoveryAttemptResult>;

  /**
   * Installs the credential a recovery enrolled and retires the old ones.
   *
   * Called after a spend, with an envelope the client sealed under the new
   * credential. The server cannot verify that sealing — it never has the seed
   * — so what it does verify is the key-set outcomes and the wallet the
   * envelope names.
   */
  promoteRecoveredCredential(request: {
    readonly walletId: string;
    readonly replacementEnvelope: PasskeyCustodyEnvelopeRecord;
    readonly requiredKeySets: readonly string[];
    readonly outcomes: readonly RecoveredKeySetOutcome[];
  }): Promise<WalletRecoveryPromotionResult>;

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
   * **This is the counting the spend route refuses to do**, and the
   * difference is authentication. An unauthenticated caller learning how many
   * of ten codes are left is an enumeration oracle; the wallet's own owner
   * learning it is the entire point of a recovery settings screen. So this
   * route sits behind credentials and the spend route does not.
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
const RECOVERY_RESERVATION_TTL_MS = 120_000;

export function createD1PasskeyCustodyRouteService(assembly: {
  readonly passkeyCustodyEnvelopes: CloudflareD1PasskeyCustodyEnvelopeStore;
  readonly walletCustodyCommits: CloudflareD1WalletCustodyCommitStore;
  readonly webAuthnStore: CloudflareD1WebAuthnStore;
  readonly logger: NormalizedLogger;
  /** Injected so the reservation window is testable without waiting. */
  readonly nowMs?: () => number;
}): RouterApiPasskeyCustodyService {
  const authenticatorStore = authenticatorStoreView(assembly.webAuthnStore);
  return {
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

      return handlePasskeyCustodyEnvelopeRetrieval({
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
    },

    spendRecoveryCode: (request) =>
      attemptWalletRecoveryWithCodeV1({
        store: assembly.walletCustodyCommits,
        walletId: request.walletId as WalletId,
        recoveryCodeBytes: request.recoveryCodeBytes,
        reservationId: request.reservationId,
        nowMs: (assembly.nowMs ?? Date.now)(),
        reservationTtlMs: RECOVERY_RESERVATION_TTL_MS,
      }),

    promoteRecoveredCredential: (request) =>
      promoteRecoveredWalletCredentialV1({
        envelopeStore: assembly.passkeyCustodyEnvelopes,
        walletId: request.walletId,
        replacementEnvelope: request.replacementEnvelope,
        requiredKeySets: request.requiredKeySets,
        outcomes: request.outcomes,
        nowMs: (assembly.nowMs ?? Date.now)(),
      }),

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
