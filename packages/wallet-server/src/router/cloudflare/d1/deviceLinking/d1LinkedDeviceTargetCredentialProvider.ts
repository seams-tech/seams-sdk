import type {
  LinkedDeviceApprovalV1,
  LinkedDeviceTargetCredentialRegistrationV1,
  LinkedDeviceTargetCredentialRegistrationResultV1,
  LinkedDeviceTargetPreparationV1,
  LinkedDeviceOrdinaryMaterialSourceContributionPreparationTupleV1,
  VerifiedTargetFactorV1,
  VerifiedLinkInputV1,
} from '@shared/device-linking/contracts';
import {
  parseLinkedDeviceTargetCredentialRegistrationV1,
  parseLinkedDeviceTargetCredentialRegistrationResultV1,
  parseLinkedDeviceTargetPreparationV1,
} from '@shared/device-linking/parsers';
import { parseLinkedDeviceOrdinaryMaterialSourceContributionPreparationTupleV1 } from '@shared/device-linking/sourceContribution';
import {
  assertLinkedDeviceTargetCredentialRegistrationMatchesPreparationV1,
  computeLinkedDeviceTargetPreparationDigestV1,
} from '@shared/device-linking/digests';
import { alphabetizeStringify } from '@shared/utils/digests';
import { errorMessage } from '@shared/utils/errors';
import { parseDigestB64u, type DigestB64u } from '@shared/utils/canonicalPrimitives';
import { routerAbMpcMaterialActivationRefFromWire } from '@shared/utils/routerAbNormalSigningIdentity';
import {
  hasControlCharacter,
  mpcMaterialActivationRefsEqual,
  parseWebAuthnCredentialIdB64u,
  parseWebAuthnRpId,
  type WalletAuthMethodId,
  type WebAuthnCredentialIdB64u,
  type WebAuthnRpId,
} from '@shared/utils/domainIds';
import { base64UrlDecode, base64UrlEncode } from '@shared/utils/base64';
import { sha256BytesUtf8 } from '@shared/utils/digests';
import { verifyWebAuthnRegistrationCredentialForIntent } from '../../../../core/authService/webauthn';
import { normalizeCorsOrigin } from '../../../../core/SessionService';
import type {
  D1DatabaseLike,
  D1PreparedStatementLike,
  D1ResultLike,
} from '../../../../storage/tenantRoute';
import { d1ChangedRows } from '../../../../storage/d1Sql';
import type { LinkedDeviceSessionRecordV1 } from '../../../../core/deviceLinking/linkedDeviceSession';
import { linkedDeviceEmailOtpDescriptorCredentialIdV1 } from '../../../../core/deviceLinking/linkedDeviceEmailOtpGrant';
import type { DeviceLinkingTargetCredentialProviderV1 } from '../../../../router/transport/fetch/routes/deviceLinking';
import type { D1LinkedDeviceSessionScopeV1 } from './d1LinkedDeviceSessionStore';
import {
  buildVerifiedTargetFactorV1,
  buildVerifiedLinkInputV1,
  type VerifiedLinkSourceReadV1,
  type VerifiedLinkSourceReaderV1,
} from './d1LinkedDeviceVerifiedLinkBuilder';
import { linkedDeviceX25519RecipientPublicKeyB64uV1 } from './d1LinkedDeviceSourceContributionPreparationPlanner';
import type { ExactAdministeredSignerV1 } from '@shared/device-linking/delegatedActivationPlan';
import type { MpcMaterialActivationRef } from '@shared/utils/domainIds';

export type VerifiedLinkedDeviceWebAuthnCredentialV1 = {
  readonly credentialIdB64u: string;
  readonly credentialPublicKeyB64u: string;
  readonly counter: number;
};

/** The consumed-grant projection an email OTP completion is committed under. */
export type VerifiedLinkedDeviceEmailOtpGrantV1 = {
  readonly grantId: string;
  readonly baseWalletAuthMethodId: WalletAuthMethodId;
  readonly authorityDigestB64u: DigestB64u;
  readonly descriptorCredentialIdB64u: WebAuthnCredentialIdB64u;
};

/**
 * The exact evidence a target registration was verified against, one branch
 * per target factor. A Passkey commit cannot carry a grant and an Email OTP
 * commit cannot carry WebAuthn material.
 */
export type VerifiedLinkedDeviceTargetFactorEvidenceV1 =
  | {
      readonly kind: 'passkey_prf';
      readonly credential: VerifiedLinkedDeviceWebAuthnCredentialV1;
      readonly grant?: never;
    }
  | {
      readonly kind: 'email_otp';
      readonly grant: VerifiedLinkedDeviceEmailOtpGrantV1;
      readonly credential?: never;
    };

export type LinkedDeviceTargetCredentialVerificationPortV1 = {
  verifyRegistrationV1(input: {
    readonly preparation: LinkedDeviceTargetPreparationV1;
    readonly registration: LinkedDeviceTargetCredentialRegistrationV1;
  }): Promise<
    | { readonly kind: 'verified'; readonly credential: VerifiedLinkedDeviceWebAuthnCredentialV1 }
    | { readonly kind: 'rejected'; readonly message: string }
  >;
};

/** Uses the canonical D1 WebAuthn registration verifier with the configured ceremony origin. */
export class LinkedDeviceWebAuthnRegistrationVerifierV1 implements LinkedDeviceTargetCredentialVerificationPortV1 {
  private readonly expectedOrigin: string;
  private readonly expectedRpId: WebAuthnRpId;

  constructor(expectedOrigin: string, expectedRpId: string) {
    const normalized = normalizeCorsOrigin(expectedOrigin);
    if (!normalized || normalized !== expectedOrigin.trim()) {
      throw new Error('linked-device target Passkey origin must be an exact origin');
    }
    this.expectedOrigin = normalized;
    const parsedRpId = parseWebAuthnRpId(expectedRpId);
    if (!parsedRpId.ok) {
      throw new Error(`linked-device target Passkey RP ID: ${parsedRpId.error.message}`);
    }
    const originHostname = new URL(normalized).hostname.toLowerCase();
    const rpId = String(parsedRpId.value).toLowerCase();
    if (originHostname !== rpId && !originHostname.endsWith(`.${rpId}`)) {
      throw new Error('linked-device target Passkey origin is outside the configured RP ID');
    }
    this.expectedRpId = parsedRpId.value;
  }

  async verifyRegistrationV1(input: {
    readonly preparation: LinkedDeviceTargetPreparationV1;
    readonly registration: LinkedDeviceTargetCredentialRegistrationV1;
  }): Promise<
    | { readonly kind: 'verified'; readonly credential: VerifiedLinkedDeviceWebAuthnCredentialV1 }
    | { readonly kind: 'rejected'; readonly message: string }
  > {
    if (
      input.preparation.targetFactor.kind !== 'passkey_prf' ||
      input.registration.targetFactor.kind !== 'passkey_prf' ||
      !input.registration.webauthnRegistration
    ) {
      return { kind: 'rejected', message: 'registration is not a Passkey registration' };
    }
    const registration = input.registration.webauthnRegistration;
    const options = input.preparation.passkeyCreationOptions;
    if (!options) {
      return { kind: 'rejected', message: 'Passkey preparation options are missing' };
    }
    if (options.rpId !== this.expectedRpId) {
      return { kind: 'rejected', message: 'Passkey preparation RP ID is no longer configured' };
    }
    const verification = await verifyWebAuthnRegistrationCredentialForIntent({
      webauthnRegistration: {
        id: registration.credentialIdB64u,
        rawId: registration.credentialIdB64u,
        type: 'public-key',
        authenticatorAttachment: registration.authenticatorAttachment ?? undefined,
        response: {
          clientDataJSON: registration.clientDataJsonB64u,
          attestationObject: registration.attestationObjectB64u,
          transports: [...registration.transports],
        },
        clientExtensionResults: {},
      },
      expectedChallenge: options.challengeB64u,
      expectedOrigin: this.expectedOrigin,
      rpId: options.rpId,
    });
    return verification.ok
      ? { kind: 'verified', credential: verification.credential }
      : { kind: 'rejected', message: verification.message };
  }
}

/**
 * Registration-time port for the Email OTP branch: validates the one-time
 * verification grant a registration carries and, after the authority install
 * commit, supplies the statements that consume the grant and persist the
 * derived linked-owner binding atomically with the credential row.
 */
export type LinkedDeviceEmailOtpGrantRegistrationPortV1 = {
  verifyRegistrationGrantV1(input: {
    readonly preparation: LinkedDeviceTargetPreparationV1;
    readonly registration: LinkedDeviceTargetCredentialRegistrationV1;
    readonly requestedAtMs: number;
  }): Promise<
    | { readonly kind: 'verified'; readonly grant: VerifiedLinkedDeviceEmailOtpGrantV1 }
    | { readonly kind: 'rejected'; readonly message: string }
  >;
  buildCompletionStatementsV1(input: {
    readonly grant: VerifiedLinkedDeviceEmailOtpGrantV1;
    readonly registration: LinkedDeviceTargetCredentialRegistrationV1;
    readonly keyManifestDigestB64u: DigestB64u;
    readonly consumedAtMs: number;
  }): Promise<readonly D1PreparedStatementLike[]>;
};

/**
 * The default when no email OTP port is wired: every email registration is
 * rejected before any credential or lane exists. Fail-closed by construction.
 */
const FAIL_CLOSED_EMAIL_OTP_REGISTRATION_PORT_V1: LinkedDeviceEmailOtpGrantRegistrationPortV1 = {
  verifyRegistrationGrantV1: () =>
    Promise.resolve({
      kind: 'rejected' as const,
      message: 'linked-device email OTP registration is not configured',
    }),
  buildCompletionStatementsV1: () =>
    Promise.reject(new Error('linked-device email OTP registration is not configured')),
};

export type LinkedDeviceTargetPlannerV1 = {
  createTargetPreparationV1(input: {
    readonly session: LinkedDeviceSessionRecordV1;
    readonly approval: LinkedDeviceApprovalV1;
    readonly requestedAtMs: number;
  }): Promise<LinkedDeviceTargetPreparationV1>;
};

/**
 * Allocates the target-side material identities after the target factor has
 * been verified. The returned tuple is the only source-preparation input that
 * Device 1 and the authority installer may consume.
 */
export type LinkedDeviceSourceContributionPreparationPlannerV1 = {
  planSourceContributionPreparationV1(input: {
    readonly session: LinkedDeviceSessionRecordV1;
    readonly approval: LinkedDeviceApprovalV1;
    readonly preparation: LinkedDeviceTargetPreparationV1;
    readonly registration: LinkedDeviceTargetCredentialRegistrationV1;
    readonly evidence: VerifiedLinkedDeviceTargetFactorEvidenceV1;
    readonly targetFactor: VerifiedTargetFactorV1;
    readonly source: VerifiedLinkSourceReadV1;
    readonly requestedAtMs: number;
  }): Promise<LinkedDeviceOrdinaryMaterialSourceContributionPreparationTupleV1>;
};

export type LinkedDeviceVerifiedLinkBuilderV1 = {
  readonly source: VerifiedLinkSourceReaderV1;
};

type TargetCredentialRowV1 = {
  readonly state?: unknown;
  readonly target_factor?: unknown;
  readonly preparation_digest_b64u?: unknown;
  readonly preparation_json?: unknown;
  readonly registration_json?: unknown;
  readonly credential_id_b64u?: unknown;
  readonly credential_public_key_b64u?: unknown;
  readonly credential_counter?: unknown;
  readonly email_otp_grant_id?: unknown;
  readonly key_manifest_digest_b64u?: unknown;
};

type TargetCommitReservationRowV1 = {
  readonly registration_digest_b64u?: unknown;
  readonly state?: unknown;
  readonly reserved_at_ms?: unknown;
  readonly committed_at_ms?: unknown;
  readonly key_manifest_digest_b64u?: unknown;
};

type PersistedTargetCredentialV1 = {
  readonly state: 'prepared' | 'registered';
  readonly preparationDigestB64u: DigestB64u;
  readonly preparation: LinkedDeviceTargetPreparationV1;
  readonly registration: {
    readonly value: LinkedDeviceTargetCredentialRegistrationV1;
    readonly evidence: VerifiedLinkedDeviceTargetFactorEvidenceV1;
    readonly keyManifestDigestB64u: DigestB64u;
  } | null;
};

type TargetCredentialRegistrationSuccessV1 = {
  readonly outcome: 'applied' | 'replayed';
  readonly keyManifestDigestB64u: DigestB64u;
  readonly targetCredential: LinkedDeviceTargetCredentialRegistrationResultV1;
};

function buildTargetCredentialRegistrationSuccessV1(input: {
  readonly outcome: 'applied' | 'replayed';
  readonly registration: LinkedDeviceTargetCredentialRegistrationV1;
  readonly targetFactor: VerifiedTargetFactorV1;
  readonly ordinarySignerMaterialPreparations: LinkedDeviceOrdinaryMaterialSourceContributionPreparationTupleV1;
  readonly keyManifestDigestB64u: DigestB64u;
}): TargetCredentialRegistrationSuccessV1 {
  if (
    input.targetFactor.authMethod.walletAuthMethodId !== input.registration.walletAuthMethodId ||
    input.targetFactor.authMethod.walletId !== input.registration.walletId
  ) {
    throw new Error('verified target factor identity differs from its registration');
  }
  const targetCredential = parseLinkedDeviceTargetCredentialRegistrationResultV1({
    kind: 'linked_device_target_credential_registration_result_v1',
    outcome: input.outcome,
    linkSessionId: input.registration.linkSessionId,
    walletId: input.registration.walletId,
    enrollmentId: input.registration.enrollmentId,
    deviceId: input.registration.deviceId,
    walletAuthMethodId: input.registration.walletAuthMethodId,
    targetPreparationDigestB64u: input.registration.targetPreparationDigestB64u,
    targetFactor: input.targetFactor,
    ordinarySignerMaterialPreparations: input.ordinarySignerMaterialPreparations,
    ordinarySignerMaterialRecipientRequests:
      input.registration.ordinarySignerMaterialRecipientRequests,
    keyManifestDigestB64u: input.keyManifestDigestB64u,
  });
  return {
    outcome: input.outcome,
    keyManifestDigestB64u: input.keyManifestDigestB64u,
    targetCredential,
  };
}

type PersistedTargetCommitReservationV1 =
  | {
      readonly state: 'reserved';
      readonly registrationDigestB64u: DigestB64u;
      readonly reservedAtMs: number;
    }
  | {
      readonly state: 'committed';
      readonly registrationDigestB64u: DigestB64u;
      readonly reservedAtMs: number;
      readonly committedAtMs: number;
      readonly keyManifestDigestB64u: DigestB64u;
    };

const TARGET_CREDENTIAL_TABLE = 'linked_device_target_credentials';
const TARGET_COMMIT_RESERVATION_TABLE = 'linked_device_target_commit_reservations';
const TARGET_COMMIT_WAIT_ATTEMPTS = 25;
const TARGET_COMMIT_WAIT_MS = 10;

export class D1LinkedDeviceTargetCredentialProviderV1 implements DeviceLinkingTargetCredentialProviderV1 {
  private readonly database: D1DatabaseLike;
  private readonly scope: D1LinkedDeviceSessionScopeV1;
  private readonly verifier: LinkedDeviceTargetCredentialVerificationPortV1;
  private readonly emailOtpGrants: LinkedDeviceEmailOtpGrantRegistrationPortV1;
  private readonly planner: LinkedDeviceTargetPlannerV1;
  private readonly sourceContributionPreparationPlanner: LinkedDeviceSourceContributionPreparationPlannerV1;
  private readonly verifiedLinkBuilder: LinkedDeviceVerifiedLinkBuilderV1;
  private readonly inFlightCommits = new Map<
    string,
    Promise<
      | TargetCredentialRegistrationSuccessV1
      | { readonly outcome: 'invalid_input'; readonly message: string }
    >
  >();

  constructor(input: {
    readonly database: D1DatabaseLike;
    readonly scope: D1LinkedDeviceSessionScopeV1;
    readonly verifier: LinkedDeviceTargetCredentialVerificationPortV1;
    readonly emailOtpGrants?: LinkedDeviceEmailOtpGrantRegistrationPortV1;
    readonly planner: LinkedDeviceTargetPlannerV1;
    readonly sourceContributionPreparationPlanner: LinkedDeviceSourceContributionPreparationPlannerV1;
    readonly verifiedLinkBuilder: LinkedDeviceVerifiedLinkBuilderV1;
  }) {
    this.database = input.database;
    this.scope = normalizeScope(input.scope);
    this.verifier = input.verifier;
    this.emailOtpGrants = input.emailOtpGrants ?? FAIL_CLOSED_EMAIL_OTP_REGISTRATION_PORT_V1;
    this.planner = input.planner;
    this.sourceContributionPreparationPlanner = input.sourceContributionPreparationPlanner;
    this.verifiedLinkBuilder = input.verifiedLinkBuilder;
  }

  async getTargetPreparationV1(input: {
    readonly session: LinkedDeviceSessionRecordV1;
    readonly approval: LinkedDeviceApprovalV1;
    readonly requestedAtMs: number;
  }): Promise<LinkedDeviceTargetPreparationV1> {
    const persisted = await this.readV1(input.session.linkSessionId);
    if (persisted) {
      assertPreparationMatchesSession(persisted.preparation, input.session, input.approval);
      return persisted.preparation;
    }
    if (input.session.state.state !== 'awaiting_target_factor') {
      throw new Error('linked-device target preparation is unavailable in this session state');
    }
    const preparation = parseLinkedDeviceTargetPreparationV1(
      await this.planner.createTargetPreparationV1(input),
    );
    assertPreparationMatchesSession(preparation, input.session, input.approval);
    if (preparation.expiresAtMs <= input.requestedAtMs) {
      throw new Error('linked-device target preparation is expired');
    }
    const preparationDigestB64u = await computeLinkedDeviceTargetPreparationDigestV1(preparation);
    await this.database
      .prepare(
        `INSERT OR IGNORE INTO ${TARGET_CREDENTIAL_TABLE} (
           namespace, org_id, project_id, env_id, link_session_id,
           wallet_id, enrollment_id, device_id, state, target_factor,
           preparation_digest_b64u, preparation_json, prepared_at_ms, expires_at_ms
         ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'prepared', ?, ?, ?, ?, ?)`,
      )
      .bind(
        ...scopeValues(this.scope),
        String(preparation.linkSessionId),
        String(preparation.walletId),
        String(preparation.enrollmentId),
        String(preparation.deviceId),
        preparation.targetFactor.kind,
        preparationDigestB64u,
        JSON.stringify(preparation),
        preparation.issuedAtMs,
        preparation.expiresAtMs,
      )
      .run();
    const stored = await this.readV1(input.session.linkSessionId);
    if (!stored) throw new Error('linked-device target preparation did not persist');
    if (
      stored.preparationDigestB64u !== preparationDigestB64u ||
      alphabetizeStringify(stored.preparation) !== alphabetizeStringify(preparation)
    ) {
      throw new Error('linked-device target preparation conflicts with its durable replay');
    }
    return stored.preparation;
  }

  async registerTargetCredentialV1(input: {
    readonly registration: LinkedDeviceTargetCredentialRegistrationV1;
    readonly preparation: LinkedDeviceTargetPreparationV1;
    readonly session: LinkedDeviceSessionRecordV1;
    readonly approval: LinkedDeviceApprovalV1;
    readonly requestedAtMs: number;
  }): Promise<
    | TargetCredentialRegistrationSuccessV1
    | { readonly outcome: 'invalid_input'; readonly message: string }
  > {
    try {
      const registration = parseLinkedDeviceTargetCredentialRegistrationV1(input.registration);
      const persisted = await this.readV1(input.session.linkSessionId);
      if (!persisted) throw new Error('linked-device target preparation is missing');
      assertPreparationReplay(persisted, input.preparation);
      await assertLinkedDeviceTargetCredentialRegistrationMatchesPreparationV1({
        preparation: persisted.preparation,
        registration,
      });
      if (persisted.registration) {
        if (
          alphabetizeStringify(persisted.registration.value) !== alphabetizeStringify(registration)
        ) {
          throw new Error('linked-device target credential conflicts with its durable replay');
        }
        const replay = await this.buildTargetCredentialRegistrationReplayV1({
          persisted,
          session: input.session,
          approval: input.approval,
          registration,
          requestedAtMs: input.requestedAtMs,
        });
        await this.finalizeReservationIfPresentV1({
          linkSessionId: input.session.linkSessionId,
          registrationDigestB64u: await digestRegistrationV1(registration),
          keyManifestDigestB64u: persisted.registration.keyManifestDigestB64u,
          committedAtMs: input.requestedAtMs,
        });
        return replay;
      }
      if (input.requestedAtMs >= persisted.preparation.expiresAtMs) {
        throw new Error('linked-device target credential registration is expired');
      }
      const registrationDigestB64u = await digestRegistrationV1(registration);
      const commitKey = String(input.session.linkSessionId);
      const inFlight = this.inFlightCommits.get(commitKey);
      if (inFlight) return await inFlight;
      const reservation = await this.reserveCommitV1({
        linkSessionId: input.session.linkSessionId,
        registrationDigestB64u,
        expiresAtMs: persisted.preparation.expiresAtMs,
        nowMs: input.requestedAtMs,
      });
      if (reservation.outcome === 'replayed') {
        const stored = await this.readV1(input.session.linkSessionId);
        if (!stored?.registration) {
          throw new Error(
            'linked-device target credential reservation is committed without a registration',
          );
        }
        assertRegistrationReplay(stored, registration, stored.registration.keyManifestDigestB64u);
        if (reservation.keyManifestDigestB64u !== stored.registration.keyManifestDigestB64u) {
          throw new Error('linked-device target commit reservation manifest digest changed');
        }
        const replay = await this.buildTargetCredentialRegistrationReplayV1({
          persisted: stored,
          session: input.session,
          approval: input.approval,
          registration,
          requestedAtMs: input.requestedAtMs,
        });
        return replay;
      }
      if (reservation.outcome === 'waiting') {
        const completed = await this.waitForCommitV1({
          linkSessionId: input.session.linkSessionId,
          registration,
          registrationDigestB64u,
          expiresAtMs: persisted.preparation.expiresAtMs,
          session: input.session,
          approval: input.approval,
          requestedAtMs: input.requestedAtMs,
        });
        return completed;
      }
      const commit = this.commitReservedTargetV1({
        input,
        persisted,
        registration,
        registrationDigestB64u,
      });
      this.inFlightCommits.set(commitKey, commit);
      try {
        return await commit;
      } finally {
        if (this.inFlightCommits.get(commitKey) === commit) this.inFlightCommits.delete(commitKey);
      }
    } catch (error: unknown) {
      return { outcome: 'invalid_input', message: errorMessage(error) };
    }
  }

  private async commitReservedTargetV1(input: {
    readonly input: {
      readonly session: LinkedDeviceSessionRecordV1;
      readonly approval: LinkedDeviceApprovalV1;
      readonly requestedAtMs: number;
    };
    readonly persisted: PersistedTargetCredentialV1;
    readonly registration: LinkedDeviceTargetCredentialRegistrationV1;
    readonly registrationDigestB64u: DigestB64u;
  }): Promise<
    | TargetCredentialRegistrationSuccessV1
    | { readonly outcome: 'invalid_input'; readonly message: string }
  > {
    try {
      const evidence = await this.verifyTargetFactorEvidenceV1({
        preparation: input.persisted.preparation,
        registration: input.registration,
        requestedAtMs: input.input.requestedAtMs,
      });
      const planned = await this.planSourceContributionPreparationV1({
        session: input.input.session,
        approval: input.input.approval,
        preparation: input.persisted.preparation,
        registration: input.registration,
        evidence,
        requestedAtMs: input.input.requestedAtMs,
      });
      const keyManifestDigestB64u = await digestJsonV1(planned.source.signerManifest);
      const result = await this.persistRegisteredTargetV1({
        session: input.input.session,
        persisted: input.persisted,
        registration: input.registration,
        evidence,
        keyManifestDigestB64u,
        registeredAtMs: input.input.requestedAtMs,
      });
      const stored = await this.readV1(input.input.session.linkSessionId);
      if (!stored?.registration) throw new Error('linked-device target credential did not persist');
      assertRegistrationReplay(stored, input.registration, keyManifestDigestB64u);
      await this.commitReservationV1({
        linkSessionId: input.input.session.linkSessionId,
        registrationDigestB64u: input.registrationDigestB64u,
        keyManifestDigestB64u,
        committedAtMs: input.input.requestedAtMs,
      });
      return {
        ...buildTargetCredentialRegistrationSuccessV1({
          outcome: result.applied ? 'applied' : 'replayed',
          registration: input.registration,
          targetFactor: planned.targetFactor,
          ordinarySignerMaterialPreparations: planned.preparations,
          keyManifestDigestB64u: stored.registration.keyManifestDigestB64u,
        }),
      };
    } catch (error: unknown) {
      await this.releaseCommitReservationV1({
        linkSessionId: input.input.session.linkSessionId,
        registrationDigestB64u: input.registrationDigestB64u,
      });
      return { outcome: 'invalid_input', message: errorMessage(error) };
    }
  }

  /** Verifies the registration through its factor's own port — never the other's. */
  private async verifyTargetFactorEvidenceV1(input: {
    readonly preparation: LinkedDeviceTargetPreparationV1;
    readonly registration: LinkedDeviceTargetCredentialRegistrationV1;
    readonly requestedAtMs: number;
  }): Promise<VerifiedLinkedDeviceTargetFactorEvidenceV1> {
    switch (input.registration.targetFactor.kind) {
      case 'passkey_prf': {
        const verification = await this.verifier.verifyRegistrationV1({
          preparation: input.preparation,
          registration: input.registration,
        });
        if (verification.kind === 'rejected') throw new Error(verification.message);
        const credentialId = parseWebAuthnCredentialIdB64u(
          verification.credential.credentialIdB64u,
        );
        if (!credentialId.ok) throw new Error(credentialId.error.message);
        if (
          !input.registration.webauthnRegistration ||
          credentialId.value !== input.registration.webauthnRegistration.credentialIdB64u
        ) {
          throw new Error('verified WebAuthn credential id differs from its registration');
        }
        if (
          !Number.isSafeInteger(verification.credential.counter) ||
          verification.credential.counter < 0 ||
          !isCanonicalNonemptyBase64Url(verification.credential.credentialPublicKeyB64u)
        ) {
          throw new Error('verified WebAuthn credential material is invalid');
        }
        return { kind: 'passkey_prf', credential: verification.credential };
      }
      case 'email_otp': {
        const verification = await this.emailOtpGrants.verifyRegistrationGrantV1({
          preparation: input.preparation,
          registration: input.registration,
          requestedAtMs: input.requestedAtMs,
        });
        if (verification.kind === 'rejected') throw new Error(verification.message);
        return { kind: 'email_otp', grant: verification.grant };
      }
    }
    input.registration.targetFactor satisfies never;
    throw new Error('linked-device target registration factor is unsupported');
  }

  /**
   * Flips the credential row to `registered`. The Email OTP branch commits the
   * flip, the grant consumption, and the derived owner-binding insert in one
   * batch — either all of them happened or none did.
   */
  private async persistRegisteredTargetV1(input: {
    readonly session: LinkedDeviceSessionRecordV1;
    readonly persisted: PersistedTargetCredentialV1;
    readonly registration: LinkedDeviceTargetCredentialRegistrationV1;
    readonly evidence: VerifiedLinkedDeviceTargetFactorEvidenceV1;
    readonly keyManifestDigestB64u: DigestB64u;
    readonly registeredAtMs: number;
  }): Promise<{ readonly applied: boolean }> {
    if (input.evidence.kind === 'passkey_prf') {
      const result = await this.database
        .prepare(
          `UPDATE ${TARGET_CREDENTIAL_TABLE}
              SET state = 'registered', registration_json = ?, credential_id_b64u = ?,
                  credential_public_key_b64u = ?, credential_counter = ?,
                  key_manifest_digest_b64u = ?, registered_at_ms = ?
            WHERE namespace = ? AND org_id = ? AND project_id = ? AND env_id = ?
              AND link_session_id = ? AND state = 'prepared'
              AND preparation_digest_b64u = ?`,
        )
        .bind(
          JSON.stringify(input.registration),
          input.evidence.credential.credentialIdB64u,
          input.evidence.credential.credentialPublicKeyB64u,
          input.evidence.credential.counter,
          input.keyManifestDigestB64u,
          input.registeredAtMs,
          ...scopeValues(this.scope),
          String(input.session.linkSessionId),
          input.persisted.preparationDigestB64u,
        )
        .run();
      return { applied: d1ChangedRows(result) === 1 };
    }
    const completionStatements = await this.emailOtpGrants.buildCompletionStatementsV1({
      grant: input.evidence.grant,
      registration: input.registration,
      keyManifestDigestB64u: input.keyManifestDigestB64u,
      consumedAtMs: input.registeredAtMs,
    });
    const flip = this.database
      .prepare(
        `UPDATE ${TARGET_CREDENTIAL_TABLE}
            SET state = 'registered', registration_json = ?, credential_id_b64u = ?,
                email_otp_grant_id = ?, key_manifest_digest_b64u = ?, registered_at_ms = ?
          WHERE namespace = ? AND org_id = ? AND project_id = ? AND env_id = ?
            AND link_session_id = ? AND state = 'prepared'
            AND preparation_digest_b64u = ?`,
      )
      .bind(
        JSON.stringify(input.registration),
        String(input.evidence.grant.descriptorCredentialIdB64u),
        input.evidence.grant.grantId,
        input.keyManifestDigestB64u,
        input.registeredAtMs,
        ...scopeValues(this.scope),
        String(input.session.linkSessionId),
        input.persisted.preparationDigestB64u,
      );
    // A guard directly after the flip: if the row was not in `prepared` any
    // more, the whole batch fails before the grant consumption or binding
    // insert can run — a lost flip must not spend the grant.
    const flipGuard = this.database.prepare(
      `INSERT INTO linked_device_session_cas_guard (guard_id)
SELECT 1
 WHERE changes() = 0`,
    );
    const results = await this.database.batch<D1ResultLike>([
      flip,
      flipGuard,
      ...completionStatements,
    ]);
    const flipResult = results[0];
    if (!flipResult) throw new Error('linked-device email OTP completion batch returned nothing');
    return { applied: d1ChangedRows(flipResult) === 1 };
  }

  private async planSourceContributionPreparationV1(input: {
    readonly session: LinkedDeviceSessionRecordV1;
    readonly approval: LinkedDeviceApprovalV1;
    readonly preparation: LinkedDeviceTargetPreparationV1;
    readonly registration: LinkedDeviceTargetCredentialRegistrationV1;
    readonly evidence: VerifiedLinkedDeviceTargetFactorEvidenceV1;
    readonly requestedAtMs: number;
  }): Promise<{
    readonly source: VerifiedLinkSourceReadV1;
    readonly targetFactor: VerifiedTargetFactorV1;
    readonly preparations: LinkedDeviceOrdinaryMaterialSourceContributionPreparationTupleV1;
  }> {
    const source = await readVerifiedSourceForTargetCredentialV1({
      source: this.verifiedLinkBuilder.source,
      registration: input.registration,
      approval: input.approval,
      requestedAtMs: input.requestedAtMs,
    });
    const targetFactor = await buildVerifiedTargetFactorV1({
      registration: input.registration,
      evidence: input.evidence,
      sourceAuthMethod: source.authMethod,
      requestedAtMs: input.requestedAtMs,
    });
    const preparations = parseLinkedDeviceOrdinaryMaterialSourceContributionPreparationTupleV1(
      await this.sourceContributionPreparationPlanner.planSourceContributionPreparationV1({
        ...input,
        targetFactor,
        source,
      }),
    );
    assertSourceContributionPreparationContextV1({
      preparations,
      session: input.session,
      approval: input.approval,
      preparation: input.preparation,
      registration: input.registration,
      targetFactor,
      source,
    });
    return { source, targetFactor, preparations };
  }

  private async buildTargetCredentialRegistrationReplayV1(input: {
    readonly persisted: PersistedTargetCredentialV1;
    readonly session: LinkedDeviceSessionRecordV1;
    readonly approval: LinkedDeviceApprovalV1;
    readonly registration: LinkedDeviceTargetCredentialRegistrationV1;
    readonly requestedAtMs: number;
  }): Promise<TargetCredentialRegistrationSuccessV1> {
    if (!input.persisted.registration) {
      throw new Error('linked-device target credential replay is not registered');
    }
    const preparations = input.session.sourceContributionPreparation;
    if (!preparations) {
      throw new Error('linked-device source contribution preparation is missing from the session');
    }
    const source = await readVerifiedSourceForTargetCredentialV1({
      source: this.verifiedLinkBuilder.source,
      registration: input.registration,
      approval: input.approval,
      requestedAtMs: input.requestedAtMs,
    });
    const targetFactor = await buildVerifiedTargetFactorV1({
      registration: input.registration,
      evidence: input.persisted.registration.evidence,
      sourceAuthMethod: source.authMethod,
      requestedAtMs: input.requestedAtMs,
    });
    const parsedPreparations =
      parseLinkedDeviceOrdinaryMaterialSourceContributionPreparationTupleV1(preparations);
    assertSourceContributionPreparationContextV1({
      preparations: parsedPreparations,
      session: input.session,
      approval: input.approval,
      preparation: input.persisted.preparation,
      registration: input.registration,
      targetFactor,
      source,
    });
    const keyManifestDigestB64u = await digestJsonV1(source.signerManifest);
    if (keyManifestDigestB64u !== input.persisted.registration.keyManifestDigestB64u) {
      throw new Error('linked-device source manifest replay digest changed');
    }
    return buildTargetCredentialRegistrationSuccessV1({
      outcome: 'replayed',
      registration: input.registration,
      targetFactor,
      ordinarySignerMaterialPreparations: parsedPreparations,
      keyManifestDigestB64u,
    });
  }

  async buildVerifiedLinkInputV1(input: {
    readonly session: LinkedDeviceSessionRecordV1;
    readonly approval: LinkedDeviceApprovalV1;
    readonly requestedAtMs: number;
  }): Promise<VerifiedLinkInputV1> {
    const persisted = await this.readV1(input.session.linkSessionId);
    if (!persisted?.registration) {
      throw new Error('linked-device target credential is not registered');
    }
    if (!input.session.sourceContributionPreparation) {
      throw new Error('linked-device source contribution preparation is missing from the session');
    }
    const verifiedLinkInput = await this.buildVerifiedLinkInputWithRegistrationV1({
      session: input.session,
      approval: input.approval,
      preparation: persisted.preparation,
      registration: persisted.registration.value,
      evidence: persisted.registration.evidence,
      requestedAtMs: input.requestedAtMs,
    });
    if (
      (await digestJsonV1(verifiedLinkInput.signerManifest)) !==
      persisted.registration.keyManifestDigestB64u
    ) {
      throw new Error('linked-device source manifest replay digest changed');
    }
    return verifiedLinkInput;
  }

  private async buildVerifiedLinkInputWithRegistrationV1(input: {
    readonly session: LinkedDeviceSessionRecordV1;
    readonly approval: LinkedDeviceApprovalV1;
    readonly preparation: LinkedDeviceTargetPreparationV1;
    readonly registration: LinkedDeviceTargetCredentialRegistrationV1;
    readonly evidence: VerifiedLinkedDeviceTargetFactorEvidenceV1;
    readonly requestedAtMs: number;
  }): Promise<VerifiedLinkInputV1> {
    return await buildVerifiedLinkInputV1({
      ...input,
      source: this.verifiedLinkBuilder.source,
    });
  }

  private async finalizeReservationIfPresentV1(input: {
    readonly linkSessionId: string;
    readonly registrationDigestB64u: DigestB64u;
    readonly keyManifestDigestB64u: DigestB64u;
    readonly committedAtMs: number;
  }): Promise<void> {
    const reservation = await this.readCommitReservationV1(input.linkSessionId);
    if (!reservation) return;
    if (reservation.registrationDigestB64u !== input.registrationDigestB64u) {
      throw new Error('linked-device target credential reservation differs from its registration');
    }
    if (reservation.state === 'reserved') {
      await this.commitReservationV1(input);
      return;
    }
    if (reservation.keyManifestDigestB64u !== input.keyManifestDigestB64u) {
      throw new Error('linked-device target credential reservation manifest digest changed');
    }
  }

  private async reserveCommitV1(input: {
    readonly linkSessionId: string;
    readonly registrationDigestB64u: DigestB64u;
    readonly expiresAtMs: number;
    readonly nowMs: number;
  }): Promise<
    | { readonly outcome: 'acquired' | 'waiting' }
    | { readonly outcome: 'replayed'; readonly keyManifestDigestB64u: DigestB64u }
  > {
    const result = await this.database
      .prepare(
        `INSERT OR IGNORE INTO ${TARGET_COMMIT_RESERVATION_TABLE} (
           namespace, org_id, project_id, env_id, link_session_id,
           registration_digest_b64u, state, reserved_at_ms
         ) VALUES (?, ?, ?, ?, ?, ?, 'reserved', ?)`,
      )
      .bind(
        ...scopeValues(this.scope),
        input.linkSessionId,
        input.registrationDigestB64u,
        input.nowMs,
      )
      .run();
    if (d1ChangedRows(result) === 1) return { outcome: 'acquired' };
    const row = await this.readCommitReservationV1(input.linkSessionId);
    if (!row) return await this.reserveCommitV1(input);
    if (row.registrationDigestB64u !== input.registrationDigestB64u) {
      throw new Error(
        'linked-device target credential conflicts with its durable commit reservation',
      );
    }
    if (row.state === 'committed') {
      return { outcome: 'replayed', keyManifestDigestB64u: row.keyManifestDigestB64u };
    }
    if (row.reservedAtMs >= input.expiresAtMs || input.nowMs >= input.expiresAtMs) {
      await this.database
        .prepare(
          `DELETE FROM ${TARGET_COMMIT_RESERVATION_TABLE}
             WHERE namespace = ? AND org_id = ? AND project_id = ? AND env_id = ?
               AND link_session_id = ? AND state = 'reserved'`,
        )
        .bind(...scopeValues(this.scope), input.linkSessionId)
        .run();
      return await this.reserveCommitV1(input);
    }
    return { outcome: 'waiting' };
  }

  private async waitForCommitV1(input: {
    readonly linkSessionId: string;
    readonly registration: LinkedDeviceTargetCredentialRegistrationV1;
    readonly registrationDigestB64u: DigestB64u;
    readonly expiresAtMs: number;
    readonly session: LinkedDeviceSessionRecordV1;
    readonly approval: LinkedDeviceApprovalV1;
    readonly requestedAtMs: number;
  }): Promise<
    | TargetCredentialRegistrationSuccessV1
    | { readonly outcome: 'invalid_input'; readonly message: string }
  > {
    for (let attempt = 0; attempt < TARGET_COMMIT_WAIT_ATTEMPTS; attempt += 1) {
      const stored = await this.readV1(input.linkSessionId);
      if (stored?.registration) {
        assertRegistrationReplay(
          stored,
          input.registration,
          stored.registration.keyManifestDigestB64u,
        );
        const replay = await this.buildTargetCredentialRegistrationReplayV1({
          persisted: stored,
          session: input.session,
          approval: input.approval,
          registration: input.registration,
          requestedAtMs: input.requestedAtMs,
        });
        return replay;
      }
      const reservation = await this.readCommitReservationV1(input.linkSessionId);
      if (!reservation || reservation.registrationDigestB64u !== input.registrationDigestB64u) {
        throw new Error('linked-device target credential commit reservation changed during replay');
      }
      if (reservation.state === 'committed') {
        throw new Error(
          'linked-device target credential reservation is committed without a registration',
        );
      }
      await waitForTargetCommitV1(TARGET_COMMIT_WAIT_MS);
    }
    throw new Error('linked-device target credential commit is already in progress');
  }

  private async readCommitReservationV1(
    linkSessionId: string,
  ): Promise<PersistedTargetCommitReservationV1 | null> {
    const row = await this.database
      .prepare(
        `SELECT registration_digest_b64u, state, reserved_at_ms,
                committed_at_ms, key_manifest_digest_b64u
           FROM ${TARGET_COMMIT_RESERVATION_TABLE}
          WHERE namespace = ? AND org_id = ? AND project_id = ? AND env_id = ?
            AND link_session_id = ? LIMIT 1`,
      )
      .bind(...scopeValues(this.scope), linkSessionId)
      .first<TargetCommitReservationRowV1>();
    if (!row) return null;
    if (typeof row.registration_digest_b64u !== 'string')
      throw new Error('linked-device target commit reservation digest is invalid');
    const registrationDigestB64u = parseDigestB64u(row.registration_digest_b64u);
    if (row.state !== 'reserved' && row.state !== 'committed')
      throw new Error('linked-device target commit reservation state is invalid');
    if (!Number.isSafeInteger(row.reserved_at_ms) || Number(row.reserved_at_ms) < 0)
      throw new Error('linked-device target commit reservation time is invalid');
    if (row.state === 'reserved') {
      if (
        (row.committed_at_ms !== null && row.committed_at_ms !== undefined) ||
        (row.key_manifest_digest_b64u !== null && row.key_manifest_digest_b64u !== undefined)
      ) {
        throw new Error('linked-device reserved target reservation contains commit data');
      }
      return {
        state: 'reserved',
        registrationDigestB64u,
        reservedAtMs: Number(row.reserved_at_ms),
      };
    }
    if (row.state === 'committed') {
      if (
        !Number.isSafeInteger(row.committed_at_ms) ||
        Number(row.committed_at_ms) < 0 ||
        typeof row.key_manifest_digest_b64u !== 'string'
      ) {
        throw new Error('linked-device committed target reservation is incomplete');
      }
      return {
        state: 'committed',
        registrationDigestB64u,
        reservedAtMs: Number(row.reserved_at_ms),
        committedAtMs: Number(row.committed_at_ms),
        keyManifestDigestB64u: parseDigestB64u(row.key_manifest_digest_b64u),
      };
    }
    throw new Error('linked-device target commit reservation state is invalid');
  }

  private async commitReservationV1(input: {
    readonly linkSessionId: string;
    readonly registrationDigestB64u: DigestB64u;
    readonly keyManifestDigestB64u: DigestB64u;
    readonly committedAtMs: number;
  }): Promise<void> {
    const result = await this.database
      .prepare(
        `UPDATE ${TARGET_COMMIT_RESERVATION_TABLE}
            SET state = 'committed', committed_at_ms = ?, key_manifest_digest_b64u = ?
          WHERE namespace = ? AND org_id = ? AND project_id = ? AND env_id = ?
            AND link_session_id = ? AND state = 'reserved'
            AND registration_digest_b64u = ?`,
      )
      .bind(
        input.committedAtMs,
        input.keyManifestDigestB64u,
        ...scopeValues(this.scope),
        input.linkSessionId,
        input.registrationDigestB64u,
      )
      .run();
    if (d1ChangedRows(result) === 1) return;
    const row = await this.readCommitReservationV1(input.linkSessionId);
    if (
      !row ||
      row.registrationDigestB64u !== input.registrationDigestB64u ||
      row.state !== 'committed' ||
      row.keyManifestDigestB64u !== input.keyManifestDigestB64u
    ) {
      throw new Error('linked-device target commit reservation did not persist');
    }
  }

  private async releaseCommitReservationV1(input: {
    readonly linkSessionId: string;
    readonly registrationDigestB64u: DigestB64u;
  }): Promise<void> {
    await this.database
      .prepare(
        `DELETE FROM ${TARGET_COMMIT_RESERVATION_TABLE}
           WHERE namespace = ? AND org_id = ? AND project_id = ? AND env_id = ?
             AND link_session_id = ? AND state = 'reserved'
             AND registration_digest_b64u = ?`,
      )
      .bind(...scopeValues(this.scope), input.linkSessionId, input.registrationDigestB64u)
      .run();
  }

  private async readV1(linkSessionId: string): Promise<PersistedTargetCredentialV1 | null> {
    const row = await this.database
      .prepare(
        `SELECT state, target_factor, preparation_digest_b64u, preparation_json,
                registration_json, credential_id_b64u, credential_public_key_b64u,
                credential_counter, email_otp_grant_id, key_manifest_digest_b64u
           FROM ${TARGET_CREDENTIAL_TABLE}
          WHERE namespace = ? AND org_id = ? AND project_id = ? AND env_id = ?
            AND link_session_id = ?
          LIMIT 1`,
      )
      .bind(...scopeValues(this.scope), linkSessionId)
      .first<TargetCredentialRowV1>();
    if (!row) return null;
    const parsed = await parseTargetCredentialRow(row);
    if (
      parsed.preparationDigestB64u !==
      (await computeLinkedDeviceTargetPreparationDigestV1(parsed.preparation))
    ) {
      throw new Error('linked-device target preparation digest is invalid');
    }
    return parsed;
  }
}

function assertPreparationReplay(
  persisted: PersistedTargetCredentialV1,
  preparation: LinkedDeviceTargetPreparationV1,
): void {
  if (alphabetizeStringify(persisted.preparation) !== alphabetizeStringify(preparation)) {
    throw new Error('linked-device target preparation differs from its durable record');
  }
}

function assertRegistrationReplay(
  persisted: PersistedTargetCredentialV1,
  registration: LinkedDeviceTargetCredentialRegistrationV1,
  keyManifestDigestB64u: DigestB64u,
): void {
  if (
    !persisted.registration ||
    persisted.registration.keyManifestDigestB64u !== keyManifestDigestB64u ||
    alphabetizeStringify(persisted.registration.value) !== alphabetizeStringify(registration)
  ) {
    throw new Error('linked-device target credential conflicts with its durable record');
  }
}

function assertPreparationMatchesSession(
  preparation: LinkedDeviceTargetPreparationV1,
  session: LinkedDeviceSessionRecordV1,
  approval: LinkedDeviceApprovalV1,
): void {
  const sourceSignerManifest = session.approvalTranscript?.sourceSignerManifest;
  if (!sourceSignerManifest) {
    throw new Error('linked-device verified source signer manifest is unavailable');
  }
  if (
    preparation.linkSessionId !== session.linkSessionId ||
    preparation.linkSessionId !== approval.linkSessionId ||
    preparation.walletId !== approval.walletId ||
    preparation.enrollmentId !== approval.enrollmentId ||
    preparation.deviceId !== approval.deviceId ||
    preparation.targetFactor.kind !== approval.targetFactor.kind ||
    !preparationBaseFactorMatchesApprovalV1(preparation, approval) ||
    preparation.ordinarySignerMaterialRecipientRequirements.length !==
      sourceSignerManifest.signers.length
  ) {
    throw new Error('linked-device target preparation differs from its approved session');
  }
  for (
    let index = 0;
    index < preparation.ordinarySignerMaterialRecipientRequirements.length;
    index += 1
  ) {
    const requirement = preparation.ordinarySignerMaterialRecipientRequirements[index];
    const approved = sourceSignerManifest.signers[index];
    if (
      !requirement ||
      !approved ||
      requirement.walletKeyId !== approved.walletKeyId ||
      requirement.keyFamily !== approved.keyFamily
    ) {
      throw new Error(
        `linked-device target preparation recipient requirement ${index} is not approved`,
      );
    }
  }
}

function preparationBaseFactorMatchesApprovalV1(
  preparation: LinkedDeviceTargetPreparationV1,
  approval: LinkedDeviceApprovalV1,
): boolean {
  if (isEmailOtpPreparationV1(preparation)) {
    const approvalTargetFactor = approval.targetFactor;
    return (
      approvalTargetFactor.kind === 'email_otp' &&
      preparation.baseWalletAuthMethodId === approvalTargetFactor.baseWalletAuthMethodId
    );
  }
  return (
    preparation.targetFactor.kind === 'passkey_prf' && approval.targetFactor.kind === 'passkey_prf'
  );
}

function isEmailOtpPreparationV1(
  preparation: LinkedDeviceTargetPreparationV1,
): preparation is Extract<
  LinkedDeviceTargetPreparationV1,
  { readonly targetFactor: { readonly kind: 'email_otp' } }
> {
  return preparation.targetFactor.kind === 'email_otp';
}

async function readVerifiedSourceForTargetCredentialV1(input: {
  readonly source: VerifiedLinkSourceReaderV1;
  readonly registration: LinkedDeviceTargetCredentialRegistrationV1;
  readonly approval: LinkedDeviceApprovalV1;
  readonly requestedAtMs: number;
}): Promise<VerifiedLinkSourceReadV1> {
  if (input.approval.ownerAuthorization.kind !== 'wallet_session') {
    throw new Error('verified device linking requires an ordinary Wallet Session');
  }
  const keyFamily = input.registration.ordinarySignerMaterialRecipientRequests[0]?.keyFamily;
  if (!keyFamily) throw new Error('verified device linking source signer manifest is missing');
  return await input.source.readVerifiedSourceV1({
    walletId: input.registration.walletId,
    walletSessionId: String(input.approval.ownerAuthorization.walletSessionId),
    authorizationId: String(input.approval.ownerAuthorization.authorizationId),
    keyFamily,
    requestedAtMs: input.requestedAtMs,
  });
}

function assertSourceContributionPreparationContextV1(input: {
  readonly preparations: LinkedDeviceOrdinaryMaterialSourceContributionPreparationTupleV1;
  readonly session: LinkedDeviceSessionRecordV1;
  readonly approval: LinkedDeviceApprovalV1;
  readonly preparation: LinkedDeviceTargetPreparationV1;
  readonly registration: LinkedDeviceTargetCredentialRegistrationV1;
  readonly targetFactor: VerifiedTargetFactorV1;
  readonly source: VerifiedLinkSourceReadV1;
}): void {
  if (
    input.session.linkSessionId !== input.registration.linkSessionId ||
    input.approval.linkSessionId !== input.registration.linkSessionId ||
    input.preparation.linkSessionId !== input.registration.linkSessionId ||
    (input.session.state.state !== 'awaiting_target_factor' &&
      input.session.state.state !== 'awaiting_source_contribution' &&
      input.session.state.state !== 'provisioning' &&
      input.session.state.state !== 'authority_pending_local_install' &&
      input.session.state.state !== 'active')
  ) {
    throw new Error('linked-device source contribution preparation session is invalid');
  }
  if (
    input.targetFactor.authMethod.walletId !== input.registration.walletId ||
    input.targetFactor.authMethod.walletAuthMethodId !== input.registration.walletAuthMethodId ||
    input.targetFactor.verificationDigestB64u.length === 0
  ) {
    throw new Error('linked-device source contribution preparation target factor is invalid');
  }
  const signers = input.source.signerManifest.signers;
  if (
    input.preparations.length !== signers.length ||
    input.registration.ordinarySignerMaterialRecipientRequests.length !== signers.length ||
    input.preparation.ordinarySignerMaterialRecipientRequirements.length !== signers.length
  ) {
    throw new Error(
      'linked-device source contribution preparations do not cover the signer manifest',
    );
  }
  const targetActivations = input.preparations.map((value) =>
    'kind' in value ? value.targetMaterialActivation : value.target.activation,
  );
  for (let index = 0; index < targetActivations.length; index += 1) {
    const current = targetActivations[index];
    if (!current) throw new Error(`linked-device source preparation ${index} is missing`);
    for (let prior = 0; prior < index; prior += 1) {
      const previous = targetActivations[prior];
      if (previous && mpcMaterialActivationRefsEqual(previous, current)) {
        throw new Error('linked-device source preparations repeat a target activation');
      }
    }
  }
  for (let index = 0; index < signers.length; index += 1) {
    const signer = signers[index];
    const preparation = input.preparations[index];
    const request = input.registration.ordinarySignerMaterialRecipientRequests[index];
    const requirement = input.preparation.ordinarySignerMaterialRecipientRequirements[index];
    if (!signer || !preparation || !request || !requirement) {
      throw new Error(`linked-device source preparation ${index} is incomplete`);
    }
    if (
      preparation.linkSessionId !== input.registration.linkSessionId ||
      preparation.enrollmentId !== input.registration.enrollmentId ||
      preparation.sourceAuthorityId !== input.source.authority.authorityId ||
      requirement.walletKeyId !== signer.walletKeyId ||
      requirement.keyFamily !== signer.keyFamily ||
      request.walletKeyId !== signer.walletKeyId ||
      request.keyFamily !== signer.keyFamily
    ) {
      throw new Error(
        `linked-device source preparation ${index} identity differs from the manifest`,
      );
    }
    const sourceMaterialActivation = sourceMaterialActivationForSignerV1(input.source, signer);
    if ('kind' in preparation) {
      if (
        signer.keyFamily !== 'ed25519' ||
        preparation.walletKeyId !== signer.walletKeyId ||
        String(preparation.targetDeviceId) !== String(input.registration.deviceId) ||
        preparation.targetFactorVerificationDigestB64u !==
          input.targetFactor.verificationDigestB64u ||
        preparation.sourceRegisteredPublicKeyB64u !== signer.registeredPublicKeyB64u ||
        !mpcMaterialActivationRefsEqual(
          routerAbMpcMaterialActivationRefFromWire(preparation.sourceBinding.material_activation),
          sourceMaterialActivation,
        ) ||
        !mpcMaterialActivationRefsEqual(
          routerAbMpcMaterialActivationRefFromWire(
            preparation.targetAdmission.binding.material_activation,
          ),
          preparation.targetMaterialActivation,
        ) ||
        preparation.targetClientRecipientPublicKeyB64u !==
          ('recipientPublicKeyB64u' in request ? request.recipientPublicKeyB64u : '')
      ) {
        throw new Error(
          `linked-device Ed25519 source preparation ${index} differs from its inputs`,
        );
      }
      continue;
    }
    if (
      signer.keyFamily !== 'ecdsa_secp256k1' ||
      String(preparation.target.targetDeviceId) !== String(input.registration.deviceId) ||
      preparation.target.targetFactorVerificationDigestB64u !==
        input.targetFactor.verificationDigestB64u ||
      preparation.source.thresholdPublicKey33B64u !== signer.thresholdPublicKey33B64u ||
      !mpcMaterialActivationRefsEqual(preparation.source.activation, sourceMaterialActivation) ||
      preparation.target.clientRecipientPublicKeyB64u !==
        ('clientEphemeralPublicKey' in request
          ? linkedDeviceX25519RecipientPublicKeyB64uV1(request.clientEphemeralPublicKey)
          : '')
    ) {
      throw new Error(`linked-device ECDSA source preparation ${index} differs from its inputs`);
    }
  }
}

function sourceMaterialActivationForSignerV1(
  source: VerifiedLinkSourceReadV1,
  signer: ExactAdministeredSignerV1,
): MpcMaterialActivationRef {
  const activation =
    signer.keyFamily === 'ed25519'
      ? source.authority.signerActivations.ed25519
      : source.authority.signerActivations.ecdsa;
  if (!activation || activation.signer.walletKeyId !== signer.walletKeyId) {
    throw new Error(`linked-device ${signer.keyFamily} source activation is unavailable`);
  }
  return activation.materialActivation;
}

async function parseTargetCredentialRow(
  row: TargetCredentialRowV1,
): Promise<PersistedTargetCredentialV1> {
  if (row.state !== 'prepared' && row.state !== 'registered') {
    throw new Error('linked-device target credential state is invalid');
  }
  if (typeof row.preparation_json !== 'string') {
    throw new Error('linked-device target preparation JSON is missing');
  }
  const preparation = parseLinkedDeviceTargetPreparationV1(JSON.parse(row.preparation_json));
  const preparationDigestB64u = parseDigestB64u(row.preparation_digest_b64u);
  if (row.target_factor !== preparation.targetFactor.kind) {
    throw new Error('linked-device target factor column differs from its preparation');
  }
  if (row.state === 'prepared') {
    if (row.registration_json !== null && row.registration_json !== undefined) {
      throw new Error('prepared linked-device target contains registration data');
    }
    return { state: 'prepared', preparationDigestB64u, preparation, registration: null };
  }
  if (
    typeof row.registration_json !== 'string' ||
    typeof row.credential_id_b64u !== 'string' ||
    typeof row.key_manifest_digest_b64u !== 'string'
  ) {
    throw new Error('registered linked-device target is incomplete');
  }
  const credentialId = parseWebAuthnCredentialIdB64u(row.credential_id_b64u);
  if (!credentialId.ok) throw new Error(credentialId.error.message);
  const registration = parseLinkedDeviceTargetCredentialRegistrationV1(
    JSON.parse(row.registration_json),
  );
  if (registration.targetFactor.kind !== preparation.targetFactor.kind) {
    throw new Error('linked-device stored registration factor differs from its preparation');
  }
  const keyManifestDigestB64u = parseDigestB64u(row.key_manifest_digest_b64u);
  if (registration.targetFactor.kind === 'passkey_prf') {
    if (
      typeof row.credential_public_key_b64u !== 'string' ||
      !Number.isSafeInteger(row.credential_counter) ||
      row.email_otp_grant_id != null
    ) {
      throw new Error('registered linked-device passkey target is incomplete');
    }
    if (
      !registration.webauthnRegistration ||
      registration.webauthnRegistration.credentialIdB64u !== credentialId.value
    ) {
      throw new Error('linked-device credential id differs from its stored registration');
    }
    return {
      state: 'registered',
      preparationDigestB64u,
      preparation,
      registration: {
        value: registration,
        evidence: {
          kind: 'passkey_prf',
          credential: {
            credentialIdB64u: credentialId.value,
            credentialPublicKeyB64u: row.credential_public_key_b64u,
            counter: row.credential_counter as number,
          },
        },
        keyManifestDigestB64u,
      },
    };
  }
  const wireGrant = registration.emailOtpVerificationGrant;
  if (
    !wireGrant ||
    typeof row.email_otp_grant_id !== 'string' ||
    row.email_otp_grant_id !== wireGrant.grantId ||
    row.credential_public_key_b64u != null ||
    row.credential_counter != null
  ) {
    throw new Error('registered linked-device email OTP target is incomplete');
  }
  const descriptorCredentialIdB64u = await linkedDeviceEmailOtpDescriptorCredentialIdV1(
    preparation.walletAuthMethodId,
  );
  if (descriptorCredentialIdB64u !== credentialId.value) {
    throw new Error('linked-device email OTP descriptor binding differs from its stored grant');
  }
  return {
    state: 'registered',
    preparationDigestB64u,
    preparation,
    registration: {
      value: registration,
      evidence: {
        kind: 'email_otp',
        grant: {
          grantId: wireGrant.grantId,
          baseWalletAuthMethodId: wireGrant.baseWalletAuthMethodId,
          authorityDigestB64u: wireGrant.authorityDigestB64u,
          descriptorCredentialIdB64u,
        },
      },
      keyManifestDigestB64u,
    },
  };
}

function normalizeScope(scope: D1LinkedDeviceSessionScopeV1): D1LinkedDeviceSessionScopeV1 {
  return {
    namespace: requiredScope(scope.namespace, 'namespace'),
    orgId: requiredScope(scope.orgId, 'orgId'),
    projectId: requiredScope(scope.projectId, 'projectId'),
    envId: requiredScope(scope.envId, 'envId'),
  };
}

function requiredScope(value: string, field: string): string {
  if (
    typeof value !== 'string' ||
    value.length === 0 ||
    value.trim() !== value ||
    hasControlCharacter(value)
  ) {
    throw new Error(`${field} is invalid`);
  }
  return value;
}

function scopeValues(scope: D1LinkedDeviceSessionScopeV1): readonly string[] {
  return [scope.namespace, scope.orgId, scope.projectId, scope.envId];
}

function isCanonicalNonemptyBase64Url(value: string): boolean {
  try {
    const bytes = base64UrlDecode(value);
    return bytes.length > 0 && base64UrlEncode(bytes) === value;
  } catch {
    return false;
  }
}

async function digestRegistrationV1(
  registration: LinkedDeviceTargetCredentialRegistrationV1,
): Promise<DigestB64u> {
  return parseDigestB64u(
    base64UrlEncode(
      await sha256BytesUtf8(
        `seams/r103/target-credential/v1\u0000${alphabetizeStringify(registration)}`,
      ),
    ),
  );
}

async function digestJsonV1(value: unknown): Promise<DigestB64u> {
  return parseDigestB64u(base64UrlEncode(await sha256BytesUtf8(alphabetizeStringify(value))));
}

async function waitForTargetCommitV1(delayMs: number): Promise<void> {
  await new Promise<void>((resolve) => setTimeout(resolve, delayMs));
}
