/**
 * Refactor 103 Phase 6 — D1 persistence for linked-device Email OTP
 * verification grants, and the registration-time port that consumes them.
 *
 * A grant is issued once, after the emailed code verifies against the exact
 * link-session binding, and consumed exactly once, in the same D1 batch that
 * flips the target credential to `registered` and persists the derived
 * linked-owner binding. The CAS guard makes a lost consumption fail that
 * whole batch, so a grant can never authorize two completions and a
 * completion can never commit against an already-spent grant.
 */
import type {
  LinkedDeviceTargetCredentialRegistrationV1,
  LinkedDeviceTargetPreparationV1,
} from '@shared/device-linking/contracts';
import { parseDigestB64u, type DigestB64u } from '@shared/utils/canonicalPrimitives';
import type { TenantId } from '@shared/authorization/capabilityKinds';
import type { WalletAuthMethodId, WalletId } from '@shared/utils/domainIds';
import {
  buildLinkedOwnerEmailOtpAuthBindingV1,
  linkedOwnerAuthMethodIdV1,
  linkedOwnerEmailOtpBaseAuthMethodIdV1,
} from '@shared/device-linking/ownerAuthBinding';
import {
  computeLinkedDeviceEmailOtpAuthorityDigestV1,
  computeLinkedDeviceEmailOtpGrantTokenDigestV1,
  linkedDeviceEmailOtpDescriptorCredentialIdV1,
  linkedDeviceEmailOtpGrantAdmitsUseV1,
  parseLinkedDeviceEmailOtpGrantRecordV1,
  type LinkedDeviceEmailOtpGrantRecordV1,
} from '../../../../core/deviceLinking/linkedDeviceEmailOtpGrant';
import type { D1DatabaseLike, D1PreparedStatementLike } from '../../../../storage/tenantRoute';
import type { D1LinkedDeviceSessionScopeV1 } from './d1LinkedDeviceSessionStore';
import type {
  LinkedDeviceEmailOtpGrantRegistrationPortV1,
  VerifiedLinkedDeviceEmailOtpGrantV1,
} from './d1LinkedDeviceTargetCredentialProvider';

const GRANT_TABLE = 'linked_device_email_otp_grants';
const GRANT_CAS_GUARD_SQL = `INSERT INTO linked_device_session_cas_guard (guard_id)
SELECT 1
 WHERE changes() = 0`;

export class D1LinkedDeviceEmailOtpGrantStoreV1 {
  private readonly database: D1DatabaseLike;
  private readonly scope: D1LinkedDeviceSessionScopeV1;

  constructor(input: {
    readonly database: D1DatabaseLike;
    readonly scope: D1LinkedDeviceSessionScopeV1;
  }) {
    this.database = input.database;
    this.scope = input.scope;
  }

  async issueV1(record: LinkedDeviceEmailOtpGrantRecordV1): Promise<void> {
    const parsed = parseLinkedDeviceEmailOtpGrantRecordV1(record);
    if (parsed.state.kind !== 'issued') {
      throw new Error('a linked-device email OTP grant is only ever inserted as issued');
    }
    await this.database
      .prepare(
        `INSERT INTO ${GRANT_TABLE} (
           namespace, org_id, project_id, env_id, grant_id,
           grant_token_digest_b64u, wallet_id, link_session_id, enrollment_id,
           device_id, target_factor, target_preparation_digest_b64u,
           base_wallet_auth_method_id, linked_owner_auth_method_id,
           authority_digest_b64u, challenge_id, state, record_json,
           issued_at_ms, expires_at_ms, consumed_at_ms
         ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'email_otp', ?, ?, ?, ?, ?, 'issued', ?, ?, ?, NULL)`,
      )
      .bind(
        ...scopeValues(this.scope),
        parsed.grantId,
        parsed.grantTokenDigestB64u,
        String(parsed.walletId),
        String(parsed.linkSessionId),
        String(parsed.enrollmentId),
        String(parsed.deviceId),
        parsed.targetPreparationDigestB64u,
        String(parsed.baseWalletAuthMethodId),
        String(parsed.linkedOwnerAuthMethodId),
        parsed.authorityDigestB64u,
        parsed.challengeId,
        JSON.stringify(parsed),
        parsed.issuedAtMs,
        parsed.expiresAtMs,
      )
      .run();
  }

  async readByIdV1(grantId: string): Promise<LinkedDeviceEmailOtpGrantRecordV1 | null> {
    const row = await this.database
      .prepare(
        `SELECT record_json FROM ${GRANT_TABLE}
          WHERE namespace = ? AND org_id = ? AND project_id = ? AND env_id = ?
            AND grant_id = ? LIMIT 1`,
      )
      .bind(...scopeValues(this.scope), grantId)
      .first<{ readonly record_json?: unknown }>();
    if (!row) return null;
    if (typeof row.record_json !== 'string') {
      throw new Error('linked-device email OTP grant record is invalid');
    }
    return parseLinkedDeviceEmailOtpGrantRecordV1(JSON.parse(row.record_json));
  }

  /**
   * The consumption as statements: a CAS flip from `issued` to `consumed`
   * followed by the guard, so a batch that includes them either consumed the
   * grant exactly now or did not commit at all.
   */
  buildConsumeStatementsV1(input: {
    readonly grantId: string;
    readonly consumedAtMs: number;
  }): readonly D1PreparedStatementLike[] {
    return [
      this.database
        .prepare(
          `UPDATE ${GRANT_TABLE}
              SET state = 'consumed', consumed_at_ms = ?,
                  record_json = json_set(
                    record_json,
                    '$.state', json_object('kind', 'consumed', 'consumedAtMs', ?)
                  )
            WHERE namespace = ? AND org_id = ? AND project_id = ? AND env_id = ?
              AND grant_id = ? AND state = 'issued' AND expires_at_ms > ?`,
        )
        .bind(
          input.consumedAtMs,
          input.consumedAtMs,
          ...scopeValues(this.scope),
          input.grantId,
          input.consumedAtMs,
        ),
      this.database.prepare(GRANT_CAS_GUARD_SQL),
    ];
  }
}

/**
 * Resolves the base wallet Email OTP factor's stored identity columns for the
 * binding insert. Implemented against the canonical wallet auth-method store;
 * returning `null` refuses the completion.
 */
export type LinkedDeviceEmailOtpBaseFactorResolverV1 = (input: {
  readonly walletId: WalletId;
  readonly baseWalletAuthMethodId: WalletAuthMethodId;
}) => Promise<{
  readonly emailHashHex: string;
  readonly registrationAuthorityId: string;
} | null>;

/**
 * The registration-time port the target-credential provider consumes. It
 * validates the exact grant the registration carries — token digest, every
 * bound identity, TTL, unconsumed state — and, once the R102 commit succeeds,
 * hands back the statements that consume the grant and persist the derived
 * linked-owner binding atomically with the credential row flip.
 */
export function createLinkedDeviceEmailOtpRegistrationPortV1(input: {
  readonly grants: D1LinkedDeviceEmailOtpGrantStoreV1;
  readonly bindingWriter: {
    buildInsertV1(binding: ReturnType<typeof buildLinkedOwnerEmailOtpAuthBindingV1>): {
      readonly statement: D1PreparedStatementLike;
    };
  };
  readonly resolveBaseEmailOtpFactorV1: LinkedDeviceEmailOtpBaseFactorResolverV1;
  readonly tenantId: TenantId;
}): LinkedDeviceEmailOtpGrantRegistrationPortV1 {
  return {
    async verifyRegistrationGrantV1(request: {
      readonly preparation: LinkedDeviceTargetPreparationV1;
      readonly registration: LinkedDeviceTargetCredentialRegistrationV1;
      readonly requestedAtMs: number;
    }): Promise<
      | { readonly kind: 'verified'; readonly grant: VerifiedLinkedDeviceEmailOtpGrantV1 }
      | { readonly kind: 'rejected'; readonly message: string }
    > {
      const registration = request.registration;
      const wireGrant = registration.emailOtpVerificationGrant;
      if (registration.targetFactor.kind !== 'email_otp' || !wireGrant) {
        return { kind: 'rejected', message: 'registration does not carry an email OTP grant' };
      }
      const ownerEnrollment = request.preparation.ownerEnrollment;
      if (ownerEnrollment.kind !== 'linked_device_email_otp_owner_enrollment_v1') {
        return {
          kind: 'rejected',
          message: 'target preparation is not an email OTP owner enrollment',
        };
      }
      const stored = await input.grants.readByIdV1(wireGrant.grantId);
      if (!stored) return { kind: 'rejected', message: 'email OTP verification grant is unknown' };
      if (!linkedDeviceEmailOtpGrantAdmitsUseV1(stored, request.requestedAtMs)) {
        return {
          kind: 'rejected',
          message:
            stored.state.kind === 'consumed'
              ? 'email OTP verification grant is already consumed'
              : 'email OTP verification grant is expired',
        };
      }
      const tokenDigest = await computeLinkedDeviceEmailOtpGrantTokenDigestV1(wireGrant.grantToken);
      if (tokenDigest !== stored.grantTokenDigestB64u) {
        return { kind: 'rejected', message: 'email OTP verification grant token is invalid' };
      }
      const preparationDigestB64u = parseDigestB64u(registration.targetPreparationDigestB64u);
      if (
        stored.walletId !== registration.walletId ||
        stored.linkSessionId !== registration.linkSessionId ||
        stored.enrollmentId !== registration.enrollmentId ||
        stored.deviceId !== registration.deviceId ||
        stored.targetPreparationDigestB64u !== preparationDigestB64u
      ) {
        return {
          kind: 'rejected',
          message: 'email OTP verification grant is bound to a different enrollment',
        };
      }
      if (
        stored.baseWalletAuthMethodId !== wireGrant.baseWalletAuthMethodId ||
        stored.linkedOwnerAuthMethodId !== wireGrant.linkedOwnerAuthMethodId ||
        stored.authorityDigestB64u !== wireGrant.authorityDigestB64u ||
        stored.linkSessionId !== wireGrant.linkSessionId ||
        stored.walletId !== wireGrant.walletId ||
        stored.enrollmentId !== wireGrant.enrollmentId ||
        stored.deviceId !== wireGrant.deviceId ||
        stored.targetPreparationDigestB64u !== wireGrant.targetPreparationDigestB64u ||
        stored.challengeId !== wireGrant.challengeId ||
        stored.issuedAtMs !== wireGrant.issuedAtMs ||
        stored.expiresAtMs !== wireGrant.expiresAtMs
      ) {
        return {
          kind: 'rejected',
          message: 'email OTP verification grant identity differs from its durable record',
        };
      }
      if (stored.baseWalletAuthMethodId !== ownerEnrollment.baseWalletAuthMethodId) {
        return {
          kind: 'rejected',
          message: 'email OTP verification grant base factor differs from the approved ceremony',
        };
      }
      const expectedAuthorityDigest = await computeLinkedDeviceEmailOtpAuthorityDigestV1({
        walletId: stored.walletId,
        enrollmentId: stored.enrollmentId,
        deviceId: stored.deviceId,
        linkedOwnerAuthMethodId: stored.linkedOwnerAuthMethodId,
        baseWalletAuthMethodId: stored.baseWalletAuthMethodId,
      });
      if (expectedAuthorityDigest !== stored.authorityDigestB64u) {
        return {
          kind: 'rejected',
          message: 'email OTP verification grant authority digest is not this authority',
        };
      }
      return {
        kind: 'verified',
        grant: {
          grantId: stored.grantId,
          baseWalletAuthMethodId: stored.baseWalletAuthMethodId,
          linkedOwnerAuthMethodId: stored.linkedOwnerAuthMethodId,
          authorityDigestB64u: stored.authorityDigestB64u,
          descriptorCredentialIdB64u: await linkedDeviceEmailOtpDescriptorCredentialIdV1(
            stored.linkedOwnerAuthMethodId,
          ),
        },
      };
    },

    async buildCompletionStatementsV1(request: {
      readonly grant: VerifiedLinkedDeviceEmailOtpGrantV1;
      readonly registration: LinkedDeviceTargetCredentialRegistrationV1;
      readonly keyManifestDigestB64u: DigestB64u;
      readonly consumedAtMs: number;
    }): Promise<readonly D1PreparedStatementLike[]> {
      const base = await input.resolveBaseEmailOtpFactorV1({
        walletId: request.registration.walletId,
        baseWalletAuthMethodId: request.grant.baseWalletAuthMethodId,
      });
      if (!base) {
        throw new Error('base wallet email OTP factor is unavailable for completion');
      }
      const binding = buildLinkedOwnerEmailOtpAuthBindingV1({
        tenantId: input.tenantId,
        walletId: request.registration.walletId,
        enrollmentId: request.registration.enrollmentId,
        deviceId: request.registration.deviceId,
        keyManifestDigestB64u: request.keyManifestDigestB64u,
        activatedAtMs: request.consumedAtMs,
        emailHashHex: base.emailHashHex,
        registrationAuthorityId: base.registrationAuthorityId,
        baseWalletAuthMethodId: linkedOwnerEmailOtpBaseAuthMethodIdV1({
          walletId: request.registration.walletId,
          emailHashHex: base.emailHashHex,
          registrationAuthorityId: base.registrationAuthorityId,
        }),
      });
      // The binding the batch persists must be the principal the grant named —
      // a resolver returning another factor's identity fails here, not later.
      if (binding.walletAuthMethodId !== request.grant.linkedOwnerAuthMethodId) {
        throw new Error('derived linked-owner authority differs from the consumed grant');
      }
      if (binding.factor.kind !== 'email_otp') {
        throw new Error('linked-owner binding factor must be email_otp');
      }
      if (binding.factor.baseWalletAuthMethodId !== request.grant.baseWalletAuthMethodId) {
        throw new Error('linked-owner base factor differs from the consumed grant');
      }
      return [
        ...input.grants.buildConsumeStatementsV1({
          grantId: request.grant.grantId,
          consumedAtMs: request.consumedAtMs,
        }),
        input.bindingWriter.buildInsertV1(binding).statement,
      ];
    },
  };
}

/**
 * Derives the linked-owner auth-method id at grant-issuance time, before any
 * binding exists — from the same inputs the binding builder will later use,
 * so issuance and completion cannot disagree.
 */
export function deriveLinkedDeviceEmailOtpOwnerAuthMethodIdV1(input: {
  readonly walletId: WalletId;
  readonly enrollmentId: LinkedDeviceEmailOtpGrantRecordV1['enrollmentId'];
  readonly deviceId: LinkedDeviceEmailOtpGrantRecordV1['deviceId'];
  readonly emailHashHex: string;
  readonly registrationAuthorityId: string;
}): WalletAuthMethodId {
  return linkedOwnerAuthMethodIdV1({
    walletId: input.walletId,
    enrollmentId: input.enrollmentId,
    deviceId: input.deviceId,
    factor: {
      kind: 'email_otp',
      emailHashHex: input.emailHashHex,
      registrationAuthorityId: input.registrationAuthorityId,
      baseWalletAuthMethodId: linkedOwnerEmailOtpBaseAuthMethodIdV1({
        walletId: input.walletId,
        emailHashHex: input.emailHashHex,
        registrationAuthorityId: input.registrationAuthorityId,
      }),
    },
  });
}

function scopeValues(scope: D1LinkedDeviceSessionScopeV1): readonly string[] {
  return [scope.namespace, scope.orgId, scope.projectId, scope.envId];
}
