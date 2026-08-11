import type {
  LinkedDeviceApprovalV1,
  LinkedDeviceTargetCredentialRegistrationV1,
  LinkedDeviceTargetPreparationV1,
} from '@shared/device-linking/contracts';
import {
  parseLinkedDeviceTargetCredentialRegistrationV1,
  parseLinkedDeviceTargetPreparationV1,
} from '@shared/device-linking/parsers';
import {
  assertLinkedDeviceTargetCredentialRegistrationMatchesPreparationV1,
  computeLinkedDeviceTargetPreparationDigestV1,
} from '@shared/device-linking/digests';
import { alphabetizeStringify } from '@shared/utils/digests';
import { errorMessage } from '@shared/utils/errors';
import { parseDigestB64u, type DigestB64u } from '@shared/utils/canonicalPrimitives';
import { parseWebAuthnCredentialIdB64u } from '@shared/utils/domainIds';
import { base64UrlDecode, base64UrlEncode } from '@shared/utils/base64';
import type { D1DatabaseLike, D1ResultLike } from '../../../../storage/tenantRoute';
import type { LinkedDeviceSessionRecordV1 } from '../../../../core/deviceLinking/linkedDeviceSession';
import { verifyWebAuthnRegistrationCredentialForIntent } from '../../../../core/authService/webauthn';
import type { DeviceLinkingTargetCredentialProviderV1 } from '../../../../router/transport/fetch/routes/deviceLinking';
import type { D1LinkedDeviceSessionScopeV1 } from './d1LinkedDeviceSessionStore';

export type VerifiedLinkedDeviceWebAuthnCredentialV1 = {
  readonly credentialIdB64u: string;
  readonly credentialPublicKeyB64u: string;
  readonly counter: number;
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

export class LinkedDeviceWebAuthnRegistrationVerifierV1 implements LinkedDeviceTargetCredentialVerificationPortV1 {
  private readonly expectedOrigin: string;

  constructor(input: { readonly expectedOrigin: string }) {
    const expectedOrigin = input.expectedOrigin.trim();
    if (!expectedOrigin) throw new Error('linked-device WebAuthn expected origin is required');
    this.expectedOrigin = expectedOrigin;
  }

  async verifyRegistrationV1(input: {
    readonly preparation: LinkedDeviceTargetPreparationV1;
    readonly registration: LinkedDeviceTargetCredentialRegistrationV1;
  }): Promise<
    | { readonly kind: 'verified'; readonly credential: VerifiedLinkedDeviceWebAuthnCredentialV1 }
    | { readonly kind: 'rejected'; readonly message: string }
  > {
    const webauthn = input.registration.webauthnRegistration;
    const verification = await verifyWebAuthnRegistrationCredentialForIntent({
      webauthnRegistration: {
        id: webauthn.credentialIdB64u,
        rawId: webauthn.credentialIdB64u,
        type: 'public-key',
        authenticatorAttachment: webauthn.authenticatorAttachment ?? undefined,
        response: {
          clientDataJSON: webauthn.clientDataJsonB64u,
          attestationObject: webauthn.attestationObjectB64u,
          transports: [...webauthn.transports],
        },
        clientExtensionResults: {},
      },
      expectedChallenge: input.preparation.challengeB64u,
      expectedOrigin: this.expectedOrigin,
      rpId: input.preparation.rpId,
    });
    return verification.ok
      ? { kind: 'verified', credential: verification.credential }
      : { kind: 'rejected', message: verification.message };
  }
}

export type LinkedDeviceTargetPreparationSourceV1 = {
  createTargetPreparationV1(input: {
    readonly session: LinkedDeviceSessionRecordV1;
    readonly approval: LinkedDeviceApprovalV1;
    readonly requestedAtMs: number;
  }): Promise<LinkedDeviceTargetPreparationV1>;
};

export type LinkedDeviceVerifiedTargetCommitterV1 = {
  commitVerifiedTargetV1(input: {
    readonly preparation: LinkedDeviceTargetPreparationV1;
    readonly registration: LinkedDeviceTargetCredentialRegistrationV1;
    readonly credential: VerifiedLinkedDeviceWebAuthnCredentialV1;
    readonly requestedAtMs: number;
  }): Promise<{ readonly keyManifestDigestB64u: DigestB64u }>;
};

type TargetCredentialRowV1 = {
  readonly state?: unknown;
  readonly preparation_digest_b64u?: unknown;
  readonly preparation_json?: unknown;
  readonly registration_json?: unknown;
  readonly credential_id_b64u?: unknown;
  readonly credential_public_key_b64u?: unknown;
  readonly credential_counter?: unknown;
  readonly key_manifest_digest_b64u?: unknown;
};

type PersistedTargetCredentialV1 = {
  readonly state: 'prepared' | 'registered';
  readonly preparationDigestB64u: DigestB64u;
  readonly preparation: LinkedDeviceTargetPreparationV1;
  readonly registration: {
    readonly value: LinkedDeviceTargetCredentialRegistrationV1;
    readonly credential: VerifiedLinkedDeviceWebAuthnCredentialV1;
    readonly keyManifestDigestB64u: DigestB64u;
  } | null;
};

const TARGET_CREDENTIAL_TABLE = 'linked_device_target_credentials';

export class D1LinkedDeviceTargetCredentialProviderV1 implements DeviceLinkingTargetCredentialProviderV1 {
  private readonly database: D1DatabaseLike;
  private readonly scope: D1LinkedDeviceSessionScopeV1;
  private readonly preparationSource: LinkedDeviceTargetPreparationSourceV1;
  private readonly verifier: LinkedDeviceTargetCredentialVerificationPortV1;
  private readonly committer: LinkedDeviceVerifiedTargetCommitterV1;

  constructor(input: {
    readonly database: D1DatabaseLike;
    readonly scope: D1LinkedDeviceSessionScopeV1;
    readonly preparationSource: LinkedDeviceTargetPreparationSourceV1;
    readonly verifier: LinkedDeviceTargetCredentialVerificationPortV1;
    readonly committer: LinkedDeviceVerifiedTargetCommitterV1;
  }) {
    this.database = input.database;
    this.scope = normalizeScope(input.scope);
    this.preparationSource = input.preparationSource;
    this.verifier = input.verifier;
    this.committer = input.committer;
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
    if (input.session.state.state !== 'awaiting_target_passkey') {
      throw new Error('linked-device target preparation is unavailable in this session state');
    }
    const preparation = parseLinkedDeviceTargetPreparationV1(
      await this.preparationSource.createTargetPreparationV1(input),
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
           wallet_id, enrollment_id, device_id, state,
           preparation_digest_b64u, preparation_json, prepared_at_ms, expires_at_ms
         ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'prepared', ?, ?, ?, ?)`,
      )
      .bind(
        ...scopeValues(this.scope),
        String(preparation.linkSessionId),
        String(preparation.walletId),
        String(preparation.enrollmentId),
        String(preparation.deviceId),
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
    readonly requestedAtMs: number;
  }): Promise<
    | { readonly outcome: 'applied' | 'replayed'; readonly keyManifestDigestB64u: DigestB64u }
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
        return {
          outcome: 'replayed',
          keyManifestDigestB64u: persisted.registration.keyManifestDigestB64u,
        };
      }
      if (input.requestedAtMs >= persisted.preparation.expiresAtMs) {
        throw new Error('linked-device target credential registration is expired');
      }
      const verification = await this.verifier.verifyRegistrationV1({
        preparation: persisted.preparation,
        registration,
      });
      if (verification.kind === 'rejected') throw new Error(verification.message);
      const credentialId = parseWebAuthnCredentialIdB64u(verification.credential.credentialIdB64u);
      if (!credentialId.ok) throw new Error(credentialId.error.message);
      if (credentialId.value !== registration.webauthnRegistration.credentialIdB64u) {
        throw new Error('verified WebAuthn credential id differs from its registration');
      }
      if (
        !Number.isSafeInteger(verification.credential.counter) ||
        verification.credential.counter < 0 ||
        !isCanonicalNonemptyBase64Url(verification.credential.credentialPublicKeyB64u)
      ) {
        throw new Error('verified WebAuthn credential material is invalid');
      }
      const committed = await this.committer.commitVerifiedTargetV1({
        preparation: persisted.preparation,
        registration,
        credential: verification.credential,
        requestedAtMs: input.requestedAtMs,
      });
      const keyManifestDigestB64u = parseDigestB64u(committed.keyManifestDigestB64u);
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
          JSON.stringify(registration),
          credentialId.value,
          verification.credential.credentialPublicKeyB64u,
          verification.credential.counter,
          keyManifestDigestB64u,
          input.requestedAtMs,
          ...scopeValues(this.scope),
          String(input.session.linkSessionId),
          persisted.preparationDigestB64u,
        )
        .run();
      const stored = await this.readV1(input.session.linkSessionId);
      if (!stored?.registration) throw new Error('linked-device target credential did not persist');
      assertRegistrationReplay(stored, registration, keyManifestDigestB64u);
      return {
        outcome: changedRows(result) === 1 ? 'applied' : 'replayed',
        keyManifestDigestB64u: stored.registration.keyManifestDigestB64u,
      };
    } catch (error: unknown) {
      return { outcome: 'invalid_input', message: errorMessage(error) };
    }
  }

  private async readV1(linkSessionId: string): Promise<PersistedTargetCredentialV1 | null> {
    const row = await this.database
      .prepare(
        `SELECT state, preparation_digest_b64u, preparation_json, registration_json,
                credential_id_b64u, credential_public_key_b64u, credential_counter,
                key_manifest_digest_b64u
           FROM ${TARGET_CREDENTIAL_TABLE}
          WHERE namespace = ? AND org_id = ? AND project_id = ? AND env_id = ?
            AND link_session_id = ?
          LIMIT 1`,
      )
      .bind(...scopeValues(this.scope), linkSessionId)
      .first<TargetCredentialRowV1>();
    if (!row) return null;
    const parsed = parseTargetCredentialRow(row);
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
  if (
    preparation.linkSessionId !== session.linkSessionId ||
    preparation.linkSessionId !== approval.linkSessionId ||
    preparation.walletId !== approval.walletId ||
    preparation.enrollmentId !== approval.enrollmentId ||
    preparation.deviceId !== approval.deviceId ||
    preparation.orderedChildren.length !== approval.orderedKeyBindings.length
  ) {
    throw new Error('linked-device target preparation differs from its approved session');
  }
  for (let index = 0; index < preparation.orderedChildren.length; index += 1) {
    const child = preparation.orderedChildren[index];
    const approved = approval.orderedKeyBindings[index];
    if (
      !child ||
      !approved ||
      child.walletKeyId !== approved.walletKeyId ||
      child.keyFamily !== approved.keyFamily ||
      child.targetLaneId !== approved.targetLaneId ||
      child.targetLaneShareEpoch !== approved.targetLaneShareEpoch
    ) {
      throw new Error(`linked-device target preparation child ${index} is not approved`);
    }
  }
}

function parseTargetCredentialRow(row: TargetCredentialRowV1): PersistedTargetCredentialV1 {
  if (row.state !== 'prepared' && row.state !== 'registered') {
    throw new Error('linked-device target credential state is invalid');
  }
  if (typeof row.preparation_json !== 'string') {
    throw new Error('linked-device target preparation JSON is missing');
  }
  const preparation = parseLinkedDeviceTargetPreparationV1(JSON.parse(row.preparation_json));
  const preparationDigestB64u = parseDigestB64u(row.preparation_digest_b64u);
  if (row.state === 'prepared') {
    if (row.registration_json !== null && row.registration_json !== undefined) {
      throw new Error('prepared linked-device target contains registration data');
    }
    return { state: 'prepared', preparationDigestB64u, preparation, registration: null };
  }
  if (
    typeof row.registration_json !== 'string' ||
    typeof row.credential_id_b64u !== 'string' ||
    typeof row.credential_public_key_b64u !== 'string' ||
    !Number.isSafeInteger(row.credential_counter) ||
    typeof row.key_manifest_digest_b64u !== 'string'
  ) {
    throw new Error('registered linked-device target is incomplete');
  }
  const credentialId = parseWebAuthnCredentialIdB64u(row.credential_id_b64u);
  if (!credentialId.ok) throw new Error(credentialId.error.message);
  const registration = parseLinkedDeviceTargetCredentialRegistrationV1(
    JSON.parse(row.registration_json),
  );
  if (registration.webauthnRegistration.credentialIdB64u !== credentialId.value) {
    throw new Error('linked-device credential id differs from its stored registration');
  }
  return {
    state: 'registered',
    preparationDigestB64u,
    preparation,
    registration: {
      value: registration,
      credential: {
        credentialIdB64u: credentialId.value,
        credentialPublicKeyB64u: row.credential_public_key_b64u,
        counter: row.credential_counter as number,
      },
      keyManifestDigestB64u: parseDigestB64u(row.key_manifest_digest_b64u),
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
    /[\u0000-\u001f\u007f]/.test(value)
  ) {
    throw new Error(`${field} is invalid`);
  }
  return value;
}

function scopeValues(scope: D1LinkedDeviceSessionScopeV1): readonly string[] {
  return [scope.namespace, scope.orgId, scope.projectId, scope.envId];
}

function changedRows(result: D1ResultLike): number {
  const value = result.meta?.changes;
  return typeof value === 'number' ? value : Number(value || 0);
}

function isCanonicalNonemptyBase64Url(value: string): boolean {
  try {
    const bytes = base64UrlDecode(value);
    return bytes.length > 0 && base64UrlEncode(bytes) === value;
  } catch {
    return false;
  }
}
