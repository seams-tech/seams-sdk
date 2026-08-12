import type {
  LinkedDeviceTargetDeploymentDescriptorRequestV1,
  LinkedDeviceTargetDeploymentDescriptorSignerV1,
  LinkedDeviceTargetDeploymentDescriptorVerifierV1,
  LinkedDeviceTargetDeploymentDescriptorV1,
  LinkedDeviceTargetDeploymentDescriptorUnsignedV1,
} from '@shared/device-linking/targetDeploymentDescriptor';
import {
  buildLinkedDeviceTargetDeploymentDescriptorV1,
  computeLinkedDeviceTargetDeploymentDescriptorDigestV1,
  encodeLinkedDeviceTargetDeploymentDescriptorV1,
  parseLinkedDeviceTargetDeploymentDescriptorRequestV1,
  parseLinkedDeviceTargetDeploymentDescriptorUnsignedV1,
  parseLinkedDeviceTargetDeploymentDescriptorV1,
} from '@shared/device-linking/targetDeploymentDescriptor';
import type { EcdsaTargetCapabilityBindingV1, LaneTargetSigningWorkerV1 } from '@shared/signing-lanes/rotation';
import type { Ed25519YaoSuiteId } from '@shared/signing-lanes/ids';
import type { DigestB64u } from '@shared/utils/canonicalPrimitives';
import { parseDigestB64u } from '@shared/utils/canonicalPrimitives';
import { alphabetizeStringify, sha256BytesUtf8 } from '@shared/utils/digests';
import { base64UrlEncode } from '@shared/utils/base64';
import type { D1DatabaseLike } from '../../../../storage/tenantRoute';
import { d1ChangedRows, parseD1JsonColumn } from '../../../../storage/d1Sql';
import type { D1LinkedDeviceSessionScopeV1 } from './d1LinkedDeviceSessionStore';

const TARGET_DESCRIPTOR_TABLE = 'linked_device_target_deployment_descriptors';

export type LinkedDeviceTargetEcdsaCapabilityAllocatorV1 = {
  allocateEcdsaTargetCapabilityV1(input: {
    readonly request: Extract<
      LinkedDeviceTargetDeploymentDescriptorRequestV1,
      { readonly keyFamily: 'ecdsa_secp256k1' }
    >;
    readonly issuedAtMs: number;
    readonly expiresAtMs: number;
  }): Promise<{
    readonly targetCapability: EcdsaTargetCapabilityBindingV1;
    readonly reshareChannelBindingDigestB64u: DigestB64u;
  }>;
};

export type D1LinkedDeviceTargetDeploymentDescriptorProviderOptionsV1 = {
  readonly database: D1DatabaseLike;
  readonly scope: D1LinkedDeviceSessionScopeV1;
  readonly targetSigningWorker: LaneTargetSigningWorkerV1;
  readonly descriptorSigner: LinkedDeviceTargetDeploymentDescriptorSignerV1;
  readonly descriptorVerifier: LinkedDeviceTargetDeploymentDescriptorVerifierV1;
  readonly ecdsaCapabilityAllocator: LinkedDeviceTargetEcdsaCapabilityAllocatorV1;
  readonly ed25519: {
    readonly yaoSuiteId: Ed25519YaoSuiteId;
    readonly circuitDigestB64u: DigestB64u;
  };
};

export type LinkedDeviceTargetDeploymentDescriptorProviderV1 = {
  resolveTargetDeploymentDescriptorV1(input: {
    readonly request: LinkedDeviceTargetDeploymentDescriptorRequestV1;
    readonly issuedAtMs: number;
    readonly expiresAtMs: number;
  }): Promise<LinkedDeviceTargetDeploymentDescriptorV1>;
};

type TargetDescriptorRowV1 = {
  readonly request_digest_b64u?: unknown;
  readonly registration_digest_b64u?: unknown;
  readonly descriptor_digest_b64u?: unknown;
  readonly descriptor_json?: unknown;
};

/**
 * D1-backed target deployment authority. The descriptor is allocated only
 * after the target preparation and credential registration digests are known;
 * the persisted row is the replay fence for the exact descriptor bytes.
 */
export class D1LinkedDeviceTargetDeploymentDescriptorProviderV1
  implements LinkedDeviceTargetDeploymentDescriptorProviderV1
{
  private readonly database: D1DatabaseLike;
  private readonly scope: D1LinkedDeviceSessionScopeV1;
  private readonly targetSigningWorker: LaneTargetSigningWorkerV1;
  private readonly descriptorSigner: LinkedDeviceTargetDeploymentDescriptorSignerV1;
  private readonly descriptorVerifier: LinkedDeviceTargetDeploymentDescriptorVerifierV1;
  private readonly ecdsaCapabilityAllocator: LinkedDeviceTargetEcdsaCapabilityAllocatorV1;
  private readonly ed25519: D1LinkedDeviceTargetDeploymentDescriptorProviderOptionsV1['ed25519'];

  constructor(options: D1LinkedDeviceTargetDeploymentDescriptorProviderOptionsV1) {
    this.database = options.database;
    this.scope = normalizeScope(options.scope);
    this.targetSigningWorker = options.targetSigningWorker;
    this.descriptorSigner = options.descriptorSigner;
    this.descriptorVerifier = options.descriptorVerifier;
    this.ecdsaCapabilityAllocator = options.ecdsaCapabilityAllocator;
    this.ed25519 = {
      yaoSuiteId: options.ed25519.yaoSuiteId,
      circuitDigestB64u: parseDigestB64u(options.ed25519.circuitDigestB64u),
    };
  }

  async resolveTargetDeploymentDescriptorV1(input: {
    readonly request: LinkedDeviceTargetDeploymentDescriptorRequestV1;
    readonly issuedAtMs: number;
    readonly expiresAtMs: number;
  }): Promise<LinkedDeviceTargetDeploymentDescriptorV1> {
    const request = parseLinkedDeviceTargetDeploymentDescriptorRequestV1(input.request);
    assertDescriptorLifetime(input.issuedAtMs, input.expiresAtMs);
    const requestDigestB64u = await digestJson(request);
    const existing = await this.readV1(request);
    if (existing) {
      if (existing.requestDigestB64u !== requestDigestB64u) {
        throw new Error('linked-device target deployment descriptor request conflicts with persisted descriptor');
      }
      await verifyDescriptorV1(this.descriptorVerifier, existing.descriptor);
      return existing.descriptor;
    }

    const descriptor = await this.allocateDescriptorV1({
      request,
      issuedAtMs: input.issuedAtMs,
      expiresAtMs: input.expiresAtMs,
    });
    await this.persistOrReplayV1({
      request,
      requestDigestB64u,
      descriptor,
    });
    return descriptor;
  }

  private async allocateDescriptorV1(input: {
    readonly request: LinkedDeviceTargetDeploymentDescriptorRequestV1;
    readonly issuedAtMs: number;
    readonly expiresAtMs: number;
  }): Promise<LinkedDeviceTargetDeploymentDescriptorV1> {
    const descriptorId = descriptorIdV1(input.request);
    const common = {
      kind: 'linked_device_target_deployment_descriptor_v1' as const,
      descriptorId,
      signingKeyId: this.descriptorSigner.signingKeyId,
      request: input.request,
      targetHolderParticipantId: input.request.targetHolderParticipantId,
      targetSigningWorker: this.targetSigningWorker,
      issuedAtMs: input.issuedAtMs,
      expiresAtMs: input.expiresAtMs,
    };
    const unsignedRaw =
      input.request.keyFamily === 'ed25519'
        ? {
            ...common,
            keyFamily: 'ed25519',
            yaoSuiteId: this.ed25519.yaoSuiteId,
            circuitDigestB64u: this.ed25519.circuitDigestB64u,
          }
        : {
            ...common,
            keyFamily: 'ecdsa_secp256k1',
            ...(await this.ecdsaCapabilityAllocator.allocateEcdsaTargetCapabilityV1({
              request: input.request,
              issuedAtMs: input.issuedAtMs,
              expiresAtMs: input.expiresAtMs,
            })),
          };
    const unsigned = parseLinkedDeviceTargetDeploymentDescriptorUnsignedV1(
      unsignedRaw,
      'target deployment descriptor',
    );
    const descriptorDigestB64u = await computeLinkedDeviceTargetDeploymentDescriptorDigestV1(unsigned);
    const signatureB64u = await this.descriptorSigner.signTargetDeploymentDescriptorV1({
      encodedPayload: encodeLinkedDeviceTargetDeploymentDescriptorV1(unsigned),
      descriptorDigestB64u,
      request: input.request,
    });
    return buildLinkedDeviceTargetDeploymentDescriptorV1({
      ...unsigned,
      signatureB64u,
    });
  }

  private async readV1(
    request: LinkedDeviceTargetDeploymentDescriptorRequestV1,
  ): Promise<{ readonly requestDigestB64u: DigestB64u; readonly descriptor: LinkedDeviceTargetDeploymentDescriptorV1 } | null> {
    const row = await this.database
      .prepare(
        `SELECT request_digest_b64u, registration_digest_b64u,
                descriptor_digest_b64u, descriptor_json
           FROM ${TARGET_DESCRIPTOR_TABLE}
          WHERE namespace = ? AND org_id = ? AND project_id = ? AND env_id = ?
            AND link_session_id = ? AND target_preparation_digest_b64u = ?
            AND registration_digest_b64u = ? AND child_index = ?
          LIMIT 1`,
      )
      .bind(
        ...scopeValues(this.scope),
        String(request.linkSessionId),
        request.targetPreparationDigestB64u,
        request.registrationDigestB64u,
        request.childIndex,
      )
      .first<TargetDescriptorRowV1>();
    if (!row) return null;
    const descriptor = parseLinkedDeviceTargetDeploymentDescriptorV1(
      parseD1JsonColumn(row.descriptor_json),
      'persisted target deployment descriptor',
    );
    const descriptorDigestB64u = parseDigestB64u(row.descriptor_digest_b64u);
    if (descriptor.descriptorDigestB64u !== descriptorDigestB64u) {
      throw new Error('persisted target deployment descriptor digest differs');
    }
    if (parseDigestB64u(row.registration_digest_b64u) !== request.registrationDigestB64u) {
      throw new Error('persisted target deployment descriptor registration digest differs');
    }
    await verifyDescriptorV1(this.descriptorVerifier, descriptor);
    return {
      requestDigestB64u: parseDigestB64u(row.request_digest_b64u),
      descriptor,
    };
  }

  private async persistOrReplayV1(input: {
    readonly request: LinkedDeviceTargetDeploymentDescriptorRequestV1;
    readonly requestDigestB64u: DigestB64u;
    readonly descriptor: LinkedDeviceTargetDeploymentDescriptorV1;
  }): Promise<void> {
    try {
      const result = await this.database
        .prepare(
          `INSERT INTO ${TARGET_DESCRIPTOR_TABLE} (
             namespace, org_id, project_id, env_id,
             link_session_id,
             target_preparation_digest_b64u, registration_digest_b64u,
             child_index, request_digest_b64u, descriptor_digest_b64u,
             descriptor_json, issued_at_ms, expires_at_ms
           ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
        )
        .bind(
          ...scopeValues(this.scope),
          String(input.request.linkSessionId),
          input.request.targetPreparationDigestB64u,
          input.request.registrationDigestB64u,
          input.request.childIndex,
          input.requestDigestB64u,
          input.descriptor.descriptorDigestB64u,
          JSON.stringify(input.descriptor),
          input.descriptor.issuedAtMs,
          input.descriptor.expiresAtMs,
        )
        .run();
      if (d1ChangedRows(result) === 1) return;
    } catch (error: unknown) {
      if (!isUniqueConstraintError(error)) throw error;
    }
    const replay = await this.readV1(input.request);
    if (!replay) throw new Error('target deployment descriptor insert did not persist');
    if (
      replay.requestDigestB64u !== input.requestDigestB64u ||
      replay.descriptor.descriptorDigestB64u !== input.descriptor.descriptorDigestB64u
    ) {
      throw new Error('target deployment descriptor replay conflicts with persisted descriptor');
    }
  }
}

async function verifyDescriptorV1(
  verifier: LinkedDeviceTargetDeploymentDescriptorVerifierV1,
  descriptor: LinkedDeviceTargetDeploymentDescriptorV1,
): Promise<void> {
  const unsigned = unsignedDescriptorV1(descriptor);
  const encodedPayload = encodeLinkedDeviceTargetDeploymentDescriptorV1(unsigned);
  const descriptorDigestB64u = await computeLinkedDeviceTargetDeploymentDescriptorDigestV1(unsigned);
  if (descriptor.descriptorDigestB64u !== descriptorDigestB64u) {
    throw new Error('target deployment descriptor digest does not match its payload');
  }
  const verified = await verifier.verifyTargetDeploymentDescriptorV1({
    descriptor,
    encodedPayload,
    descriptorDigestB64u,
  });
  if (!verified) throw new Error('target deployment descriptor signature is invalid');
}

function unsignedDescriptorV1(
  descriptor: LinkedDeviceTargetDeploymentDescriptorV1,
): LinkedDeviceTargetDeploymentDescriptorUnsignedV1 {
  const { descriptorDigestB64u: _descriptorDigestB64u, signatureB64u: _signatureB64u, ...unsigned } =
    descriptor;
  return parseLinkedDeviceTargetDeploymentDescriptorUnsignedV1(unsigned);
}

function normalizeScope(scope: D1LinkedDeviceSessionScopeV1): D1LinkedDeviceSessionScopeV1 {
  const values = [scope.namespace, scope.orgId, scope.projectId, scope.envId].map((value) => value.trim());
  if (values.some((value) => !value)) throw new Error('linked-device target descriptor scope is incomplete');
  return { namespace: values[0]!, orgId: values[1]!, projectId: values[2]!, envId: values[3]! };
}

function scopeValues(scope: D1LinkedDeviceSessionScopeV1): readonly string[] {
  return [scope.namespace, scope.orgId, scope.projectId, scope.envId];
}

function assertDescriptorLifetime(issuedAtMs: number, expiresAtMs: number): void {
  if (!Number.isSafeInteger(issuedAtMs) || issuedAtMs <= 0) {
    throw new Error('target deployment descriptor issuedAtMs is invalid');
  }
  if (!Number.isSafeInteger(expiresAtMs) || expiresAtMs <= issuedAtMs) {
    throw new Error('target deployment descriptor expiresAtMs is invalid');
  }
}

async function digestJson(value: unknown): Promise<DigestB64u> {
  return parseDigestB64u(base64UrlEncode(await sha256BytesUtf8(alphabetizeStringify(value))));
}

function descriptorIdV1(
  request: LinkedDeviceTargetDeploymentDescriptorRequestV1,
): string {
  return `linked-device-target-${request.targetPreparationDigestB64u}-${request.registrationDigestB64u}-${request.childIndex}`;
}

function isUniqueConstraintError(error: unknown): boolean {
  const message = String(error && typeof error === 'object' && 'message' in error ? error.message : error);
  return /unique|constraint/i.test(message);
}
