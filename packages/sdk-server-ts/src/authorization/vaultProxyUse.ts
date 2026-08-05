import {
  buildVaultOperationRef,
  parseAuthorizationAuditEventId,
  parseAuthorizedOperationId,
  parseCapabilityId,
  parseCapabilityOperationId,
  parsePrincipalId,
  parseTenantId,
  parseVaultId,
  parseVaultItemId,
  type AuthorizationParseResult,
  type CapabilityId,
  type CapabilityOperationId,
  type PrincipalId,
  type TenantId,
  type VaultId,
  type VaultItemId,
} from '@shared/authorization/capabilityKinds';
import {
  buildCapabilityOperationEnvelope,
  type CapabilityOperationEnvelope,
} from '@shared/authorization/operationFingerprint';
import { base64UrlEncode } from '@shared/utils/base64';
import { parseDigestB64u, type DigestB64u } from '@shared/utils/canonicalPrimitives';
import { alphabetizeStringify, sha256BytesUtf8 } from '@shared/utils/digests';
import {
  AUTHORIZED_OPERATION_REPLAY_BODY_MAX_BYTES,
  authorizedOperationReplayBodyInit,
  type AuthorizedOperation,
  type AuthorizedOperationInput,
  type AuthorizedOperationReplayResponse,
} from './domain';
import type { AuthorizationService } from './service';
import { defineRoute } from '../router/framework/routeDefinitions';
import type {
  RouterApiFetchRouteExtensionInput,
  RouterApiRouteExtension,
} from '../router/framework/routeExtensions';

const VAULT_PROXY_LANE_DIGEST_DOMAIN_V1 = 'seams:vault:proxy-use-lane:v1';
const VAULT_PROXY_INTENT_DIGEST_DOMAIN_V1 = 'seams:vault:proxy-use-intent:v1';
const VAULT_PROXY_DISPLAY_DIGEST_DOMAIN_V1 = 'seams:vault:proxy-use-display:v1';

export type VaultProxyDestination = string & {
  readonly __vaultProxyDestination: true;
};

export type VaultProxySecretRef = {
  readonly tenantId: TenantId;
  readonly capabilityId: CapabilityId;
  readonly vaultId: VaultId;
  readonly itemId: VaultItemId;
  readonly destination: VaultProxyDestination;
};

export interface VaultProxySecretStore {
  openSecret(input: VaultProxySecretRef): Promise<Uint8Array | null>;
}

export interface VaultProxyGatewayPort {
  proxy(input: {
    readonly destination: VaultProxyDestination;
    readonly secret: Uint8Array;
    readonly payload: string;
  }): Promise<Response>;
}

export type VaultProxyUseResult =
  | {
      readonly kind: 'succeeded';
      readonly status: number;
      readonly body: string;
    }
  | {
      readonly kind: 'replayed';
      readonly response: AuthorizedOperationReplayResponse;
    }
  | {
      readonly kind: 'operation_in_progress';
    }
  | {
      readonly kind: 'rejected';
      readonly reason:
        | 'authorization_failed'
        | 'secret_unavailable'
        | 'gateway_failed_after_side_effect';
    };

export class LocalWorkerVaultProxyGateway implements VaultProxyGatewayPort {
  constructor(private readonly fetcher: typeof fetch) {}

  async proxy(input: {
    readonly destination: VaultProxyDestination;
    readonly secret: Uint8Array;
    readonly payload: string;
  }): Promise<Response> {
    const credential = new TextDecoder().decode(input.secret);
    return await this.fetcher(
      new Request(input.destination, {
        method: 'POST',
        headers: {
          authorization: `Bearer ${credential}`,
          'content-type': 'application/json',
        },
        body: input.payload,
      }),
    );
  }
}

export class VaultProxyUseService {
  constructor(
    private readonly authorization: AuthorizationService,
    private readonly secrets: VaultProxySecretStore,
    private readonly gateway: VaultProxyGatewayPort,
  ) {}

  async execute(input: {
    readonly claim: AuthorizedOperationInput;
    readonly secretRef: VaultProxySecretRef;
    readonly payload: string;
    readonly completedAtMs: number;
  }): Promise<VaultProxyUseResult> {
    const expectedOperation = await buildVaultProxyUseOperation({
      tenantId: input.secretRef.tenantId,
      principalId: input.claim.operation.principalId,
      capabilityId: input.secretRef.capabilityId,
      operationId: input.claim.operation.operationId,
      vaultId: input.secretRef.vaultId,
      itemId: input.secretRef.itemId,
      destination: input.secretRef.destination,
    });
    if (
      input.claim.operation.operation.capabilityKind !== 'vault_access' ||
      input.claim.operation.operation.operationKind !== 'vault.proxy_use' ||
      input.claim.operation.tenantId !== input.secretRef.tenantId ||
      input.claim.operation.capabilityId !== input.secretRef.capabilityId ||
      input.claim.operation.digests.laneDigest !== expectedOperation.digests.laneDigest ||
      input.claim.operation.digests.intentDigest !== expectedOperation.digests.intentDigest ||
      input.claim.operation.digests.displayDigest !== expectedOperation.digests.displayDigest
    ) {
      return { kind: 'rejected', reason: 'authorization_failed' };
    }
    const claimResult = await this.authorization.admitAuthorizedOperation({
      operation: input.claim,
    });
    switch (claimResult.kind) {
      case 'operation_in_progress':
        return { kind: 'operation_in_progress' };
      case 'replayed':
        return claimResult.operation.lifecycle === 'completed'
          ? { kind: 'replayed', response: claimResult.operation.response }
          : { kind: 'operation_in_progress' };
      case 'authorization_grant_rejected':
      case 'verified_step_up_rejected':
      case 'wallet_session_quota_exhausted':
      case 'material_mismatch':
        return { kind: 'rejected', reason: 'authorization_failed' };
      case 'claimed':
        break;
    }
    const operation = claimResult.operation;

    const secret = await this.secrets.openSecret(input.secretRef);
    if (!secret) {
      const result = { kind: 'rejected', reason: 'secret_unavailable' } as const;
      await this.complete(
        operation,
        'failed_before_side_effect',
        vaultProxyUseReplayResponse(result),
        input.completedAtMs,
      );
      return result;
    }

    try {
      const response = await this.gateway.proxy({
        destination: input.secretRef.destination,
        secret,
        payload: input.payload,
      });
      const body = await response.text();
      const result = { kind: 'succeeded', status: response.status, body } as const;
      const replayResponse = vaultProxyUseReplayResponse(result);
      if (!isReplayResponseWithinBound(replayResponse)) {
        const boundedFailure = {
          kind: 'rejected',
          reason: 'gateway_failed_after_side_effect',
        } as const;
        await this.complete(
          operation,
          'failed_after_side_effect',
          vaultProxyUseReplayResponse(boundedFailure),
          input.completedAtMs,
        );
        return boundedFailure;
      }
      await this.complete(
        operation,
        'succeeded',
        replayResponse,
        input.completedAtMs,
      );
      return result;
    } catch {
      const result = { kind: 'rejected', reason: 'gateway_failed_after_side_effect' } as const;
      await this.complete(
        operation,
        'failed_after_side_effect',
        vaultProxyUseReplayResponse(result),
        input.completedAtMs,
      );
      return result;
    } finally {
      secret.fill(0);
    }
  }

  private async complete(
    claim: AuthorizedOperation,
    result: 'succeeded' | 'failed_before_side_effect' | 'failed_after_side_effect',
    response: AuthorizedOperationReplayResponse,
    completedAtMs: number,
  ): Promise<void> {
    await this.authorization.completeAuthorizedOperation({
      operation: claim,
      result,
      response,
      completedAtMs,
    });
  }
}

type ParsedVaultProxyUseRequest = {
  readonly claim: AuthorizedOperationInput;
  readonly secretRef: VaultProxySecretRef;
  readonly payload: string;
};

export function createVaultProxyUseRouteExtension(input: {
  readonly service: VaultProxyUseService;
  readonly now?: () => number;
}): RouterApiRouteExtension {
  return new VaultProxyUseRouteExtension(input.service, input.now ?? Date.now);
}

class VaultProxyUseRouteExtension implements RouterApiRouteExtension {
  readonly kind = 'fetch_route_extension' as const;
  readonly id = 'vault_proxy_use';
  readonly routes = [
    defineRoute({
      id: 'vault_proxy_use',
      surface: 'relay',
      method: 'POST',
      path: '/vault/proxy-use',
      auth: {
        plane: 'public',
        proof: 'intent_grant',
        rationale: 'The exact one-use capability grant authorizes this vault proxy operation.',
      },
      metering: { kind: 'none' },
      summary: 'Use one persisted vault secret through the configured gateway',
    }),
  ] as const;

  constructor(
    private readonly service: VaultProxyUseService,
    private readonly now: () => number,
  ) {}

  async handleFetchRoute(input: RouterApiFetchRouteExtensionInput): Promise<Response> {
    const parsed = await parseVaultProxyUseRequest(await readJson(input.request), this.now());
    const result = await this.service.execute({
      claim: parsed.claim,
      secretRef: parsed.secretRef,
      payload: parsed.payload,
      completedAtMs: this.now(),
    });
    return vaultProxyUseResponse(result);
  }
}

export async function buildVaultProxyUseOperation(input: {
  readonly tenantId: TenantId;
  readonly principalId: PrincipalId;
  readonly capabilityId: CapabilityId;
  readonly operationId: CapabilityOperationId;
  readonly vaultId: VaultId;
  readonly itemId: VaultItemId;
  readonly destination: VaultProxyDestination;
}): Promise<CapabilityOperationEnvelope> {
  const operation = buildVaultOperationRef('vault.proxy_use');
  return buildCapabilityOperationEnvelope({
    tenantId: input.tenantId,
    principalId: input.principalId,
    capabilityId: input.capabilityId,
    operationId: input.operationId,
    operation,
    digests: {
      laneDigest: await digest(VAULT_PROXY_LANE_DIGEST_DOMAIN_V1, {
        tenantId: input.tenantId,
        capabilityId: input.capabilityId,
        operation,
      }),
      intentDigest: await digest(VAULT_PROXY_INTENT_DIGEST_DOMAIN_V1, {
        tenantId: input.tenantId,
        capabilityId: input.capabilityId,
        vaultId: input.vaultId,
        itemId: input.itemId,
        destination: input.destination,
        operationId: input.operationId,
      }),
      displayDigest: await digest(VAULT_PROXY_DISPLAY_DIGEST_DOMAIN_V1, {
        vaultId: input.vaultId,
        itemId: input.itemId,
        destination: input.destination,
      }),
    },
  });
}

export function parseVaultProxyDestination(value: unknown): VaultProxyDestination {
  if (typeof value !== 'string' || value.trim() !== value) {
    throw new Error('vault proxy destination must be a canonical HTTPS URL');
  }
  let parsed: URL;
  try {
    parsed = new URL(value);
  } catch {
    throw new Error('vault proxy destination must be a canonical HTTPS URL');
  }
  if (
    parsed.protocol !== 'https:' ||
    parsed.href !== value ||
    parsed.username ||
    parsed.password ||
    parsed.hash
  ) {
    throw new Error('vault proxy destination must be a canonical HTTPS URL');
  }
  return value as VaultProxyDestination;
}

async function parseVaultProxyUseRequest(
  raw: unknown,
  claimedAtMs: number,
): Promise<ParsedVaultProxyUseRequest> {
  if (
    !isExactRecord(raw, [
      'tenantId',
      'principalId',
      'capabilityId',
      'operationId',
      'authorizedOperationId',
      'auditEventId',
      'evidenceSetDigest',
      'vaultId',
      'itemId',
      'destination',
      'payload',
    ])
  ) {
    throw new Error('vault proxy request has invalid fields');
  }
  if (typeof raw.payload !== 'string') throw new Error('vault proxy payload must be a string');
  const tenantId = requireAuthorizationId(raw.tenantId, parseTenantId);
  const principalId = requireAuthorizationId(raw.principalId, parsePrincipalId);
  const capabilityId = requireAuthorizationId(raw.capabilityId, parseCapabilityId);
  const operationId = requireAuthorizationId(raw.operationId, parseCapabilityOperationId);
  const vaultId = requireAuthorizationId(raw.vaultId, parseVaultId);
  const itemId = requireAuthorizationId(raw.itemId, parseVaultItemId);
  const destination = parseVaultProxyDestination(raw.destination);
  const operation = await buildVaultProxyUseOperation({
    tenantId,
    principalId,
    capabilityId,
    operationId,
    vaultId,
    itemId,
    destination,
  });
  return {
    secretRef: { tenantId, capabilityId, vaultId, itemId, destination },
    payload: raw.payload,
    claim: {
      tenantId,
      authorizedOperationId: requireAuthorizationId(
        raw.authorizedOperationId,
        parseAuthorizedOperationId,
      ),
      auditEventId: requireAuthorizationId(raw.auditEventId, parseAuthorizationAuditEventId),
      operation,
      claimedAtMs,
      authorization: {
        kind: 'verified_step_up',
        evidenceSetDigest: parseDigestB64u(raw.evidenceSetDigest),
      },
      quota: { kind: 'quota_neutral' },
    },
  };
}

async function digest(domain: string, value: Record<string, unknown>): Promise<DigestB64u> {
  return parseDigestB64u(
    base64UrlEncode(await sha256BytesUtf8(`${domain}|${alphabetizeStringify(value)}`)),
  );
}

async function readJson(request: Request): Promise<unknown> {
  try {
    return await request.json();
  } catch {
    throw new Error('vault proxy request body must be JSON');
  }
}

function vaultProxyUseResponse(result: VaultProxyUseResult): Response {
  if (result.kind === 'replayed') return responseFromReplay(result.response);
  return responseFromReplay(vaultProxyUseReplayResponse(result));
}

type VaultProxyUseFreshResult = Exclude<VaultProxyUseResult, { readonly kind: 'replayed' }>;

function vaultProxyUseReplayResponse(
  result: VaultProxyUseFreshResult,
): AuthorizedOperationReplayResponse {
  switch (result.kind) {
    case 'succeeded':
      return jsonReplayResponse(result, 200);
    case 'operation_in_progress':
      return jsonReplayResponse(result, 409);
    case 'rejected':
      return jsonReplayResponse(
        result,
        result.reason === 'secret_unavailable'
          ? 404
          : result.reason === 'gateway_failed_after_side_effect'
            ? 502
            : 403,
      );
  }
}

function jsonReplayResponse(body: object, status: number): AuthorizedOperationReplayResponse {
  return {
    status,
    contentType: 'application/json',
    bodyText: JSON.stringify(body),
  };
}

function isReplayResponseWithinBound(response: AuthorizedOperationReplayResponse): boolean {
  return (
    new TextEncoder().encode(response.bodyText).byteLength <=
    AUTHORIZED_OPERATION_REPLAY_BODY_MAX_BYTES
  );
}

function responseFromReplay(response: AuthorizedOperationReplayResponse): Response {
  return new Response(authorizedOperationReplayBodyInit(response), {
    status: response.status,
    headers: { 'content-type': response.contentType },
  });
}

function isExactRecord(
  value: unknown,
  fields: readonly string[],
): value is Record<string, unknown> {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return false;
  const keys = Object.keys(value);
  return keys.length === fields.length && keys.every((key) => fields.includes(key));
}

function requireAuthorizationId<T>(
  value: unknown,
  parser: (value: unknown) => AuthorizationParseResult<T>,
): T {
  const parsed = parser(value);
  if (!parsed.ok) throw new Error(parsed.error.message);
  return parsed.value;
}
