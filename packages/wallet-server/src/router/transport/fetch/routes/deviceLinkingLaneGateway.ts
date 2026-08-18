import type {
  EcdsaAdditiveLaneHolderRoundV1,
  EcdsaAdditiveLaneJobV1,
  Ed25519YaoLaneJobV1,
  LaneEnrollmentGatewayV1,
  LaneEnrollmentPreparationResultV1,
  LaneProtocolCasResultV1,
  LaneHolderPackageWireV1,
  PrepareLaneEnrollmentV1,
} from '@shared/signing-lanes';
import type { DeviceLinkingOwnerRequestInputV1 } from './deviceLinking';
import type { FetchRouterApiContext } from '../createFetchRouter';
import {
  parseEcdsaAdditiveLaneHolderRoundV1,
  parseLaneEnrollmentManifestV1,
  parseLaneHolderPackageWireV1,
  parseRotatableSigningLaneJobV1,
} from '@shared/signing-lanes/rotationParsers';
import { parseLaneOperationId } from '@shared/signing-lanes/ids';
import { parseDigestB64u } from '@shared/utils/canonicalPrimitives';
import { json, readJson } from '../../../framework/http';
import { sha256Bytes } from '@shared/utils/digests';
import { base64UrlEncode } from '@shared/utils/base64';
import type {
  RouterAbEd25519YaoActivationKeysetV1,
  RouterAbEd25519YaoCeremonyBindingV1,
} from '@shared/utils/routerAbEd25519Yao';
import type {
  DeviceLinkingOwnerRequestAuthenticationV1,
  DeviceLinkingOwnerWalletSessionContextV1,
} from './deviceLinkingOwnerAuthorization';

/** Private owner-authenticated Gateway boundary for browser source-lane work. */
export const LINKED_DEVICE_GATEWAY_LANE_BASE_V1 =
  '/internal/gateway/device-linking/v1/lanes' as const;

export const LINKED_DEVICE_GATEWAY_LANE_PATHS_V1 = Object.freeze({
  prepare: `${LINKED_DEVICE_GATEWAY_LANE_BASE_V1}/prepare`,
  protocolCommit: `${LINKED_DEVICE_GATEWAY_LANE_BASE_V1}/protocol-commit`,
  ceremonyBinding: `${LINKED_DEVICE_GATEWAY_LANE_BASE_V1}/ceremony-binding`,
} as const);

/** Request bodies are the exact shared gateway inputs; no browser-specific shape exists. */
export type DeviceLinkingLaneGatewayRequestV1 =
  | { readonly action: 'prepare'; readonly body: PrepareLaneEnrollmentV1 }
  | { readonly action: 'protocol-commit'; readonly body: DeviceLinkingLaneProtocolCommitRequestV1 }
  | { readonly action: 'ceremony-binding'; readonly body: DeviceLinkingLaneCeremonyBindingRequestV1 };

export type DeviceLinkingLaneGatewayResponseV1 =
  | LaneEnrollmentPreparationResultV1
  | DeviceLinkingLaneProtocolCommitResultV1
  | DeviceLinkingLaneCeremonyBindingResponseV1;

export type DeviceLinkingLaneProtocolCommitRequestV1 =
  | {
      readonly curve: 'ed25519_yao';
      readonly job: Ed25519YaoLaneJobV1;
      readonly requestJson: string;
      readonly expectedVersion: number;
    }
  | {
      readonly curve: 'ecdsa_additive';
      readonly job: EcdsaAdditiveLaneJobV1;
      readonly holderRound: EcdsaAdditiveLaneHolderRoundV1;
      readonly holderPackage: Extract<
        LaneHolderPackageWireV1,
        { readonly kind: 'ecdsa_additive_lane_holder_package_v1' }
      >;
      readonly encryptedDeltaPackageJson: string;
      readonly expectedVersion: number;
    };

export type DeviceLinkingLaneCeremonyBindingRequestV1 = {
  readonly operationId: import('@shared/signing-lanes/ids').LaneOperationId;
};

export type DeviceLinkingLaneCeremonyBindingResponseV1 = {
  readonly operationId: import('@shared/signing-lanes/ids').LaneOperationId;
  readonly binding: RouterAbEd25519YaoCeremonyBindingV1;
  readonly keyset: RouterAbEd25519YaoActivationKeysetV1;
};

export type DeviceLinkingLaneProtocolCommitResultV1 =
  | {
      readonly curve: 'ed25519_yao';
      readonly receipt: import('@shared/signing-lanes').LaneProtocolCommitReceiptV1;
      readonly protocolCasResult: LaneProtocolCasResultV1;
      readonly responseJson: string;
    }
  | {
      readonly curve: 'ecdsa_additive';
      readonly receipt: import('@shared/signing-lanes').LaneProtocolCommitReceiptV1;
      readonly protocolCasResult: LaneProtocolCasResultV1;
    };

export type DeviceLinkingLaneGatewayRouteServiceV1 = {
  readonly authenticateOwnerRequestV1: (
    input: DeviceLinkingOwnerRequestInputV1,
  ) => Promise<DeviceLinkingOwnerRequestAuthenticationV1>;
  readonly executeOwnerAuthorizedRequestV1: (input: {
    readonly owner: DeviceLinkingOwnerWalletSessionContextV1;
    readonly request: DeviceLinkingLaneGatewayRequestV1;
  }) => Promise<DeviceLinkingLaneGatewayResponseV1 | DeviceLinkingLaneProtocolCommitResultV1>;
};

/** Owner-authenticated source preparation and protocol commit transport. */
export async function handleDeviceLinkingLaneGateway(
  ctx: FetchRouterApiContext,
  service: DeviceLinkingLaneGatewayRouteServiceV1 | undefined,
): Promise<Response | null> {
  const action = actionForPath(ctx.pathname);
  if (!action) return null;
  if (ctx.method !== 'POST' && !(action === 'ceremony-binding' && ctx.method === 'GET')) {
    return json({ ok: false, code: 'method_not_allowed' }, { status: 405 });
  }
  if (!service) {
    return json(
      { ok: false, code: 'not_supported', message: 'Linked-device lane Gateway is not configured' },
      { status: 501 },
    );
  }
  let body: DeviceLinkingLaneGatewayRequestV1;
  let bodyDigestB64u: import('@shared/utils/canonicalPrimitives').DigestB64u;
  try {
    bodyDigestB64u = await requestBodyDigest(ctx.request);
    const rawBody =
      action === 'ceremony-binding' && ctx.method === 'GET'
        ? { operationId: ctx.url.searchParams.get('operationId') }
        : await readJson(ctx.request.clone());
    body = parseRequest(action, rawBody);
  } catch (error: unknown) {
    return json(
      {
        ok: false,
        code: 'invalid_body',
        message: error instanceof Error ? error.message : 'Lane Gateway body is invalid',
      },
      { status: 400 },
    );
  }
  const authenticated = await service.authenticateOwnerRequestV1({
    request: ctx.request,
    method: ctx.method,
    pathname: ctx.pathname,
    bodyDigestB64u,
    requestedAtMs: Date.now(),
  });
  if (authenticated.kind === 'denied') {
    const status = authenticated.code === 'invalid' ? 403 : 401;
    return json(
      { ok: false, code: authenticated.code, message: authenticated.message },
      { status },
    );
  }
  try {
    const result = await service.executeOwnerAuthorizedRequestV1({
      owner: authenticated.owner,
      request: body,
    });
    return json(result, { status: 200 });
  } catch (error: unknown) {
    return json(
      { ok: false, code: 'rejected', message: error instanceof Error ? error.message : String(error) },
      { status: 403 },
    );
  }
}

type LaneGatewayAction = DeviceLinkingLaneGatewayRequestV1['action'];

function actionForPath(pathname: string): LaneGatewayAction | null {
  if (pathname === LINKED_DEVICE_GATEWAY_LANE_PATHS_V1.prepare) return 'prepare';
  if (pathname === LINKED_DEVICE_GATEWAY_LANE_PATHS_V1.protocolCommit) return 'protocol-commit';
  if (pathname === LINKED_DEVICE_GATEWAY_LANE_PATHS_V1.ceremonyBinding) return 'ceremony-binding';
  return null;
}

function parseRequest(action: LaneGatewayAction, raw: unknown): DeviceLinkingLaneGatewayRequestV1 {
  switch (action) {
    case 'prepare':
      return { action, body: parsePrepareRequest(raw) };
    case 'protocol-commit':
      return { action, body: parseProtocolCommitRequest(raw) };
    case 'ceremony-binding':
      return { action, body: parseCeremonyBindingRequest(raw) };
  }
}

function parsePrepareRequest(raw: unknown): PrepareLaneEnrollmentV1 {
  const value = exactRecord(raw, ['manifest', 'children'], 'prepare');
  const parsedChildren = requiredArray(value.children, 'prepare.children').map((child, index) =>
    parseRotatableSigningLaneJobV1(child, `prepare.children[${index}]`),
  );
  const first = parsedChildren[0];
  if (!first) throw new Error('prepare.children must be non-empty');
  return {
    manifest: parseLaneEnrollmentManifestV1(value.manifest),
    children: [first, ...parsedChildren.slice(1)],
  };
}

function parseProtocolCommitRequest(raw: unknown): DeviceLinkingLaneProtocolCommitRequestV1 {
  const value = requireRecord(raw, 'protocol-commit');
  if (value.curve === 'ed25519_yao') {
    const record = exactRecord(value, ['curve', 'job', 'requestJson', 'expectedVersion'], 'protocol-commit');
    const job = parseRotatableSigningLaneJobV1(record.job, 'protocol-commit.job');
    if (job.kind !== 'ed25519_yao_lane_job_v1') throw new Error('protocol-commit.job curve mismatch');
    return {
      curve: 'ed25519_yao',
      job,
      requestJson: requiredString(record.requestJson, 'protocol-commit.requestJson'),
      expectedVersion: safeInteger(record.expectedVersion, 'protocol-commit.expectedVersion'),
    };
  }
  if (value.curve === 'ecdsa_additive') {
    const record = exactRecord(
      value,
      ['curve', 'job', 'holderRound', 'holderPackage', 'encryptedDeltaPackageJson', 'expectedVersion'],
      'protocol-commit',
    );
    const job = parseRotatableSigningLaneJobV1(record.job, 'protocol-commit.job');
    if (job.kind !== 'ecdsa_additive_lane_job_v1') throw new Error('protocol-commit.job curve mismatch');
    const holderPackage = parseLaneHolderPackageWireV1(record.holderPackage);
    if (holderPackage.kind !== 'ecdsa_additive_lane_holder_package_v1') {
      throw new Error('protocol-commit.holderPackage curve mismatch');
    }
    return {
      curve: 'ecdsa_additive',
      job,
      holderRound: parseEcdsaAdditiveLaneHolderRoundV1(record.holderRound),
      holderPackage,
      encryptedDeltaPackageJson: requiredString(
        record.encryptedDeltaPackageJson,
        'protocol-commit.encryptedDeltaPackageJson',
      ),
      expectedVersion: safeInteger(record.expectedVersion, 'protocol-commit.expectedVersion'),
    };
  }
  throw new Error('protocol-commit.curve is invalid');
}

function parseCeremonyBindingRequest(raw: unknown): DeviceLinkingLaneCeremonyBindingRequestV1 {
  const value = exactRecord(raw, ['operationId'], 'ceremony-binding');
  const parsed = parseLaneOperationId(value.operationId);
  if (!parsed.ok) throw new Error(parsed.error.message);
  return { operationId: parsed.value };
}

function exactRecord(raw: unknown, keys: readonly string[], label: string): Record<string, unknown> {
  const value = requireRecord(raw, label);
  const expected = new Set(keys);
  const actual = Object.keys(value);
  if (actual.length !== expected.size || actual.some((key) => !expected.has(key))) {
    throw new Error(`${label} has unexpected fields`);
  }
  return value;
}

function requireRecord(raw: unknown, label: string): Record<string, unknown> {
  if (!isRecord(raw)) throw new Error(`${label} must be an object`);
  return raw;
}

function isRecord(raw: unknown): raw is Record<string, unknown> {
  return raw !== null && typeof raw === 'object' && !Array.isArray(raw);
}

function requiredArray(raw: unknown, label: string): readonly unknown[] {
  if (!Array.isArray(raw)) throw new Error(`${label} must be an array`);
  return raw;
}

function requiredString(raw: unknown, label: string): string {
  if (typeof raw !== 'string' || raw.length === 0) throw new Error(`${label} must be a non-empty string`);
  return raw;
}

function safeInteger(raw: unknown, label: string): number {
  if (!Number.isSafeInteger(raw)) throw new Error(`${label} must be a safe integer`);
  return Number(raw);
}

async function requestBodyDigest(request: Request): Promise<import('@shared/utils/canonicalPrimitives').DigestB64u> {
  const bytes = new Uint8Array(await request.clone().arrayBuffer());
  return parseDigestB64u(base64UrlEncode(await sha256Bytes(bytes)));
}

/** Composition target for a server-side Gateway adapter. */
export type DeviceLinkingLaneGatewayPortV1 = LaneEnrollmentGatewayV1;
