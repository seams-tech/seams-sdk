import { parseSigningLaneRecord, parseWalletKeyRecord } from '@shared/signing-lanes/recordParsers';
import type { SigningLaneRecord, WalletKeyRecord } from '@shared/signing-lanes';
import {
  parseMpcMaterialActivationRef,
  type MpcMaterialActivationRef,
} from '@shared/utils/domainIds';
import { parseDigestB64u, type DigestB64u } from '@shared/utils/canonicalPrimitives';
import {
  buildBearerAuthorizationHeader,
  buildRelayerJsonPostRequestInit,
  normalizeRelayerBaseUrl,
} from './relayerHttp';

export const OWNER_WALLET_EXECUTION_LANE_PREFLIGHT_PATH = '/wallet/execution-lane/owner';

export type OwnerWalletExecutionLaneProjectionV1 = {
  readonly kind: 'active_owner_wallet_execution_lane_projection_v1';
  readonly walletKey: WalletKeyRecord;
  readonly lane: Extract<
    SigningLaneRecord,
    { readonly laneKind: 'owner_passkey' | 'owner_email_otp' }
  >;
  readonly materialActivation: MpcMaterialActivationRef;
  readonly verifiedActivationReceiptDigestB64u: DigestB64u;
};

export async function readOwnerWalletExecutionLaneProjectionV1(input: {
  readonly relayerUrl: string;
  readonly walletSessionJwt: string;
  readonly curve: 'ed25519' | 'ecdsa_secp256k1';
  readonly expectedMaterialActivation: MpcMaterialActivationRef;
}): Promise<OwnerWalletExecutionLaneProjectionV1> {
  const response = await fetch(
    `${normalizeRelayerBaseUrl(input.relayerUrl)}${OWNER_WALLET_EXECUTION_LANE_PREFLIGHT_PATH}`,
    buildRelayerJsonPostRequestInit({
      headers: buildBearerAuthorizationHeader({
        token: input.walletSessionJwt,
        missingMessage: 'Owner execution-lane preflight requires a Wallet Session JWT',
      }),
      body: {
        curve: input.curve,
        expectedMaterialActivation: input.expectedMaterialActivation,
      },
    }),
  );
  const raw = (await response.json().catch(() => null)) as unknown;
  if (!response.ok) {
    const message = isRecord(raw) ? String(raw.message || raw.reason || '').trim() : '';
    throw new Error(message || `Owner execution-lane preflight returned HTTP ${response.status}`);
  }
  return parseOwnerWalletExecutionLaneProjectionResponseV1(raw, input.curve);
}

export function parseOwnerWalletExecutionLaneProjectionResponseV1(
  value: unknown,
  curve: 'ed25519' | 'ecdsa_secp256k1',
): OwnerWalletExecutionLaneProjectionV1 {
  const response = exactRecord(value, ['ok', 'projection'], 'owner execution-lane response');
  if (response.ok !== true) throw new Error('owner execution-lane response is unsuccessful');
  const projection = exactRecord(
    response.projection,
    ['kind', 'walletKey', 'lane', 'materialActivation', 'verifiedActivationReceiptDigestB64u'],
    'owner execution-lane projection',
  );
  if (projection.kind !== 'active_owner_wallet_execution_lane_projection_v1') {
    throw new Error('owner execution-lane projection kind is invalid');
  }
  const walletKey = parseWalletKeyRecord(projection.walletKey);
  const lane = parseSigningLaneRecord(projection.lane);
  const materialActivation = parseMpcMaterialActivationRef(projection.materialActivation);
  if (!materialActivation.ok) throw new Error(materialActivation.error.message);
  if (
    walletKey.keyFamily !== curve ||
    lane.walletId !== walletKey.walletId ||
    lane.walletKeyId !== walletKey.walletKeyId ||
    (lane.laneKind !== 'owner_passkey' && lane.laneKind !== 'owner_email_otp')
  ) {
    throw new Error('owner execution-lane projection identity is inconsistent');
  }
  return {
    kind: 'active_owner_wallet_execution_lane_projection_v1',
    walletKey,
    lane,
    materialActivation: materialActivation.value,
    verifiedActivationReceiptDigestB64u: parseDigestB64u(
      projection.verifiedActivationReceiptDigestB64u,
    ),
  };
}

function exactRecord(value: unknown, fields: readonly string[], label: string) {
  if (!isRecord(value)) throw new Error(`${label} must be an object`);
  const actual = Object.keys(value);
  if (actual.length !== fields.length || actual.some((field) => !fields.includes(field))) {
    throw new Error(`${label} fields are invalid`);
  }
  return value;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}
