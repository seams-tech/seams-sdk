import {
  ROUTER_AB_ECDSA_DERIVATION_OPERATION_STEP_UP_PATH,
  computeRouterAbEcdsaOperationStepUpChallengeB64u,
  parseRouterAbEcdsaOperationStepUpAuthorizationResponseV1,
  parseRouterAbEcdsaOperationStepUpAuthorizationRequestV1,
  parseRouterAbEcdsaDerivationNormalSigningScopeV1,
  type RouterAbEcdsaDerivationNormalSigningScopeV1,
  type RouterAbEcdsaOperationStepUpPreparationV1Wire,
  type RouterAbEcdsaOperationStepUpAuthorizationRequestV1Wire,
  type RouterAbEcdsaOperationStepUpAuthorizationResponseV1Wire,
} from '@shared/utils/routerAbEcdsaDerivation';
import { routerAbMpcMaterialActivationRefToWire } from '@shared/utils/routerAbNormalSigningIdentity';
import type { OperationDigestSet } from '@shared/authorization/operationFingerprint';
import type { EvmEcdsaMpcOperationKind } from '@shared/authorization/capabilityKinds';
import type { MpcMaterialActivationRef } from '@shared/utils/domainIds';
import type { AppSessionJwt } from '@shared/utils/domainIds';

export type EcdsaOperationStepUpSessionAuth =
  | {
      readonly kind: 'app_session_jwt';
      readonly appSessionJwt: AppSessionJwt;
    }
  | {
      readonly kind: 'app_session_cookie';
      readonly appSessionJwt?: never;
    };

export type PreparedEcdsaOperationStepUp = {
  readonly operation: RouterAbEcdsaOperationStepUpPreparationV1Wire;
  readonly challengeB64u: string;
};

function requireResponseRecord(value: unknown): Record<string, unknown> {
  if (!value || typeof value !== 'object' || Array.isArray(value)) {
    throw new Error('ECDSA operation step-up response must be an object');
  }
  return value as Record<string, unknown>;
}

function parseEcdsaOperationStepUpAuthorizationResponse(
  value: unknown,
): RouterAbEcdsaOperationStepUpAuthorizationResponseV1Wire {
  try {
    return parseRouterAbEcdsaOperationStepUpAuthorizationResponseV1(value);
  } catch (error: unknown) {
    throw new Error(
      error instanceof Error ? error.message : 'ECDSA operation step-up response is invalid',
    );
  }
}

function operationStepUpEndpoint(relayerUrl: string): string {
  const baseUrl = String(relayerUrl || '')
    .trim()
    .replace(/\/+$/g, '');
  if (!baseUrl) throw new Error('ECDSA operation step-up relayerUrl is required');
  return `${baseUrl}${ROUTER_AB_ECDSA_DERIVATION_OPERATION_STEP_UP_PATH}`;
}

export function buildEcdsaOperationStepUpPreparation(args: {
  readonly walletId: string;
  readonly operationKind: EvmEcdsaMpcOperationKind;
  readonly operationId: string;
  readonly operationDigests: OperationDigestSet;
  readonly materialActivation: MpcMaterialActivationRef;
  readonly normalSigningScope: RouterAbEcdsaDerivationNormalSigningScopeV1;
  readonly keyHandle: string;
  readonly relayerKeyId: string;
  readonly participantIds: readonly [number, number];
  readonly expiresAtMs: number;
}): RouterAbEcdsaOperationStepUpPreparationV1Wire {
  const walletId = String(args.walletId || '').trim();
  const operationId = String(args.operationId || '').trim();
  const expiresAtMs = Math.floor(Number(args.expiresAtMs));
  if (!walletId || !operationId) {
    throw new Error('ECDSA operation step-up identity is required');
  }
  if (!Number.isSafeInteger(expiresAtMs) || expiresAtMs <= Date.now()) {
    throw new Error('ECDSA operation step-up expiry is invalid');
  }
  const materialActivation = routerAbMpcMaterialActivationRefToWire(args.materialActivation);
  const normalSigningScope = parseRouterAbEcdsaDerivationNormalSigningScopeV1(
    args.normalSigningScope,
  );
  const keyHandle = String(args.keyHandle || '').trim();
  const relayerKeyId = String(args.relayerKeyId || '').trim();
  const participantIds = args.participantIds;
  if (
    normalSigningScope.wallet_id !== walletId ||
    normalSigningScope.signing_worker.server_id !== materialActivation.signing_worker ||
    !keyHandle ||
    !relayerKeyId ||
    participantIds.length !== 2 ||
    participantIds.some(
      (participantId) => !Number.isSafeInteger(participantId) || participantId <= 0,
    )
  ) {
    throw new Error('ECDSA operation step-up signing identity is inconsistent');
  }
  return {
    wallet_id: walletId,
    operation_kind: args.operationKind,
    operation_id: operationId,
    operation_digests: {
      lane_digest_b64u: args.operationDigests.laneDigest,
      intent_digest_b64u: args.operationDigests.intentDigest,
      display_digest_b64u: args.operationDigests.displayDigest,
    },
    material_activation: materialActivation,
    normal_signing_scope: normalSigningScope,
    signing_worker_id: materialActivation.signing_worker,
    key_handle: keyHandle,
    relayer_key_id: relayerKeyId,
    participant_ids: [participantIds[0], participantIds[1]],
    expires_at_ms: expiresAtMs,
  };
}

export async function prepareEcdsaOperationStepUp(args: Parameters<
  typeof buildEcdsaOperationStepUpPreparation
>[0]): Promise<PreparedEcdsaOperationStepUp> {
  const operation = buildEcdsaOperationStepUpPreparation(args);
  return {
    operation,
    challengeB64u: await computeRouterAbEcdsaOperationStepUpChallengeB64u(operation),
  };
}

export async function issueEcdsaOperationStepUpAuthorization(args: {
  readonly relayerUrl: string;
  readonly sessionAuth: EcdsaOperationStepUpSessionAuth;
  readonly request: RouterAbEcdsaOperationStepUpAuthorizationRequestV1Wire;
  readonly fetchImpl?: typeof fetch;
}): Promise<RouterAbEcdsaOperationStepUpAuthorizationResponseV1Wire> {
  const request = parseRouterAbEcdsaOperationStepUpAuthorizationRequestV1(args.request);
  const fetchImpl = args.fetchImpl ?? globalThis.fetch;
  if (typeof fetchImpl !== 'function') {
    throw new Error('fetch is unavailable for ECDSA operation step-up');
  }
  const response = await fetchImpl(operationStepUpEndpoint(args.relayerUrl), {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      ...(args.sessionAuth.kind === 'app_session_jwt'
        ? { Authorization: `Bearer ${args.sessionAuth.appSessionJwt}` }
        : {}),
    },
    credentials: args.sessionAuth.kind === 'app_session_cookie' ? 'include' : 'omit',
    body: JSON.stringify(request),
  });
  const body = await response.json().catch(() => null);
  if (!response.ok) {
    const error = requireResponseRecord(body);
    throw new Error(
      `ECDSA operation step-up failed: ${String(error.message || `HTTP ${response.status}`)}`,
    );
  }
  return parseEcdsaOperationStepUpAuthorizationResponse(body);
}
