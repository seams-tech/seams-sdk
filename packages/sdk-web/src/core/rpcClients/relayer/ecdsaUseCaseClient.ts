import {
  type BootstrapEcdsaSessionRouteInput,
  type BootstrapEcdsaSessionRouteOutput,
  type EcdsaBootstrapRouteAuth,
  type EcdsaRelayerClient,
  type RelayerResult,
} from '@/core/platform';
import { buildEcdsaRoleLocalPublicFacts } from '@/core/signingEngine/session/persistence/ecdsaRoleLocalRecords';
import {
  toEcdsaHssSigningRootId,
  toEcdsaHssSigningRootVersion,
} from '@/core/signingEngine/session/identity/emailOtpHssIdentity';
import { signingRootScopeFromRuntimePolicyScope } from '@shared/threshold/signingRootScope';
import { computeSdkEcdsaHssApplicationBindingDigestB64u } from '@shared/threshold/ecdsaHssRoleLocalBootstrap';
import {
  thresholdEcdsaHssRoleLocalBootstrap,
  type ThresholdEcdsaHssRoleLocalBootstrapValue,
  type ThresholdEcdsaHssRouteAuth,
} from './thresholdEcdsa';

export type ThresholdEcdsaRelayerClientConfig = {
  relayerUrl: string;
};

function routeAuthToThresholdAuth(auth: EcdsaBootstrapRouteAuth): ThresholdEcdsaHssRouteAuth {
  switch (auth.kind) {
    case 'app_session':
      return { kind: 'app_session', jwt: auth.jwt };
    case 'wallet_session':
      return { kind: 'wallet_session', jwt: auth.jwt };
    case 'bootstrap_grant':
      return { kind: 'bootstrap_grant', token: auth.token };
    case 'publishable_key':
      return { kind: 'publishable_key', token: auth.token };
  }
  auth satisfies never;
  throw new Error('[relayer][ecdsa] unsupported route auth');
}

function sameString(left: unknown, right: unknown): boolean {
  return String(left || '').trim() === String(right || '').trim();
}

function participantIdsFromRoute(value: readonly number[]): readonly [1, 2] {
  if (value.length !== 2 || value[0] !== 1 || value[1] !== 2) {
    throw new Error('[relayer][ecdsa] route returned unsupported participantIds');
  }
  return [1, 2] as const;
}

function signingRootFromRouteInput(input: BootstrapEcdsaSessionRouteInput): {
  signingRootId: ReturnType<typeof toEcdsaHssSigningRootId>;
  signingRootVersion: ReturnType<typeof toEcdsaHssSigningRootVersion>;
} {
  const scope = signingRootScopeFromRuntimePolicyScope(input.runtimePolicyScope);
  return {
    signingRootId: toEcdsaHssSigningRootId(scope.signingRootId),
    signingRootVersion: toEcdsaHssSigningRootVersion(scope.signingRootVersion),
  };
}

async function parseBootstrapOutput(
  input: BootstrapEcdsaSessionRouteInput,
  value: ThresholdEcdsaHssRoleLocalBootstrapValue,
): Promise<BootstrapEcdsaSessionRouteOutput> {
  const signingRoot = signingRootFromRouteInput(input);
  if (
    !sameString(value.walletId, input.walletId) ||
    !sameString(value.evmFamilySigningKeySlotId, input.evmFamilySigningKeySlotId) ||
    !sameString(value.ecdsaThresholdKeyId, input.ecdsaThresholdKeyId) ||
    !sameString(value.signingRootId, signingRoot.signingRootId) ||
    !sameString(value.signingRootVersion, signingRoot.signingRootVersion) ||
    !sameString(value.relayerKeyId, input.relayerKeyId)
  ) {
    throw new Error('[relayer][ecdsa] route output identity mismatch');
  }
  const participantIds = participantIdsFromRoute(value.participantIds);
  const applicationBindingDigestB64u = await computeSdkEcdsaHssApplicationBindingDigestB64u({
    walletId: input.walletId,
    ecdsaThresholdKeyId: input.ecdsaThresholdKeyId,
    signingRootId: signingRoot.signingRootId,
    signingRootVersion: signingRoot.signingRootVersion,
  });
  const publicFacts = buildEcdsaRoleLocalPublicFacts({
    walletId: input.walletId,
    evmFamilySigningKeySlotId: input.evmFamilySigningKeySlotId,
    chainTarget: input.chainTarget,
    keyHandle: value.keyHandle,
    ecdsaThresholdKeyId: input.ecdsaThresholdKeyId,
    signingRootId: signingRoot.signingRootId,
    signingRootVersion: signingRoot.signingRootVersion,
    applicationBindingDigestB64u,
    clientParticipantId: 1,
    relayerParticipantId: 2,
    participantIds,
    contextBinding32B64u: input.clientBootstrap.contextBinding32B64u,
    hssClientSharePublicKey33B64u: value.publicIdentity.hssClientSharePublicKey33B64u,
    relayerPublicKey33B64u: value.publicIdentity.relayerPublicKey33B64u,
    groupPublicKey33B64u: value.publicIdentity.groupPublicKey33B64u,
    ethereumAddress: value.publicIdentity.ethereumAddress,
  });
  return {
    kind: 'bootstrap_ecdsa_session_route_output_v1',
    walletId: input.walletId,
    evmFamilySigningKeySlotId: input.evmFamilySigningKeySlotId,
    ecdsaThresholdKeyId: input.ecdsaThresholdKeyId,
    keyHandle: value.keyHandle,
    relayerPublicIdentity: {
      relayerKeyId: input.relayerKeyId,
      relayerPublicKey33B64u: publicFacts.relayerPublicKey33B64u,
      groupPublicKey33B64u: publicFacts.groupPublicKey33B64u,
      ethereumAddress: publicFacts.ethereumAddress,
    },
    clientShareRetryCounter: value.clientShareRetryCounter,
    relayerShareRetryCounter: value.relayerShareRetryCounter,
    participantIds,
    thresholdSessionId: value.thresholdSessionId,
    signingGrantId: value.signingGrantId,
    expiresAtMs: value.expiresAtMs,
    remainingUses: value.remainingUses,
    walletSessionJwt: String(value.jwt || '').trim(),
  };
}

function mapRouteFailure(args: {
  code: string;
  message: string;
}): RelayerResult<
  BootstrapEcdsaSessionRouteOutput,
  'unavailable' | 'request_rejected' | 'malformed_response'
> {
  const normalizedCode = String(args.code || '').trim();
  if (!normalizedCode || normalizedCode === 'network_error' || normalizedCode === 'timeout') {
    return {
      ok: false,
      code: 'unavailable',
      message: args.message,
      retryable: true,
    };
  }
  return {
    ok: false,
    code: 'request_rejected',
    message: args.message,
    retryable: false,
  };
}

export function createThresholdEcdsaRelayerClient(
  config: ThresholdEcdsaRelayerClientConfig,
): EcdsaRelayerClient {
  return {
    async bootstrapEcdsaSession(input) {
      const signingRoot = signingRootFromRouteInput(input);
      const response = await thresholdEcdsaHssRoleLocalBootstrap(config.relayerUrl, {
        formatVersion: 'ecdsa-hss-role-local',
        walletId: input.walletId,
        evmFamilySigningKeySlotId: input.evmFamilySigningKeySlotId,
        ecdsaThresholdKeyId: input.ecdsaThresholdKeyId,
        signingRootId: signingRoot.signingRootId,
        signingRootVersion: signingRoot.signingRootVersion,
        keyScope: 'evm-family',
        relayerKeyId: input.relayerKeyId,
        hssClientSharePublicKey33B64u: input.clientBootstrap.hssClientSharePublicKey33B64u,
        clientShareRetryCounter: input.clientBootstrap.clientShareRetryCounter,
        contextBinding32B64u: input.clientBootstrap.contextBinding32B64u,
        requestId: input.requestId,
        sessionId: input.sessionId,
        signingGrantId: input.signingGrantId,
        ttlMs: input.ttlMs,
        remainingUses: input.remainingUses,
        participantIds: [...input.participantIds],
        auth: routeAuthToThresholdAuth(input.auth),
        runtimePolicyScope: input.runtimePolicyScope,
      });
      if (!response.ok) {
        return mapRouteFailure({
          code: response.code || '',
          message: response.message || response.error || 'Threshold ECDSA relayer bootstrap failed',
        });
      }
      try {
        return { ok: true, value: await parseBootstrapOutput(input, response.value) };
      } catch (error) {
        return {
          ok: false,
          code: 'malformed_response',
          message: error instanceof Error ? error.message : String(error),
          retryable: false,
        };
      }
    },
  };
}
