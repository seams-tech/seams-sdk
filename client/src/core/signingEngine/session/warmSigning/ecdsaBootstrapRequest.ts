import { toAccountId } from '@/core/types/accountIds';
import {
  getPrimaryAndSecondaryEcdsaCapabilities,
  normalizeParticipantIds,
  toOptionalNonEmptyString,
} from './ecdsaProvisioner';
import type {
  ResolveWarmEcdsaBootstrapRequestArgs,
  WarmEcdsaBootstrapRequest,
} from './types';
import type { WarmSessionEnvelope } from './types';

function cloneOptionalFixed32Bytes(value: Uint8Array | undefined): Uint8Array | undefined {
  if (!(value instanceof Uint8Array)) return undefined;
  if (value.length !== 32) {
    throw new Error('clientRootShare32 must be 32 bytes');
  }
  return value;
}

export function resolveWarmEcdsaBootstrapRequestFromSession(args: {
  request: ResolveWarmEcdsaBootstrapRequestArgs;
  warmSession: WarmSessionEnvelope;
}): WarmEcdsaBootstrapRequest {
  const request = args.request;
  const nearAccountId = toAccountId(request.nearAccountId);
  const { primary: primaryCapability, secondary: secondaryCapability } =
    getPrimaryAndSecondaryEcdsaCapabilities({
      warmSession: args.warmSession,
      chain: request.chain,
    });
  const primaryWarmCapability =
    primaryCapability.prfClaim?.state === 'warm' ? primaryCapability : null;
  const reusableWarmCapability = primaryWarmCapability;

  const explicitParticipantIds = normalizeParticipantIds(request.participantIds);
  const explicitRelayerUrl = toOptionalNonEmptyString(request.relayerUrl);
  const explicitThresholdRouteAuth = request.thresholdRouteAuth;
  const explicitSessionId = toOptionalNonEmptyString(request.sessionId);
  const explicitWalletSigningSessionId = toOptionalNonEmptyString(request.walletSigningSessionId);
  const explicitThresholdKeyId = toOptionalNonEmptyString(request.ecdsaThresholdKeyId);
  const explicitClientRootShare32 = cloneOptionalFixed32Bytes(request.clientRootShare32);
  const explicitClientRootShare32B64u = toOptionalNonEmptyString(request.clientRootShare32B64u);
  const explicitWebauthnAuthentication = request.webauthnAuthentication;
  const shouldUseFreshWebAuthnBootstrap = Boolean(explicitWebauthnAuthentication);
  const explicitRuntimeScopeBootstrap =
    request.runtimeScopeBootstrap &&
    String(request.runtimeScopeBootstrap.environmentId || '').trim() &&
    String(request.runtimeScopeBootstrap.publishableKey || '').trim()
      ? {
          environmentId: String(request.runtimeScopeBootstrap.environmentId || '').trim(),
          publishableKey: String(request.runtimeScopeBootstrap.publishableKey || '').trim(),
        }
      : null;
  const preferredMetadataCapability = primaryCapability.record
    ? primaryCapability
    : secondaryCapability.record
      ? secondaryCapability
      : null;
  const preferredParticipantIds =
    normalizeParticipantIds(primaryCapability.record?.participantIds) ||
    normalizeParticipantIds(secondaryCapability.record?.participantIds);
  const preferredSessionKind =
    primaryCapability.record?.thresholdSessionKind ||
    secondaryCapability.record?.thresholdSessionKind ||
    'jwt';

  return {
    nearAccountId,
    chain: request.chain,
    chainId: request.chainId,
    ...(request.emailOtpAuthContext ? { emailOtpAuthContext: request.emailOtpAuthContext } : {}),
    ...(explicitRelayerUrl
      ? { relayerUrl: explicitRelayerUrl }
      : toOptionalNonEmptyString(preferredMetadataCapability?.record?.relayerUrl)
        ? {
            relayerUrl: String(
              toOptionalNonEmptyString(preferredMetadataCapability?.record?.relayerUrl) || '',
            ).trim(),
          }
        : {}),
    ...(explicitThresholdKeyId
      ? { ecdsaThresholdKeyId: explicitThresholdKeyId }
      : toOptionalNonEmptyString(primaryCapability.record?.ecdsaThresholdKeyId)
        ? {
            ecdsaThresholdKeyId: String(
              toOptionalNonEmptyString(primaryCapability.record?.ecdsaThresholdKeyId) || '',
            ).trim(),
          }
        : toOptionalNonEmptyString(secondaryCapability.record?.ecdsaThresholdKeyId)
          ? {
              ecdsaThresholdKeyId: String(
                toOptionalNonEmptyString(secondaryCapability.record?.ecdsaThresholdKeyId) || '',
              ).trim(),
            }
          : {}),
    ...(explicitParticipantIds
      ? { participantIds: explicitParticipantIds }
      : preferredParticipantIds
        ? {
            participantIds: preferredParticipantIds,
          }
        : {}),
    sessionKind: request.sessionKind || preferredSessionKind,
    ...(explicitSessionId
      ? { sessionId: explicitSessionId }
      : toOptionalNonEmptyString(reusableWarmCapability?.record?.thresholdSessionId)
        ? {
            sessionId: String(
              toOptionalNonEmptyString(reusableWarmCapability?.record?.thresholdSessionId) || '',
            ).trim(),
          }
        : {}),
    ...(explicitWalletSigningSessionId
      ? { walletSigningSessionId: explicitWalletSigningSessionId }
      : toOptionalNonEmptyString(reusableWarmCapability?.record?.walletSigningSessionId)
        ? {
            walletSigningSessionId: String(
              toOptionalNonEmptyString(reusableWarmCapability?.record?.walletSigningSessionId) ||
                '',
            ).trim(),
          }
        : {}),
    ...(explicitThresholdRouteAuth
      ? { thresholdRouteAuth: explicitThresholdRouteAuth }
      : !shouldUseFreshWebAuthnBootstrap &&
          toOptionalNonEmptyString(reusableWarmCapability?.auth?.thresholdSessionJwt)
        ? {
            thresholdRouteAuth: {
              kind: 'threshold_session',
              jwt: String(
                toOptionalNonEmptyString(reusableWarmCapability?.auth?.thresholdSessionJwt) || '',
              ).trim(),
            },
          }
        : {}),
    ...(request.runtimePolicyScope ? { runtimePolicyScope: request.runtimePolicyScope } : {}),
    ...(explicitRuntimeScopeBootstrap
      ? { runtimeScopeBootstrap: explicitRuntimeScopeBootstrap }
      : {}),
    ...(explicitClientRootShare32 ? { clientRootShare32: explicitClientRootShare32 } : {}),
    ...(explicitClientRootShare32B64u
      ? { clientRootShare32B64u: explicitClientRootShare32B64u }
      : {}),
    ...(explicitWebauthnAuthentication
      ? { webauthnAuthentication: explicitWebauthnAuthentication }
      : {}),
  };
}
