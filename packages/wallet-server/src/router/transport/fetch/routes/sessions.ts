import {
  extractBearerCredential,
  resolveSourceIpFromFetchHeaders,
} from '../../../auth/routerApiKeyAuth';
import { emitRouterApiWebhookEvent } from '../../../framework/routerApiWebhooks';
import type { FetchRouterApiContext } from '../createFetchRouter';
import { json, readJson } from '../../../framework/http';
import { normalizeRuntimePolicyScope } from '@shared/threshold/signingRootScope';
import { alphabetizeStringify, sha256HexUtf8 } from '@shared/utils/digests';
import {
  handleWalletUnlockChallengeRoute,
  handleWalletUnlockVerifyRoute,
  type WalletUnlockEcdsaCustodySignerV1,
  type WalletUnlockEcdsaAuthorization,
  type WalletUnlockEcdsaSessionContext,
  type WalletUnlockCapabilityContext,
} from '../../../domains/walletUnlock/walletUnlockRouteHandlers';
import type { RouterAbEd25519YaoActiveCapabilityDescriptorV1 } from '../../../domains/ed25519Yao/recovery/routerAbEd25519YaoRecovery';
import { handleStrictEcdsaSessionActivation } from './thresholdEcdsa';
import {
  parseRouterAbEcdsaPostRegistrationSessionActivationPolicyV1,
  parseRouterAbEcdsaCredentialFreeSessionActivationResponseV1,
  parseRouterAbEcdsaPostRegistrationSessionActivationResponseV1,
  type RouterAbEcdsaPostRegistrationSessionActivationRequestV1,
} from '@shared/utils/routerAbEcdsaDerivation';
import {
  routerAbMpcMaterialActivationRefToWire,
  sameRouterAbMpcMaterialActivationRef,
} from '@shared/utils/routerAbNormalSigningIdentity';
import type { MpcMaterialActivationRef } from '@shared/utils/domainIds';
import {
  routerApiEmailOtpRouteService,
  type RouterApiWalletSessionAuthorizationV2AdmissionContext,
} from '../../../framework/authServicePort';
import {
  handleEmailOtpDevCleanupGoogleRegistrationRoute,
  handleEmailOtpDevOutboxRoute,
  handleEmailOtpRegistrationSealRoute,
  sealEmailOtpFactorSecretForWorker,
} from '../../../domains/emailOtp/emailOtpRouteHandlers';
import {
  parseOrgId,
  parseProviderSubject,
  parseWalletAuthMethodId,
  parseWalletId,
  type WalletAuthMethodId,
  type WalletId,
} from '@shared/utils/domainIds';
import {
  EMAIL_OTP_CHANNEL,
  WALLET_EMAIL_OTP_EXPORT_OPERATION,
  type WalletEmailOtpLoginOperation,
  type WalletEmailOtpOperation,
} from '@shared/utils/emailOtpDomain';
import { parseWalletUnlockRequestedCapabilitiesRequest } from '../../../domains/walletUnlock/walletUnlockRequestedCapabilitiesValidation';
import { parseWalletEmailOtpLoginOperation } from '../../../domains/emailOtp/emailOtpRequestValidation';
import {
  emailOtpStatusCode,
  hashEmailOtpOperationBinding,
} from '../../../domains/emailOtp/emailOtpSessionRouteHelpers';
import { authorizeEmailOtpExportPolicy } from '../../../domains/emailOtp/emailOtpExportPolicy';
import { isPlainObject } from '@shared/utils/validation';
import {
  parseMpcWalletSigningQuotaId,
  parseWalletSessionId,
  type MpcWalletSigningQuotaId,
  type TenantId,
  type WalletSessionId,
} from '@shared/authorization/capabilityKinds';
import { parseWebAuthnCredentialIdB64u, parseWebAuthnRpId } from '@shared/utils/domainIds';
import { walletIdFromString } from '@shared/utils/registrationIntent';
import {
  parseHostedWalletSeamsSessionExchangeCode,
  parseHostedWalletSeamsSessionExchangeNonce,
  parsePrimaryWalletSessionOperationCredentialToken,
  parseSessionOrigin,
  projectExactWalletSessionAuthorizationV1,
  type ExactWalletSessionStatusV2,
  type SessionOrigin,
} from '../../../../authorization/domain';
import { walletAuthAuthorityRef } from '@shared/utils/walletAuthAuthority';
import { parseDigestB64u, type DigestB64u } from '@shared/utils/canonicalPrimitives';
import type { ActiveWalletAuthorityV1 } from '@shared/authorization/walletAuthority';
import { base58Encode } from '@shared/utils/base58';

const HOSTED_WALLET_EXCHANGE_TTL_MS = 5 * 60 * 1000;

function parseExactHostedWalletExchangeBody(
  value: unknown,
  fields: readonly string[],
): Record<string, unknown> {
  if (!isPlainObject(value)) throw new Error('hosted-wallet exchange body is invalid');
  const allowed = new Set(fields);
  for (const key of Object.keys(value)) {
    if (!allowed.has(key)) throw new Error(`Unsupported hosted-wallet exchange field: ${key}`);
  }
  for (const field of fields) {
    if (!Object.hasOwn(value, field))
      throw new Error(`Missing hosted-wallet exchange field: ${field}`);
  }
  return value;
}

function requiredExchangeOrigin(record: Record<string, unknown>, field: string): SessionOrigin {
  return parseSessionOrigin(record[field]);
}

function requestOrigin(request: Request): SessionOrigin {
  return parseSessionOrigin(request.headers.get('origin'));
}

function hostedWalletOriginIsAllowed(ctx: FetchRouterApiContext, origin: SessionOrigin): boolean {
  return (ctx.opts.hostedWalletOrigins ?? []).some((candidate) => {
    try {
      return parseSessionOrigin(candidate) === origin;
    } catch {
      return false;
    }
  });
}

type ParsedWalletEmailOtpChallengeRequest = {
  readonly walletId: WalletId;
  readonly walletAuthMethodId: WalletAuthMethodId;
  readonly operation: WalletEmailOtpLoginOperation;
  readonly operationFingerprintDigest?: DigestB64u;
};

function parseWalletEmailOtpChallengeRequest(value: unknown): ParsedWalletEmailOtpChallengeRequest {
  if (!isPlainObject(value)) throw new Error('Expected JSON object body');
  const fields = Object.keys(value).sort().join(',');
  const hasExactFields =
    fields === 'operation,otpChannel,walletAuthMethodId,walletId' ||
    fields === 'operation,operationFingerprintDigest,otpChannel,walletAuthMethodId,walletId';
  if (!hasExactFields) {
    throw new Error(
      'Email OTP challenge body must contain walletId, walletAuthMethodId, otpChannel, operation, and optionally operationFingerprintDigest',
    );
  }

  const parsedWalletId = parseWalletId(value.walletId);
  if (!parsedWalletId.ok) throw new Error(parsedWalletId.error.message);
  const parsedOperation = parseWalletEmailOtpLoginOperation(value.operation);
  if (!parsedOperation.ok) throw new Error(parsedOperation.message);
  if (value.otpChannel !== EMAIL_OTP_CHANNEL) {
    throw new Error('otpChannel must be email_otp');
  }

  const operationFingerprintDigest = Object.hasOwn(value, 'operationFingerprintDigest')
    ? parseDigestB64u(value.operationFingerprintDigest)
    : undefined;
  const parsedWalletAuthMethodId = parseWalletAuthMethodId(value.walletAuthMethodId);
  if (!parsedWalletAuthMethodId.ok) {
    throw new Error(parsedWalletAuthMethodId.error.message);
  }
  return {
    walletId: parsedWalletId.value,
    walletAuthMethodId: parsedWalletAuthMethodId.value,
    operation: parsedOperation.operation,
    ...(operationFingerprintDigest ? { operationFingerprintDigest } : {}),
  };
}

async function resolveWalletEmailOtpChallengeAuthority(args: {
  readonly ctx: FetchRouterApiContext;
  readonly walletId: WalletId;
  readonly orgId: string;
  readonly providerUserId: string;
  readonly walletAuthMethodId: WalletAuthMethodId;
}): Promise<Awaited<ReturnType<FetchRouterApiContext['service']['walletUnlock']['resolveEmailOtpAuthorityForUnlock']>>> {
  return await args.ctx.service.walletUnlock.resolveEmailOtpAuthorityForUnlock({
    walletId: args.walletId,
    orgId: args.orgId,
    walletAuthMethodId: args.walletAuthMethodId,
    providerUserId: args.providerUserId,
  });
}

type WalletEmailOtpChallengeEd25519Identity = {
  readonly materialActivation: MpcMaterialActivationRef;
  readonly nearAccountId: string;
  readonly signerSlot: number;
  readonly operationalPublicKey: string;
  readonly thresholdSessionId: string;
  readonly runtimePolicyScope: ReturnType<typeof normalizeRuntimePolicyScope>;
};

async function resolveWalletEmailOtpChallengeEd25519Identity(args: {
  readonly ctx: FetchRouterApiContext;
  readonly authority: ActiveWalletAuthorityV1;
  readonly materialActivation: MpcMaterialActivationRef;
}): Promise<
  | { readonly ok: true; readonly identity: WalletEmailOtpChallengeEd25519Identity }
  | { readonly ok: false; readonly code: string; readonly message: string }
> {
  const resolved = await args.ctx.service.walletRegistration.resolveEd25519MaterialActivation({
    walletId: String(args.authority.walletId),
    materialActivation: routerAbMpcMaterialActivationRefToWire(args.materialActivation),
  });
  if (!resolved.ok) return resolved;
  if (
    !sameRouterAbMpcMaterialActivationRef(
      routerAbMpcMaterialActivationRefToWire(args.materialActivation),
      resolved.materialActivation,
    )
  ) {
    return {
      ok: false,
      code: 'invalid_authority',
      message: 'Ed25519 material does not belong to the selected wallet authority',
    };
  }
  return {
    ok: true,
    identity: {
      materialActivation: args.materialActivation,
      nearAccountId: resolved.nearAccountId,
      signerSlot: resolved.signerSlot,
      operationalPublicKey: `ed25519:${base58Encode(
        Uint8Array.from(resolved.exportIdentity.registered_public_key),
      )}`,
      thresholdSessionId: resolved.exportIdentity.scope.threshold_session_id,
      runtimePolicyScope: normalizeRuntimePolicyScope(resolved.runtimePolicyScope),
    },
  };
}

async function resolveWalletEmailOtpChallengeSignerSelection(args: {
  readonly ctx: FetchRouterApiContext;
  readonly authority: ActiveWalletAuthorityV1;
}): Promise<
  | {
      readonly ok: true;
      readonly selection:
        | {
            readonly kind: 'ed25519_only';
            readonly materialActivation: MpcMaterialActivationRef;
            readonly nearAccountId: string;
            readonly signerSlot: number;
            readonly operationalPublicKey: string;
            readonly thresholdSessionId: string;
            readonly runtimePolicyScope: ReturnType<typeof normalizeRuntimePolicyScope>;
          }
        | {
            readonly kind: 'ecdsa';
            readonly keyHandle: string;
            readonly runtimePolicyScope: ReturnType<typeof normalizeRuntimePolicyScope>;
            readonly ed25519:
              | {
                  readonly kind: 'present';
                  readonly materialActivation: MpcMaterialActivationRef;
                  readonly nearAccountId: string;
                  readonly signerSlot: number;
                  readonly operationalPublicKey: string;
                  readonly thresholdSessionId: string;
                  readonly runtimePolicyScope: ReturnType<typeof normalizeRuntimePolicyScope>;
                }
              | { readonly kind: 'absent' };
          };
    }
  | { readonly ok: false; readonly code: string; readonly message: string }
> {
  const ecdsaActivation = args.authority.signerActivations.ecdsa;
  if (!ecdsaActivation) {
    const ed25519Activation = args.authority.signerActivations.ed25519;
    if (!ed25519Activation) {
      return { ok: false, code: 'invalid_authority', message: 'Wallet authority has no signer' };
    }
    const resolvedEd25519 = await resolveWalletEmailOtpChallengeEd25519Identity({
      ctx: args.ctx,
      authority: args.authority,
      materialActivation: ed25519Activation.materialActivation,
    });
    if (!resolvedEd25519.ok) return resolvedEd25519;
    return {
      ok: true,
      selection: {
        kind: 'ed25519_only',
        ...resolvedEd25519.identity,
      },
    };
  }
  const resolved = await args.ctx.service.walletRegistration.resolveEcdsaMaterialActivation({
    walletId: String(args.authority.walletId),
    materialActivation: routerAbMpcMaterialActivationRefToWire(ecdsaActivation.materialActivation),
  });
  if (!resolved.ok) {
    return { ok: false, code: resolved.code, message: resolved.message };
  }
  if (
    !sameRouterAbMpcMaterialActivationRef(
      routerAbMpcMaterialActivationRefToWire(ecdsaActivation.materialActivation),
      resolved.materialActivation,
    )
  ) {
    return {
      ok: false,
      code: 'invalid_authority',
      message: 'ECDSA material does not belong to the selected wallet authority',
    };
  }
  const ed25519Activation = args.authority.signerActivations.ed25519;
  const resolvedEd25519 = ed25519Activation
    ? await resolveWalletEmailOtpChallengeEd25519Identity({
        ctx: args.ctx,
        authority: args.authority,
        materialActivation: ed25519Activation.materialActivation,
      })
    : null;
  if (resolvedEd25519 && !resolvedEd25519.ok) return resolvedEd25519;
  return {
    ok: true,
    selection: {
      kind: 'ecdsa',
      keyHandle: resolved.keyHandle,
      runtimePolicyScope: normalizeRuntimePolicyScope(resolved.runtimePolicyScope),
      ed25519: resolvedEd25519?.ok
        ? { kind: 'present', ...resolvedEd25519.identity }
        : { kind: 'absent' },
    },
  };
}

function hostedWalletExchangeFailure(result: { readonly kind: string }): {
  readonly status: number;
  readonly code: string;
  readonly message: string;
} {
  switch (result.kind) {
    case 'expired':
      return {
        status: 410,
        code: 'exchange_expired',
        message: 'Hosted-wallet exchange is expired',
      };
    case 'already_consumed':
      return {
        status: 409,
        code: 'exchange_already_consumed',
        message: 'Hosted-wallet exchange was already redeemed',
      };
    case 'nonce_mismatch':
    case 'app_origin_mismatch':
    case 'wallet_origin_mismatch':
    case 'invalid_code':
      return {
        status: 401,
        code: 'exchange_invalid',
        message: 'Hosted-wallet exchange is invalid',
      };
    default:
      return {
        status: 503,
        code: 'wallet_session_unavailable',
        message: 'Wallet Session is unavailable',
      };
  }
}

export async function handleHostedWalletSessionExchangeIssue(
  ctx: FetchRouterApiContext,
): Promise<Response | null> {
  if (ctx.method !== 'POST' || ctx.pathname !== '/wallet/session/exchange/issue') return null;
  let record: Record<string, unknown>;
  try {
    record = parseExactHostedWalletExchangeBody(await readJson(ctx.request), [
      'appOrigin',
      'walletOrigin',
    ]);
  } catch (error) {
    return json({ ok: false, code: 'invalid_body', message: String(error) }, { status: 400 });
  }
  let appOrigin: SessionOrigin;
  let walletOrigin: SessionOrigin;
  try {
    appOrigin = requiredExchangeOrigin(record, 'appOrigin');
    walletOrigin = requiredExchangeOrigin(record, 'walletOrigin');
    if (requestOrigin(ctx.request) !== appOrigin)
      throw new Error('request Origin does not match appOrigin');
    if (!hostedWalletOriginIsAllowed(ctx, walletOrigin)) {
      throw new Error('walletOrigin is not an allowed server origin');
    }
  } catch (error) {
    return json({ ok: false, code: 'origin_mismatch', message: String(error) }, { status: 403 });
  }
  const token = extractBearerCredential(ctx.request.headers);
  if (!token)
    return json(
      { ok: false, code: 'unauthorized', message: 'No valid Wallet Session' },
      { status: 401 },
    );
  let primaryToken: string;
  try {
    primaryToken = parsePrimaryWalletSessionOperationCredentialToken(token);
  } catch {
    return json(
      { ok: false, code: 'unauthorized', message: 'No valid Wallet Session' },
      { status: 401 },
    );
  }
  let resolved: Awaited<
    ReturnType<
      FetchRouterApiContext['service']['authorizationSessions']['readWalletSessionAuthorizationV2ByOperationCredential']
    >
  >;
  try {
    resolved =
      await ctx.service.authorizationSessions.readWalletSessionAuthorizationV2ByOperationCredential(
        {
          tenantId: ctx.service.authorizationSessions.tenantId,
          token: primaryToken,
          nowMs: Date.now(),
        },
      );
  } catch {
    return json(
      { ok: false, code: 'wallet_session_unavailable', message: 'Wallet Session is unavailable' },
      { status: 503 },
    );
  }
  if (!resolved)
    return json(
      { ok: false, code: 'unauthorized', message: 'No valid Wallet Session' },
      { status: 401 },
    );
  let delivery: Awaited<
    ReturnType<
      FetchRouterApiContext['service']['authorizationSessions']['mintHostedWalletSeamsSessionExchange']
    >
  >;
  try {
    const issuedAtMs = Date.now();
    delivery = await ctx.service.authorizationSessions.mintHostedWalletSeamsSessionExchange({
      authorization: resolved.authorization,
      appOrigin,
      walletOrigin,
      issuedAtMs,
      expiresAtMs: issuedAtMs + HOSTED_WALLET_EXCHANGE_TTL_MS,
    });
  } catch {
    return json(
      { ok: false, code: 'wallet_session_unavailable', message: 'Wallet Session is unavailable' },
      { status: 503 },
    );
  }
  return json(
    {
      ok: true,
      delivery: {
        exchangeCode: delivery.exchangeCode,
        nonce: delivery.nonce,
        appOrigin: delivery.appOrigin,
        walletOrigin: delivery.walletOrigin,
        expiresAtMs: delivery.expiresAtMs,
      },
    },
    { status: 200 },
  );
}

export async function handleHostedWalletSessionExchangeRedeem(
  ctx: FetchRouterApiContext,
): Promise<Response | null> {
  if (ctx.method !== 'POST' || ctx.pathname !== '/wallet/session/exchange/redeem') return null;
  let record: Record<string, unknown>;
  try {
    record = parseExactHostedWalletExchangeBody(await readJson(ctx.request), [
      'exchangeCode',
      'nonce',
      'appOrigin',
      'walletOrigin',
    ]);
  } catch (error) {
    return json({ ok: false, code: 'invalid_body', message: String(error) }, { status: 400 });
  }
  let exchangeCode: ReturnType<typeof parseHostedWalletSeamsSessionExchangeCode>;
  let nonce: ReturnType<typeof parseHostedWalletSeamsSessionExchangeNonce>;
  let appOrigin: SessionOrigin;
  let walletOrigin: SessionOrigin;
  try {
    exchangeCode = parseHostedWalletSeamsSessionExchangeCode(record.exchangeCode);
    nonce = parseHostedWalletSeamsSessionExchangeNonce(record.nonce);
    appOrigin = requiredExchangeOrigin(record, 'appOrigin');
    walletOrigin = requiredExchangeOrigin(record, 'walletOrigin');
    if (requestOrigin(ctx.request) !== walletOrigin) {
      throw new Error('request Origin does not match walletOrigin');
    }
    if (!hostedWalletOriginIsAllowed(ctx, walletOrigin)) {
      throw new Error('walletOrigin is not an allowed server origin');
    }
  } catch (error) {
    return json({ ok: false, code: 'origin_mismatch', message: String(error) }, { status: 403 });
  }
  const result = await ctx.service.authorizationSessions.redeemHostedWalletSeamsSessionExchange({
    exchangeCode,
    nonce,
    appOrigin,
    walletOrigin,
    redeemedAtMs: Date.now(),
  });
  if (result.kind !== 'redeemed') {
    const failure = hostedWalletExchangeFailure(result);
    return json(
      { ok: false, code: failure.code, message: failure.message },
      { status: failure.status },
    );
  }
  return json(
    {
      ok: true,
      walletSessionId: result.walletSessionId,
      operationCredential: result.operationCredential,
      expiresAtMs: result.expiresAtMs,
    },
    { status: 200 },
  );
}

function projectWalletUnlockEcdsaCustodySigner(
  signer: Awaited<
    ReturnType<
      FetchRouterApiContext['service']['walletRegistration']['listWalletEcdsaCustodyContinuity']
    >
  >[number],
): WalletUnlockEcdsaCustodySignerV1 {
  return {
    chainTarget: signer.chainTarget,
    walletKey: {
      walletId: signer.walletKey.walletId,
      keyHandle: signer.walletKey.keyHandle,
      ecdsaThresholdKeyId: signer.walletKey.ecdsaThresholdKeyId,
      signingRootId: signer.walletKey.signingRootId,
      signingRootVersion: signer.walletKey.signingRootVersion,
      relayerKeyId: signer.walletKey.relayerKeyId,
      contextBinding32B64u: signer.walletKey.contextBinding32B64u,
      derivationClientSharePublicKey33B64u: signer.walletKey.derivationClientSharePublicKey33B64u,
      participantIds: signer.walletKey.participantIds,
      publicCapability: signer.walletKey.publicCapability,
    },
    activationReceipt: signer.activationReceipt,
    runtimePolicyScope: signer.runtimePolicyScope,
  };
}

export type WalletUnlockEcdsaAuthoredRequest = {
  readonly request: RouterAbEcdsaPostRegistrationSessionActivationRequestV1;
  readonly activationReceipt: WalletUnlockEcdsaCustodySignerV1['activationReceipt'];
  readonly continuity: {
    readonly kind: 'wallet_custody_ecdsa_sync_continuity_v1';
    readonly signers: readonly WalletUnlockEcdsaCustodySignerV1[];
  };
};

export async function authorWalletUnlockEcdsaRequest(
  ctx: FetchRouterApiContext,
  walletId: string,
  policy: ReturnType<typeof parseRouterAbEcdsaPostRegistrationSessionActivationPolicyV1>,
): Promise<
  | { readonly ok: true; readonly value: WalletUnlockEcdsaAuthoredRequest }
  | { readonly ok: false; readonly status: number; readonly code: string; readonly message: string }
> {
  const signers = await ctx.service.walletRegistration.listWalletEcdsaCustodyContinuity({
    walletId,
  });
  const matching = signers.filter((signer) => signer.walletKey.keyHandle === policy.key_handle);
  const first = matching[0];
  if (!first) {
    return {
      ok: false,
      status: 404,
      code: 'ecdsa_key_not_found',
      message: 'ECDSA key handle is not active for this wallet',
    };
  }
  const requestedScope = normalizeRuntimePolicyScope(policy.session_policy.runtime_policy_scope);
  if (
    matching.some(
      (signer) =>
        alphabetizeStringify(signer.runtimePolicyScope) !== alphabetizeStringify(requestedScope) ||
        alphabetizeStringify(signer.walletKey.publicCapability) !==
          alphabetizeStringify(first.walletKey.publicCapability) ||
        alphabetizeStringify(signer.activationReceipt) !==
          alphabetizeStringify(first.activationReceipt),
    )
  ) {
    return {
      ok: false,
      status: 409,
      code: 'ecdsa_key_continuity_conflict',
      message: 'ECDSA key handle resolves to conflicting active custody records',
    };
  }
  return {
    ok: true,
    value: {
      request: {
        kind: 'router_ab_ecdsa_post_registration_session_activation_v1',
        public_capability: first.walletKey.publicCapability,
        session_policy: policy.session_policy,
      },
      activationReceipt: first.activationReceipt,
      continuity: {
        kind: 'wallet_custody_ecdsa_sync_continuity_v1',
        signers: matching.map(projectWalletUnlockEcdsaCustodySigner),
      },
    },
  };
}

function parseWalletUnlockEcdsaActivationResponse(
  responseBody: unknown,
  authorization: WalletUnlockEcdsaAuthorization,
) {
  switch (authorization.kind) {
    case 'verified_wallet_unlock':
      return parseRouterAbEcdsaPostRegistrationSessionActivationResponseV1(responseBody);
    case 'wallet_session_operation_credential_v1':
      return parseRouterAbEcdsaCredentialFreeSessionActivationResponseV1(responseBody);
  }
}

function walletUnlockEcdsaSessionContext(
  ctx: FetchRouterApiContext,
  body: unknown,
): WalletUnlockEcdsaSessionContext {
  if (isPlainObject(body) && body.ecdsaSessionActivation !== undefined) {
    throw new Error('ecdsaSessionActivation is no longer accepted; send ecdsaSessionPolicy');
  }
  if (!isPlainObject(body) || body.ecdsaSessionPolicy === undefined) {
    return { kind: 'no_ecdsa_session' };
  }
  const policy = parseRouterAbEcdsaPostRegistrationSessionActivationPolicyV1(
    body.ecdsaSessionPolicy,
  );
  const walletId = String(body.walletId || '').trim();
  if (!walletId) throw new Error('walletId is required with ecdsaSessionPolicy');
  return {
    kind: 'provision_first_ecdsa_session',
    walletId,
    policy,
    provisionWalletSession: async (authorization) => {
      const authored = await authorWalletUnlockEcdsaRequest(ctx, walletId, policy);
      if (!authored.ok) return authored;
      const { request, activationReceipt, continuity } = authored.value;
      let response: Response;
      if (authorization.kind === 'wallet_session_operation_credential_v1') {
        response = await handleStrictEcdsaSessionActivation({
          ctx,
          body: request,
          source: 'wallet_session_operation_credential_v1',
          operationCredential: authorization.operationCredential,
          proof: authorization.proof,
        });
      } else {
        response = await handleStrictEcdsaSessionActivation({
          ctx,
          body: request,
          source: 'verified_wallet_unlock',
          proof: authorization.proof,
        });
      }
      const responseBody: unknown = await response.json();
      if (!response.ok) {
        const failure = isPlainObject(responseBody) ? responseBody : {};
        return {
          ok: false,
          status: response.status,
          code: String(failure.code || 'ecdsa_session_activation_failed'),
          message: String(failure.message || 'ECDSA Wallet Session activation failed'),
        };
      }
      return {
        ok: true,
        activation: parseWalletUnlockEcdsaActivationResponse(responseBody, authorization),
        activationReceipt,
        continuity,
      };
    },
  };
}

async function emitEmailOtpWebhookEvent(
  ctx: FetchRouterApiContext,
  input: {
    eventType: string;
    claims?: Record<string, unknown> | null;
    userId: string;
    walletId?: string;
    eventId?: string;
    payload?: Record<string, unknown>;
  },
): Promise<void> {
  await emitRouterApiWebhookEvent({
    logger: ctx.logger,
    webhooks: ctx.opts.routerApiWebhooks,
    eventType: input.eventType,
    claims: input.claims || undefined,
    userId: input.userId,
    ...(input.eventId ? { eventId: input.eventId } : {}),
    payload: {
      ...(input.walletId ? { walletId: input.walletId } : {}),
      ...(input.payload || {}),
    },
  });
}

async function emitEmailOtpWebhookDescriptor(
  ctx: FetchRouterApiContext,
  input: {
    descriptor: { eventType: string; eventId?: string; payload: Record<string, unknown> };
    claims?: Record<string, unknown> | null;
    userId: string;
    walletId?: string;
  },
): Promise<void> {
  await emitEmailOtpWebhookEvent(ctx, {
    eventType: input.descriptor.eventType,
    claims: input.claims,
    userId: input.userId,
    walletId: input.walletId,
    ...(input.descriptor.eventId ? { eventId: input.descriptor.eventId } : {}),
    payload: input.descriptor.payload,
  });
}

function parseExactWalletSessionStatusBody(body: unknown): {
  readonly walletSessionId: WalletSessionId;
  readonly quotaId: MpcWalletSigningQuotaId;
} | null {
  if (!isPlainObject(body)) return null;
  const fields = Object.keys(body);
  if (
    fields.length !== 2 ||
    !fields.every((field) => field === 'walletSessionId' || field === 'quotaId')
  ) {
    return null;
  }
  const walletSessionId = parseWalletSessionId(body.walletSessionId);
  const quotaId = parseMpcWalletSigningQuotaId(body.quotaId);
  if (!walletSessionId.ok || !quotaId.ok) return null;
  return {
    walletSessionId: walletSessionId.value,
    quotaId: quotaId.value,
  };
}

type ExactWalletSessionStatusRequest = {
  readonly walletSessionId: WalletSessionId;
  readonly quotaId: MpcWalletSigningQuotaId;
};

/**
 * The immutable identities the presented operation credential must carry. The
 * credential resolves one authorization; the request may only name the Wallet
 * Session and quota that authorization already committed. Authority and auth
 * method identity is validated against their own rows in persistence, so the
 * route never infers either from wallet-wide uniqueness.
 */
function exactWalletSessionStatusIdentityMatches(input: {
  readonly status: ExactWalletSessionStatusV2;
  readonly request: ExactWalletSessionStatusRequest;
  readonly tenantId: TenantId;
}): boolean {
  if (input.status.kind === 'missing') return true;
  const session = input.status.session;
  if (
    session.tenantId !== input.tenantId ||
    session.walletSessionId !== input.request.walletSessionId ||
    session.quotaId !== input.request.quotaId
  ) {
    return false;
  }
  switch (input.status.kind) {
    case 'active':
    case 'exhausted':
    case 'expired':
      return (
        input.status.quota.tenantId === session.tenantId &&
        input.status.quota.principalId === session.principalId &&
        input.status.quota.walletSessionId === session.walletSessionId &&
        input.status.quota.quotaId === session.quotaId
      );
    default:
      return true;
  }
}

/**
 * Projects the persistence lifecycle onto the status vocabulary. Every branch
 * that observed a stored authorization publishes the complete digest-free
 * authorization projection and its quota, so a browser reconciles its own
 * record from one read; the credential digest never leaves persistence.
 *
 * Retirement is `superseded`; exact absence is `invalid`, which is also the
 * only branch a caller cannot distinguish from a credential that never existed.
 */
function exactWalletSessionStatusResponseBody(
  status: ExactWalletSessionStatusV2,
  request: ExactWalletSessionStatusRequest,
): Record<string, unknown> {
  const identity = { walletSessionId: request.walletSessionId, quotaId: request.quotaId };
  if (status.kind === 'missing') return { ok: true, status: 'invalid', ...identity };
  const observed = {
    ...identity,
    remainingUses: status.quota.remainingUses,
    expiresAtMs: status.quota.expiresAtMs,
    quotaLifecycle: status.quota.lifecycle,
    authorization: projectExactWalletSessionAuthorizationV1(status.session),
  };
  switch (status.kind) {
    case 'active':
    case 'exhausted':
    case 'expired':
    case 'authority_unavailable':
    case 'method_unavailable':
    case 'capability_unavailable':
      return { ok: true, status: status.kind, ...observed };
    case 'retired':
      return { ok: true, status: 'superseded', ...observed };
  }
}

export async function handleExactWalletSessionStatus(
  ctx: FetchRouterApiContext,
): Promise<Response | null> {
  if (ctx.method !== 'POST' || ctx.pathname !== '/wallet/session/status') return null;
  const request = parseExactWalletSessionStatusBody(await readJson(ctx.request));
  if (!request) {
    return json(
      {
        ok: false,
        code: 'invalid_body',
        message: 'Wallet Session status requires exact walletSessionId and quotaId',
      },
      { status: 400 },
    );
  }
  const bearerToken = extractBearerCredential(ctx.request.headers);
  if (!bearerToken) {
    return json(
      { authenticated: false, code: 'unauthorized', message: 'No valid Wallet Session' },
      { status: 401 },
    );
  }

  const tenantId = ctx.service.authorizationSessions.tenantId;
  const status =
    await ctx.service.authorizationSessions.readExactWalletSessionStatusByOperationCredential({
      tenantId,
      token: bearerToken,
      nowMs: Date.now(),
    });
  if (!exactWalletSessionStatusIdentityMatches({ status, request, tenantId })) {
    return json(
      {
        ok: false,
        code: 'wallet_session_scope_mismatch',
        message: 'Wallet Session status does not match the verified Wallet Session',
      },
      { status: 403 },
    );
  }
  return json(exactWalletSessionStatusResponseBody(status, request), { status: 200 });
}

export async function handleWalletUnlockChallenge(
  ctx: FetchRouterApiContext,
): Promise<Response | null> {
  if (ctx.method !== 'POST' || ctx.pathname !== '/wallet/unlock/challenge') return null;
  const body = walletUnlockBodyWithAuthoritativeOrgId(
    await readJson(ctx.request),
    ctx.service.authorizedOperations.tenantId,
  );
  const authorityError = await validateWalletUnlockEmailOtpChallengeAuthority(ctx, body);
  if (authorityError) return authorityError;
  const response = await handleWalletUnlockChallengeRoute({
    body,
    service: ctx.service.walletUnlock,
  });
  return json(response.body, { status: response.status });
}

function walletUnlockBodyWithAuthoritativeOrgId(body: unknown, orgId: string): unknown {
  if (!body || typeof body !== 'object' || Array.isArray(body)) return body;
  return { ...body, orgId };
}

async function validateWalletUnlockEmailOtpChallengeAuthority(
  ctx: FetchRouterApiContext,
  body: unknown,
): Promise<Response | null> {
  if (!isPlainObject(body) || body.unlockBackend !== EMAIL_OTP_CHANNEL) return null;

  const walletId = parseWalletId(body.walletId);
  const walletAuthMethodId = parseWalletAuthMethodId(body.walletAuthMethodId);
  if (!walletId.ok) {
    return json(
      {
        ok: false,
        code: 'invalid_body',
        message: walletId.error.message,
      },
      { status: 400 },
    );
  }
  if (!walletAuthMethodId.ok) {
    return json(
      {
        ok: false,
        code: 'invalid_body',
        message: `walletAuthMethodId ${walletAuthMethodId.error.message}`,
      },
      { status: 400 },
    );
  }

  const orgId = ctx.service.authorizedOperations.tenantId;
  const enrollment = await ctx.service.emailOtp.readActiveEmailOtpEnrollment({
    walletId: walletId.value,
    orgId,
  });
  if (!enrollment.ok) {
    return json(enrollment, { status: emailOtpStatusCode(enrollment.code) });
  }

  const authority = await ctx.service.walletUnlock.resolveEmailOtpAuthorityForUnlock({
    walletId: walletId.value,
    orgId,
    walletAuthMethodId: walletAuthMethodId.value,
    providerUserId: enrollment.enrollment.providerUserId,
  });
  if (authority.kind === 'rejected') {
    return json(
      { ok: false, code: authority.code, message: authority.message },
      { status: authority.code === 'internal' ? 500 : 403 },
    );
  }
  return null;
}

export async function handleWalletEmailOtpChallenge(
  ctx: FetchRouterApiContext,
): Promise<Response | null> {
  if (ctx.method !== 'POST' || ctx.pathname !== '/wallet/email-otp/challenge') return null;
  const origin = ctx.request.headers.get('origin');
  let requestOrigin: SessionOrigin;
  let request: ParsedWalletEmailOtpChallengeRequest;
  try {
    requestOrigin = parseSessionOrigin(origin);
    request = parseWalletEmailOtpChallengeRequest(await readJson(ctx.request));
  } catch (error: unknown) {
    return json(
      {
        ok: false,
        code: 'invalid_body',
        message: error instanceof Error ? error.message : 'Email OTP challenge request is invalid',
      },
      { status: 400 },
    );
  }
  const walletId = request.walletId;
  const orgId = ctx.service.authorizedOperations.tenantId;
  const enrollment = await ctx.service.emailOtp.readActiveEmailOtpEnrollment({ walletId, orgId });
  if (!enrollment.ok) {
    return json(enrollment, { status: emailOtpStatusCode(enrollment.code) });
  }
  const authorityResolution = await resolveWalletEmailOtpChallengeAuthority({
    ctx,
    walletId,
    orgId,
    providerUserId: enrollment.enrollment.providerUserId,
    walletAuthMethodId: request.walletAuthMethodId,
  });
  if (authorityResolution.kind === 'rejected') {
    return json(
      {
        ok: false,
        code: authorityResolution.code,
        message: authorityResolution.message,
      },
      { status: 403 },
    );
  }
  const authority = authorityResolution.walletAuthAuthority;
  const signerSelection = await resolveWalletEmailOtpChallengeSignerSelection({
    ctx,
    authority: authorityResolution.authority,
  });
  if (!signerSelection.ok) {
    return json(
      { ok: false, code: signerSelection.code, message: signerSelection.message },
      { status: 500 },
    );
  }
  const ownerProofBindingDigest = await hashEmailOtpOperationBinding({
    walletId,
    providerUserId: enrollment.enrollment.providerUserId,
    orgId,
    operation: request.operation,
    requestOrigin,
    audience: requestOrigin,
    authorityRef: await walletAuthAuthorityRef({ authority }),
    ...(request.operationFingerprintDigest
      ? { operationFingerprintDigest: request.operationFingerprintDigest }
      : {}),
  });
  if (request.operation === WALLET_EMAIL_OTP_EXPORT_OPERATION) {
    const policy = await authorizeEmailOtpExportPolicy(ctx.opts, {
      operation: WALLET_EMAIL_OTP_EXPORT_OPERATION,
      phase: 'challenge',
      userId: enrollment.enrollment.providerUserId,
      walletId,
      orgId,
      ownerProofBindingDigest,
      sourceIp: resolveSourceIpFromFetchHeaders(ctx.request.headers) || undefined,
    });
    if (!policy.ok) {
      return json({ ok: false, code: policy.code, message: policy.message }, { status: 403 });
    }
  }
  const result = await ctx.service.emailOtp.createEmailOtpChallenge({
    userId: enrollment.enrollment.providerUserId,
    walletId,
    orgId,
    email: enrollment.enrollment.verifiedEmail,
    otpChannel: EMAIL_OTP_CHANNEL,
    ownerProofBindingDigest,
    clientIp: resolveSourceIpFromFetchHeaders(ctx.request.headers) || undefined,
    requestOrigin,
    operation: request.operation,
    reuseActiveChallenge: true,
  });
  if (!result.ok) {
    return json(result, { status: emailOtpStatusCode(result.code) });
  }
  return json(
    {
      ok: true,
      challenge: result.challenge,
      delivery: result.delivery,
      walletAuthMethodId: authority.bindingId,
      signerSelection: signerSelection.selection,
    },
    { status: 200 },
  );
}

type WalletEmailOtpFactorReleaseRequest = {
  readonly walletId: unknown;
  readonly workerEphemeralPublicKey65B64u: unknown;
} & (
  | { readonly kind: 'verified_grant'; readonly loginGrant: unknown }
  | { readonly kind: 'wallet_session' }
  | {
      readonly kind: 'email_otp';
      readonly walletAuthMethodId: unknown;
      readonly challengeId: unknown;
      readonly otpCode: unknown;
      readonly operation: WalletEmailOtpOperation;
    }
);

function parseWalletEmailOtpFactorReleaseRequest(
  value: unknown,
): WalletEmailOtpFactorReleaseRequest {
  if (!isPlainObject(value)) throw new Error('Expected JSON object body');
  const kind = value.kind;
  const expectedFields =
    kind === 'verified_grant'
      ? ['kind', 'loginGrant', 'walletId', 'workerEphemeralPublicKey65B64u']
      : kind === 'wallet_session'
        ? ['kind', 'walletId', 'workerEphemeralPublicKey65B64u']
        : kind === 'email_otp'
          ? [
              'challengeId',
              'kind',
              'operation',
              'otpCode',
              'walletId',
              'walletAuthMethodId',
              'workerEphemeralPublicKey65B64u',
            ].sort()
          : null;
  if (!expectedFields || Object.keys(value).sort().join(',') !== expectedFields.join(',')) {
    throw new Error('Email OTP factor release body has invalid fields');
  }
  if (kind === 'verified_grant') {
    return {
      kind,
      walletId: value.walletId,
      loginGrant: value.loginGrant,
      workerEphemeralPublicKey65B64u: value.workerEphemeralPublicKey65B64u,
    };
  }
  if (kind === 'wallet_session') {
    return {
      kind,
      walletId: value.walletId,
      workerEphemeralPublicKey65B64u: value.workerEphemeralPublicKey65B64u,
    };
  }
  const operation = parseWalletEmailOtpLoginOperation(value.operation);
  if (!operation.ok) throw new Error(operation.message);
  return {
    kind: 'email_otp',
    walletId: value.walletId,
    walletAuthMethodId: value.walletAuthMethodId,
    challengeId: value.challengeId,
    otpCode: value.otpCode,
    operation: operation.operation,
    workerEphemeralPublicKey65B64u: value.workerEphemeralPublicKey65B64u,
  };
}

function hasEd25519SigningSubject(
  context: RouterApiWalletSessionAuthorizationV2AdmissionContext,
): boolean {
  for (const subject of context.authorization.session.capabilitySubjects) {
    if (subject.kind === 'sign' && subject.keyFamily === 'ed25519') return true;
  }
  return false;
}

export async function handleWalletEmailOtpFactorRelease(
  ctx: FetchRouterApiContext,
): Promise<Response | null> {
  if (ctx.method !== 'POST' || ctx.pathname !== '/wallet/email-otp/factor-release') return null;
  let body: WalletEmailOtpFactorReleaseRequest;
  try {
    body = parseWalletEmailOtpFactorReleaseRequest(await readJson(ctx.request));
  } catch (error: unknown) {
    return json(
      {
        ok: false,
        code: 'invalid_body',
        message:
          error instanceof Error ? error.message : 'Email OTP factor release request is invalid',
      },
      { status: 400 },
    );
  }
  const walletId = parseWalletId(body.walletId);
  const orgId = parseOrgId(ctx.service.authorizedOperations.tenantId);
  const workerEphemeralPublicKey65B64u =
    typeof body.workerEphemeralPublicKey65B64u === 'string'
      ? body.workerEphemeralPublicKey65B64u.trim()
      : '';
  if (!walletId.ok || !orgId.ok || !workerEphemeralPublicKey65B64u) {
    return json(
      { ok: false, code: 'invalid_body', message: 'Email OTP factor release request is invalid' },
      { status: 400 },
    );
  }
  const enrollment = await ctx.service.emailOtp.readActiveEmailOtpEnrollment({
    walletId: walletId.value,
    orgId: orgId.value,
  });
  if (!enrollment.ok) {
    return json(enrollment, { status: emailOtpStatusCode(enrollment.code) });
  }
  const providerSubject = parseProviderSubject(enrollment.enrollment.providerUserId);
  if (!providerSubject.ok) {
    return json(
      { ok: false, code: 'scope_mismatch', message: 'Email OTP enrollment identity is invalid' },
      { status: 403 },
    );
  }
  let factorReleaseChallengeId: string;
  if (body.kind === 'wallet_session') {
    const token = extractBearerCredential(ctx.request.headers);
    const exact = token
      ? await ctx.service.authorizationSessions.readWalletSessionAuthorizationV2ByOperationCredential(
          {
            tenantId: ctx.service.authorizationSessions.tenantId,
            token,
            nowMs: Date.now(),
          },
        )
      : null;
    const enrollmentEmailHashHex = await sha256HexUtf8(enrollment.enrollment.verifiedEmail);
    if (
      !exact ||
      exact.authorization.session.walletId !== walletId.value ||
      exact.authMethod.kind !== 'email_otp' ||
      exact.authMethod.emailHashHex !== enrollmentEmailHashHex ||
      !hasEd25519SigningSubject(exact)
    ) {
      return json(
        { ok: false, code: 'unauthorized', message: 'No valid Email OTP Wallet Session' },
        { status: 401 },
      );
    }
    factorReleaseChallengeId = `wallet-session:${exact.authorization.session.walletSessionId}`;
  } else {
    let loginGrant: string;
    if (body.kind === 'verified_grant') {
      loginGrant = typeof body.loginGrant === 'string' ? body.loginGrant.trim() : '';
    } else {
      const challengeId = typeof body.challengeId === 'string' ? body.challengeId.trim() : '';
      const otpCode = typeof body.otpCode === 'string' ? body.otpCode.trim() : '';
      if (!challengeId || !otpCode) {
        return json(
          { ok: false, code: 'invalid_body', message: 'Email OTP verification is invalid' },
          { status: 400 },
        );
      }
      const origin = requestOrigin(ctx.request);
      const walletAuthMethodId = parseWalletAuthMethodId(body.walletAuthMethodId);
      if (!walletAuthMethodId.ok) {
        return json(
          { ok: false, code: 'invalid_body', message: 'walletAuthMethodId is invalid' },
          { status: 400 },
        );
      }
      const authority = await ctx.service.walletUnlock.resolveEmailOtpAuthorityForUnlock({
        walletId: walletId.value,
        orgId: orgId.value,
        walletAuthMethodId: walletAuthMethodId.value,
        providerUserId: enrollment.enrollment.providerUserId,
      });
      if (authority.kind === 'rejected') {
        return json(
          { ok: false, code: authority.code, message: authority.message },
          { status: authority.code === 'internal' ? 500 : 403 },
        );
      }
      const ownerProofBindingDigest = await hashEmailOtpOperationBinding({
        walletId: walletId.value,
        providerUserId: enrollment.enrollment.providerUserId,
        orgId: orgId.value,
        operation: body.operation,
        requestOrigin: origin,
        audience: origin,
        authorityRef: await walletAuthAuthorityRef({ authority: authority.walletAuthAuthority }),
      });
      const verified = await ctx.service.emailOtp.verifyEmailOtpChallenge({
        userId: enrollment.enrollment.providerUserId,
        walletId: String(walletId.value),
        orgId: orgId.value,
        challengeId,
        otpCode,
        otpChannel: EMAIL_OTP_CHANNEL,
        ownerProofBindingDigest,
        operation: body.operation,
      });
      if (!verified.ok) return json(verified, { status: emailOtpStatusCode(verified.code) });
      loginGrant = verified.loginGrant;
    }
    if (!loginGrant) {
      return json(
        { ok: false, code: 'invalid_body', message: 'Email OTP factor release grant is required' },
        { status: 400 },
      );
    }
    const consumed = await ctx.service.emailOtp.consumeEmailOtpGrant({
      subject: {
        kind: 'provider_identity',
        orgId: orgId.value,
        providerSubject: providerSubject.value,
        walletId: walletId.value,
      },
      loginGrant,
      otpChannel: EMAIL_OTP_CHANNEL,
      clientIp: resolveSourceIpFromFetchHeaders(ctx.request.headers) || undefined,
    });
    if (!consumed.ok) {
      return json(consumed, { status: emailOtpStatusCode(consumed.code) });
    }
    factorReleaseChallengeId = consumed.challengeId;
  }
  const unsealed = await ctx.service.emailOtp.removeEmailOtpServerSeal({
    wrappedCiphertext: enrollment.enrollment.serverSealedFactorCiphertextB64u,
  });
  if (!unsealed.ok) {
    return json(unsealed, { status: emailOtpStatusCode(unsealed.code) });
  }
  if (unsealed.enrollmentSealKeyVersion !== enrollment.enrollment.enrollmentSealKeyVersion) {
    return json(
      {
        ok: false,
        code: 'scope_mismatch',
        message: 'Email OTP factor release seal key version changed',
      },
      { status: 409 },
    );
  }
  const sealed = await sealEmailOtpFactorSecretForWorker({
    factorSecret32B64u: unsealed.ciphertext,
    workerEphemeralPublicKey65B64u,
    walletId: String(walletId.value),
    enrollmentId: enrollment.enrollment.enrollmentId,
    enrollmentSealKeyVersion: enrollment.enrollment.enrollmentSealKeyVersion,
    challengeId: factorReleaseChallengeId,
  });
  if (!sealed.ok) {
    return json(sealed, { status: emailOtpStatusCode(sealed.code) });
  }
  return json(
    {
      ok: true,
      kind: 'email_otp_factor_release_v1',
      challengeId: factorReleaseChallengeId,
      enrollmentId: enrollment.enrollment.enrollmentId,
      enrollmentSealKeyVersion: enrollment.enrollment.enrollmentSealKeyVersion,
      serverEphemeralPublicKey65B64u: sealed.serverEphemeralPublicKey65B64u,
      nonce12B64u: sealed.nonce12B64u,
      ciphertextB64u: sealed.ciphertextB64u,
    },
    { status: 200 },
  );
}

export async function handleWalletUnlockVerify(
  ctx: FetchRouterApiContext,
): Promise<Response | null> {
  if (ctx.method !== 'POST' || ctx.pathname !== '/wallet/unlock/verify') return null;
  const body = walletUnlockBodyWithAuthoritativeOrgId(
    await readJson(ctx.request),
    ctx.service.authorizedOperations.tenantId,
  );
  let ecdsaSession: WalletUnlockEcdsaSessionContext;
  try {
    ecdsaSession = walletUnlockEcdsaSessionContext(ctx, body);
  } catch (error: unknown) {
    return json(
      {
        ok: false,
        code: 'invalid_body',
        message:
          error instanceof Error ? error.message : 'ECDSA Wallet Session activation is invalid',
      },
      { status: 400 },
    );
  }
  const parsedRequestedCapabilities = parseWalletUnlockRequestedCapabilitiesRequest(body);
  if (!parsedRequestedCapabilities.ok) {
    return json(parsedRequestedCapabilities.body, { status: parsedRequestedCapabilities.status });
  }
  const capabilityContext: WalletUnlockCapabilityContext = parsedRequestedCapabilities.request
    ? {
        kind: 'email_otp',
        request: parsedRequestedCapabilities.request,
        provisionWalletSession: async (request, proof) =>
          await ctx.service.walletRegistration.provisionEd25519YaoWalletSession({
            ...request,
            proof,
          }),
      }
    : {
        kind: 'passkey_unlock',
        provisionWalletSession: async (request) =>
          await ctx.service.walletRegistration.provisionEd25519YaoWalletSession(request),
      };
  const response = await handleWalletUnlockVerifyRoute({
    body,
    origin: String(ctx.request.headers.get('origin') || '').trim() || undefined,
    service: ctx.service.walletUnlock,
    resolveEmailOtpCustody: async (input) => {
      const request = {
        walletId: walletIdFromString(input.walletId),
        factor: {
          kind: 'email_otp' as const,
          enrollmentId: input.enrollmentId,
          enrollmentSealKeyVersion: input.enrollmentSealKeyVersion,
        },
      };
      switch (input.kind) {
        case 'factor':
          return await ctx.service.passkeyCustody.readVerifiedFactorCustody(request);
        case 'wallet_auth_method':
          return await ctx.service.passkeyCustody.readVerifiedEmailOtpMethodCustody({
            ...request,
            walletAuthMethodId: input.walletAuthMethodId,
          });
      }
    },
    resolvePasskeyCustody: async ({ walletId, rpId, credentialIdB64u, ed25519 }) => {
      const parsedRpId = parseWebAuthnRpId(rpId);
      const parsedCredentialId = parseWebAuthnCredentialIdB64u(credentialIdB64u);
      if (!parsedRpId.ok || !parsedCredentialId.ok) {
        throw new Error('Verified passkey custody identity is invalid');
      }
      const custody = await ctx.service.passkeyCustody.readVerifiedFactorCustody({
        walletId: walletIdFromString(walletId),
        factor: {
          kind: 'passkey',
          rpId: parsedRpId.value,
          credentialIdB64u: parsedCredentialId.value,
        },
      });
      let capability: RouterAbEd25519YaoActiveCapabilityDescriptorV1 | null = null;
      if (custody.kind !== 'active') return { custody, capability };
      if (ed25519.kind === 'active') {
        const yaoRuntime = ctx.opts.routerAbEd25519YaoProduct;
        if (!yaoRuntime) throw new Error('Ed25519 Yao product is not configured');
        const resolved = await yaoRuntime.resolveActiveCapability({
          kind: 'router_ab_ed25519_yao_active_capability_lookup_v1',
          walletId,
          nearEd25519SigningKeyId: ed25519.nearEd25519SigningKeyId,
          signerSlot: ed25519.signerSlot,
          signingWorkerId: ed25519.relayerKeyId,
          participantIds: ed25519.participantIds,
        });
        if (!resolved.ok) throw new Error(resolved.message);
        capability = resolved.capability;
      }
      return { custody, capability };
    },
    capabilityContext,
    ecdsaSession,
    tenantId: ctx.service.authorizationSessions.tenantId,
    buildVerifiedOwnerProof: ctx.service.authorizedOperations.buildVerifiedOwnerProof,
    emitRouterApiWebhook: async (event) => {
      await emitRouterApiWebhookEvent({
        logger: ctx.logger,
        webhooks: ctx.opts.routerApiWebhooks,
        eventType: event.eventType,
        userId: event.userId,
        eventId: event.eventId,
        payload: event.payload,
      });
    },
    emitEmailOtpWebhook: async (event) => {
      await emitEmailOtpWebhookDescriptor(ctx, {
        descriptor: event.descriptor,
        userId: event.userId,
        ...(event.walletId ? { walletId: event.walletId } : {}),
      });
    },
  });
  return json(response.body, { status: response.status });
}

export async function handleWalletEmailOtpDevCleanupGoogleRegistration(
  ctx: FetchRouterApiContext,
): Promise<Response | null> {
  if (
    ctx.method !== 'POST' ||
    ctx.pathname !== '/wallet/email-otp/dev/cleanup-google-registration'
  ) {
    return null;
  }

  const body = await readJson(ctx.request);
  const response = await handleEmailOtpDevCleanupGoogleRegistrationRoute({
    body,
    service: routerApiEmailOtpRouteService(ctx.service),
  });
  return json(response.body, { status: response.status });
}

export async function handleWalletEmailOtpRegistrationSeal(
  ctx: FetchRouterApiContext,
): Promise<Response | null> {
  if (ctx.method !== 'POST' || ctx.pathname !== '/wallet/email-otp/registration/seal') {
    return null;
  }
  const response = await handleEmailOtpRegistrationSealRoute({
    body: await readJson(ctx.request),
    service: routerApiEmailOtpRouteService(ctx.service),
  });
  return json(response.body, { status: response.status });
}

export async function handleWalletEmailOtpDevOutbox(
  ctx: FetchRouterApiContext,
): Promise<Response | null> {
  if (ctx.method !== 'POST' || ctx.pathname !== '/wallet/email-otp/dev/otp-outbox') {
    return null;
  }
  const response = await handleEmailOtpDevOutboxRoute({
    body: await readJson(ctx.request),
    service: routerApiEmailOtpRouteService(ctx.service),
  });
  return json(response.body, { status: response.status });
}
