import { EMAIL_OTP_CHANNEL } from '@shared/utils/emailOtpDomain';
import { ROUTER_AB_ED25519_YAO_EMAIL_OTP_RECOVERY_BOOTSTRAP_KIND_V1 } from '@shared/utils/routerAbEd25519Yao';
import type { WalletRegistrationEd25519YaoBootstrapSession } from '../../../core/registrationContracts';
import { thresholdEd25519StatusCode } from '../../../threshold/statusCodes';
import type {
  RouterApiWalletRegistrationService,
  RouterApiWalletUnlockService,
  RouterApiPasskeyCustodyService,
} from '../../framework/authServicePort';
import { parseWalletUnlockBackend } from '../emailOtp/emailOtpRequestValidation';
import {
  emailOtpFailureWebhookEventDescriptors,
  emailOtpLoggedInWebhookEventDescriptor,
  type EmailOtpWebhookEventDescriptor,
} from '../emailOtp/emailOtpSessionRouteHelpers';
import type { RouterAbEd25519YaoActiveCapabilityDescriptorV1 } from '../ed25519Yao/recovery/routerAbEd25519YaoRecovery';
import type { RouterAbEcdsaPostRegistrationSessionActivationResponseV1 } from '@shared/utils/routerAbEcdsaDerivation';
import type { PasskeyCustodyEnvelopeRecord } from '@shared/passkey-custody';
import type { WalletRecoveryPreparationKeyManifestV1 } from '../../cloudflare/d1/passkeyCustody/walletRecoveryKeyManifest';
import type {
  WalletUnlockEmailOtpRequestedCapabilitiesRequestV1,
  WalletUnlockEmailOtpRequestedCapabilitiesV1,
} from './walletUnlockRequestedCapabilitiesValidation';

export type WalletUnlockRouteResponse = {
  status: number;
  body: Record<string, unknown>;
};

export type EmitWalletUnlockRouterApiWebhook = (input: {
  eventType: string;
  userId?: string;
  eventId?: string;
  payload: Record<string, unknown>;
}) => Promise<void>;

export type EmitWalletUnlockEmailOtpWebhook = (input: {
  descriptor: EmailOtpWebhookEventDescriptor;
  userId: string;
  walletId?: string;
}) => Promise<void>;

type WalletUnlockProvisionedCapabilityMaterialV1 = {
  readonly session: WalletRegistrationEd25519YaoBootstrapSession;
  readonly capability: RouterAbEd25519YaoActiveCapabilityDescriptorV1;
};

export type WalletUnlockProvisionedCapabilityV1 =
  | (WalletUnlockProvisionedCapabilityMaterialV1 & {
      readonly kind: typeof ROUTER_AB_ED25519_YAO_EMAIL_OTP_RECOVERY_BOOTSTRAP_KIND_V1;
    });

export type WalletUnlockCapabilityContext =
  | { readonly kind: 'passkey_unlock' }
  | {
      readonly kind: 'email_otp';
      readonly request: WalletUnlockEmailOtpRequestedCapabilitiesRequestV1;
      readonly provisionWalletSession: (
        input: Omit<
          Parameters<RouterApiWalletRegistrationService['provisionEd25519YaoWalletSession']>[0],
          'seamsSessionId'
        >,
      ) => ReturnType<RouterApiWalletRegistrationService['provisionEd25519YaoWalletSession']>;
    };

type WalletUnlockEd25519YaoRequestedContext = Extract<
  WalletUnlockCapabilityContext,
  { readonly kind: 'email_otp' }
> & {
  readonly request: Omit<
    WalletUnlockEmailOtpRequestedCapabilitiesRequestV1,
    'requestedCapabilities'
  > & {
    readonly requestedCapabilities: Extract<
      WalletUnlockEmailOtpRequestedCapabilitiesV1,
      { readonly kind: 'ed25519_yao' }
    >;
  };
};

function isWalletUnlockEd25519YaoRequestedContext(
  context: WalletUnlockCapabilityContext,
): context is WalletUnlockEd25519YaoRequestedContext {
  return context.kind === 'email_otp' && context.request.requestedCapabilities.kind === 'ed25519_yao';
}

export type WalletUnlockEcdsaSessionContext =
  | { readonly kind: 'no_ecdsa_session' }
  | {
      readonly kind: 'provision_first_ecdsa_session';
      readonly walletId: string;
      readonly provisionWalletSession: (input: WalletUnlockEcdsaAuthorization) => Promise<
        | {
            readonly ok: true;
            readonly activation: RouterAbEcdsaPostRegistrationSessionActivationResponseV1;
          }
        | {
            readonly ok: false;
            readonly status: number;
            readonly code: string;
            readonly message: string;
          }
      >;
    };

export type WalletUnlockEcdsaAuthorization =
  | {
      readonly kind: 'verified_wallet_unlock';
      readonly verifiedProviderUserId?: string;
    }
  | {
      readonly kind: 'reuse_ed25519_wallet_session';
      readonly walletSessionJwt: string;
    };

export type WalletUnlockEmailOtpCustodyProjectionV1 = {
  readonly kind: 'wallet_custody_email_otp_unlock_v1';
  readonly walletId: string;
  readonly enrollmentId: string;
  readonly enrollmentSealKeyVersion: string;
  readonly envelopeId: PasskeyCustodyEnvelopeRecord['envelopeId'];
  readonly envelopeVersion: PasskeyCustodyEnvelopeRecord['envelopeVersion'];
  readonly envelopeRevision: number;
  readonly storeVersion: string;
  readonly activeKeySetIds: readonly string[];
  readonly keyManifest: WalletRecoveryPreparationKeyManifestV1;
  readonly envelope: PasskeyCustodyEnvelopeRecord;
};

type VerifiedEmailOtpUnlockResult = Extract<
  Awaited<ReturnType<RouterApiWalletUnlockService['verifyEmailOtpUnlockProof']>>,
  { readonly ok: true }
>;

type WalletUnlockEmailOtpCustodyLookup = Awaited<
  ReturnType<RouterApiPasskeyCustodyService['readVerifiedFactorCustody']>
>;

type WalletUnlockProvisionedCapabilityResult =
  | { readonly ok: true; readonly value: WalletUnlockProvisionedCapabilityV1 }
  | { readonly ok: false; readonly response: WalletUnlockRouteResponse };

type WalletUnlockEcdsaSessionResult =
  | {
      readonly ok: true;
      readonly activation: RouterAbEcdsaPostRegistrationSessionActivationResponseV1 | null;
    }
  | { readonly ok: false; readonly response: WalletUnlockRouteResponse };

type WalletUnlockEmailOtpCustodyResult =
  | { readonly ok: true; readonly projection: WalletUnlockEmailOtpCustodyProjectionV1 }
  | { readonly ok: false; readonly response: WalletUnlockRouteResponse };

function emailOtpCustodyFailureResponse(
  lookup: Exclude<
    WalletUnlockEmailOtpCustodyLookup,
    Extract<WalletUnlockEmailOtpCustodyLookup, { readonly kind: 'active' }>
  >,
): WalletUnlockEmailOtpCustodyResult {
  const status =
    lookup.kind === 'manifest_unavailable'
      ? 503
      : lookup.kind === 'conflict'
        ? 409
        : lookup.kind === 'missing'
          ? 404
          : 409;
  return {
    ok: false,
    response: {
      status,
      body: {
        ok: false,
        code:
          lookup.kind === 'manifest_unavailable'
            ? 'custody_manifest_unavailable'
            : 'custody_envelope_unavailable',
        message: 'Email OTP wallet custody is unavailable',
      },
    },
  };
}

function projectEmailOtpCustody(
  verifiedUnlock: VerifiedEmailOtpUnlockResult,
  lookup: WalletUnlockEmailOtpCustodyLookup,
): WalletUnlockEmailOtpCustodyResult {
  if (lookup.kind !== 'active') return emailOtpCustodyFailureResponse(lookup);
  const envelope = lookup.envelope;
  const manifest = lookup.keyManifest;
  const factor = envelope.factor;
  const envelopeRevision = Number(envelope.envelopeRevision);
  const activeKeySetIds = manifest.entries.map((entry) => entry.keySetId);
  if (
    envelope.lifecycle.state !== 'active' ||
    String(envelope.walletId) !== verifiedUnlock.walletId ||
    factor.kind !== 'email_otp' ||
    !verifiedUnlock.enrollmentId.trim() ||
    !verifiedUnlock.enrollmentSealKeyVersion.trim() ||
    factor.enrollmentId !== verifiedUnlock.enrollmentId ||
    factor.enrollmentSealKeyVersion !== verifiedUnlock.enrollmentSealKeyVersion ||
    String(manifest.walletId) !== verifiedUnlock.walletId ||
    manifest.version !== 'wallet_recovery_preparation_key_manifest_v1' ||
    !Number.isSafeInteger(envelopeRevision) ||
    envelopeRevision < 1 ||
    activeKeySetIds.length === 0 ||
    activeKeySetIds.some((keySetId) => !String(keySetId).trim()) ||
    new Set(activeKeySetIds).size !== activeKeySetIds.length ||
    !String(lookup.storeVersion).trim()
  ) {
    return {
      ok: false,
      response: {
        status: 500,
        body: {
          ok: false,
          code: 'custody_binding_mismatch',
          message: 'Email OTP wallet custody binding is invalid',
        },
      },
    };
  }
  return {
    ok: true,
    projection: {
      kind: 'wallet_custody_email_otp_unlock_v1',
      walletId: verifiedUnlock.walletId,
      enrollmentId: verifiedUnlock.enrollmentId,
      enrollmentSealKeyVersion: verifiedUnlock.enrollmentSealKeyVersion,
      envelopeId: envelope.envelopeId,
      envelopeVersion: envelope.envelopeVersion,
      envelopeRevision,
      storeVersion: lookup.storeVersion,
      activeKeySetIds,
      keyManifest: manifest,
      envelope,
    },
  };
}

async function provisionFirstEcdsaWalletSession(input: {
  readonly context: WalletUnlockEcdsaSessionContext;
  readonly verifiedWalletId: string;
  readonly authorization: WalletUnlockEcdsaAuthorization;
}): Promise<WalletUnlockEcdsaSessionResult> {
  switch (input.context.kind) {
    case 'no_ecdsa_session':
      return { ok: true, activation: null };
    case 'provision_first_ecdsa_session': {
      if (input.context.walletId !== input.verifiedWalletId) {
        return {
          ok: false,
          response: {
            status: 403,
            body: {
              ok: false,
              code: 'scope_mismatch',
              message: 'Wallet unlock proof does not match the requested ECDSA wallet',
            },
          },
        };
      }
      const provisioned = await input.context.provisionWalletSession(input.authorization);
      if (!provisioned.ok) {
        return {
          ok: false,
          response: {
            status: provisioned.status,
            body: {
              ok: false,
              code: provisioned.code,
              message: provisioned.message,
            },
          },
        };
      }
      return { ok: true, activation: provisioned.activation };
    }
  }
}

function walletUnlockScopeMismatchResponse(): WalletUnlockProvisionedCapabilityResult {
  return {
    ok: false,
    response: {
      status: 403,
      body: {
        ok: false,
        code: 'scope_mismatch',
        message: 'Email OTP unlock proof does not match the requested Ed25519 wallet',
      },
    },
  };
}

function walletUnlockSessionFailureResponse(input: {
  readonly result: { readonly ok: false; readonly code: string; readonly message: string };
}): WalletUnlockProvisionedCapabilityResult {
  return {
    ok: false,
    response: {
      status: thresholdEd25519StatusCode(input.result),
      body: input.result,
    },
  };
}

async function provisionEmailOtpEd25519YaoCapability(input: {
  readonly context: WalletUnlockEd25519YaoRequestedContext;
  readonly verifiedUnlock: VerifiedEmailOtpUnlockResult;
}): Promise<WalletUnlockProvisionedCapabilityResult> {
  const request = input.context.request;
  if (
    input.verifiedUnlock.walletId !== request.walletId ||
    input.verifiedUnlock.orgId !== request.orgId
  ) {
    return walletUnlockScopeMismatchResponse();
  }

  const capabilities = request.requestedCapabilities;
  if (capabilities.kind !== 'ed25519_yao') {
    throw new Error('Ed25519 Yao unlock requires its requested capability');
  }

  const provisioned = await input.context.provisionWalletSession({
    walletId: request.walletId,
    orgId: request.orgId,
    signerSlot: capabilities.signerSlot,
    remainingUses: capabilities.remainingUses,
    verifiedChallengeId: request.challengeId,
    verifiedProviderUserId: input.verifiedUnlock.providerUserId,
  });
  if (!provisioned.ok) return walletUnlockSessionFailureResponse({ result: provisioned });
  return {
    ok: true,
    value: {
      kind: ROUTER_AB_ED25519_YAO_EMAIL_OTP_RECOVERY_BOOTSTRAP_KIND_V1,
      session: provisioned.session,
      capability: provisioned.capability,
    },
  };
}

export async function handleWalletUnlockChallengeRoute(input: {
  body: unknown;
  service: RouterApiWalletUnlockService;
}): Promise<WalletUnlockRouteResponse> {
  if (!input.body || typeof input.body !== 'object' || Array.isArray(input.body)) {
    return {
      status: 400,
      body: { ok: false, code: 'invalid_body', message: 'Request body is required' },
    };
  }
  const body = input.body as Record<string, unknown>;
  const unlockBackend = parseWalletUnlockBackend(body.unlockBackend);
  if (!unlockBackend) {
    return {
      status: 400,
      body: { ok: false, code: 'invalid_body', message: 'unlockBackend is required' },
    };
  }

  const result =
    unlockBackend === 'passkey'
      ? await input.service.createWebAuthnLoginOptions({
          userId: body.userId,
          rpId: body.rpId,
          ttlMs: body.ttlMs,
        })
      : await input.service.createEmailOtpUnlockChallenge({
          walletId: body.walletId,
          orgId: body.orgId,
          ttlMs: body.ttlMs,
        });

  return {
    status: result.ok ? 200 : result.code === 'internal' ? 500 : 400,
    body: {
      ...result,
      unlockBackend,
    },
  };
}

async function verifyPasskeyWalletUnlock(input: {
  readonly body: Record<string, unknown>;
  readonly challengeId: string;
  readonly origin: string | undefined;
  readonly service: RouterApiWalletUnlockService;
}) {
  if (!input.body.webauthn_authentication || typeof input.body.webauthn_authentication !== 'object') {
    return {
      ok: false,
      verified: false,
      code: 'invalid_body',
      message: 'webauthn_authentication is required',
    } as const;
  }
  return await input.service.verifyWebAuthnLogin({
    challengeId: input.challengeId,
    webauthn_authentication: input.body.webauthn_authentication,
    expected_origin: input.origin,
  });
}

async function emitEmailOtpUnlockFailure(input: {
  readonly body: Record<string, unknown>;
  readonly challengeId: string;
  readonly code: string;
  readonly message: string;
  readonly emitEmailOtpWebhook: EmitWalletUnlockEmailOtpWebhook;
}): Promise<void> {
  const walletId = String(input.body.walletId || '').trim();
  if (!walletId) return;
  for (const descriptor of emailOtpFailureWebhookEventDescriptors({
    source: 'unlock_verify',
    code: input.code,
    message: input.message,
    challengeId: input.challengeId,
  })) {
    await input.emitEmailOtpWebhook({ descriptor, userId: walletId, walletId });
  }
}

async function emitSuccessfulWalletUnlock(input: {
  readonly unlockBackend: 'passkey' | typeof EMAIL_OTP_CHANNEL;
  readonly challengeId: string;
  readonly userId: string;
  readonly walletId: string;
  readonly emitRouterApiWebhook: EmitWalletUnlockRouterApiWebhook;
  readonly emitEmailOtpWebhook: EmitWalletUnlockEmailOtpWebhook;
}): Promise<void> {
  await input.emitRouterApiWebhook({
    eventType: 'wallet.unlocked',
    userId: input.userId,
    eventId: input.challengeId,
    payload: {
      unlocked: true,
      unlockBackend: input.unlockBackend,
      challengeId: input.challengeId,
    },
  });
  if (input.unlockBackend !== EMAIL_OTP_CHANNEL) return;
  await input.emitEmailOtpWebhook({
    descriptor: emailOtpLoggedInWebhookEventDescriptor({
      challengeId: input.challengeId,
      otpChannel: EMAIL_OTP_CHANNEL,
      unlockBackend: EMAIL_OTP_CHANNEL,
    }),
    userId: input.userId,
    walletId: input.walletId,
  });
}

function parseOptionalEd25519WalletSessionJwt(
  body: Record<string, unknown>,
): { readonly ok: true; readonly walletSessionJwt?: string } | { readonly ok: false } {
  const raw = body.ed25519WalletSessionJwt;
  if (raw === undefined) return { ok: true };
  if (typeof raw !== 'string' || !raw.trim()) return { ok: false };
  return { ok: true, walletSessionJwt: raw.trim() };
}

export async function handleWalletUnlockVerifyRoute(input: {
  body: unknown;
  origin?: string;
  service: RouterApiWalletUnlockService;
  resolveEmailOtpCustody: (input: {
    readonly walletId: string;
    readonly enrollmentId: string;
    readonly enrollmentSealKeyVersion: string;
  }) => Promise<WalletUnlockEmailOtpCustodyLookup>;
  emitRouterApiWebhook: EmitWalletUnlockRouterApiWebhook;
  emitEmailOtpWebhook: EmitWalletUnlockEmailOtpWebhook;
  capabilityContext: WalletUnlockCapabilityContext;
  ecdsaSession: WalletUnlockEcdsaSessionContext;
}): Promise<WalletUnlockRouteResponse> {
  if (!input.body || typeof input.body !== 'object' || Array.isArray(input.body)) {
    return {
      status: 400,
      body: { ok: false, code: 'invalid_body', message: 'Request body is required' },
    };
  }
  const body = input.body as Record<string, unknown>;
  const unlockBackend = parseWalletUnlockBackend(body.unlockBackend);
  if (!unlockBackend) {
    return {
      status: 400,
      body: { ok: false, code: 'invalid_body', message: 'unlockBackend is required' },
    };
  }
  const challengeId = String(body.challengeId || '').trim();
  if (!challengeId) {
    return {
      status: 400,
      body: { ok: false, code: 'invalid_body', message: 'challengeId is required' },
    };
  }

  if (unlockBackend === 'passkey') {
    if (input.capabilityContext.kind !== 'passkey_unlock') {
      return {
        status: 400,
        body: { ok: false, code: 'invalid_body', message: 'Passkey unlock context is invalid' },
      };
    }
    const result = await verifyPasskeyWalletUnlock({
      body,
      challengeId,
      origin: input.origin,
      service: input.service,
    });
    if (!result.ok || !result.verified) {
      return {
        status: result.code === 'internal' ? 500 : 400,
        body: { ...result, unlockBackend },
      };
    }
    const userId = String(result.userId || '').trim();
    if (!userId) {
      return {
        status: 500,
        body: { ok: false, code: 'internal', message: 'Verified passkey user is missing' },
      };
    }
    const ecdsaSession = await provisionFirstEcdsaWalletSession({
      context: input.ecdsaSession,
      verifiedWalletId: userId,
      authorization: { kind: 'verified_wallet_unlock' },
    });
    if (!ecdsaSession.ok) return ecdsaSession.response;
    await input.service.markEmailOtpStrongAuthSatisfied({ walletId: userId });
    await emitSuccessfulWalletUnlock({
      unlockBackend,
      challengeId,
      userId,
      walletId: userId,
      emitRouterApiWebhook: input.emitRouterApiWebhook,
      emitEmailOtpWebhook: input.emitEmailOtpWebhook,
    });
    return {
      status: 200,
      body: {
        ok: true,
        unlocked: true,
        unlockBackend,
        userId,
        ...(ecdsaSession.activation ? { ecdsaSession: ecdsaSession.activation } : {}),
      },
    };
  }

  if (input.capabilityContext.kind === 'passkey_unlock') {
    return {
      status: 400,
      body: { ok: false, code: 'invalid_body', message: 'Email OTP unlock context is invalid' },
    };
  }
  const reuseEd25519WalletSession = parseOptionalEd25519WalletSessionJwt(body);
  if (!reuseEd25519WalletSession.ok) {
    return {
      status: 400,
      body: {
        ok: false,
        code: 'invalid_body',
        message: 'ed25519WalletSessionJwt must be a non-empty string when provided',
      },
    };
  }
  const result = await input.service.verifyEmailOtpUnlockProof({
    walletId: body.walletId,
    orgId: body.orgId,
    challengeId,
    unlockProof: body.unlockProof,
  });
  if (!result.ok || !result.verified) {
    await emitEmailOtpUnlockFailure({
      body,
      challengeId,
      code: String(result.code || 'unlock_verify_failed'),
      message: String(result.message || 'Email OTP unlock verification failed'),
      emitEmailOtpWebhook: input.emitEmailOtpWebhook,
    });
    return {
      status: result.code === 'internal' ? 500 : 400,
      body: { ...result, unlockBackend },
    };
  }

  const emailOtpCustody = projectEmailOtpCustody(
    result,
    await input.resolveEmailOtpCustody({
      walletId: result.walletId,
      enrollmentId: result.enrollmentId,
      enrollmentSealKeyVersion: result.enrollmentSealKeyVersion,
    }),
  );
  if (!emailOtpCustody.ok) return emailOtpCustody.response;

  if (
    input.capabilityContext.kind === 'email_otp' &&
    input.capabilityContext.request.requestedCapabilities.kind === 'none'
  ) {
    const ecdsaSession = await provisionFirstEcdsaWalletSession({
      context: input.ecdsaSession,
      verifiedWalletId: result.walletId,
      authorization: reuseEd25519WalletSession.walletSessionJwt
        ? {
            kind: 'reuse_ed25519_wallet_session',
            walletSessionJwt: reuseEd25519WalletSession.walletSessionJwt,
          }
        : {
            kind: 'verified_wallet_unlock',
            verifiedProviderUserId: result.providerUserId,
          },
    });
    if (!ecdsaSession.ok) return ecdsaSession.response;
    await emitSuccessfulWalletUnlock({
      unlockBackend,
      challengeId,
      userId: result.userId,
      walletId: result.walletId,
      emitRouterApiWebhook: input.emitRouterApiWebhook,
      emitEmailOtpWebhook: input.emitEmailOtpWebhook,
    });
    return {
      status: 200,
      body: {
        ok: true,
        unlocked: true,
        unlockBackend,
        userId: result.userId,
        walletCustody: emailOtpCustody.projection,
        ...(ecdsaSession.activation ? { ecdsaSession: ecdsaSession.activation } : {}),
      },
    };
  }
  if (!isWalletUnlockEd25519YaoRequestedContext(input.capabilityContext)) {
    return {
      status: 400,
      body: { ok: false, code: 'invalid_body', message: 'Email OTP capability context is invalid' },
    };
  }
  const capabilityResult = await provisionEmailOtpEd25519YaoCapability({
    context: input.capabilityContext,
    verifiedUnlock: result,
  });
  if (!capabilityResult.ok) return capabilityResult.response;
  const ecdsaSession = await provisionFirstEcdsaWalletSession({
    context: input.ecdsaSession,
    verifiedWalletId: result.walletId,
    authorization: {
      kind: 'reuse_ed25519_wallet_session',
      walletSessionJwt: capabilityResult.value.session.walletSessionJwt,
    },
  });
  if (!ecdsaSession.ok) return ecdsaSession.response;
  await emitSuccessfulWalletUnlock({
    unlockBackend,
    challengeId,
    userId: result.userId,
    walletId: result.walletId,
    emitRouterApiWebhook: input.emitRouterApiWebhook,
    emitEmailOtpWebhook: input.emitEmailOtpWebhook,
  });
  return {
    status: 200,
    body: {
      ok: true,
      unlocked: true,
      unlockBackend,
      userId: result.userId,
      walletCustody: emailOtpCustody.projection,
      ed25519YaoCapability: capabilityResult.value,
      ...(ecdsaSession.activation ? { ecdsaSession: ecdsaSession.activation } : {}),
    },
  };
}
