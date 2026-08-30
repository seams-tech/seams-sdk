import { EMAIL_OTP_CHANNEL } from '@shared/utils/emailOtpDomain';
import {
  parseAuthFactorId,
  parsePrincipalId,
  type TenantId,
} from '@shared/authorization/capabilityKinds';
import { parseDigestB64u, type DigestB64u } from '@shared/utils/canonicalPrimitives';
import { alphabetizeStringify, sha256BytesUtf8 } from '@shared/utils/digests';
import { base64UrlEncode } from '@shared/utils/encoders';
import {
  parseSessionOrigin,
  parseVerifiedOwnerProofId,
  projectActiveWalletSession,
  type VerifiedOwnerProof,
} from '../../../authorization/domain';
import {
  parseEmailOtpChallengeId,
  parseWalletAuthMethodId,
  parseWalletAuthorityId,
  parseWalletId,
  parseWebAuthnCredentialIdB64u,
  parseWebAuthnRpId,
  type WalletAuthMethodId,
} from '@shared/utils/domainIds';
import {
  buildVerifiedWalletSessionEmailOtpFactorResult,
  buildVerifiedWalletSessionPasskeyFactorResult,
  type VerifiedWalletSessionFactorResult,
} from '../../../authorization/factorEvidence';
import {
  walletAuthAuthorityRef,
  type PasskeyWalletAuthAuthority,
  type WalletAuthAuthority,
} from '@shared/utils/walletAuthAuthority';
import { ROUTER_AB_ED25519_YAO_EMAIL_OTP_RECOVERY_BOOTSTRAP_KIND_V1 } from '@shared/utils/routerAbEd25519Yao';
import type {
  DirectV2IssueResult,
  IssuedWalletSessionAuthorizationV2,
} from '../../../authorization/domain';
import type { WalletSessionOperationCredentialV1 } from '@shared/device-linking/contracts';
import type { WalletRegistrationEd25519YaoBootstrapSession } from '../../../core/registrationContracts';
import { thresholdEd25519StatusCode } from '../../../threshold/statusCodes';
import type {
  RouterApiWalletRegistrationService,
  RouterApiWalletUnlockService,
  RouterApiPasskeyCustodyService,
  RouterApiAuthorizedOperationService,
  WalletUnlockIssuanceRejectionCode,
} from '../../framework/authServicePort';
import { parseWalletUnlockBackend } from '../emailOtp/emailOtpRequestValidation';
import {
  emailOtpFailureWebhookEventDescriptors,
  emailOtpLoggedInWebhookEventDescriptor,
  type EmailOtpWebhookEventDescriptor,
} from '../emailOtp/emailOtpSessionRouteHelpers';
import type { RouterAbEd25519YaoActiveCapabilityDescriptorV1 } from '../ed25519Yao/recovery/routerAbEd25519YaoRecovery';
import type {
  RouterAbEcdsaCredentialFreeSessionActivationResponseV1,
  RouterAbEcdsaPostRegistrationSessionActivationResponseV1,
  RouterAbEcdsaRegistrationActivationReceiptV1,
  RouterAbEcdsaPostRegistrationSessionActivationPolicyV1,
} from '@shared/utils/routerAbEcdsaDerivation';
import type { WalletEcdsaSignerRecord } from '../../../core/WalletStore';
import type { PasskeyCustodyEnvelopeRecord } from '@shared/passkey-custody';
import type { WalletUnlockKeyManifestV1 } from '../passkeyCustody/walletRecoveryKeyManifest';
import type {
  WalletUnlockEmailOtpRequestedCapabilitiesRequestV1,
  WalletUnlockEmailOtpRequestedCapabilitiesV1,
} from './walletUnlockRequestedCapabilitiesValidation';

export type WalletUnlockRouteResponse = {
  status: number;
  body: Record<string, unknown>;
};

export type WalletUnlockAlreadyCommittedRouteBody = {
  readonly ok: false;
  readonly unlocked: false;
  readonly unlockBackend: 'passkey' | typeof EMAIL_OTP_CHANNEL;
  readonly code: 'already_committed';
  readonly message: 'Wallet Session unlock is already committed; retry the exact method';
} & Extract<DirectV2IssueResult, { readonly kind: 'already_committed' }>;

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

export type WalletUnlockProvisionedCapabilityV1 = WalletUnlockProvisionedCapabilityMaterialV1 & {
  readonly kind: typeof ROUTER_AB_ED25519_YAO_EMAIL_OTP_RECOVERY_BOOTSTRAP_KIND_V1;
};

export type WalletUnlockCapabilityContext =
  | {
      readonly kind: 'passkey_unlock';
      readonly provisionWalletSession: (
        input: Parameters<
          RouterApiWalletRegistrationService['provisionEd25519YaoWalletSession']
        >[0],
      ) => ReturnType<RouterApiWalletRegistrationService['provisionEd25519YaoWalletSession']>;
    }
  | {
      readonly kind: 'email_otp';
      readonly request: WalletUnlockEmailOtpRequestedCapabilitiesRequestV1;
      readonly provisionWalletSession: (
        input: Omit<
          Parameters<RouterApiWalletRegistrationService['provisionEd25519YaoWalletSession']>[0],
          'proof'
        >,
        proof: WalletSessionOwnerProof,
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
  return (
    context.kind === 'email_otp' && context.request.requestedCapabilities.kind === 'ed25519_yao'
  );
}

type WalletUnlockEcdsaSessionActivation =
  | RouterAbEcdsaPostRegistrationSessionActivationResponseV1
  | RouterAbEcdsaCredentialFreeSessionActivationResponseV1;

export type WalletUnlockEcdsaSessionContext =
  | { readonly kind: 'no_ecdsa_session' }
  | {
      readonly kind: 'provision_first_ecdsa_session';
      readonly walletId: string;
      readonly policy: RouterAbEcdsaPostRegistrationSessionActivationPolicyV1;
      readonly provisionWalletSession: (input: WalletUnlockEcdsaAuthorization) => Promise<
        | {
            readonly ok: true;
            readonly activation: WalletUnlockEcdsaSessionActivation;
            readonly activationReceipt: RouterAbEcdsaRegistrationActivationReceiptV1;
            readonly continuity: WalletUnlockEcdsaCustodyContinuityV1;
          }
        | {
            readonly ok: false;
            readonly status: number;
            readonly code: string;
            readonly message: string;
          }
      >;
    };

export type WalletUnlockEcdsaCustodySignerV1 = {
  readonly chainTarget: WalletEcdsaSignerRecord['chainTarget'];
  readonly walletKey: Pick<
    WalletEcdsaSignerRecord['walletKey'],
    | 'walletId'
    | 'keyHandle'
    | 'ecdsaThresholdKeyId'
    | 'signingRootId'
    | 'signingRootVersion'
    | 'relayerKeyId'
    | 'contextBinding32B64u'
    | 'derivationClientSharePublicKey33B64u'
    | 'participantIds'
    | 'publicCapability'
  >;
  readonly activationReceipt: WalletEcdsaSignerRecord['activationReceipt'];
  readonly runtimePolicyScope: WalletEcdsaSignerRecord['runtimePolicyScope'];
};

export type WalletUnlockEcdsaCustodyContinuityV1 = {
  readonly kind: 'wallet_custody_ecdsa_sync_continuity_v1';
  readonly signers: readonly WalletUnlockEcdsaCustodySignerV1[];
};

export type WalletUnlockEcdsaAuthorization =
  | {
      readonly kind: 'verified_wallet_unlock';
      readonly proof: WalletSessionOwnerProof;
      readonly operationCredential?: never;
    }
  | {
      readonly kind: 'wallet_session_operation_credential_v1';
      readonly operationCredential: WalletSessionOperationCredentialV1;
      readonly proof: WalletSessionOwnerProof;
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
  readonly keyManifest: WalletUnlockKeyManifestV1;
  readonly envelope: PasskeyCustodyEnvelopeRecord;
};

export type WalletUnlockPasskeyCustodyProjectionV1 = {
  readonly kind: 'wallet_custody_passkey_login_v1';
  readonly envelope: PasskeyCustodyEnvelopeRecord;
  readonly storeVersion: string;
  readonly ed25519:
    | { readonly kind: 'absent' }
    | {
        readonly kind: 'active';
        readonly nearAccountId: string;
        readonly nearEd25519SigningKeyId: string;
        readonly signerSlot: number;
        readonly publicKey: string;
        readonly relayerKeyId: string;
        readonly participantIds: readonly [number, number];
        readonly capability: RouterAbEd25519YaoActiveCapabilityDescriptorV1;
      };
};

type VerifiedEmailOtpUnlockResult = Extract<
  Awaited<ReturnType<RouterApiWalletUnlockService['verifyEmailOtpUnlockProof']>>,
  { readonly ok: true }
>;

type VerifiedEmailOtpAuthorityForUnlock = Exclude<
  Awaited<ReturnType<RouterApiWalletUnlockService['resolveEmailOtpAuthorityForUnlock']>>,
  { readonly kind: 'rejected' }
>;

type WalletUnlockEmailOtpCustodyLookup = Awaited<
  ReturnType<RouterApiPasskeyCustodyService['readVerifiedFactorCustody']>
>;

type WalletUnlockPasskeyCustodyResolution = {
  readonly custody: WalletUnlockEmailOtpCustodyLookup;
  readonly capability: RouterAbEd25519YaoActiveCapabilityDescriptorV1 | null;
};

type WalletUnlockProvisionedCapabilityResult =
  | { readonly ok: true; readonly value: WalletUnlockProvisionedCapabilityV1 }
  | { readonly ok: false; readonly response: WalletUnlockRouteResponse };

type WalletUnlockEcdsaSessionResult =
  | {
      readonly ok: true;
      readonly activation: WalletUnlockEcdsaSessionActivation | null;
      readonly activationReceipt: RouterAbEcdsaRegistrationActivationReceiptV1 | null;
      readonly continuity: WalletUnlockEcdsaCustodyContinuityV1 | null;
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
    manifest.version !== 'wallet_custody_unlock_key_manifest_v1' ||
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

function projectPasskeyCustody(
  verifiedUnlock: Extract<
    Awaited<ReturnType<RouterApiWalletUnlockService['verifyWebAuthnLogin']>>,
    { readonly ok: true }
  >,
  resolution: WalletUnlockPasskeyCustodyResolution,
):
  | { readonly ok: true; readonly projection: WalletUnlockPasskeyCustodyProjectionV1 }
  | { readonly ok: false; readonly response: WalletUnlockRouteResponse } {
  const lookup = resolution.custody;
  if (lookup.kind !== 'active') {
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
          message: 'Passkey wallet custody is unavailable',
        },
      },
    };
  }
  const envelope = lookup.envelope;
  const factor = envelope.factor;
  const manifest = lookup.keyManifest;
  if (
    envelope.lifecycle.state !== 'active' ||
    String(envelope.walletId) !== verifiedUnlock.userId ||
    factor.kind !== 'passkey' ||
    String(factor.rpId) !== verifiedUnlock.rpId ||
    String(factor.credentialIdB64u) !== verifiedUnlock.credentialIdB64u ||
    String(manifest.walletId) !== verifiedUnlock.userId ||
    manifest.version !== 'wallet_custody_unlock_key_manifest_v1' ||
    !String(lookup.storeVersion).trim()
  ) {
    return {
      ok: false,
      response: {
        status: 500,
        body: {
          ok: false,
          code: 'custody_binding_mismatch',
          message: 'Passkey wallet custody binding is invalid',
        },
      },
    };
  }

  let ed25519: WalletUnlockPasskeyCustodyProjectionV1['ed25519'] = { kind: 'absent' };
  if (verifiedUnlock.ed25519.kind === 'active') {
    const verifiedEd25519 = verifiedUnlock.ed25519;
    const matchingEntry = manifest.entries.find(
      (entry) =>
        entry.kind === 'near_ed25519' &&
        entry.nearEd25519SigningKeyId === verifiedEd25519.nearEd25519SigningKeyId &&
        entry.signerSlot === verifiedEd25519.signerSlot,
    );
    const capability = resolution.capability;
    if (
      !matchingEntry ||
      !capability ||
      capability.nearAccountId !== verifiedEd25519.nearAccountId ||
      capability.applicationBinding.wallet_id !== verifiedUnlock.userId ||
      capability.applicationBinding.near_ed25519_signing_key_id !==
        verifiedEd25519.nearEd25519SigningKeyId ||
      capability.applicationBinding.key_creation_signer_slot !== verifiedEd25519.signerSlot ||
      capability.participantIds[0] !== verifiedEd25519.participantIds[0] ||
      capability.participantIds[1] !== verifiedEd25519.participantIds[1]
    ) {
      return {
        ok: false,
        response: {
          status: 500,
          body: {
            ok: false,
            code: 'custody_binding_mismatch',
            message: 'Passkey Ed25519 custody binding is invalid',
          },
        },
      };
    }
    ed25519 = { ...verifiedUnlock.ed25519, capability };
  }

  return {
    ok: true,
    projection: {
      kind: 'wallet_custody_passkey_login_v1',
      envelope,
      storeVersion: lookup.storeVersion,
      ed25519,
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
      return { ok: true, activation: null, activationReceipt: null, continuity: null };
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
      return {
        ok: true,
        activation: provisioned.activation,
        activationReceipt: provisioned.activationReceipt,
        continuity: provisioned.continuity,
      };
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

/**
 * A committed Ed25519 mint cannot hand over a second credential, so the
 * rejection carries the committed identity and the exact-method continuation
 * instead of a session.
 */
function walletUnlockEd25519SessionFailureResponse(
  result: Exclude<
    Awaited<ReturnType<RouterApiWalletRegistrationService['provisionEd25519YaoWalletSession']>>,
    { readonly ok: true }
  >,
): WalletUnlockRouteResponse {
  return result.code === 'already_committed'
    ? { status: 409, body: result }
    : { status: thresholdEd25519StatusCode(result), body: result };
}

async function provisionEmailOtpEd25519YaoCapability(input: {
  readonly context: WalletUnlockEd25519YaoRequestedContext;
  readonly verifiedUnlock: VerifiedEmailOtpUnlockResult;
  readonly authorization: WalletUnlockOwnerAuthorization;
  readonly linkedWalletSession: IssuedWalletSessionAuthorizationV2 | null;
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

  const provisioned = await input.context.provisionWalletSession(
    {
      walletId: request.walletId,
      signerSlot: capabilities.signerSlot,
      remainingUses: capabilities.remainingUses,
      verifiedChallengeId: request.challengeId,
      authority: input.authorization.authority,
      walletSessionIdentity: input.linkedWalletSession
        ? {
            kind: 'reuse_wallet_session_v2',
            authorizationId: input.linkedWalletSession.session.authorizationId,
            walletSessionId: input.linkedWalletSession.session.walletSessionId,
            quotaId: input.linkedWalletSession.session.quotaId,
            expiresAtMs: input.linkedWalletSession.session.expiresAtMs,
            remainingUses: input.linkedWalletSession.quota.remainingUses,
          }
        : { kind: 'new_wallet_session' },
    },
    input.authorization.proof,
  );
  if (!provisioned.ok) {
    return { ok: false, response: walletUnlockEd25519SessionFailureResponse(provisioned) };
  }
  return {
    ok: true,
    value: {
      kind: ROUTER_AB_ED25519_YAO_EMAIL_OTP_RECOVERY_BOOTSTRAP_KIND_V1,
      session: provisioned.session,
      capability: provisioned.capability,
    },
  };
}

type PasskeyEd25519SessionRequest =
  | { readonly kind: 'not_requested' }
  | { readonly kind: 'requested'; readonly remainingUses: number };

type PasskeyEd25519SessionProvisionResult =
  | { readonly ok: true; readonly session: WalletRegistrationEd25519YaoBootstrapSession | null }
  | { readonly ok: false; readonly response: WalletUnlockRouteResponse };

function parsePasskeyEd25519SessionRequest(value: unknown): PasskeyEd25519SessionRequest {
  if (!value || typeof value !== 'object' || Array.isArray(value)) {
    throw new Error('ed25519SessionRequest is required');
  }
  const request = value as Record<string, unknown>;
  if (request.kind === 'not_requested') return { kind: 'not_requested' };
  if (request.kind !== 'requested') {
    throw new Error('ed25519SessionRequest.kind is invalid');
  }
  const remainingUses = Math.floor(Number(request.remainingUses));
  if (!Number.isSafeInteger(remainingUses) || remainingUses < 1) {
    throw new Error('ed25519SessionRequest.remainingUses is invalid');
  }
  return { kind: 'requested', remainingUses };
}

async function provisionPasskeyEd25519YaoSession(input: {
  readonly context: Extract<WalletUnlockCapabilityContext, { readonly kind: 'passkey_unlock' }>;
  readonly ed25519:
    | { readonly kind: 'absent' }
    | { readonly kind: 'active'; readonly signerSlot: number };
  readonly request: PasskeyEd25519SessionRequest;
  readonly challengeId: string;
  readonly walletId: string;
  readonly authorization: WalletUnlockOwnerAuthorization;
  readonly linkedWalletSession: IssuedWalletSessionAuthorizationV2 | null;
}): Promise<PasskeyEd25519SessionProvisionResult> {
  if (input.request.kind === 'not_requested') return { ok: true, session: null };
  if (input.ed25519.kind !== 'active') {
    return {
      ok: false,
      response: {
        status: 409,
        body: {
          ok: false,
          code: 'capability_unavailable',
          message: 'Requested Ed25519 Wallet Session is unavailable',
        },
      },
    };
  }
  const provisioned = await input.context.provisionWalletSession({
    walletId: input.walletId,
    signerSlot: input.ed25519.signerSlot,
    remainingUses: input.request.remainingUses,
    verifiedChallengeId: input.challengeId,
    authority: input.authorization.authority,
    proof: input.authorization.proof,
    walletSessionIdentity: input.linkedWalletSession
      ? {
          kind: 'reuse_wallet_session_v2',
          authorizationId: input.linkedWalletSession.session.authorizationId,
          walletSessionId: input.linkedWalletSession.session.walletSessionId,
          quotaId: input.linkedWalletSession.session.quotaId,
          expiresAtMs: input.linkedWalletSession.session.expiresAtMs,
          remainingUses: input.linkedWalletSession.quota.remainingUses,
        }
      : { kind: 'new_wallet_session' },
  });
  if (!provisioned.ok) {
    return { ok: false, response: walletUnlockEd25519SessionFailureResponse(provisioned) };
  }
  return { ok: true, session: provisioned.session };
}

function projectPasskeyEd25519WalletSession(
  session: WalletRegistrationEd25519YaoBootstrapSession | null,
): Record<string, unknown> | null {
  if (!session) return null;
  return {
    walletId: session.walletId,
    nearAccountId: session.nearAccountId,
    nearEd25519SigningKeyId: session.nearEd25519SigningKeyId,
    relayerKeyId: session.routerAbNormalSigning.signingWorkerId,
    participantIds: session.participantIds,
    thresholdSessionId: session.thresholdSessionId,
    authorizationId: session.authorizationId,
    walletSessionId: session.walletSessionId,
    quotaId: session.quotaId,
    expiresAtMs: session.expiresAtMs,
    remainingUses: session.remainingUses,
    runtimePolicyScope: session.runtimePolicyScope,
    routerAbNormalSigning: session.routerAbNormalSigning,
    sessionKind: session.sessionKind,
    ...(session.sessionKind === 'issued_exact_wallet_session'
      ? { operationCredential: session.operationCredential }
      : {}),
  };
}

/**
 * The exact credential that authorizes the follow-on ECDSA activation. A
 * freshly issued Ed25519 session carries its own; a reused one shares the
 * credential the unlock response already delivered for that same session.
 */
function walletUnlockEcdsaOperationCredential(input: {
  readonly ed25519Session: WalletRegistrationEd25519YaoBootstrapSession;
  readonly activeOperationCredential: WalletSessionOperationCredentialV1 | null;
}): WalletSessionOperationCredentialV1 | null {
  if (input.ed25519Session.sessionKind === 'issued_exact_wallet_session') {
    return input.ed25519Session.operationCredential;
  }
  const active = input.activeOperationCredential;
  return active && active.walletSessionId === input.ed25519Session.walletSessionId ? active : null;
}

function walletUnlockEcdsaCredentialUnavailableResponse(): WalletUnlockRouteResponse {
  return {
    status: 409,
    body: {
      ok: false,
      code: 'capability_unavailable',
      message: 'ECDSA activation requires the exact Wallet Session operation credential',
    },
  };
}

export function walletUnlockAlreadyCommittedRouteResponse(input: {
  readonly unlockBackend: WalletUnlockAlreadyCommittedRouteBody['unlockBackend'];
  readonly committed: Extract<DirectV2IssueResult, { readonly kind: 'already_committed' }>;
}): WalletUnlockRouteResponse {
  const body: WalletUnlockAlreadyCommittedRouteBody = {
    ok: false,
    unlocked: false,
    unlockBackend: input.unlockBackend,
    code: 'already_committed',
    message: 'Wallet Session unlock is already committed; retry the exact method',
    ...input.committed,
  };
  return { status: 409, body };
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
  if (unlockBackend === EMAIL_OTP_CHANNEL) {
    const walletAuthMethodId = parseRequiredWalletAuthMethodId(body.walletAuthMethodId);
    if (!walletAuthMethodId.ok) {
      return {
        status: 400,
        body: { ok: false, code: 'invalid_body', message: walletAuthMethodId.message },
      };
    }
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
  if (
    !input.body.webauthn_authentication ||
    typeof input.body.webauthn_authentication !== 'object'
  ) {
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

type WalletSessionOwnerProof = Extract<VerifiedOwnerProof, { readonly purpose: 'wallet_session' }>;

type WalletUnlockOwnerAuthorization = {
  readonly authority: WalletAuthAuthority;
  readonly proof: WalletSessionOwnerProof;
};

const WALLET_UNLOCK_PROOF_TTL_MS = 60_000;

function requiredAuthorizationValue<T>(
  parsed:
    | { readonly ok: true; readonly value: T }
    | { readonly ok: false; readonly error: { readonly message: string } },
): T {
  if (!parsed.ok) throw new Error(parsed.error.message);
  return parsed.value;
}

function parseRequiredWalletAuthMethodId(
  value: unknown,
):
  | { readonly ok: true; readonly value: WalletAuthMethodId }
  | { readonly ok: false; readonly message: string } {
  if (value === undefined) {
    return { ok: false, message: 'walletAuthMethodId is required' };
  }
  const parsed = parseWalletAuthMethodId(value);
  return parsed.ok
    ? parsed
    : { ok: false, message: `walletAuthMethodId ${parsed.error.message}` };
}

async function digestWalletUnlockValue(value: unknown): Promise<DigestB64u> {
  return parseDigestB64u(base64UrlEncode(await sha256BytesUtf8(alphabetizeStringify(value))));
}

function passkeyWalletAuthAuthorityForMethod(input: {
  readonly walletId: string;
  readonly rpId: string;
  readonly credentialIdB64u: string;
  readonly walletAuthMethodId: WalletAuthMethodId;
}): PasskeyWalletAuthAuthority {
  return {
    walletId: requiredAuthorizationValue(parseWalletId(input.walletId)),
    factor: {
      kind: 'passkey',
      credentialIdB64u: requiredAuthorizationValue(
        parseWebAuthnCredentialIdB64u(input.credentialIdB64u),
      ),
    },
    verifier: {
      kind: 'webauthn',
      rpId: requiredAuthorizationValue(parseWebAuthnRpId(input.rpId)),
    },
    bindingId: input.walletAuthMethodId,
  };
}

async function buildWalletUnlockOwnerProof(input: {
  readonly challengeId: string;
  readonly factor: VerifiedWalletSessionFactorResult;
  readonly buildVerifiedOwnerProof: RouterApiAuthorizedOperationService['buildVerifiedOwnerProof'];
}): Promise<WalletSessionOwnerProof> {
  const proof = await input.buildVerifiedOwnerProof({
    purpose: 'wallet_session',
    proofId: parseVerifiedOwnerProofId(input.challengeId),
    factor: input.factor,
  });
  if (proof.purpose !== 'wallet_session') throw new Error('Wallet unlock proof purpose is invalid');
  return proof;
}

async function walletUnlockProofForPasskey(input: {
  readonly userId: string;
  readonly rpId: string;
  readonly credentialIdB64u: string;
  readonly assertion: unknown;
  readonly origin: string | undefined;
  readonly tenantId: TenantId;
  readonly buildVerifiedOwnerProof: RouterApiAuthorizedOperationService['buildVerifiedOwnerProof'];
  readonly challengeId: string;
  readonly walletAuthMethodId: WalletAuthMethodId;
}): Promise<WalletUnlockOwnerAuthorization> {
  const origin = parseSessionOrigin(input.origin);
  const principalId = requiredAuthorizationValue(parsePrincipalId(input.userId));
  const walletId = requiredAuthorizationValue(parseWalletId(input.userId));
  const authority = passkeyWalletAuthAuthorityForMethod({
    walletId,
    rpId: input.rpId,
    credentialIdB64u: input.credentialIdB64u,
    walletAuthMethodId: input.walletAuthMethodId,
  });
  const authorityRef = await walletAuthAuthorityRef({ authority });
  const verifiedAtMs = Date.now();
  const factor = buildVerifiedWalletSessionPasskeyFactorResult({
    tenantId: input.tenantId,
    principalId,
    walletId,
    authorityRef,
    requestOrigin: origin,
    audience: origin,
    factorId: requiredAuthorizationValue(parseAuthFactorId(`passkey:${input.credentialIdB64u}`)),
    credentialIdB64u: requiredAuthorizationValue(
      parseWebAuthnCredentialIdB64u(input.credentialIdB64u),
    ),
    assertionDigest: await digestWalletUnlockValue(input.assertion),
    verifiedAtMs,
    expiresAtMs: verifiedAtMs + WALLET_UNLOCK_PROOF_TTL_MS,
  });
  return {
    authority,
    proof: await buildWalletUnlockOwnerProof({
      challengeId: `wallet-unlock:passkey:${input.challengeId}`,
      factor,
      buildVerifiedOwnerProof: input.buildVerifiedOwnerProof,
    }),
  };
}

async function walletUnlockProofForEmailOtp(input: {
  readonly result: VerifiedEmailOtpUnlockResult;
  readonly challengeId: string;
  readonly origin: string | undefined;
  readonly tenantId: TenantId;
  readonly buildVerifiedOwnerProof: RouterApiAuthorizedOperationService['buildVerifiedOwnerProof'];
  readonly authority: VerifiedEmailOtpAuthorityForUnlock;
}): Promise<WalletUnlockOwnerAuthorization> {
  const origin = parseSessionOrigin(input.origin);
  const principalId = requiredAuthorizationValue(parsePrincipalId(input.result.providerUserId));
  const authority = input.authority.walletAuthAuthority;
  const authorityRef = await walletAuthAuthorityRef({ authority });
  const verifiedAtMs = Date.now();
  const factor = buildVerifiedWalletSessionEmailOtpFactorResult({
    tenantId: input.tenantId,
    principalId,
    walletId: requiredAuthorizationValue(parseWalletId(input.result.walletId)),
    authorityRef,
    requestOrigin: origin,
    audience: origin,
    factorId: requiredAuthorizationValue(
      parseAuthFactorId(`email_otp:${authority.factor.provider}:${input.result.providerUserId}`),
    ),
    challengeId: requiredAuthorizationValue(parseEmailOtpChallengeId(input.challengeId)),
    verificationReceiptDigest: await digestWalletUnlockValue({
      challengeId: input.challengeId,
      providerUserId: input.result.providerUserId,
    }),
    verifiedAtMs,
    expiresAtMs: verifiedAtMs + WALLET_UNLOCK_PROOF_TTL_MS,
  });
  return {
    authority,
    proof: await buildWalletUnlockOwnerProof({
      challengeId: `wallet-unlock:email_otp:${input.challengeId}`,
      factor,
      buildVerifiedOwnerProof: input.buildVerifiedOwnerProof,
    }),
  };
}

export async function handleWalletUnlockVerifyRoute(input: {
  body: unknown;
  origin?: string;
  service: RouterApiWalletUnlockService;
  resolveEmailOtpCustody: (
    input: {
      readonly walletId: string;
      readonly enrollmentId: string;
      readonly enrollmentSealKeyVersion: string;
    } & (
      | { readonly kind: 'factor' }
      | { readonly kind: 'wallet_auth_method'; readonly walletAuthMethodId: WalletAuthMethodId }
    ),
  ) => Promise<WalletUnlockEmailOtpCustodyLookup>;
  resolvePasskeyCustody: (input: {
    readonly walletId: string;
    readonly rpId: string;
    readonly credentialIdB64u: string;
    readonly ed25519: Extract<
      Awaited<ReturnType<RouterApiWalletUnlockService['verifyWebAuthnLogin']>>,
      { readonly ok: true }
    >['ed25519'];
  }) => Promise<WalletUnlockPasskeyCustodyResolution>;
  emitRouterApiWebhook: EmitWalletUnlockRouterApiWebhook;
  emitEmailOtpWebhook: EmitWalletUnlockEmailOtpWebhook;
  capabilityContext: WalletUnlockCapabilityContext;
  ecdsaSession: WalletUnlockEcdsaSessionContext;
  tenantId: TenantId;
  buildVerifiedOwnerProof: RouterApiAuthorizedOperationService['buildVerifiedOwnerProof'];
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
    let ed25519SessionRequest: PasskeyEd25519SessionRequest;
    try {
      ed25519SessionRequest = parsePasskeyEd25519SessionRequest(body.ed25519SessionRequest);
    } catch (error: unknown) {
      return {
        status: 400,
        body: {
          ok: false,
          code: 'invalid_body',
          message: error instanceof Error ? error.message : 'Ed25519 session request is invalid',
        },
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
    const walletId = parseWalletId(userId);
    const walletAuthMethodId = parseWalletAuthMethodId(result.walletAuthMethodId);
    const walletAuthorityId = parseWalletAuthorityId(result.walletAuthorityId);
    const rpId = parseWebAuthnRpId(result.rpId);
    const credentialIdB64u = parseWebAuthnCredentialIdB64u(result.credentialIdB64u);
    if (
      !walletId.ok ||
      !walletAuthMethodId.ok ||
      !walletAuthorityId.ok ||
      !rpId.ok ||
      !credentialIdB64u.ok
    ) {
      return {
        status: 500,
        body: {
          ok: false,
          code: 'internal',
          message: 'Verified passkey identity is invalid',
        },
      };
    }
    let authorization: WalletUnlockOwnerAuthorization;
    try {
      authorization = await walletUnlockProofForPasskey({
        userId,
        rpId: result.rpId,
        credentialIdB64u: result.credentialIdB64u,
        assertion: body.webauthn_authentication,
        origin: input.origin,
        tenantId: input.tenantId,
        buildVerifiedOwnerProof: input.buildVerifiedOwnerProof,
        challengeId,
        walletAuthMethodId: walletAuthMethodId.value,
      });
    } catch (error: unknown) {
      return {
        status: 403,
        body: {
          ok: false,
          code: 'owner_proof_rejected',
          message: error instanceof Error ? error.message : 'Passkey owner proof is invalid',
        },
      };
    }
    let activeWalletSession: IssuedWalletSessionAuthorizationV2 | null = null;
    let activeOperationCredential: WalletSessionOperationCredentialV1 | null = null;
    let passkeyCustodyRequired = false;
    try {
      const authorityResolution = await input.service.issueWalletSessionForPasskeyUnlock({
        walletId: walletId.value,
        walletAuthMethodId: walletAuthMethodId.value,
        walletAuthorityId: walletAuthorityId.value,
        rpId: rpId.value,
        credentialIdB64u: credentialIdB64u.value,
        verifiedChallengeId: challengeId,
      });
      switch (authorityResolution.kind) {
        case 'active_authority':
          activeWalletSession = authorityResolution.walletSession;
          activeOperationCredential = authorityResolution.operationCredential;
          passkeyCustodyRequired =
            authorityResolution.authorityProvenanceKind === 'wallet_recovery';
          break;
        case 'already_committed':
          return walletUnlockAlreadyCommittedRouteResponse({
            unlockBackend,
            committed: authorityResolution.committed,
          });
        case 'wallet_registration':
          passkeyCustodyRequired = true;
          break;
        case 'rejected':
          return {
            status: walletUnlockIssuanceRejectionStatus(authorityResolution),
            body: {
              ok: false,
              code: authorityResolution.code,
              message: authorityResolution.message,
            },
          };
      }
    } catch (error: unknown) {
      return {
        status: 500,
        body: {
          ok: false,
          code: 'internal',
          message: error instanceof Error ? error.message : 'Passkey authority resolution failed',
        },
      };
    }

    let passkeyCustody: WalletUnlockPasskeyCustodyProjectionV1 | null = null;
    if (passkeyCustodyRequired) {
      try {
        const custodyResult = projectPasskeyCustody(
          result,
          await input.resolvePasskeyCustody({
            walletId: userId,
            rpId: result.rpId,
            credentialIdB64u: result.credentialIdB64u,
            ed25519: result.ed25519,
          }),
        );
        if (!custodyResult.ok) return custodyResult.response;
        passkeyCustody = custodyResult.projection;
      } catch (error: unknown) {
        return {
          status: 503,
          body: {
            ok: false,
            code: 'custody_unavailable',
            message:
              error instanceof Error ? error.message : 'Passkey wallet custody is unavailable',
          },
        };
      }
    }
    const ed25519Session = await provisionPasskeyEd25519YaoSession({
      context: input.capabilityContext,
      ed25519: passkeyCustody?.ed25519 ?? result.ed25519,
      request: ed25519SessionRequest,
      challengeId,
      walletId: userId,
      authorization,
      linkedWalletSession: activeWalletSession,
    });
    if (!ed25519Session.ok) return ed25519Session.response;
    let ecdsaAuthorization: WalletUnlockEcdsaAuthorization = {
      kind: 'verified_wallet_unlock',
      proof: authorization.proof,
    };
    if (ed25519Session.session) {
      const operationCredential = walletUnlockEcdsaOperationCredential({
        ed25519Session: ed25519Session.session,
        activeOperationCredential,
      });
      if (!operationCredential) return walletUnlockEcdsaCredentialUnavailableResponse();
      ecdsaAuthorization = {
        kind: 'wallet_session_operation_credential_v1',
        operationCredential,
        proof: authorization.proof,
      };
    }
    const ecdsaSession: WalletUnlockEcdsaSessionResult = passkeyCustody
      ? await provisionFirstEcdsaWalletSession({
          context: input.ecdsaSession,
          verifiedWalletId: userId,
          authorization: ecdsaAuthorization,
        })
      : { ok: true, activation: null, activationReceipt: null, continuity: null };
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
        ...(passkeyCustody ? { walletCustody: passkeyCustody } : {}),
        ...(activeWalletSession
          ? {
              walletSession: projectActiveWalletSession(activeWalletSession),
              operationCredential: activeOperationCredential,
            }
          : {}),
        ed25519Session: projectPasskeyEd25519WalletSession(ed25519Session.session),
        ...(ecdsaSession.activation ? { ecdsaSession: ecdsaSession.activation } : {}),
        ...(ecdsaSession.activationReceipt
          ? { ecdsaActivationReceipt: ecdsaSession.activationReceipt }
          : {}),
        ...(ecdsaSession.continuity ? { ecdsaCustody: ecdsaSession.continuity } : {}),
      },
    };
  }

  if (input.capabilityContext.kind === 'passkey_unlock') {
    return {
      status: 400,
      body: { ok: false, code: 'invalid_body', message: 'Email OTP unlock context is invalid' },
    };
  }
  const requestedWalletAuthMethodId = parseRequiredWalletAuthMethodId(body.walletAuthMethodId);
  if (!requestedWalletAuthMethodId.ok) {
    return {
      status: 400,
      body: { ok: false, code: 'invalid_body', message: requestedWalletAuthMethodId.message },
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

  const walletId = parseWalletId(result.walletId);
  if (!walletId.ok) {
    return {
      status: 500,
      body: {
        ok: false,
        code: 'internal',
        message: 'Verified Email OTP wallet identity is invalid',
      },
    };
  }
  let authorityResolution: Awaited<
    ReturnType<RouterApiWalletUnlockService['resolveEmailOtpAuthorityForUnlock']>
  >;
  try {
    authorityResolution = await input.service.resolveEmailOtpAuthorityForUnlock({
      walletId: walletId.value,
      orgId: result.orgId,
      walletAuthMethodId: requestedWalletAuthMethodId.value,
      providerUserId: result.providerUserId,
    });
  } catch (error: unknown) {
    return {
      status: 500,
      body: {
        ok: false,
        code: 'internal',
        message: error instanceof Error ? error.message : 'Email OTP authority resolution failed',
      },
    };
  }
  if (authorityResolution.kind === 'rejected') {
    return {
      status: authorityResolution.code === 'internal' ? 500 : 403,
      body: {
        ok: false,
        code: authorityResolution.code,
        message: authorityResolution.message,
      },
    };
  }
  const exactEmailOtpAuthority: VerifiedEmailOtpAuthorityForUnlock = authorityResolution;

  const verifiedAuthorityProjection = {
    kind: 'email_otp_verified_authority_projection_v1' as const,
    authority: exactEmailOtpAuthority.authority,
    authMethod: exactEmailOtpAuthority.authMethod,
  };

  const emailOtpCustody =
    exactEmailOtpAuthority.authority.provenance.kind === 'device_link'
      ? null
      : projectEmailOtpCustody(
          result,
          await input.resolveEmailOtpCustody({
            walletId: result.walletId,
            enrollmentId: result.enrollmentId,
            enrollmentSealKeyVersion: result.enrollmentSealKeyVersion,
            kind: 'wallet_auth_method',
            walletAuthMethodId: exactEmailOtpAuthority.authMethod.walletAuthMethodId,
          }),
        );
  if (emailOtpCustody && !emailOtpCustody.ok) return emailOtpCustody.response;

  let authorization: WalletUnlockOwnerAuthorization;
  try {
    authorization = await walletUnlockProofForEmailOtp({
      result,
      challengeId,
      origin: input.origin,
      tenantId: input.tenantId,
      buildVerifiedOwnerProof: input.buildVerifiedOwnerProof,
      authority: exactEmailOtpAuthority,
    });
  } catch (error: unknown) {
    return {
      status: 403,
      body: {
        ok: false,
        code: 'owner_proof_rejected',
        message: error instanceof Error ? error.message : 'Email OTP owner proof is invalid',
      },
    };
  }

  let activeWalletSession: IssuedWalletSessionAuthorizationV2 | null = null;
  let activeOperationCredential: WalletSessionOperationCredentialV1 | null = null;
  if (
    input.capabilityContext.request.requestedCapabilities.kind !== 'none'
  ) {
    const walletId = parseWalletId(result.walletId);
    if (!walletId.ok) {
      return {
        status: 500,
        body: {
          ok: false,
          code: 'internal',
          message: 'Verified Email OTP wallet identity is invalid',
        },
      };
    }
    let sessionResolution: Awaited<
      ReturnType<RouterApiWalletUnlockService['issueWalletSessionForEmailOtpUnlock']>
    >;
    try {
      sessionResolution = await input.service.issueWalletSessionForEmailOtpUnlock({
        walletId: walletId.value,
        orgId: result.orgId,
        walletAuthMethodId: requestedWalletAuthMethodId.value,
        providerUserId: result.providerUserId,
        verifiedChallengeId: challengeId,
      });
    } catch (error: unknown) {
      return {
        status: 500,
        body: {
          ok: false,
          code: 'internal',
          message:
            error instanceof Error ? error.message : 'Email OTP Wallet Session issuance failed',
        },
      };
    }
    switch (sessionResolution.kind) {
      case 'active_authority':
        activeWalletSession = sessionResolution.walletSession;
        activeOperationCredential = sessionResolution.operationCredential;
        break;
      case 'already_committed':
        return walletUnlockAlreadyCommittedRouteResponse({
          unlockBackend,
          committed: sessionResolution.committed,
        });
      case 'wallet_registration':
        break;
      case 'rejected':
        return {
          status: walletUnlockIssuanceRejectionStatus(sessionResolution),
          body: {
            ok: false,
            code: sessionResolution.code,
            message: sessionResolution.message,
          },
        };
    }
  }

  if (
    input.capabilityContext.kind === 'email_otp' &&
    (input.capabilityContext.request.requestedCapabilities.kind === 'none' ||
      input.capabilityContext.request.requestedCapabilities.kind === 'wallet_session')
  ) {
    const ecdsaSession = await provisionFirstEcdsaWalletSession({
      context: input.ecdsaSession,
      verifiedWalletId: result.walletId,
      authorization: {
        kind: 'verified_wallet_unlock',
        proof: authorization.proof,
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
        ...(verifiedAuthorityProjection ? { verifiedAuthorityProjection } : {}),
        ...(emailOtpCustody ? { walletCustody: emailOtpCustody.projection } : {}),
        ...(activeWalletSession
          ? {
              walletSession: projectActiveWalletSession(activeWalletSession),
              operationCredential: activeOperationCredential,
            }
          : {}),
        ...(ecdsaSession.activation ? { ecdsaSession: ecdsaSession.activation } : {}),
        ...(ecdsaSession.activationReceipt
          ? { ecdsaActivationReceipt: ecdsaSession.activationReceipt }
          : {}),
        ...(ecdsaSession.continuity ? { ecdsaCustody: ecdsaSession.continuity } : {}),
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
    authorization,
    linkedWalletSession: activeWalletSession,
  });
  if (!capabilityResult.ok) return capabilityResult.response;
  const ed25519OperationCredential = walletUnlockEcdsaOperationCredential({
    ed25519Session: capabilityResult.value.session,
    activeOperationCredential,
  });
  if (!ed25519OperationCredential) return walletUnlockEcdsaCredentialUnavailableResponse();
  const ecdsaSession = await provisionFirstEcdsaWalletSession({
    context: input.ecdsaSession,
    verifiedWalletId: result.walletId,
    authorization: {
      kind: 'wallet_session_operation_credential_v1',
      operationCredential: ed25519OperationCredential,
      proof: authorization.proof,
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
      ...(verifiedAuthorityProjection ? { verifiedAuthorityProjection } : {}),
      ...(emailOtpCustody ? { walletCustody: emailOtpCustody.projection } : {}),
      ed25519YaoCapability: capabilityResult.value,
      ...(activeWalletSession
        ? {
            walletSession: projectActiveWalletSession(activeWalletSession),
            operationCredential: activeOperationCredential,
          }
        : {}),
      ...(ecdsaSession.activation ? { ecdsaSession: ecdsaSession.activation } : {}),
      ...(ecdsaSession.activationReceipt
        ? { ecdsaActivationReceipt: ecdsaSession.activationReceipt }
        : {}),
      ...(ecdsaSession.continuity ? { ecdsaCustody: ecdsaSession.continuity } : {}),
    },
  };
}

type WalletUnlockIssuanceRejection = Extract<
  Awaited<ReturnType<RouterApiWalletUnlockService['issueWalletSessionForPasskeyUnlock']>>,
  { readonly kind: 'rejected' }
>;

function walletUnlockIssuanceRejectionStatus(
  rejection: WalletUnlockIssuanceRejection,
): 403 | 409 | 500 {
  switch (rejection.code) {
    case 'internal':
      return 500;
    case 'unauthorized':
    case 'invalid_body':
    case 'invalid_state':
    case 'not_found':
    case 'tenant_scope_mismatch':
    case 'provider_identity_mismatch':
      return 403;
  }
}
