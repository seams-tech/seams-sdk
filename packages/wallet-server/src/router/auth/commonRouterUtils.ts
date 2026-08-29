import type {
  EcdsaDerivationServerBootstrapResponse,
  ThresholdRuntimePolicyScope,
} from '../../core/types';
import type { RouterApiAuthorizationSessionService } from '../framework/authServicePort';
import type { RouterApiWalletSessionAuthorizationV2AdmissionContext } from '../framework/authServicePort';
import {
  type IssuedOpaqueWalletSessionToken,
  type OpaqueOwnerWalletSessionBinding,
  type ResolvedOpaqueWalletSessionToken,
} from '../../authorization/service';
import type {
  RouterApiProjectEnvironmentResolver,
  RouterApiPublishableKeyAuthAdapter,
} from '../framework/routerApi';
import { extractBearerCredential } from './routerApiKeyAuth';
import { normalizeThresholdEd25519ParticipantIds } from '@shared/threshold/participants';
import {
  type VerifiedOwnerEcdsaWalletSessionAuth,
  type VerifiedOwnerEd25519WalletSessionAuth,
} from './verifiedWalletSessionAuth';
import {
  ROUTER_AB_ECDSA_DERIVATION_NORMAL_SIGNING_STATE_KIND_V1,
  parseRouterAbEcdsaDerivationNormalSigningStateV1,
  type RouterAbEcdsaDerivationNormalSigningStateV1,
} from '@shared/utils/routerAbEcdsaDerivation';
import type { RouterAbPublicKeysetV2 } from '@shared/utils/routerAbPublicKeyset';
import type { RootShareEpoch } from '@shared/utils/domainIds';
import type { RouterAbMpcMaterialActivationRefWire } from '@shared/utils/routerAbNormalSigningIdentity';
import type { VerifiedOwnerProof } from '../../authorization/domain';
import {
  normalizeRuntimePolicyScope,
  normalizeRuntimePolicyScopeFields,
  type RuntimePolicyScope,
} from '@shared/threshold/signingRootScope';
import { base64UrlEncode } from '@shared/utils/encoders';
import { parseDigestB64u, type DigestB64u } from '@shared/utils/canonicalPrimitives';
import {
  walletAuthAuthorityRef,
  type WalletAuthAuthorityRef,
} from '@shared/utils/walletAuthAuthority';
import {
  parseMpcWalletSigningQuotaId,
  parsePrincipalId,
  parseTenantId,
  parseEcdsaAuthorizationSessionId,
  parseWalletSessionAuthorizationId,
  parseWalletSessionId,
  type MpcWalletSigningQuotaId,
  type TenantId,
  type EcdsaAuthorizationSessionId,
  type WalletSessionAuthorizationId,
  type WalletSessionId,
} from '@shared/authorization/capabilityKinds';
import { parseWalletId } from '@shared/utils/domainIds';
import {
  walletSessionFailure,
  walletSessionFailureMessage,
  type WalletSessionFailureCode,
} from './walletSessionFailure';
import {
  resolveWalletSessionAuthorizationV2AdministrationAdmission,
  resolveWalletSessionAuthorizationV2Admission,
  type WalletSessionAuthorizationV2AdministrationAdmissionResult,
  type WalletSessionAuthorizationV2AdministrationOperation,
  type WalletSessionAuthorizationV2AdmissionResult,
  type WalletSessionAuthorizationV2RequestedOperation,
} from '../domains/signingOperations/walletExecutionAdmission';

type PlainObject = Record<string, unknown>;
type AuthorizeErr = {
  ok: false;
  code: 'sessions_disabled' | WalletSessionFailureCode;
  message: string;
};

function isPlainObject(input: unknown): input is PlainObject {
  return !!input && typeof input === 'object' && !Array.isArray(input);
}

export type OpaqueOwnerWalletSessionAdmission =
  | {
      readonly kind: 'owner_wallet_session';
      readonly curve: 'ed25519';
      readonly binding: Extract<OpaqueOwnerWalletSessionBinding, { readonly curve: 'ed25519' }>;
      readonly walletSessionAuth: VerifiedOwnerEd25519WalletSessionAuth;
      readonly resolved: ResolvedOpaqueWalletSessionToken;
    }
  | {
      readonly kind: 'owner_wallet_session';
      readonly curve: 'ecdsa';
      readonly binding: Extract<OpaqueOwnerWalletSessionBinding, { readonly curve: 'ecdsa' }>;
      readonly walletSessionAuth: VerifiedOwnerEcdsaWalletSessionAuth;
      readonly resolved: ResolvedOpaqueWalletSessionToken;
    };

export type WalletSessionOperationCredentialAdmission =
  | {
      readonly kind: 'wallet_session_operation_credential_v1';
      readonly curve: 'ed25519';
      readonly context: RouterApiWalletSessionAuthorizationV2AdmissionContext;
      readonly admission: Extract<
        WalletSessionAuthorizationV2AdmissionResult,
        { readonly ok: true; readonly keyFamily: 'ed25519' }
      >;
    }
  | {
      readonly kind: 'wallet_session_operation_credential_v1';
      readonly curve: 'ecdsa';
      readonly context: RouterApiWalletSessionAuthorizationV2AdmissionContext;
      readonly admission: Extract<
        WalletSessionAuthorizationV2AdmissionResult,
        { readonly ok: true; readonly keyFamily: 'ecdsa_secp256k1' }
      >;
    };

export type WalletSessionOperationCredentialResolution =
  | { readonly kind: 'not_found' }
  | { readonly kind: 'rejected' }
  | { readonly kind: 'admitted'; readonly admission: WalletSessionOperationCredentialAdmission };

type WalletSessionOperationCredentialRequest =
  | Pick<
      Extract<WalletSessionAuthorizationV2RequestedOperation, { readonly keyFamily: 'ed25519' }>,
      'keyFamily' | 'operationKind'
    >
  | Pick<
      Extract<
        WalletSessionAuthorizationV2RequestedOperation,
        { readonly keyFamily: 'ecdsa_secp256k1' }
      >,
      'keyFamily' | 'operationKind'
    >;

export function resolveWalletSessionOperationCredentialAdmissionFromContext(input: {
  readonly context: RouterApiWalletSessionAuthorizationV2AdmissionContext;
  readonly nowMs: number;
  readonly operation: WalletSessionOperationCredentialRequest;
}): Exclude<WalletSessionOperationCredentialResolution, { readonly kind: 'not_found' }> {
  const context = input.context;
  const identity = {
    tenantId: context.authorization.session.tenantId,
    principalId: context.authorization.session.principalId,
    walletId: context.authorization.session.walletId,
  };
  const operation: WalletSessionAuthorizationV2RequestedOperation =
    input.operation.keyFamily === 'ed25519'
      ? { ...identity, keyFamily: 'ed25519', operationKind: input.operation.operationKind }
      : {
          ...identity,
          keyFamily: 'ecdsa_secp256k1',
          operationKind: input.operation.operationKind,
        };
  const admission = resolveWalletSessionAuthorizationV2Admission({
    authorization: context.authorization.session,
    authority: context.authority,
    authMethod: context.authMethod,
    operation,
    retiredAtMs: context.retiredAtMs,
    nowMs: input.nowMs,
  });
  if (!admission.ok || admission.keyFamily !== input.operation.keyFamily) {
    return { kind: 'rejected' };
  }
  if (admission.keyFamily === 'ed25519') {
    return {
      kind: 'admitted',
      admission: {
        kind: 'wallet_session_operation_credential_v1',
        curve: 'ed25519',
        context,
        admission,
      },
    };
  }
  return {
    kind: 'admitted',
    admission: {
      kind: 'wallet_session_operation_credential_v1',
      curve: 'ecdsa',
      context,
      admission,
    },
  };
}

export async function resolveWalletSessionOperationCredentialAdmission(input: {
  readonly authorizationSessions: RouterApiAuthorizationSessionService;
  readonly token: string;
  readonly nowMs: number;
  readonly operation: WalletSessionOperationCredentialRequest;
}): Promise<WalletSessionOperationCredentialResolution> {
  const context =
    await input.authorizationSessions.readWalletSessionAuthorizationV2ByOperationCredential({
      tenantId: input.authorizationSessions.tenantId,
      token: input.token,
      nowMs: input.nowMs,
    });
  if (!context) return { kind: 'not_found' };
  return resolveWalletSessionOperationCredentialAdmissionFromContext({
    context,
    nowMs: input.nowMs,
    operation: input.operation,
  });
}

export type WalletSessionAdministrationRequest = Pick<
  WalletSessionAuthorizationV2AdministrationOperation,
  'kind' | 'walletId'
>;

export type WalletSessionAdministrationAdmission = {
  readonly kind: 'wallet_session_administration_v1';
  readonly operationKind: 'link_devices';
  readonly context: RouterApiWalletSessionAuthorizationV2AdmissionContext;
  readonly admission: Extract<
    WalletSessionAuthorizationV2AdministrationAdmissionResult,
    { readonly ok: true }
  >;
};

export type WalletSessionAdministrationResolution =
  | { readonly kind: 'not_found' }
  | { readonly kind: 'rejected' }
  | { readonly kind: 'admitted'; readonly admission: WalletSessionAdministrationAdmission };

export async function resolveWalletSessionAdministrationAdmission(input: {
  readonly authorizationSessions: RouterApiAuthorizationSessionService;
  readonly token: string;
  readonly nowMs: number;
  readonly operation: WalletSessionAdministrationRequest;
}): Promise<WalletSessionAdministrationResolution> {
  const context =
    await input.authorizationSessions.readWalletSessionAuthorizationV2ByOperationCredential({
      tenantId: input.authorizationSessions.tenantId,
      token: input.token,
      nowMs: input.nowMs,
    });
  if (!context) return { kind: 'not_found' };
  const session = context.authorization.session;
  const admission = resolveWalletSessionAuthorizationV2AdministrationAdmission({
    authorization: session,
    authority: context.authority,
    authMethod: context.authMethod,
    operation: {
      kind: input.operation.kind,
      tenantId: session.tenantId,
      principalId: session.principalId,
      walletId: input.operation.walletId,
    },
    retiredAtMs: context.retiredAtMs,
    nowMs: input.nowMs,
  });
  if (!admission.ok) return { kind: 'rejected' };
  return {
    kind: 'admitted',
    admission: {
      kind: 'wallet_session_administration_v1',
      operationKind: admission.operationKind,
      context,
      admission,
    },
  };
}

export type ThresholdEd25519SessionTokenInputs =
  | {
      readonly ok: true;
      readonly kind: 'owner_wallet_session';
      admission: Extract<OpaqueOwnerWalletSessionAdmission, { readonly curve: 'ed25519' }>;
      binding: Extract<OpaqueOwnerWalletSessionAdmission, { readonly curve: 'ed25519' }>['binding'];
      walletSessionAuth: VerifiedOwnerEd25519WalletSessionAuth;
      body: PlainObject;
    }
  | {
      readonly ok: true;
      readonly kind: 'wallet_session_operation_credential_v1';
      readonly admission: Extract<
        WalletSessionOperationCredentialAdmission,
        { readonly curve: 'ed25519' }
      >;
      readonly context: RouterApiWalletSessionAuthorizationV2AdmissionContext;
      readonly body: PlainObject;
    }
  | AuthorizeErr;

export async function validateRouterAbEd25519WalletSessionTokenInputs(input: {
  body: unknown;
  headers: Record<string, string | string[] | undefined>;
  authorizationSessions: RouterApiAuthorizationSessionService | null | undefined;
  nowMs?: () => number;
  operationKind: Extract<
    WalletSessionAuthorizationV2RequestedOperation,
    { readonly keyFamily: 'ed25519' }
  >['operationKind'];
}): Promise<ThresholdEd25519SessionTokenInputs> {
  const authorizationSessions = input.authorizationSessions;
  if (!authorizationSessions) {
    return {
      ok: false,
      code: 'sessions_disabled',
      message: 'Sessions are not configured on this server',
    };
  }

  const token = extractBearerCredential(input.headers);
  if (!token) return walletSessionFailure('wallet_session_missing');
  const nowMs = input.nowMs || Date.now;
  let resolution: WalletSessionOperationCredentialResolution;
  try {
    resolution = await resolveWalletSessionOperationCredentialAdmission({
      authorizationSessions,
      token,
      nowMs: nowMs(),
      operation: { keyFamily: 'ed25519', operationKind: input.operationKind },
    });
  } catch {
    return walletSessionFailure('wallet_session_unavailable');
  }
  if (resolution.kind === 'rejected') {
    return walletSessionFailure('wallet_session_scope_mismatch');
  }
  if (resolution.kind === 'not_found') {
    return {
      ok: false,
      code: 'wallet_session_invalid',
      message: walletSessionFailureMessage('wallet_session_invalid'),
    };
  }
  if (resolution.admission.curve !== 'ed25519') {
    return walletSessionFailure('wallet_session_scope_mismatch');
  }
  return {
    ok: true,
    kind: 'wallet_session_operation_credential_v1',
    admission: resolution.admission,
    context: resolution.admission.context,
    body: isPlainObject(input.body) ? input.body : {},
  };
}

export type ThresholdEcdsaSessionInputs =
  | {
      ok: true;
      readonly kind: 'owner_wallet_session';
      admission: Extract<OpaqueOwnerWalletSessionAdmission, { readonly curve: 'ecdsa' }>;
      binding: Extract<OpaqueOwnerWalletSessionAdmission, { readonly curve: 'ecdsa' }>['binding'];
      walletSessionAuth: VerifiedOwnerEcdsaWalletSessionAuth;
      body: PlainObject;
    }
  | {
      readonly ok: true;
      readonly kind: 'wallet_session_operation_credential_v1';
      readonly admission: WalletSessionOperationCredentialAdmission;
      readonly context: RouterApiWalletSessionAuthorizationV2AdmissionContext;
      readonly body: PlainObject;
    }
  | AuthorizeErr;

export async function validateRouterAbEcdsaDerivationWalletSessionInputs(input: {
  body: unknown;
  headers: Record<string, string | string[] | undefined>;
  authorizationSessions: RouterApiAuthorizationSessionService | null | undefined;
  nowMs?: () => number;
  operationKind: Extract<
    WalletSessionAuthorizationV2RequestedOperation,
    { readonly keyFamily: 'ecdsa_secp256k1' }
  >['operationKind'];
}): Promise<ThresholdEcdsaSessionInputs> {
  const authorizationSessions = input.authorizationSessions;
  if (!authorizationSessions) {
    return {
      ok: false,
      code: 'sessions_disabled',
      message: 'Sessions are not configured on this server',
    };
  }

  const token = extractBearerCredential(input.headers);
  if (!token) return walletSessionFailure('wallet_session_missing');
  const nowMs = input.nowMs || Date.now;
  let resolution: WalletSessionOperationCredentialResolution;
  try {
    resolution = await resolveWalletSessionOperationCredentialAdmission({
      authorizationSessions,
      token,
      nowMs: nowMs(),
      operation: { keyFamily: 'ecdsa_secp256k1', operationKind: input.operationKind },
    });
  } catch {
    return walletSessionFailure('wallet_session_unavailable');
  }
  if (resolution.kind === 'rejected') {
    return walletSessionFailure('wallet_session_scope_mismatch');
  }
  if (resolution.kind === 'not_found') {
    return {
      ok: false,
      code: 'wallet_session_invalid',
      message: walletSessionFailureMessage('wallet_session_invalid'),
    };
  }
  if (resolution.admission.curve !== 'ecdsa') {
    return walletSessionFailure('wallet_session_scope_mismatch');
  }
  return {
    ok: true,
    kind: 'wallet_session_operation_credential_v1',
    admission: resolution.admission,
    context: resolution.admission.context,
    body: isPlainObject(input.body) ? input.body : {},
  };
}

export type WalletSessionIssuanceResult =
  | {
      ok: true;
      authorizationKind: 'owner_wallet_session';
      token: string;
      thresholdSessionId: string;
      thresholdExpiresAtMs: number;
      expiresAtMs: number;
      participantIds: number[];
    }
  | {
      ok: false;
      status: 400 | 500;
      code: 'sessions_disabled' | 'invalid_body' | 'internal';
      message: string;
    };

type WalletSessionIssuanceFailure = Extract<WalletSessionIssuanceResult, { ok: false }>;

type RouterAbOpaqueWalletSessionSigningInputCommon = {
  tenantId: TenantId;
  userId: unknown;
  relayerKeyId: unknown;
  sessionInfo: {
    sessionKind: 'opaque';
    thresholdSessionId?: unknown;
    authorizationId?: unknown;
    walletSessionId?: unknown;
    quotaId?: unknown;
    expiresAtMs?: unknown;
    participantIds?: unknown;
    runtimePolicyScope?: unknown;
    keyManifestDigestB64u: unknown;
  };
  fallbackParticipantIds?: unknown;
  invalidPayloadErrorMessage: string;
  sessionsDisabledMessage?: string;
};

type RouterAbOpaqueWalletSessionSigningInput = RouterAbOpaqueWalletSessionSigningInputCommon & {
  opaqueWalletSessions: Pick<RouterApiAuthorizationSessionService, 'issueOpaqueWalletSessionToken'>;
};

type OpaqueWalletSessionTokenIssueInput = {
  readonly tenantId: TenantId;
  readonly curve: 'ecdsa' | 'ed25519';
  readonly proof: Extract<VerifiedOwnerProof, { readonly purpose: 'wallet_session' }>;
  readonly binding: OpaqueOwnerWalletSessionBinding;
  readonly invalidPayloadErrorMessage: string;
  readonly opaqueWalletSessions: Pick<
    RouterApiAuthorizationSessionService,
    'issueOpaqueWalletSessionToken'
  >;
};

export type RouterAbEcdsaDerivationOpaqueWalletSessionSigningInput =
  RouterAbOpaqueWalletSessionSigningInput & {
    proof: Extract<VerifiedOwnerProof, { readonly purpose: 'wallet_session' }>;
    walletAuthAuthorityRef: WalletAuthAuthorityRef;
    authSource: Extract<OpaqueOwnerWalletSessionBinding, { readonly curve: 'ecdsa' }>['authSource'];
    sessionInfo: RouterAbOpaqueWalletSessionSigningInput['sessionInfo'] & {
      sessionKind: 'opaque';
      authorizationKind: 'owner_wallet_session';
      authorizationId: unknown;
      authorizationSessionId: unknown;
      keyHandle: unknown;
      stableKeyContext: unknown;
      publicIdentity: unknown;
      activationEpoch: unknown;
      signingWorkerId: unknown;
      routerAbEcdsaDerivationNormalSigning: unknown;
    };
  };

type NormalizedRouterAbWalletSessionSigningBase = {
  userId: string;
  relayerKeyId: string;
  thresholdSessionId: string;
  authorizationId: WalletSessionAuthorizationId;
  walletSessionId: WalletSessionId;
  quotaId: MpcWalletSigningQuotaId;
  thresholdExpiresAtMs: number;
  participantIds: number[];
  keyManifestDigestB64u: DigestB64u;
};

function normalizeRouterAbOpaqueWalletSessionSigningBase(
  args: RouterAbOpaqueWalletSessionSigningInput,
): { ok: true; value: NormalizedRouterAbWalletSessionSigningBase } | WalletSessionIssuanceFailure {
  const userId = String(args.userId || '').trim();
  const relayerKeyId = String(args.relayerKeyId || '').trim();
  const thresholdSessionId = String(args.sessionInfo?.thresholdSessionId || '').trim();
  const authorizationId = parseWalletSessionAuthorizationId(args.sessionInfo?.authorizationId);
  const walletSessionId = parseWalletSessionId(args.sessionInfo?.walletSessionId);
  const quotaId = parseMpcWalletSigningQuotaId(args.sessionInfo?.quotaId);
  const thresholdExpiresAtMs = Number(args.sessionInfo?.expiresAtMs);
  const participantIds =
    normalizeThresholdEd25519ParticipantIds(args.sessionInfo?.participantIds) ||
    normalizeThresholdEd25519ParticipantIds(args.fallbackParticipantIds);
  // Registration verified this manifest against the wallet's key set and
  // recorded it on the signer record. Carrying it here is what lets a later
  // owner-authenticated decision name a manifest without re-deriving one.
  let keyManifestDigestB64u: DigestB64u;
  try {
    keyManifestDigestB64u = parseDigestB64u(args.sessionInfo?.keyManifestDigestB64u);
  } catch {
    return {
      ok: false,
      status: 500,
      code: 'internal',
      message: args.invalidPayloadErrorMessage,
    };
  }

  if (
    !userId ||
    !relayerKeyId ||
    !thresholdSessionId ||
    !authorizationId.ok ||
    !walletSessionId.ok ||
    !quotaId.ok ||
    !Number.isFinite(thresholdExpiresAtMs) ||
    thresholdExpiresAtMs <= 0 ||
    !participantIds ||
    participantIds.length < 2
  ) {
    return {
      ok: false,
      status: 500,
      code: 'internal',
      message: args.invalidPayloadErrorMessage,
    };
  }

  return {
    ok: true,
    value: {
      userId,
      relayerKeyId,
      thresholdSessionId,
      authorizationId: authorizationId.value,
      walletSessionId: walletSessionId.value,
      quotaId: quotaId.value,
      thresholdExpiresAtMs,
      participantIds,
      keyManifestDigestB64u,
    },
  };
}

function decodeEthereumAddress20Hex(address: string): Uint8Array {
  const normalized = String(address || '')
    .trim()
    .toLowerCase()
    .replace(/^0x/, '');
  if (!/^[0-9a-f]{40}$/.test(normalized)) {
    throw new Error(
      'Router A/B ECDSA derivation normal-signing state requires a 20-byte owner address',
    );
  }
  const bytes = new Uint8Array(20);
  for (let i = 0; i < bytes.length; i += 1) {
    bytes[i] = Number.parseInt(normalized.slice(i * 2, i * 2 + 2), 16);
  }
  return bytes;
}

export function buildRouterAbEcdsaDerivationNormalSigningStateForBootstrap(input: {
  bootstrap: Omit<EcdsaDerivationServerBootstrapResponse, 'routerAbEcdsaDerivationNormalSigning'>;
  activationEpoch: RootShareEpoch;
  routerAbPublicKeyset: RouterAbPublicKeysetV2 | null | undefined;
  signingWorkerId: string;
  materialActivation: RouterAbMpcMaterialActivationRefWire;
}):
  | { ok: true; state: RouterAbEcdsaDerivationNormalSigningStateV1 }
  | { ok: false; code: 'not_configured' | 'internal'; message: string } {
  const signingWorkerId = String(input.signingWorkerId || '').trim();
  const signingWorkerHpke = input.routerAbPublicKeyset?.signing_worker_server_output_hpke;
  if (!signingWorkerId || !signingWorkerHpke) {
    return {
      ok: false,
      code: 'not_configured',
      message:
        'Router A/B public keyset is required for Router A/B ECDSA derivation Wallet Session signing',
    };
  }

  try {
    const bootstrap = input.bootstrap;
    const state = parseRouterAbEcdsaDerivationNormalSigningStateV1({
      kind: ROUTER_AB_ECDSA_DERIVATION_NORMAL_SIGNING_STATE_KIND_V1,
      scope: {
        wallet_id: bootstrap.walletId,
        ecdsa_threshold_key_id: bootstrap.ecdsaThresholdKeyId,
        signing_root_id: bootstrap.signingRootId,
        signing_root_version: bootstrap.signingRootVersion,
        context: {
          application_binding_digest_b64u: bootstrap.applicationBindingDigestB64u,
        },
        public_identity: {
          context_binding_b64u: bootstrap.contextBinding32B64u,
          derivation_client_share_public_key33_b64u:
            bootstrap.publicIdentity.derivationClientSharePublicKey33B64u,
          server_public_key33_b64u: bootstrap.publicIdentity.relayerPublicKey33B64u,
          threshold_public_key33_b64u: bootstrap.publicIdentity.groupPublicKey33B64u,
          ethereum_address20_b64u: base64UrlEncode(
            decodeEthereumAddress20Hex(bootstrap.publicIdentity.ethereumAddress),
          ),
          client_share_retry_counter: bootstrap.clientShareRetryCounter,
          server_share_retry_counter: bootstrap.relayerShareRetryCounter,
        },
        signing_worker: {
          server_id: signingWorkerId,
          key_epoch: signingWorkerHpke.key_epoch,
          recipient_encryption_key: signingWorkerHpke.public_key,
        },
        material_activation: input.materialActivation,
        activation_epoch: input.activationEpoch,
      },
    });
    if (!state) {
      return {
        ok: false,
        code: 'internal',
        message: 'Router A/B ECDSA derivation normal-signing state could not be built',
      };
    }
    return { ok: true, state };
  } catch (error) {
    return {
      ok: false,
      code: 'internal',
      message:
        error && typeof error === 'object' && 'message' in error
          ? String(
              (error as { message?: unknown }).message ||
                'invalid Router A/B ECDSA derivation state',
            )
          : 'invalid Router A/B ECDSA derivation state',
    };
  }
}

function rejectInvalidRouterAbEcdsaDerivationBinding(
  args: RouterAbEcdsaDerivationOpaqueWalletSessionSigningInput,
):
  | {
      ok: true;
      normalSigning: RouterAbEcdsaDerivationNormalSigningStateV1;
    }
  | WalletSessionIssuanceFailure {
  try {
    const normalSigning = parseRouterAbEcdsaDerivationNormalSigningStateV1(
      args.sessionInfo.routerAbEcdsaDerivationNormalSigning,
    );
    if (normalSigning && doesEcdsaDerivationBindingMatchSessionInfo(args, normalSigning)) {
      return {
        ok: true,
        normalSigning,
      };
    }
  } catch {
    // Fall through to the shared failure below.
  }
  return {
    ok: false,
    status: 500,
    code: 'internal',
    message: args.invalidPayloadErrorMessage,
  };
}

function parseOptionalRuntimePolicyScope(
  raw: unknown,
  invalidPayloadErrorMessage: string,
): { ok: true; value?: RuntimePolicyScope } | WalletSessionIssuanceFailure {
  if (raw === undefined || raw === null || raw === '') return { ok: true };
  if (!isPlainObject(raw)) {
    return {
      ok: false,
      status: 500,
      code: 'internal',
      message: invalidPayloadErrorMessage,
    };
  }
  try {
    return { ok: true, value: normalizeRuntimePolicyScope(raw) };
  } catch {
    return {
      ok: false,
      status: 500,
      code: 'internal',
      message: invalidPayloadErrorMessage,
    };
  }
}

function doesEcdsaDerivationBindingMatchSessionInfo(
  args: RouterAbEcdsaDerivationOpaqueWalletSessionSigningInput,
  normalSigning: RouterAbEcdsaDerivationNormalSigningStateV1,
): boolean {
  const stableKeyContext = isPlainObject(args.sessionInfo.stableKeyContext)
    ? args.sessionInfo.stableKeyContext
    : null;
  const publicIdentity = isPlainObject(args.sessionInfo.publicIdentity)
    ? args.sessionInfo.publicIdentity
    : null;
  if (!stableKeyContext || !publicIdentity) return false;

  const identity = normalSigning.scope.public_identity;
  const signingWorker = normalSigning.scope.signing_worker;
  const expectedEthereumAddress20B64u = (() => {
    try {
      return base64UrlEncode(
        decodeEthereumAddress20Hex(String(publicIdentity.ethereumAddress || '')),
      );
    } catch {
      return '';
    }
  })();

  return (
    String(args.sessionInfo.keyHandle || '').trim() !== '' &&
    String(args.sessionInfo.activationEpoch || '').trim() ===
      normalSigning.scope.activation_epoch &&
    String(args.sessionInfo.signingWorkerId || '').trim() === signingWorker.server_id &&
    String(stableKeyContext.walletId || '').trim() === normalSigning.scope.wallet_id &&
    String(stableKeyContext.ecdsaThresholdKeyId || '').trim() ===
      normalSigning.scope.ecdsa_threshold_key_id &&
    String(stableKeyContext.signingRootId || '').trim() === normalSigning.scope.signing_root_id &&
    String(stableKeyContext.signingRootVersion || '').trim() ===
      normalSigning.scope.signing_root_version &&
    String(stableKeyContext.applicationBindingDigestB64u || '').trim() ===
      normalSigning.scope.context.application_binding_digest_b64u &&
    String(stableKeyContext.contextBinding32B64u || '').trim() === identity.context_binding_b64u &&
    String(publicIdentity.derivationClientSharePublicKey33B64u || '').trim() ===
      identity.derivation_client_share_public_key33_b64u &&
    String(publicIdentity.relayerPublicKey33B64u || '').trim() ===
      identity.server_public_key33_b64u &&
    String(publicIdentity.groupPublicKey33B64u || '').trim() ===
      identity.threshold_public_key33_b64u &&
    expectedEthereumAddress20B64u === identity.ethereum_address20_b64u
  );
}

type RouterAbEcdsaDerivationWalletSessionBindingBuildInput = {
  base: NormalizedRouterAbWalletSessionSigningBase;
  walletAuthAuthorityRef: WalletAuthAuthorityRef;
  authSource: Extract<OpaqueOwnerWalletSessionBinding, { readonly curve: 'ecdsa' }>['authSource'];
  authorizationSessionId: EcdsaAuthorizationSessionId;
  keyHandle: string;
  runtimePolicyScope?: RuntimePolicyScope;
  binding: {
    normalSigning: RouterAbEcdsaDerivationNormalSigningStateV1;
  };
};

function buildRouterAbEcdsaDerivationWalletSessionBinding(
  input: RouterAbEcdsaDerivationWalletSessionBindingBuildInput,
): Extract<OpaqueOwnerWalletSessionBinding, { readonly curve: 'ecdsa' }> {
  const walletId = parseWalletId(input.base.userId);
  if (!walletId.ok) throw new Error('invalid wallet id for owner Wallet Session binding');
  const binding: Extract<OpaqueOwnerWalletSessionBinding, { readonly curve: 'ecdsa' }> = {
    kind: 'opaque_owner_wallet_session_binding_v1',
    curve: 'ecdsa',
    subjectId: input.base.userId,
    walletId: walletId.value,
    thresholdSessionId: input.base.thresholdSessionId,
    authorizationId: input.base.authorizationId,
    authorizationSessionId: input.authorizationSessionId,
    walletAuthAuthorityRef: input.walletAuthAuthorityRef,
    authSource: input.authSource,
    walletSessionId: input.base.walletSessionId,
    quotaId: input.base.quotaId,
    keyHandle: input.keyHandle,
    relayerKeyId: input.base.relayerKeyId,
    routerAbEcdsaDerivationNormalSigning: input.binding.normalSigning,
    participantIds: input.base.participantIds,
    thresholdExpiresAtMs: input.base.thresholdExpiresAtMs,
    keyManifestDigestB64u: input.base.keyManifestDigestB64u,
  };
  return input.runtimePolicyScope
    ? { ...binding, runtimePolicyScope: input.runtimePolicyScope }
    : binding;
}

async function issueOpaqueWalletSessionToken(
  args: OpaqueWalletSessionTokenIssueInput,
): Promise<WalletSessionIssuanceResult> {
  const runtimePolicyScope =
    args.binding.curve === 'ecdsa'
      ? args.binding.runtimePolicyScope
      : args.binding.runtimePolicyScope;
  const tenantId = runtimePolicyScope
    ? parseTenantId(runtimePolicyScope.orgId)
    : { ok: true as const, value: args.tenantId };
  if (!tenantId.ok || tenantId.value !== args.tenantId) {
    return {
      ok: false,
      status: 500,
      code: 'internal',
      message: args.invalidPayloadErrorMessage,
    };
  }
  if (!(await ownerWalletSessionProofMatchesBinding(args))) {
    return {
      ok: false,
      status: 500,
      code: 'internal',
      message: args.invalidPayloadErrorMessage,
    };
  }
  try {
    const consumedAtMs = Date.now();
    const issued: IssuedOpaqueWalletSessionToken =
      await args.opaqueWalletSessions.issueOpaqueWalletSessionToken({
        tenantId: tenantId.value,
        authorizationId: args.binding.authorizationId,
        walletSessionId: args.binding.walletSessionId,
        quotaId: args.binding.quotaId,
        expiresAtMs: args.binding.thresholdExpiresAtMs,
        proof: args.proof,
        consumedAtMs,
        curve: args.curve,
        binding: args.binding,
      });
    return {
      ok: true,
      authorizationKind: 'owner_wallet_session',
      token: issued.token,
      thresholdSessionId: args.binding.thresholdSessionId,
      thresholdExpiresAtMs: args.binding.thresholdExpiresAtMs,
      expiresAtMs: issued.expiresAtMs,
      participantIds: [...args.binding.participantIds],
    };
  } catch {
    return {
      ok: false,
      status: 500,
      code: 'internal',
      message: args.invalidPayloadErrorMessage,
    };
  }
}

async function ownerWalletSessionProofMatchesBinding(input: {
  readonly proof: Extract<VerifiedOwnerProof, { readonly purpose: 'wallet_session' }>;
  readonly binding: OpaqueOwnerWalletSessionBinding;
}): Promise<boolean> {
  if (String(input.proof.walletId) !== String(input.binding.walletId)) return false;
  const authorityRef =
    input.binding.curve === 'ed25519'
      ? await walletAuthAuthorityRef({ authority: input.binding.authority })
      : input.binding.walletAuthAuthorityRef;
  if (String(input.proof.authority.authorityDigest) !== String(authorityRef.authorityDigest)) {
    return false;
  }
  const principalSubject =
    input.binding.curve === 'ed25519'
      ? input.binding.authority.factor.kind === 'email_otp'
        ? input.binding.authority.factor.providerUserId
        : input.binding.walletId
      : input.binding.authSource.kind === 'oidc_provider'
        ? input.binding.authSource.providerSubject
        : input.binding.walletId;
  const principalId = parsePrincipalId(principalSubject);
  return principalId.ok && principalId.value === input.proof.principalId;
}

export async function issueRouterAbEcdsaDerivationOpaqueWalletSessionToken(
  args: RouterAbEcdsaDerivationOpaqueWalletSessionSigningInput,
): Promise<WalletSessionIssuanceResult> {
  const base = normalizeRouterAbOpaqueWalletSessionSigningBase(args);
  if (!base.ok) return base;
  const authorizationSessionId = parseEcdsaAuthorizationSessionId(
    args.sessionInfo.authorizationSessionId,
  );
  if (!authorizationSessionId.ok) {
    return {
      ok: false,
      status: 500,
      code: 'internal',
      message: args.invalidPayloadErrorMessage,
    };
  }
  const rawBinding = rejectInvalidRouterAbEcdsaDerivationBinding(args);
  if (!rawBinding.ok) return rawBinding;
  const runtimePolicyScope = parseOptionalRuntimePolicyScope(
    args.sessionInfo.runtimePolicyScope,
    args.invalidPayloadErrorMessage,
  );
  if (!runtimePolicyScope.ok) return runtimePolicyScope;
  const keyHandle = String(args.sessionInfo.keyHandle || '').trim();
  if (!keyHandle) {
    return {
      ok: false,
      status: 500,
      code: 'internal',
      message: args.invalidPayloadErrorMessage,
    };
  }
  const binding = buildRouterAbEcdsaDerivationWalletSessionBinding({
    base: base.value,
    walletAuthAuthorityRef: args.walletAuthAuthorityRef,
    authSource: args.authSource,
    authorizationSessionId: authorizationSessionId.value,
    keyHandle,
    runtimePolicyScope: runtimePolicyScope.value,
    binding: rawBinding,
  });
  return await issueOpaqueWalletSessionToken({
    opaqueWalletSessions: args.opaqueWalletSessions,
    tenantId: args.tenantId,
    curve: 'ecdsa',
    proof: args.proof,
    binding,
    invalidPayloadErrorMessage: args.invalidPayloadErrorMessage,
  });
}

export type ThresholdRuntimePolicyScopeResolution =
  | { ok: true; scope?: ThresholdRuntimePolicyScope }
  | {
      ok: false;
      status: 401 | 403 | 500;
      code: 'route_auth_not_configured' | 'unauthorized' | 'forbidden';
      message: string;
    };

export async function resolveThresholdRuntimePolicyScope(input: {
  explicitScopeRaw: unknown;
  projectEnvironmentIdRaw?: unknown;
  headers: Headers | Record<string, string | string[] | undefined>;
  origin?: string | null;
  publishableKeyAuth?: RouterApiPublishableKeyAuthAdapter | null;
  orgProjectEnv?: RouterApiProjectEnvironmentResolver | null;
}): Promise<ThresholdRuntimePolicyScopeResolution> {
  if (isPlainObject(input.explicitScopeRaw)) {
    try {
      const scope = await resolveActiveRuntimePolicyScopeFromFields({
        orgProjectEnv: input.orgProjectEnv || null,
        fields: normalizeRuntimePolicyScopeFields(input.explicitScopeRaw),
      });
      return {
        ok: true,
        scope,
      };
    } catch {
      return { ok: true };
    }
  }

  // The publishable key is the trigger and the source of truth: its own row
  // carries the environment it belongs to, and the scope below is built purely
  // from the authenticated principal. `projectEnvironmentId` is therefore
  // optional — when a client does send one it is forwarded as a cross-check, so
  // a staging key aimed at a production environment id still fails closed.
  const projectEnvironmentId = String(input.projectEnvironmentIdRaw || '').trim();
  const publishableKey = extractBearerCredential(input.headers);
  if (!publishableKey) {
    // No managed credential presented: this is not a managed deployment.
    if (!projectEnvironmentId) return { ok: true };
    return {
      ok: false,
      status: 401,
      code: 'unauthorized',
      message: 'Managed runtime scope bootstrap requires a publishable key',
    };
  }

  const publishableKeyAuth = input.publishableKeyAuth || null;
  if (!publishableKeyAuth) {
    return {
      ok: false,
      status: 500,
      code: 'route_auth_not_configured',
      message: 'Runtime scope bootstrap requires publishable key auth on this server',
    };
  }

  const origin = String(input.origin || '').trim();
  if (!origin) {
    return {
      ok: false,
      status: 403,
      code: 'forbidden',
      message: 'Managed runtime scope bootstrap requires an Origin header',
    };
  }

  const authResult = await publishableKeyAuth.authenticate({
    secret: publishableKey,
    origin,
    environmentId: projectEnvironmentId,
  });
  if (!authResult.ok) {
    return {
      ok: false,
      status: authResult.status,
      code: authResult.status === 403 ? 'forbidden' : 'unauthorized',
      message: authResult.message,
    };
  }

  const projectEnvironment = await resolveRuntimeProjectEnvironment({
    orgProjectEnv: input.orgProjectEnv || null,
    orgId: authResult.principal.orgId,
    environmentId: authResult.principal.environmentId,
  });
  if (!projectEnvironment) return { ok: true };

  return {
    ok: true,
    scope: {
      orgId: authResult.principal.orgId,
      projectId: projectEnvironment.projectId,
      envId: projectEnvironment.envId,
      signingRootVersion: projectEnvironment.signingRootVersion,
    },
  };
}

export async function resolveActiveRuntimePolicyScopeFromFields(input: {
  orgProjectEnv: RouterApiProjectEnvironmentResolver | null;
  fields: Omit<ThresholdRuntimePolicyScope, 'signingRootVersion'> & {
    readonly signingRootVersion?: string;
  };
}): Promise<ThresholdRuntimePolicyScope> {
  const resolved = await resolveActiveRuntimePolicyScopeForEnvironment({
    orgProjectEnv: input.orgProjectEnv,
    orgId: input.fields.orgId,
    projectId: input.fields.projectId,
    envId: input.fields.envId,
    fallbackSigningRootVersion: input.fields.signingRootVersion,
  });
  if (resolved) return resolved;
  return normalizeRuntimePolicyScope(input.fields);
}

export async function resolveActiveRuntimePolicyScopeForEnvironment(input: {
  orgProjectEnv: RouterApiProjectEnvironmentResolver | null;
  orgId: string;
  environmentId?: string;
  projectId?: string;
  envId?: string;
  fallbackSigningRootVersion?: string;
}): Promise<ThresholdRuntimePolicyScope | undefined> {
  const orgId = String(input.orgId || '').trim();
  if (!orgId) return undefined;
  const activeEnvironment = await resolveRuntimeProjectEnvironment({
    orgProjectEnv: input.orgProjectEnv,
    orgId,
    environmentId: input.environmentId,
    projectId: input.projectId,
    envId: input.envId,
  });
  if (activeEnvironment) {
    return {
      orgId,
      projectId: activeEnvironment.projectId,
      envId: activeEnvironment.envId,
      signingRootVersion: activeEnvironment.signingRootVersion,
    };
  }
  const projectId = String(input.projectId || '').trim();
  const envId = String(input.envId || '').trim();
  const signingRootVersion = String(input.fallbackSigningRootVersion || '').trim();
  if (projectId && envId && signingRootVersion) {
    return { orgId, projectId, envId, signingRootVersion };
  }
  return undefined;
}

async function resolveRuntimeProjectEnvironment(input: {
  orgProjectEnv: RouterApiProjectEnvironmentResolver | null;
  orgId: string;
  environmentId?: string;
  projectId?: string;
  envId?: string;
}): Promise<{ projectId: string; envId: string; signingRootVersion: string } | undefined> {
  if (!input.orgProjectEnv) return undefined;
  try {
    const environmentId = String(input.environmentId || '').trim();
    const projectIdFilter = String(input.projectId || '').trim();
    const envIdFilter = String(input.envId || '').trim();
    const environments = await input.orgProjectEnv.listEnvironments({
      orgId: input.orgId,
      actorUserId: 'runtime-scope-bootstrap',
      roles: ['system'],
      ...(environmentId ? { environmentId } : {}),
      ...(projectIdFilter ? { projectId: projectIdFilter } : {}),
    });
    const environment = environments.find((entry) => {
      if (environmentId && entry.id !== environmentId) return false;
      if (projectIdFilter && entry.projectId !== projectIdFilter) return false;
      if (envIdFilter && entry.key !== envIdFilter) return false;
      return true;
    });
    const projectId = String(environment?.projectId || '').trim();
    const envId = String(environment?.key || '').trim();
    const signingRootVersion = String(environment?.signingRootVersion || '').trim();
    return projectId && envId && signingRootVersion
      ? { projectId, envId, signingRootVersion }
      : undefined;
  } catch {
    return undefined;
  }
}
