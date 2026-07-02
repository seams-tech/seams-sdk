import type {
  EcdsaHssServerBootstrapResponse,
  ThresholdEd25519AuthorityScope,
  ThresholdRuntimePolicyScope,
} from '../core/types';
import {
  parseRouterAbEd25519WalletSessionClaims,
  parseRouterAbEcdsaHssWalletSessionClaims,
  parseThresholdEd25519AuthorityScope,
  type RouterAbEd25519WalletSessionClaims,
  type RouterAbEcdsaHssWalletSessionClaims,
} from '../core/ThresholdService/validation';
import type { SessionAdapter } from './routerApi';
import type { RouterApiPublishableKeyAuthAdapter } from './routerApi';
import type { ConsoleOrgProjectEnvService } from '../console/orgProjectEnv';
import { extractBearerCredential } from './routerApiKeyAuth';
import { normalizeThresholdEd25519ParticipantIds } from '@shared/threshold/participants';
import {
  ROUTER_AB_ECDSA_HSS_WALLET_SESSION_JWT_KIND,
  ROUTER_AB_ED25519_WALLET_SESSION_JWT_KIND,
} from '@shared/utils/sessionTokens';
import {
  parseRouterAbEd25519NormalSigningState,
  type RouterAbEd25519NormalSigningState,
} from '@shared/utils/signingSessionSeal';
import {
  buildVerifiedEcdsaWalletSessionAuth,
  buildVerifiedEd25519WalletSessionAuth,
  type VerifiedEcdsaWalletSessionAuth,
  type VerifiedEd25519WalletSessionAuth,
} from './verifiedWalletSessionAuth';
import {
  ROUTER_AB_ECDSA_HSS_NORMAL_SIGNING_STATE_KIND_V1,
  parseRouterAbEcdsaHssNormalSigningStateV1,
  type RouterAbEcdsaHssNormalSigningStateV1,
} from '@shared/utils/routerAbEcdsaHss';
import type { RouterAbPublicKeysetV2 } from '@shared/utils/routerAbPublicKeyset';
import {
  normalizeRuntimePolicyScope,
  normalizeRuntimePolicyScopeFields,
  type RuntimePolicyScope,
} from '@shared/threshold/signingRootScope';
import { base64UrlEncode } from '@shared/utils/encoders';

type PlainObject = Record<string, unknown>;
type AuthorizeErr = { ok: false; code: 'sessions_disabled' | 'unauthorized'; message: string };

function isPlainObject(input: unknown): input is PlainObject {
  return !!input && typeof input === 'object' && !Array.isArray(input);
}

export type ThresholdEd25519SessionTokenInputs =
  | {
      ok: true;
      claims: NonNullable<ReturnType<typeof parseRouterAbEd25519WalletSessionClaims>>;
      walletSessionAuth: VerifiedEd25519WalletSessionAuth;
      body: PlainObject;
    }
  | AuthorizeErr;

export async function validateRouterAbEd25519WalletSessionTokenInputs(input: {
  body: unknown;
  headers: Record<string, string | string[] | undefined>;
  session: SessionAdapter | null | undefined;
}): Promise<ThresholdEd25519SessionTokenInputs> {
  const session = input.session;
  if (!session) {
    return {
      ok: false,
      code: 'sessions_disabled',
      message: 'Sessions are not configured on this server',
    };
  }

  const parsed = await session.parse(input.headers);
  if (!parsed.ok) {
    return {
      ok: false,
      code: 'unauthorized',
      message: 'Missing or invalid Wallet Session JWT',
    };
  }

  const claims = parseRouterAbEd25519WalletSessionClaims(parsed.claims);
  if (!claims) {
    return { ok: false, code: 'unauthorized', message: 'Invalid Router A/B Wallet Session claims' };
  }

  const body = isPlainObject(input.body) ? input.body : {};
  return {
    ok: true,
    claims,
    walletSessionAuth: buildVerifiedEd25519WalletSessionAuth(claims),
    body,
  };
}

export type ThresholdEcdsaSessionInputs =
  | {
      ok: true;
      claims: NonNullable<ReturnType<typeof parseRouterAbEcdsaHssWalletSessionClaims>>;
      walletSessionAuth: VerifiedEcdsaWalletSessionAuth;
      body: PlainObject;
    }
  | AuthorizeErr;

export async function validateRouterAbEcdsaHssWalletSessionInputs(input: {
  body: unknown;
  headers: Record<string, string | string[] | undefined>;
  session: SessionAdapter | null | undefined;
}): Promise<ThresholdEcdsaSessionInputs> {
  const session = input.session;
  if (!session) {
    return {
      ok: false,
      code: 'sessions_disabled',
      message: 'Sessions are not configured on this server',
    };
  }

  const parsed = await session.parse(input.headers);
  if (!parsed.ok) {
    return {
      ok: false,
      code: 'unauthorized',
      message: 'Missing or invalid Wallet Session token',
    };
  }

  const claims = parseRouterAbEcdsaHssWalletSessionClaims(parsed.claims);
  if (!claims) {
    return { ok: false, code: 'unauthorized', message: 'Invalid Wallet Session token claims' };
  }

  const body = isPlainObject(input.body) ? input.body : {};
  return {
    ok: true,
    claims,
    walletSessionAuth: buildVerifiedEcdsaWalletSessionAuth(claims),
    body,
  };
}

export type WalletSessionJwtSigningResult =
  | {
      ok: true;
      jwt: string;
      thresholdSessionId: string;
      thresholdExpiresAtMs: number;
      participantIds: number[];
    }
  | {
      ok: false;
      status: 400 | 500;
      code: 'sessions_disabled' | 'invalid_body' | 'internal';
      message: string;
    };

type WalletSessionJwtSigningFailure = Extract<WalletSessionJwtSigningResult, { ok: false }>;

type RouterAbWalletSessionJwtSigningInput = {
  session: SessionAdapter | null | undefined;
  userId: unknown;
  relayerKeyId: unknown;
  sessionInfo: {
    sessionKind: 'jwt';
    thresholdSessionId?: unknown;
    signingGrantId?: unknown;
    expiresAtMs?: unknown;
    participantIds?: unknown;
    runtimePolicyScope?: unknown;
  };
  fallbackParticipantIds?: unknown;
  requireJwtErrorMessage: string;
  invalidPayloadErrorMessage: string;
  sessionsDisabledMessage?: string;
};

export type RouterAbEd25519WalletSessionJwtSigningInput = RouterAbWalletSessionJwtSigningInput & {
  authorityScope: unknown;
  sessionInfo: RouterAbWalletSessionJwtSigningInput['sessionInfo'] & {
    sessionKind: 'jwt';
    walletId: unknown;
    nearAccountId: unknown;
    nearEd25519SigningKeyId: unknown;
    runtimePolicyScope: unknown;
    routerAbNormalSigning: unknown;
  };
};

export type RouterAbEd25519WalletSessionJwtSessionInfo =
  RouterAbEd25519WalletSessionJwtSigningInput['sessionInfo'];

export type RouterAbEcdsaHssWalletSessionJwtSigningInput = RouterAbWalletSessionJwtSigningInput & {
  evmFamilySigningKeySlotId: unknown;
  sessionInfo: RouterAbWalletSessionJwtSigningInput['sessionInfo'] & {
    sessionKind: 'jwt';
    keyHandle: unknown;
    stableKeyContext: unknown;
    publicIdentity: unknown;
    activationEpoch: unknown;
    signingWorkerId: unknown;
    routerAbEcdsaHssNormalSigning: unknown;
  };
};

export type RouterAbEcdsaHssWalletSessionJwtSessionInfo =
  RouterAbEcdsaHssWalletSessionJwtSigningInput['sessionInfo'];

export function parseRouterAbEd25519WalletSessionJwtSessionInfo(
  input: unknown,
): RouterAbEd25519WalletSessionJwtSessionInfo | null {
  if (!isPlainObject(input)) return null;
  if (String(input.sessionKind || '').trim() !== 'jwt') return null;
  if (
    !('walletId' in input) ||
    !('nearAccountId' in input) ||
    !('nearEd25519SigningKeyId' in input) ||
    !('runtimePolicyScope' in input) ||
    !('routerAbNormalSigning' in input)
  )
    return null;
  return {
    sessionKind: 'jwt',
    walletId: input.walletId,
    nearAccountId: input.nearAccountId,
    nearEd25519SigningKeyId: input.nearEd25519SigningKeyId,
    thresholdSessionId: input.thresholdSessionId,
    signingGrantId: input.signingGrantId,
    expiresAtMs: input.expiresAtMs,
    participantIds: input.participantIds,
    runtimePolicyScope: input.runtimePolicyScope,
    routerAbNormalSigning: input.routerAbNormalSigning,
  };
}

export function parseRouterAbEd25519BootstrapSessionJwtSessionInfo(
  input: unknown,
): RouterAbEd25519WalletSessionJwtSessionInfo | null {
  if (!isPlainObject(input)) return null;
  return parseRouterAbEd25519WalletSessionJwtSessionInfo({
    sessionKind: input.sessionKind,
    walletId: input.walletId,
    nearAccountId: input.nearAccountId,
    nearEd25519SigningKeyId: input.nearEd25519SigningKeyId,
    thresholdSessionId: input.thresholdSessionId,
    signingGrantId: input.signingGrantId,
    expiresAtMs: input.expiresAtMs,
    participantIds: input.participantIds,
    runtimePolicyScope: input.runtimePolicyScope,
    routerAbNormalSigning: input.routerAbNormalSigning,
  });
}

function rejectNonJwtWalletSessionKind(
  args: RouterAbWalletSessionJwtSigningInput,
): WalletSessionJwtSigningFailure | null {
  const sessionKind = String(args.sessionInfo?.sessionKind || '')
    .trim()
    .toLowerCase();
  if (sessionKind === 'jwt') return null;
  return {
    ok: false,
    status: 400,
    code: 'invalid_body',
    message: args.requireJwtErrorMessage,
  };
}

type NormalizedRouterAbWalletSessionSigningBase = {
  userId: string;
  relayerKeyId: string;
  thresholdSessionId: string;
  signingGrantId: string;
  thresholdExpiresAtMs: number;
  participantIds: number[];
  iat: number;
  exp: number;
};

function normalizeRouterAbWalletSessionSigningBase(
  args: RouterAbWalletSessionJwtSigningInput,
):
  | { ok: true; value: NormalizedRouterAbWalletSessionSigningBase }
  | WalletSessionJwtSigningFailure {
  const invalidSessionKind = rejectNonJwtWalletSessionKind(args);
  if (invalidSessionKind) return invalidSessionKind;

  const userId = String(args.userId || '').trim();
  const relayerKeyId = String(args.relayerKeyId || '').trim();
  const thresholdSessionId = String(args.sessionInfo?.thresholdSessionId || '').trim();
  const signingGrantId = String(args.sessionInfo?.signingGrantId || '').trim();
  const thresholdExpiresAtMs = Number(args.sessionInfo?.expiresAtMs);
  const participantIds =
    normalizeThresholdEd25519ParticipantIds(args.sessionInfo?.participantIds) ||
    normalizeThresholdEd25519ParticipantIds(args.fallbackParticipantIds);

  if (
    !userId ||
    !relayerKeyId ||
    !thresholdSessionId ||
    !signingGrantId ||
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
      signingGrantId,
      thresholdExpiresAtMs,
      participantIds,
      iat: Math.floor(Date.now() / 1000),
      exp: Math.floor(thresholdExpiresAtMs / 1000),
    },
  };
}

function rejectInvalidRouterAbEd25519Binding(args: RouterAbEd25519WalletSessionJwtSigningInput):
  | {
      ok: true;
      walletId: string;
      nearAccountId: string;
      nearEd25519SigningKeyId: string;
      runtimePolicyScope: RuntimePolicyScope;
      routerAbNormalSigning: RouterAbEd25519NormalSigningState;
    }
  | WalletSessionJwtSigningFailure {
  try {
    const walletId = String(args.sessionInfo.walletId || '').trim();
    const nearAccountId = String(args.sessionInfo.nearAccountId || '').trim();
    const nearEd25519SigningKeyId = String(args.sessionInfo.nearEd25519SigningKeyId || '').trim();
    const subjectWalletId = String(args.userId || '').trim();
    if (!walletId || !nearAccountId || !nearEd25519SigningKeyId || walletId !== subjectWalletId) {
      throw new Error('invalid Ed25519 wallet session identity');
    }
    const routerAbNormalSigning = parseRouterAbEd25519NormalSigningState(
      args.sessionInfo.routerAbNormalSigning,
    );
    if (!routerAbNormalSigning) throw new Error('missing routerAbNormalSigning');
    const runtimePolicyScope = normalizeRuntimePolicyScope(
      args.sessionInfo.runtimePolicyScope as Record<string, unknown>,
    );
    return { ok: true, walletId, nearAccountId, nearEd25519SigningKeyId, runtimePolicyScope, routerAbNormalSigning };
  } catch {
    return {
      ok: false,
      status: 500,
      code: 'internal',
      message: args.invalidPayloadErrorMessage,
    };
  }
}

function decodeEthereumAddress20Hex(address: string): Uint8Array {
  const normalized = String(address || '')
    .trim()
    .toLowerCase()
    .replace(/^0x/, '');
  if (!/^[0-9a-f]{40}$/.test(normalized)) {
    throw new Error('Router A/B ECDSA-HSS normal-signing state requires a 20-byte owner address');
  }
  const bytes = new Uint8Array(20);
  for (let i = 0; i < bytes.length; i += 1) {
    bytes[i] = Number.parseInt(normalized.slice(i * 2, i * 2 + 2), 16);
  }
  return bytes;
}

export function buildRouterAbEcdsaHssNormalSigningStateForBootstrap(input: {
  bootstrap: EcdsaHssServerBootstrapResponse;
  routerAbPublicKeyset: RouterAbPublicKeysetV2 | null | undefined;
  signingWorkerId: string;
}):
  | { ok: true; state: RouterAbEcdsaHssNormalSigningStateV1 }
  | { ok: false; code: 'not_configured' | 'internal'; message: string } {
  const signingWorkerId = String(input.signingWorkerId || '').trim();
  const signingWorkerHpke = input.routerAbPublicKeyset?.signing_worker_server_output_hpke;
  if (!signingWorkerId || !signingWorkerHpke) {
    return {
      ok: false,
      code: 'not_configured',
      message: 'Router A/B public keyset is required for ECDSA-HSS Wallet Session signing',
    };
  }

  try {
    const bootstrap = input.bootstrap;
    const state = parseRouterAbEcdsaHssNormalSigningStateV1({
      kind: ROUTER_AB_ECDSA_HSS_NORMAL_SIGNING_STATE_KIND_V1,
      scope: {
        wallet_key_id: bootstrap.evmFamilySigningKeySlotId,
        wallet_id: bootstrap.walletId,
        ecdsa_threshold_key_id: bootstrap.ecdsaThresholdKeyId,
        signing_root_id: bootstrap.signingRootId,
        signing_root_version: bootstrap.signingRootVersion,
        context: {
          application_binding_digest_b64u: bootstrap.applicationBindingDigestB64u,
        },
        public_identity: {
          context_binding_b64u: bootstrap.contextBinding32B64u,
          client_public_key33_b64u: bootstrap.publicIdentity.hssClientSharePublicKey33B64u,
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
        activation_epoch: bootstrap.thresholdSessionId,
      },
    });
    if (!state) {
      return {
        ok: false,
        code: 'internal',
        message: 'Router A/B ECDSA-HSS normal-signing state could not be built',
      };
    }
    return { ok: true, state };
  } catch (error) {
    return {
      ok: false,
      code: 'internal',
      message:
        error && typeof error === 'object' && 'message' in error
          ? String((error as { message?: unknown }).message || 'invalid ECDSA-HSS state')
          : 'invalid ECDSA-HSS state',
    };
  }
}

function rejectInvalidRouterAbEcdsaHssBinding(args: RouterAbEcdsaHssWalletSessionJwtSigningInput):
  | {
      ok: true;
      normalSigning: RouterAbEcdsaHssNormalSigningStateV1;
    }
  | WalletSessionJwtSigningFailure {
  try {
    const normalSigning = parseRouterAbEcdsaHssNormalSigningStateV1(
      args.sessionInfo.routerAbEcdsaHssNormalSigning,
    );
    if (normalSigning && doesEcdsaHssBindingMatchSessionInfo(args, normalSigning)) {
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
): { ok: true; value?: RuntimePolicyScope } | WalletSessionJwtSigningFailure {
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

function doesEcdsaHssBindingMatchSessionInfo(
  args: RouterAbEcdsaHssWalletSessionJwtSigningInput,
  normalSigning: RouterAbEcdsaHssNormalSigningStateV1,
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
    String(stableKeyContext.evmFamilySigningKeySlotId || '').trim() === normalSigning.scope.wallet_key_id &&
    String(stableKeyContext.walletId || '').trim() === normalSigning.scope.wallet_id &&
    String(stableKeyContext.ecdsaThresholdKeyId || '').trim() ===
      normalSigning.scope.ecdsa_threshold_key_id &&
    String(stableKeyContext.signingRootId || '').trim() === normalSigning.scope.signing_root_id &&
    String(stableKeyContext.signingRootVersion || '').trim() ===
      normalSigning.scope.signing_root_version &&
    String(stableKeyContext.applicationBindingDigestB64u || '').trim() ===
      normalSigning.scope.context.application_binding_digest_b64u &&
    String(stableKeyContext.contextBinding32B64u || '').trim() === identity.context_binding_b64u &&
    String(publicIdentity.hssClientSharePublicKey33B64u || '').trim() ===
      identity.client_public_key33_b64u &&
    String(publicIdentity.relayerPublicKey33B64u || '').trim() ===
      identity.server_public_key33_b64u &&
    String(publicIdentity.groupPublicKey33B64u || '').trim() ===
      identity.threshold_public_key33_b64u &&
    expectedEthereumAddress20B64u === identity.ethereum_address20_b64u
  );
}

type RouterAbWalletSessionClaimsToSign =
  | RouterAbEd25519WalletSessionClaims
  | RouterAbEcdsaHssWalletSessionClaims;

type RouterAbEd25519WalletSessionClaimsBuildInput = {
  base: NormalizedRouterAbWalletSessionSigningBase;
  authorityScope: ThresholdEd25519AuthorityScope;
  binding: {
    nearAccountId: string;
    nearEd25519SigningKeyId: string;
    runtimePolicyScope: RuntimePolicyScope;
    routerAbNormalSigning: RouterAbEd25519NormalSigningState;
  };
};

type RouterAbEcdsaHssWalletSessionClaimsBuildInput = {
  base: NormalizedRouterAbWalletSessionSigningBase;
  evmFamilySigningKeySlotId: string;
  keyHandle: string;
  runtimePolicyScope?: RuntimePolicyScope;
  binding: {
    normalSigning: RouterAbEcdsaHssNormalSigningStateV1;
  };
};

function buildRouterAbEd25519WalletSessionClaims(
  input: RouterAbEd25519WalletSessionClaimsBuildInput,
): RouterAbEd25519WalletSessionClaims {
  return {
    sub: input.base.userId,
    kind: ROUTER_AB_ED25519_WALLET_SESSION_JWT_KIND,
    walletId: input.base.userId,
    nearAccountId: input.binding.nearAccountId,
    nearEd25519SigningKeyId: input.binding.nearEd25519SigningKeyId,
    thresholdSessionId: input.base.thresholdSessionId,
    signingGrantId: input.base.signingGrantId,
    relayerKeyId: input.base.relayerKeyId,
    authorityScope: input.authorityScope,
    runtimePolicyScope: input.binding.runtimePolicyScope,
    routerAbNormalSigning: input.binding.routerAbNormalSigning,
    participantIds: input.base.participantIds,
    thresholdExpiresAtMs: input.base.thresholdExpiresAtMs,
    iat: input.base.iat,
    exp: input.base.exp,
  };
}

function buildRouterAbEcdsaHssWalletSessionClaims(
  input: RouterAbEcdsaHssWalletSessionClaimsBuildInput,
): RouterAbEcdsaHssWalletSessionClaims {
  const claims: RouterAbEcdsaHssWalletSessionClaims = {
    sub: input.base.userId,
    kind: ROUTER_AB_ECDSA_HSS_WALLET_SESSION_JWT_KIND,
    walletId: input.base.userId,
    thresholdSessionId: input.base.thresholdSessionId,
    signingGrantId: input.base.signingGrantId,
    keyScope: 'evm-family',
    keyHandle: input.keyHandle,
    relayerKeyId: input.base.relayerKeyId,
    evmFamilySigningKeySlotId: input.evmFamilySigningKeySlotId,
    routerAbEcdsaHssNormalSigning: input.binding.normalSigning,
    participantIds: input.base.participantIds,
    thresholdExpiresAtMs: input.base.thresholdExpiresAtMs,
    iat: input.base.iat,
    exp: input.base.exp,
  };
  if (input.runtimePolicyScope) {
    claims.runtimePolicyScope = input.runtimePolicyScope;
  }
  return claims;
}

async function signRouterAbWalletSessionClaims(args: {
  session: SessionAdapter | null | undefined;
  claims: RouterAbWalletSessionClaimsToSign;
  invalidPayloadErrorMessage: string;
  sessionsDisabledMessage?: string;
}): Promise<WalletSessionJwtSigningResult> {
  const session = args.session;
  if (!session) {
    return {
      ok: false,
      status: 500,
      code: 'sessions_disabled',
      message: args.sessionsDisabledMessage || 'Session signing is not configured on this server',
    };
  }

  const validClaims =
    args.claims.kind === ROUTER_AB_ED25519_WALLET_SESSION_JWT_KIND
      ? parseRouterAbEd25519WalletSessionClaims(args.claims)
      : parseRouterAbEcdsaHssWalletSessionClaims(args.claims);
  if (!validClaims) {
    return {
      ok: false,
      status: 500,
      code: 'internal',
      message: args.invalidPayloadErrorMessage,
    };
  }
  const jwt = await session.signJwt(args.claims.sub, args.claims);
  return {
    ok: true,
    jwt,
    thresholdSessionId: args.claims.thresholdSessionId,
    thresholdExpiresAtMs: args.claims.thresholdExpiresAtMs,
    participantIds: args.claims.participantIds,
  };
}

export async function signRouterAbEd25519WalletSessionJwt(
  args: RouterAbEd25519WalletSessionJwtSigningInput,
): Promise<WalletSessionJwtSigningResult> {
  const base = normalizeRouterAbWalletSessionSigningBase(args);
  if (!base.ok) return base;
  const authorityScope = parseThresholdEd25519AuthorityScope(args.authorityScope);
  if (!authorityScope) {
    return {
      ok: false,
      status: 500,
      code: 'internal',
      message: args.invalidPayloadErrorMessage,
    };
  }
  const binding = rejectInvalidRouterAbEd25519Binding(args);
  if (!binding.ok) return binding;
  const claims = buildRouterAbEd25519WalletSessionClaims({
    base: base.value,
    authorityScope,
    binding,
  });
  return await signRouterAbWalletSessionClaims({
    session: args.session,
    claims,
    invalidPayloadErrorMessage: args.invalidPayloadErrorMessage,
    sessionsDisabledMessage: args.sessionsDisabledMessage,
  });
}

export async function signRouterAbEcdsaHssWalletSessionJwt(
  args: RouterAbEcdsaHssWalletSessionJwtSigningInput,
): Promise<WalletSessionJwtSigningResult> {
  const base = normalizeRouterAbWalletSessionSigningBase(args);
  if (!base.ok) return base;
  const binding = rejectInvalidRouterAbEcdsaHssBinding(args);
  if (!binding.ok) return binding;
  const evmFamilySigningKeySlotId = String(args.evmFamilySigningKeySlotId || '').trim();
  if (!evmFamilySigningKeySlotId || evmFamilySigningKeySlotId !== binding.normalSigning.scope.wallet_key_id) {
    return {
      ok: false,
      status: 500,
      code: 'internal',
      message: args.invalidPayloadErrorMessage,
    };
  }
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
  const claims = buildRouterAbEcdsaHssWalletSessionClaims({
    base: base.value,
    evmFamilySigningKeySlotId,
    keyHandle,
    runtimePolicyScope: runtimePolicyScope.value,
    binding,
  });
  return await signRouterAbWalletSessionClaims({
    session: args.session,
    claims,
    invalidPayloadErrorMessage: args.invalidPayloadErrorMessage,
    sessionsDisabledMessage: args.sessionsDisabledMessage,
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
  runtimeEnvironmentIdRaw?: unknown;
  headers: Headers | Record<string, string | string[] | undefined>;
  origin?: string | null;
  publishableKeyAuth?: RouterApiPublishableKeyAuthAdapter | null;
  orgProjectEnv?: ConsoleOrgProjectEnvService | null;
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

  const runtimeEnvironmentId = String(input.runtimeEnvironmentIdRaw || '').trim();
  if (!runtimeEnvironmentId) return { ok: true };

  const publishableKeyAuth = input.publishableKeyAuth || null;
  if (!publishableKeyAuth) {
    return {
      ok: false,
      status: 500,
      code: 'route_auth_not_configured',
      message: 'Runtime scope bootstrap requires publishable key auth on this server',
    };
  }

  const publishableKey = extractBearerCredential(input.headers);
  if (!publishableKey) {
    return {
      ok: false,
      status: 401,
      code: 'unauthorized',
      message: 'Managed runtime scope bootstrap requires a publishable key',
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
    environmentId: runtimeEnvironmentId,
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
  orgProjectEnv: ConsoleOrgProjectEnvService | null;
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
  orgProjectEnv: ConsoleOrgProjectEnvService | null;
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
  orgProjectEnv: ConsoleOrgProjectEnvService | null;
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
