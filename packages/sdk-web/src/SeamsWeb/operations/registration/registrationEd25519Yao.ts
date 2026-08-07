/**
 * Ed25519 Yao registration work and the Ed25519 material persistence that
 * follows it, for both the passkey and Email OTP factors.
 *
 * Moved verbatim out of `registration.ts`. `RegistrationYaoWork` is the
 * deferred-work handle the registration flow claims once the Yao branch
 * settles; everything here either produces it, settles it, or persists what it
 * yielded.
 */

import { parseThresholdEd25519SessionId, type WebAuthnRpId } from '@shared/utils/domainIds';
import type { ThresholdEd25519SessionId } from '@/core/signingEngine/session/operationState/types';
import type { RegistrationWebContext } from '@/SeamsWeb/signingSurface/types';
import { IndexedDBManager } from '@/core/indexedDB';
import type {
  RegistrationAuthMethodInput,
  RegistrationIntentV1,
  WalletId,
} from '@shared/utils/registrationIntent';
import { parseNearEd25519SigningKeyId } from '@shared/utils/registrationIntent';
import { base64UrlDecode } from '@shared/utils/base64';
import { toRpId } from '@/core/signingEngine/session/identity/evmFamilyEcdsaIdentity';
import {
  type WalletRegistrationRespondEd25519DeferredWork,
  type WalletRegistrationEd25519YaoPublicResult,
  type WalletRegistrationFinalizeResponse,
} from '@/core/rpcClients/relayer/walletRegistration';
import { collectPasskeyRegistrationAuthority } from '@/SeamsWeb/operations/authMethods/passkey/registrationAuthority';
import type { PrepareEmailOtpRegistrationEnrollmentMaterialInternalResult as EmailOtpRegistrationEnrollmentMaterial } from '@/core/signingEngine/flows/signEvmFamily/emailOtpPublic';
import {
  startEmailOtpEd25519YaoWorkerRegistrationV1,
  EmailOtpEd25519YaoWorkerPendingRegistrationV1,
  type EmailOtpEd25519YaoWorkerActiveClientV1,
  type EmailOtpEd25519YaoRegistrationDiagnosticsV1,
} from '@/core/signingEngine/session/emailOtp/ed25519YaoWorkerClient';
import {
  emailOtpAuthContextProviderUserId,
  type ThresholdEcdsaEmailOtpAuthContext,
} from '@/core/signingEngine/session/identity/laneIdentity';
import {
  buildPasskeyWalletAuthAuthority,
  walletAuthAuthorityRef,
  type WalletAuthAuthority,
  type WalletAuthAuthorityRef,
} from '@shared/utils/walletAuthAuthority';
import { registerVerifiedPasskeyEd25519YaoV1 } from '@/core/signingEngine/flows/registration/services/passkeyEd25519YaoRegistration';
import type {
  ProductEd25519YaoBrowserMaterialPersistencePortV1,
  ProductEd25519YaoPendingRegistrationPortV1,
  ProductEd25519YaoRegistrationResultV1,
} from '@/core/signingEngine/flows/registration/services/ed25519YaoRegistration';
import type {
  RouterAbEd25519YaoActiveClientMetadataV1,
  RouterAbEd25519YaoSealableActiveClientV1,
} from '@/core/signingEngine/threshold/ed25519/yaoClient';
import { persistPasskeyEd25519YaoSignerMaterialV1 } from '@/core/signingEngine/session/passkey/ed25519YaoLocalMaterial';
import { nearEd25519YaoMaterialActivationFromMetadata } from '@/core/signingEngine/session/material/nearEd25519YaoMaterialActivation';
import {
  buildPasskeyEd25519RestoreMetadata,
  persistPasskeyEd25519YaoSessionForRefresh,
} from '@/core/signingEngine/session/passkey/ed25519YaoSealedSession';
import {
  buildPasskeyRouterAbEd25519WalletSessionState,
  buildEmailOtpRouterAbEd25519WalletSessionState,
  type ResolvedRouterAbEd25519WalletSessionState,
} from '@/core/signingEngine/session/warmCapabilities/routerAbEd25519WalletSessionState';
import { buildRouterAbEd25519SigningWalletSession } from '@/core/signingEngine/session/routerAbSigningWalletSession';
import { toAccountId } from '@/core/types/accountIds';
import {
  normalizeRuntimePolicyScope,
  signingRootScopeFromRuntimePolicyScope,
} from '@shared/threshold/signingRootScope';
import type {
  RegistrationEstablishedEd25519Session,
  RegistrationEstablishedSession,
} from '@shared/utils/registrationEstablishedSession';
import { type RouterAbTraceContextV1 } from '@shared/utils/routerAbTraceContext';
import { ROUTER_AB_ED25519_NORMAL_SIGNING_STATE_KIND } from '@shared/utils/signingSessionSeal';
import {
  RegistrationTimingRecorder,
  assertNever,
  parseYaoServerTimingBuckets,
} from './registrationTiming';
import { sameRuntimePolicyScope } from './registrationStrictEcdsa';
import type { RegistrationPersistenceAuth } from './registration';
type PasskeyAuthorityCredential = {
  readonly id?: unknown;
  readonly rawId?: unknown;
};

export function passkeyWalletAuthAuthorityFromCredential(args: {
  walletId: WalletId | string;
  rpId: WebAuthnRpId | string;
  credential: PasskeyAuthorityCredential;
}): WalletAuthAuthority {
  return buildPasskeyWalletAuthAuthority({
    walletId: args.walletId,
    rpId: args.rpId,
    credentialIdB64u: String(args.credential.rawId || args.credential.id || '').trim(),
  });
}

export async function requireEmailOtpRegistrationEnrollmentMaterial(input: {
  material: Promise<EmailOtpRegistrationEnrollmentMaterial> | null;
  operation: string;
}): Promise<EmailOtpRegistrationEnrollmentMaterial> {
  if (!input.material) {
    throw new Error(`Email OTP registration ${input.operation} is missing enrollment material`);
  }
  return await input.material;
}

type RegistrationYaoWorkCompletion =
  | {
      kind: 'pending';
      pending: ProductEd25519YaoPendingRegistrationPortV1;
      /** Raw Router Server-Timing for the execute call. Diagnostics only. */
      routerServerTiming?: string;
      /** Client-observed Yao sub-steps in ms. Diagnostics only. */
      clientTimings?: { admissionMs: number; sessionCreateMs: number };
    }
  | {
      kind: 'failed';
      error: Error;
    };

function registrationYaoWorkError(value: unknown): Error {
  return value instanceof Error ? value : new Error(String(value));
}

function completeRegistrationYaoWork(
  result: ProductEd25519YaoRegistrationResultV1,
): RegistrationYaoWorkCompletion {
  return result.ok
    ? {
        kind: 'pending',
        pending: result.registration,
        ...(result.routerServerTiming ? { routerServerTiming: result.routerServerTiming } : {}),
        ...(result.clientTimings ? { clientTimings: result.clientTimings } : {}),
      }
    : { kind: 'failed', error: new Error(result.message) };
}

function failRegistrationYaoWork(error: unknown): RegistrationYaoWorkCompletion {
  return { kind: 'failed', error: registrationYaoWorkError(error) };
}

function completeRegistrationYaoPending(
  pending: ProductEd25519YaoPendingRegistrationPortV1,
): RegistrationYaoWorkCompletion {
  return { kind: 'pending', pending };
}

function settleRegistrationYaoResult(
  result: Promise<ProductEd25519YaoRegistrationResultV1>,
): Promise<RegistrationYaoWorkCompletion> {
  return result.then(completeRegistrationYaoWork, failRegistrationYaoWork);
}

function settleRegistrationYaoPending(
  pending: Promise<ProductEd25519YaoPendingRegistrationPortV1>,
): Promise<RegistrationYaoWorkCompletion> {
  return pending.then(completeRegistrationYaoPending, failRegistrationYaoWork);
}

type RegistrationYaoWorkState =
  | { kind: 'disabled' }
  | {
      kind: 'running';
      completion: Promise<RegistrationYaoWorkCompletion>;
    }
  | {
      kind: 'pending';
      pending: ProductEd25519YaoPendingRegistrationPortV1;
    }
  | { kind: 'failed'; error: Error }
  | { kind: 'committed' }
  | { kind: 'disposed' };

type ClaimedRegistrationYao =
  | { kind: 'disabled' }
  | {
      kind: 'pending';
      pending: ProductEd25519YaoPendingRegistrationPortV1;
      clientPublicKey: string;
    };

type RegistrationEd25519MaterialFacts = {
  identity: {
    walletId: string;
    nearAccountId: string;
    nearEd25519SigningKeyId: string;
    thresholdSessionId: ThresholdEd25519SessionId;
    signerSlot: number;
    signingRootId: string;
    signingRootVersion: string;
    signingWorkerId: string;
  };
  stableServerScope: {
    relayerKeyId: string;
    participantIds: readonly [number, number];
    runtimePolicyScope: ReturnType<typeof normalizeRuntimePolicyScope>;
    routerAbNormalSigning: {
      kind: typeof ROUTER_AB_ED25519_NORMAL_SIGNING_STATE_KIND;
      signingWorkerId: string;
    };
  };
};

export function requireDeferredNearWork(
  value: WalletRegistrationRespondEd25519DeferredWork | null,
): WalletRegistrationRespondEd25519DeferredWork {
  if (!value) throw new Error('Mixed registration is missing deferred NEAR material facts');
  return value;
}

export function registrationEd25519MaterialFacts(args: {
  deferredNear: WalletRegistrationRespondEd25519DeferredWork;
  finalized: WalletRegistrationEd25519YaoPublicResult;
  walletId: WalletId;
  expectedRuntimePolicyScope: ReturnType<typeof normalizeRuntimePolicyScope>;
}): RegistrationEd25519MaterialFacts {
  const admission = args.deferredNear.admissionRequest;
  const thresholdSessionId = parseThresholdEd25519SessionId(admission.scope.threshold_session_id);
  if (!thresholdSessionId.ok) {
    throw new Error('Ed25519 registration threshold-session identity is invalid');
  }
  const participantIds = admission.participant_ids;
  const finalizedRuntimePolicyScope = normalizeRuntimePolicyScope(
    args.finalized.runtimePolicyScope,
  );
  if (
    admission.application_binding.wallet_id !== args.walletId ||
    admission.application_binding.near_ed25519_signing_key_id !==
      args.finalized.nearEd25519SigningKeyId ||
    admission.application_binding.key_creation_signer_slot !== args.finalized.signerSlot ||
    participantIds[0] !== args.finalized.participantIds[0] ||
    participantIds[1] !== args.finalized.participantIds[1] ||
    !sameRuntimePolicyScope(finalizedRuntimePolicyScope, args.expectedRuntimePolicyScope) ||
    admission.application_binding.signing_root_id !==
      `${finalizedRuntimePolicyScope.projectId}:${finalizedRuntimePolicyScope.envId}` ||
    admission.scope.root_share_epoch !== finalizedRuntimePolicyScope.signingRootVersion ||
    admission.scope.signing_worker_id !== args.finalized.routerAbNormalSigning.signingWorkerId ||
    args.finalized.relayerKeyId !== args.finalized.routerAbNormalSigning.signingWorkerId
  ) {
    throw new Error('Ed25519 registration material changed the admitted signer identity');
  }
  return {
    identity: {
      walletId: String(args.walletId),
      nearAccountId: args.finalized.nearAccountId,
      nearEd25519SigningKeyId: args.finalized.nearEd25519SigningKeyId,
      thresholdSessionId: thresholdSessionId.value,
      signerSlot: args.finalized.signerSlot,
      signingRootId: admission.application_binding.signing_root_id,
      signingRootVersion: admission.scope.root_share_epoch,
      signingWorkerId: admission.scope.signing_worker_id,
    },
    stableServerScope: {
      relayerKeyId: args.finalized.relayerKeyId,
      participantIds: args.finalized.participantIds,
      runtimePolicyScope: finalizedRuntimePolicyScope,
      routerAbNormalSigning: args.finalized.routerAbNormalSigning,
    },
  };
}

export function registrationEstablishedEd25519Session(
  session: RegistrationEstablishedSession,
): RegistrationEstablishedEd25519Session {
  switch (session.tokens.kind) {
    case 'near_ed25519':
    case 'near_ed25519_and_evm_family_ecdsa':
      return session.tokens.ed25519;
    case 'evm_family_ecdsa':
      throw new Error('Registration-established session is missing Ed25519 authorization');
    default:
      return assertNever(session.tokens);
  }
}

function buildRegistrationPasskeyEd25519SessionState(args: {
  registrationEstablishedSession: RegistrationEstablishedSession;
  walletId: WalletId;
  nearAccountId: string;
  nearEd25519SigningKeyId: string;
  thresholdSessionId: string;
  runtimePolicyScope: ReturnType<typeof normalizeRuntimePolicyScope>;
  signerSlot: number;
  relayerUrl: string;
  auth: Extract<RegistrationPersistenceAuth, { kind: 'passkey' }>;
  authority: WalletAuthAuthorityRef;
}): ResolvedRouterAbEd25519WalletSessionState {
  const token = registrationEstablishedEd25519Session(args.registrationEstablishedSession);
  if (
    token.nearAccountId !== String(args.nearAccountId) ||
    token.nearEd25519SigningKeyId !== String(args.nearEd25519SigningKeyId) ||
    token.thresholdSessionId !== String(args.thresholdSessionId) ||
    !sameRuntimePolicyScope(token.runtimePolicyScope, args.runtimePolicyScope)
  ) {
    throw new Error('Registration-established Ed25519 session changed the signer identity');
  }
  const signingRoot = signingRootScopeFromRuntimePolicyScope(token.runtimePolicyScope);
  const signingRootVersion = signingRoot.signingRootVersion;
  if (!signingRootVersion) {
    throw new Error('Registration-established Ed25519 session is missing a signing-root version');
  }
  const signingWalletSession = buildRouterAbEd25519SigningWalletSession({
    walletId: String(args.walletId),
    nearAccountId: String(args.nearAccountId),
    nearEd25519SigningKeyId: String(args.nearEd25519SigningKeyId),
    walletSessionId: String(args.registrationEstablishedSession.walletSessionId),
    quotaId: String(args.registrationEstablishedSession.quotaId),
    thresholdSessionId: token.thresholdSessionId,
    remainingUses: args.registrationEstablishedSession.remainingUses,
    expiresAtMs: args.registrationEstablishedSession.expiresAtMs,
    runtimePolicyScope: token.runtimePolicyScope,
    signingRootId: signingRoot.signingRootId,
    signingRootVersion,
    routerAbNormalSigning: token.routerAbNormalSigning,
    walletSessionJwt: token.walletSessionJwt,
    nowMs: Date.now(),
  });
  if (!signingWalletSession.ok) {
    throw new Error(
      `Registration-established Ed25519 session is unusable (${signingWalletSession.reason})`,
    );
  }
  const credentialIdB64u = String(
    args.auth.credential.rawId || args.auth.credential.id || '',
  ).trim();
  if (!credentialIdB64u) {
    throw new Error('Registration passkey authority is missing its credential identity');
  }
  return buildPasskeyRouterAbEd25519WalletSessionState({
    walletId: args.walletId,
    nearAccountId: toAccountId(args.nearAccountId),
    nearEd25519SigningKeyId: parseNearEd25519SigningKeyId(args.nearEd25519SigningKeyId),
    signerSlot: args.signerSlot,
    rpId: toRpId(args.auth.rpId),
    credentialIdB64u,
    relayerUrl: args.relayerUrl,
    authority: args.authority,
    signingWalletSession: signingWalletSession.value,
  });
}

export async function buildRegistrationEmailOtpEd25519SessionState(args: {
  registrationEstablishedSession: RegistrationEstablishedSession;
  walletId: WalletId;
  nearAccountId: string;
  nearEd25519SigningKeyId: string;
  thresholdSessionId: string;
  runtimePolicyScope: ReturnType<typeof normalizeRuntimePolicyScope>;
  signerSlot: number;
  relayerUrl: string;
  emailOtpAuthContext: ThresholdEcdsaEmailOtpAuthContext;
}): Promise<ResolvedRouterAbEd25519WalletSessionState> {
  const token = registrationEstablishedEd25519Session(args.registrationEstablishedSession);
  if (
    token.nearAccountId !== String(args.nearAccountId) ||
    token.nearEd25519SigningKeyId !== String(args.nearEd25519SigningKeyId) ||
    token.thresholdSessionId !== String(args.thresholdSessionId) ||
    !sameRuntimePolicyScope(token.runtimePolicyScope, args.runtimePolicyScope)
  ) {
    throw new Error('Registration-established Email OTP Ed25519 session changed signer identity');
  }
  const signingRoot = signingRootScopeFromRuntimePolicyScope(token.runtimePolicyScope);
  const signingRootVersion = signingRoot.signingRootVersion;
  if (!signingRootVersion) {
    throw new Error('Registration-established Ed25519 session is missing a signing-root version');
  }
  const signingWalletSession = buildRouterAbEd25519SigningWalletSession({
    walletId: String(args.walletId),
    nearAccountId: String(args.nearAccountId),
    nearEd25519SigningKeyId: String(args.nearEd25519SigningKeyId),
    walletSessionId: String(args.registrationEstablishedSession.walletSessionId),
    quotaId: String(args.registrationEstablishedSession.quotaId),
    thresholdSessionId: token.thresholdSessionId,
    remainingUses: args.registrationEstablishedSession.remainingUses,
    expiresAtMs: args.registrationEstablishedSession.expiresAtMs,
    runtimePolicyScope: token.runtimePolicyScope,
    signingRootId: signingRoot.signingRootId,
    signingRootVersion,
    routerAbNormalSigning: token.routerAbNormalSigning,
    walletSessionJwt: token.walletSessionJwt,
    nowMs: Date.now(),
  });
  if (!signingWalletSession.ok) {
    throw new Error(
      `Registration-established Email OTP Ed25519 session is unusable (${signingWalletSession.reason})`,
    );
  }
  const authority = await walletAuthAuthorityRef({
    authority: args.emailOtpAuthContext.authority,
  });
  return buildEmailOtpRouterAbEd25519WalletSessionState({
    walletId: args.walletId,
    nearAccountId: toAccountId(args.nearAccountId),
    nearEd25519SigningKeyId: parseNearEd25519SigningKeyId(args.nearEd25519SigningKeyId),
    providerSubjectId: emailOtpAuthContextProviderUserId(args.emailOtpAuthContext),
    signerSlot: args.signerSlot,
    relayerUrl: args.relayerUrl,
    authority,
    signingWalletSession: signingWalletSession.value,
  });
}

export async function persistRegistrationPasskeyEd25519SealedRuntime(args: {
  context: RegistrationWebContext;
  registrationEstablishedSession: RegistrationEstablishedSession;
  walletId: WalletId;
  nearAccountId: string;
  nearEd25519SigningKeyId: string;
  thresholdSessionId: string;
  runtimePolicyScope: ReturnType<typeof normalizeRuntimePolicyScope>;
  signerSlot: number;
  relayerUrl: string;
  auth: Extract<RegistrationPersistenceAuth, { kind: 'passkey' }>;
  metadata: RouterAbEd25519YaoActiveClientMetadataV1;
}): Promise<void> {
  const token = registrationEstablishedEd25519Session(args.registrationEstablishedSession);
  const materialActivation = nearEd25519YaoMaterialActivationFromMetadata(args.metadata);
  const credentialIdB64u = String(
    args.auth.credential.rawId || args.auth.credential.id || '',
  ).trim();
  if (!credentialIdB64u) {
    throw new Error('Registration passkey authority is missing its credential identity');
  }
  const authority = await walletAuthAuthorityRef({
    authority: passkeyWalletAuthAuthorityFromCredential({
      walletId: args.walletId,
      rpId: args.auth.rpId,
      credential: args.auth.credential,
    }),
  });
  const session = buildRegistrationPasskeyEd25519SessionState({
    ...args,
    authority,
  });
  const ed25519Restore = buildPasskeyEd25519RestoreMetadata({
    rpId: args.auth.rpId,
    nearAccountId: args.nearAccountId,
    nearEd25519SigningKeyId: args.nearEd25519SigningKeyId,
    relayerKeyId: token.routerAbNormalSigning.signingWorkerId,
    participantIds: args.metadata.participantIds,
    runtimePolicyScope: token.runtimePolicyScope,
    signerSlot: args.signerSlot,
    routerAbNormalSigning: token.routerAbNormalSigning,
    credentialIdB64u,
    materialActivation,
  });
  await persistPasskeyEd25519YaoSessionForRefresh({
    persistence: args.context.signingEngine,
    session,
    prfFirstB64u: args.auth.passkeyPrfFirstB64u,
    ed25519Restore,
    materialActivation,
  });
}

type PasskeyRegistrationEd25519MaterialPersistenceArgs = {
  facts: RegistrationEd25519MaterialFacts;
  rpId: string;
  credentialIdB64u: string;
  passkeyPrfFirstB64u: string;
};

class PasskeyRegistrationEd25519MaterialPersistencePort implements ProductEd25519YaoBrowserMaterialPersistencePortV1 {
  constructor(private readonly args: PasskeyRegistrationEd25519MaterialPersistenceArgs) {}

  async persist(
    activeClient: RouterAbEd25519YaoSealableActiveClientV1,
  ): Promise<RouterAbEd25519YaoActiveClientMetadataV1> {
    await persistPasskeyEd25519YaoSignerMaterialV1({
      store: IndexedDBManager,
      activeClient,
      identity: {
        ...this.args.facts.identity,
        rpId: this.args.rpId,
        credentialIdB64u: this.args.credentialIdB64u,
      },
      stableServerScope: this.args.facts.stableServerScope,
      passkeyPrfFirstB64u: this.args.passkeyPrfFirstB64u,
    });
    return activeClient.metadata();
  }
}

export async function persistPasskeyRegistrationEd25519Material(
  args: PasskeyRegistrationEd25519MaterialPersistenceArgs & {
    pending: ProductEd25519YaoPendingRegistrationPortV1;
  },
): Promise<RouterAbEd25519YaoActiveClientMetadataV1> {
  return await args.pending.persistRegistrationMaterial({
    kind: 'browser_owned',
    persistence: new PasskeyRegistrationEd25519MaterialPersistencePort(args),
  });
}

async function persistEmailOtpRegistrationEd25519Material(args: {
  pending: ProductEd25519YaoPendingRegistrationPortV1;
  facts: RegistrationEd25519MaterialFacts;
  expectedOperationalPublicKey: string;
  providerSubject: string;
  sessionPolicy: {
    thresholdSessionId: string;
    expiresAtMs: number;
    remainingUses: number;
  };
}): Promise<RouterAbEd25519YaoActiveClientMetadataV1> {
  return await args.pending.persistRegistrationMaterial({
    kind: 'worker_owned',
    walletId: args.facts.identity.walletId,
    providerSubject: args.providerSubject,
    nearAccountId: args.facts.identity.nearAccountId,
    nearEd25519SigningKeyId: args.facts.identity.nearEd25519SigningKeyId,
    signerSlot: args.facts.identity.signerSlot,
    signingRootVersion: args.facts.identity.signingRootVersion,
    expectedOperationalPublicKey: args.expectedOperationalPublicKey,
    sessionPolicy: args.sessionPolicy,
  });
}

export class RegistrationYaoWork {
  private state: RegistrationYaoWorkState;
  private persistedEmailOtpActiveClient: EmailOtpEd25519YaoWorkerActiveClientV1 | null = null;
  /** Router Server-Timing captured when the ceremony settled. Diagnostics only. */
  private routerServerTiming: string | null = null;
  /** Client-observed Yao sub-step durations. Diagnostics only. */
  private yaoClientTimings: { admissionMs: number; sessionCreateMs: number } | null = null;

  /** Wall-clock start of the Yao branch, for `yaoBranchTotalMs`. */
  private readonly startedAtMs: number = performance.now();
  /**
   * Stamped when the ceremony's own promise settles, not when the join is
   * reached. Measuring at the join would report max(ECDSA, Yao), because the
   * claim is only awaited after the ECDSA branch completes.
   */
  private settledAtMs: number | null = null;

  private constructor(state: RegistrationYaoWorkState) {
    this.state = state;
    if (state.kind === 'running') {
      void state.completion.then(
        () => this.stampSettled(),
        () => this.stampSettled(),
      );
    }
  }

  private stampSettled(): void {
    if (this.settledAtMs === null) this.settledAtMs = performance.now();
  }

  /** Duration of the Yao branch itself. Diagnostics only. */
  elapsedMs(): number {
    const settledAtMs = this.settledAtMs ?? performance.now();
    return Math.max(0, settledAtMs - this.startedAtMs);
  }

  static disabled(): RegistrationYaoWork {
    return new RegistrationYaoWork({ kind: 'disabled' });
  }

  static start(
    input: Parameters<typeof registerVerifiedPasskeyEd25519YaoV1>[0],
  ): RegistrationYaoWork {
    return new RegistrationYaoWork({
      kind: 'running',
      completion: settleRegistrationYaoResult(registerVerifiedPasskeyEd25519YaoV1(input)),
    });
  }

  static startPending(
    pending: Promise<ProductEd25519YaoPendingRegistrationPortV1>,
  ): RegistrationYaoWork {
    return new RegistrationYaoWork({
      kind: 'running',
      completion: settleRegistrationYaoPending(pending),
    });
  }

  consumeClientTimings(): { admissionMs: number; sessionCreateMs: number } | null {
    const value = this.yaoClientTimings;
    this.yaoClientTimings = null;
    return value;
  }

  consumeRouterServerTiming(): string | null {
    const value = this.routerServerTiming;
    this.routerServerTiming = null;
    return value;
  }

  async requirePending(): Promise<ProductEd25519YaoPendingRegistrationPortV1> {
    switch (this.state.kind) {
      case 'running': {
        const completion = await this.state.completion;
        if (completion.kind === 'failed') {
          this.state = completion;
          throw completion.error;
        }
        this.routerServerTiming = completion.routerServerTiming || null;
        this.yaoClientTimings = completion.clientTimings || null;
        this.state = completion;
        return completion.pending;
      }
      case 'pending':
        return this.state.pending;
      case 'disabled':
        throw new Error('Ed25519 Yao work was not requested');
      case 'failed':
        throw this.state.error;
      case 'committed':
        throw new Error('Ed25519 Yao registration is already committed');
      case 'disposed':
        throw new Error('Ed25519 Yao registration is disposed');
      default:
        return assertNever(this.state);
    }
  }

  async persistMaterial(
    args:
      | {
          kind: 'passkey';
          facts: RegistrationEd25519MaterialFacts;
          rpId: string;
          credentialIdB64u: string;
          passkeyPrfFirstB64u: string;
        }
      | {
          kind: 'email_otp';
          facts: RegistrationEd25519MaterialFacts;
          expectedOperationalPublicKey: string;
          providerSubject: string;
          sessionPolicy: {
            thresholdSessionId: string;
            expiresAtMs: number;
            remainingUses: number;
          };
        },
  ): Promise<RouterAbEd25519YaoActiveClientMetadataV1> {
    if (this.state.kind !== 'pending') {
      throw new Error('Ed25519 Yao registration must be pending before material persistence');
    }
    const pending = this.state.pending;
    let metadata: RouterAbEd25519YaoActiveClientMetadataV1;
    switch (args.kind) {
      case 'passkey':
        metadata = await persistPasskeyRegistrationEd25519Material({ pending, ...args });
        break;
      case 'email_otp':
        metadata = await persistEmailOtpRegistrationEd25519Material({ pending, ...args });
        if (pending instanceof EmailOtpEd25519YaoWorkerPendingRegistrationV1) {
          this.persistedEmailOtpActiveClient = pending.persistedActiveClient();
        }
        break;
      default:
        return assertNever(args);
    }
    this.state = { kind: 'committed' };
    return metadata;
  }

  persistedEmailOtpYaoActiveClient(): EmailOtpEd25519YaoWorkerActiveClientV1 {
    if (!this.persistedEmailOtpActiveClient) {
      throw new Error('Email OTP Ed25519 Yao registration active material is unavailable');
    }
    return this.persistedEmailOtpActiveClient;
  }

  releasePersistedEmailOtpYaoActiveClient(): void {
    this.persistedEmailOtpActiveClient = null;
  }

  async dispose(): Promise<void> {
    switch (this.state.kind) {
      case 'running': {
        const completion = await this.state.completion;
        if (completion.kind === 'pending') await completion.pending.dispose();
        this.state = { kind: 'disposed' };
        return;
      }
      case 'pending':
        await this.state.pending.dispose();
        this.state = { kind: 'disposed' };
        return;
      case 'disabled':
      case 'failed':
        this.state = { kind: 'disposed' };
        return;
      case 'committed':
        this.persistedEmailOtpActiveClient?.dispose();
        this.persistedEmailOtpActiveClient = null;
        return;
      case 'disposed':
        return;
      default:
        return assertNever(this.state);
    }
  }
}

/**
 * Starts deferred passkey Yao work from respond's admission, using the setup
 * challenge and the ceremony's carried bearer credential. Never awaited by
 * registration: the ECDSA wallet is already usable.
 */
export function startMixedRegistrationYaoWork(args: {
  intent: ReturnType<typeof requirePasskeyRegistrationIntent>;
  registrationIntentDigestB64u: string;
  signedSetup: string;
  registrationCeremonyId: string;
  passkeyAuthority: RegistrationPasskeyAuthority;
  deferredNear: WalletRegistrationRespondEd25519DeferredWork;
  relayerUrl: string;
  traceContext: RouterAbTraceContextV1;
}): RegistrationYaoWork {
  return RegistrationYaoWork.start({
    kind: 'verified_passkey_ed25519_yao_registration_input_v1',
    verifiedIntent: {
      kind: 'verified_passkey_registration_intent_v1',
      intent: args.intent,
      registrationIntentDigestB64u: args.registrationIntentDigestB64u,
      registrationBearerToken: args.signedSetup,
      registrationCeremonyId: args.registrationCeremonyId,
    },
    verifiedAuthority: {
      kind: 'verified_passkey_registration_authority_v1',
      walletId: args.intent.walletId,
      registrationIntentDigestB64u: args.registrationIntentDigestB64u,
      credentialIdB64u: String(
        args.passkeyAuthority.credential.rawId || args.passkeyAuthority.credential.id || '',
      ).trim(),
      ownedPasskeyPrfFirst: base64UrlDecode(args.passkeyAuthority.prfFirstB64u),
    },
    admissionRequest: args.deferredNear.admissionRequest,
    admissionReceipt: args.deferredNear.admissionReceipt,
    httpTransport: {
      kind: 'passkey_ed25519_yao_http_transport_v1',
      routerOrigin: new URL(args.relayerUrl).origin,
      fetch: globalThis.fetch,
      traceContext: args.traceContext,
    },
  });
}

function requireEmailOtpEd25519YaoPendingFactorHandle(
  material: EmailOtpRegistrationEnrollmentMaterial,
) {
  if (material.ed25519YaoFactor.kind !== 'issued') {
    throw new Error('Email OTP registration did not issue the required Ed25519 Yao factor');
  }
  return material.ed25519YaoFactor.pendingFactorHandle;
}

export function startEmailOtpRegistrationYaoWork(args: {
  recorder: RegistrationTimingRecorder;
  context: RegistrationWebContext;
  enrollmentMaterial: Promise<EmailOtpRegistrationEnrollmentMaterial> | null;
  deferredNear: WalletRegistrationRespondEd25519DeferredWork;
  walletId: string;
  providerSubject: string;
  registrationAuthorityId: string;
  signedSetup: string;
  registrationCeremonyId: string;
  relayerUrl: string;
}): RegistrationYaoWork {
  return RegistrationYaoWork.startPending(
    args.recorder.measure(
      'emailOtpYaoTotalMs',
      createEmailOtpRegistrationYaoPending.bind(undefined, args),
    ),
  );
}

async function createEmailOtpRegistrationYaoPending(args: {
  recorder: RegistrationTimingRecorder;
  context: RegistrationWebContext;
  enrollmentMaterial: Promise<EmailOtpRegistrationEnrollmentMaterial> | null;
  deferredNear: WalletRegistrationRespondEd25519DeferredWork;
  walletId: string;
  providerSubject: string;
  registrationAuthorityId: string;
  signedSetup: string;
  registrationCeremonyId: string;
  relayerUrl: string;
}): Promise<ProductEd25519YaoPendingRegistrationPortV1> {
  const material = await args.recorder.measure(
    'emailOtpYaoEnrollmentMaterialWaitMs',
    requireEmailOtpRegistrationEnrollmentMaterial.bind(undefined, {
      material: args.enrollmentMaterial,
      operation: 'Ed25519 Yao activation',
    }),
  );
  return args.recorder.measure(
    'emailOtpYaoWorkerRegistrationMs',
    startEmailOtpEd25519YaoWorkerRegistrationV1.bind(undefined, {
      kind: 'verified_email_otp_ed25519_yao_registration_worker_input_v1',
      workerContext: args.context.signingEngine.getSignerWorkerContext(),
      pendingFactorHandle: requireEmailOtpEd25519YaoPendingFactorHandle(material),
      admissionRequest: args.deferredNear.admissionRequest,
      admissionReceipt: args.deferredNear.admissionReceipt,
      walletId: args.walletId,
      providerSubject: args.providerSubject,
      registrationAuthorityId: args.registrationAuthorityId,
      registrationBearerToken: args.signedSetup,
      routerOrigin: args.relayerUrl,
      onYaoDiagnostics: recordEmailOtpRegistrationYaoDiagnostics.bind(undefined, args.recorder),
    }),
  );
}

function recordEmailOtpRegistrationYaoDiagnostics(
  recorder: RegistrationTimingRecorder,
  diagnostics: EmailOtpEd25519YaoRegistrationDiagnosticsV1,
): void {
  for (const [bucket, durationMs] of parseYaoServerTimingBuckets(diagnostics.routerServerTiming)) {
    recorder.record(bucket, durationMs);
  }
  if (!diagnostics.clientTimings) return;
  recorder.record('yaoAdmissionMs', diagnostics.clientTimings.admissionMs);
  recorder.record('yaoClientSessionCreateMs', diagnostics.clientTimings.sessionCreateMs);
}

export type RegistrationPasskeyAuthority = Awaited<
  ReturnType<typeof collectPasskeyRegistrationAuthority>
>;

export function requirePasskeyRegistrationIntent(
  intent: RegistrationIntentV1,
): RegistrationIntentV1 & {
  authMethod: Extract<RegistrationAuthMethodInput, { kind: 'passkey' }>;
} {
  if (intent.authMethod.kind !== 'passkey') {
    throw new Error('Ed25519 Yao registration requires a passkey registration intent');
  }
  return {
    version: intent.version,
    walletId: intent.walletId,
    authMethod: intent.authMethod,
    signerSelection: intent.signerSelection,
    ...(intent.runtimePolicyScope ? { runtimePolicyScope: intent.runtimePolicyScope } : {}),
    nonceB64u: intent.nonceB64u,
  };
}

export function requireEd25519YaoRegistrationPublicResultMatches(args: {
  clientPublicKey: string;
  finalized: Extract<
    WalletRegistrationFinalizeResponse,
    { kind: 'near_ed25519' | 'near_ed25519_and_evm_family_ecdsa' }
  >;
  expectedRpId: string;
  expectedWalletId: WalletId;
}): { rpId: string; credentialIdB64u: string } {
  if (args.finalized.authMethod.kind !== 'passkey' || args.finalized.rpId !== args.expectedRpId) {
    throw new Error('Ed25519 Yao finalize returned a different passkey authority');
  }
  if (args.finalized.walletId !== args.expectedWalletId) {
    throw new Error('Ed25519 Yao finalize returned a different wallet');
  }
  if (
    args.finalized.ed25519.publicKey !== args.clientPublicKey ||
    args.finalized.ed25519.nearEd25519SigningKeyId !==
      args.finalized.resolvedAccount.nearEd25519SigningKeyId ||
    args.finalized.ed25519.nearAccountId !== args.finalized.resolvedAccount.nearAccountId
  ) {
    throw new Error('Ed25519 Yao finalize returned mismatched signer identity');
  }
  return {
    rpId: args.finalized.rpId,
    credentialIdB64u: args.finalized.authMethod.credentialIdB64u,
  };
}

export function requireEmailOtpEd25519YaoRegistrationPublicResultMatches(args: {
  clientPublicKey: string;
  finalized: Extract<
    WalletRegistrationFinalizeResponse,
    { kind: 'near_ed25519' | 'near_ed25519_and_evm_family_ecdsa' }
  >;
  expectedRegistrationAuthorityId: string;
  expectedWalletId: WalletId;
}): void {
  if (
    args.finalized.authMethod.kind !== 'email_otp' ||
    args.finalized.authMethod.registrationAuthorityId !== args.expectedRegistrationAuthorityId
  ) {
    throw new Error('Ed25519 Yao finalize returned a different Email OTP authority');
  }
  if (args.finalized.walletId !== args.expectedWalletId) {
    throw new Error('Ed25519 Yao finalize returned a different wallet');
  }
  if (
    args.finalized.ed25519.publicKey !== args.clientPublicKey ||
    args.finalized.ed25519.nearEd25519SigningKeyId !==
      args.finalized.resolvedAccount.nearEd25519SigningKeyId ||
    args.finalized.ed25519.nearAccountId !== args.finalized.resolvedAccount.nearAccountId
  ) {
    throw new Error('Ed25519 Yao finalize returned mismatched signer identity');
  }
}
