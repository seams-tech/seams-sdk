import type { AccountId } from '@/core/types/accountIds';
import type { ResolveSelectedWalletAuthorityResultV1 } from '@/core/indexedDB/seamsWalletDB/repositories';
import { type VerifiedEcdsaPublicFacts } from '@/core/signingEngine/session/identity/evmFamilyEcdsaIdentity';
import type {
  ThresholdEcdsaChainTarget,
  WalletId,
  WalletSessionRef,
} from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import type { ThresholdRuntimePolicyScope } from '@/core/signingEngine/threshold/sessionPolicy';
import type { WorkerOperationContext } from '@/core/signingEngine/workerManager/executeWorkerOperation';
import type { ResolvedWalletCustodyEd25519ExportV1 } from './ed25519ExportContext';
import { throwEmailOtpSigningSessionAuthStateError } from './routePlan';
import {
  walletAuthAuthorityRef,
  type WalletAuthAuthorityRef,
} from '@shared/utils/walletAuthAuthority';
import {
  EMAIL_OTP_CHANNEL,
  WALLET_EMAIL_OTP_EXPORT_OPERATION,
  WALLET_EMAIL_OTP_TRANSACTION_SIGN_OPERATION,
  type WalletEmailOtpExportOperation,
  type WalletEmailOtpTransactionSignOperation,
} from '@shared/utils/emailOtpDomain';
import {
  buildEmailOtpRoutePlan,
  type EmailOtpRoutePlan,
  type EmailOtpSigningSessionAuthLane,
} from '@/core/signingEngine/stepUpConfirmation/otpPrompt/authLane';
import type {
  RequestEmailOtpChallengeArgs,
  RequestEmailOtpExportChallengeArgs,
} from './exportRecoveryRuntime';
import type {
  EmailOtpThresholdEcdsaExportPreparation,
  PrepareEmailOtpEcdsaExportCapabilityArgs,
} from './ecdsaLogin';
import type { EmailOtpWalletAuthAuthority } from '@shared/utils/walletAuthAuthority';
import { exportEcdsaDerivationKey } from '../../flows/recovery/ecdsaDerivationExport';
import type { EmailOtpChallengeDelivery, EmailOtpTransactionSigningChallenge } from './publicTypes';
import type { PersistedEcdsaRoleLocalMaterial } from '../material/ecdsaRoleLocalMaterialResolver';
import type { EcdsaExplicitExportOperationAuthorization } from '../../threshold/ecdsa/activation';
import { disposeWalletCustodyEd25519ActiveClientV1 } from '../../walletCustody/ed25519ActiveClient';
import type { EmailOtpEd25519YaoExportMaterialV1 } from '../../workerManager/workerTypes';
import type { DigestB64u } from '@shared/utils/canonicalPrimitives';

type EmailOtpEcdsaRouteChain = ThresholdEcdsaChainTarget['kind'];
type EmailOtpRouteChain = 'near' | EmailOtpEcdsaRouteChain;
export type EmailOtpSigningSessionChallengeOperation =
  | WalletEmailOtpTransactionSignOperation
  | WalletEmailOtpExportOperation;

export type EmailOtpEcdsaExportArtifact = {
  publicKeyHex: string;
  privateKeyHex: string;
  ethereumAddress: string;
};

type EmailOtpEcdsaExportLogin = (
  args: PrepareEmailOtpEcdsaExportCapabilityArgs,
) => Promise<EmailOtpThresholdEcdsaExportPreparation>;

type EmailOtpWorkerPorts = {
  getSignerWorkerContext: () => WorkerOperationContext | null | undefined;
  requireRelayUrl: () => string;
  requireSigningSessionSealGroupId: () => string;
  resolveSelectedWalletAuthority: (
    walletId: string,
  ) => Promise<ResolveSelectedWalletAuthorityResultV1>;
  buildSigningSessionRoutePlan: (args: {
    authLane: EmailOtpSigningSessionAuthLane;
    operation: EmailOtpSigningSessionChallengeOperation;
  }) => EmailOtpRoutePlan;
};

type EmailOtpChallengeAuthoritySelection =
  | { readonly kind: 'exact'; readonly walletAuthMethodId: string }
  | { readonly kind: 'canonical' };

async function resolveEmailOtpChallengeAuthoritySelection(
  ports: Pick<EmailOtpWorkerPorts, 'resolveSelectedWalletAuthority'>,
  walletId: WalletId,
): Promise<EmailOtpChallengeAuthoritySelection> {
  const selected = await ports.resolveSelectedWalletAuthority(String(walletId));
  if (selected.kind === 'missing_selection') return { kind: 'canonical' };
  if (selected.kind !== 'resolved') {
    throw new Error(`Email OTP challenge authority selection is unavailable: ${selected.kind}`);
  }
  if (selected.authMethod.kind !== 'email_otp') return { kind: 'canonical' };
  if (
    selected.authMethod.status !== 'active' ||
    selected.authority.state !== 'active' ||
    String(selected.authMethod.walletId) !== String(walletId) ||
    String(selected.authority.walletId) !== String(walletId) ||
    String(selected.authMethod.walletAuthorityId) !== String(selected.authority.authorityId)
  ) {
    throw new Error('Email OTP challenge selected authority is not active');
  }
  return {
    kind: 'exact',
    walletAuthMethodId: String(selected.authMethod.walletAuthMethodId),
  };
}

function emailOtpExpectedCurveForRouteChain(chain: EmailOtpRouteChain): 'ed25519' | 'ecdsa' {
  return chain === 'near' ? 'ed25519' : 'ecdsa';
}

function requireProvidedEmailOtpSigningSessionAuthLane(args: {
  authLane: EmailOtpSigningSessionAuthLane;
  chain: EmailOtpRouteChain;
  chainTarget?: ThresholdEcdsaChainTarget;
}): EmailOtpSigningSessionAuthLane {
  const authLane = args.authLane;
  if (authLane?.kind !== 'signing_session') {
    throwEmailOtpSigningSessionAuthStateError({
      kind: 'auth_lane_missing',
      source: 'provided_route_auth',
      expectedCurve: emailOtpExpectedCurveForRouteChain(args.chain),
    });
  }
  return authLane;
}

// The export operation is authorized by the discriminated branch and bound to
// the exact material activation. The record supplies transport only, so the
// check is that the route auth was derived from this very record's material.
async function requestEmailOtpChallengeWithRoutePlan(
  ports: Pick<
    EmailOtpWorkerPorts,
    'getSignerWorkerContext' | 'requireRelayUrl' | 'resolveSelectedWalletAuthority'
  >,
  args:
    | {
        kind: 'wallet_session';
        walletId: WalletId;
        routePlan: EmailOtpRoutePlan;
        operationFingerprintDigest?: DigestB64u;
      }
    | {
        kind: 'near_account';
        walletSession: WalletSessionRef;
        nearAccountId: AccountId;
        routePlan: EmailOtpRoutePlan;
        operationFingerprintDigest?: DigestB64u;
      },
): Promise<EmailOtpTransactionSigningChallenge> {
  const walletId = args.kind === 'wallet_session' ? args.walletId : args.walletSession.walletId;
  const relayUrl = ports.requireRelayUrl();
  const workerCtx = ports.getSignerWorkerContext();
  if (!workerCtx) {
    throw new Error('Email OTP signing requires the dedicated emailOtp worker');
  }
  const authoritySelection = await resolveEmailOtpChallengeAuthoritySelection(ports, walletId);
  const response = await workerCtx.requestWorkerOperation({
    kind: 'emailOtp',
    request: {
      type: 'requestEmailOtpChallenge',
      timeoutMs: 30_000,
      payload: {
        relayUrl,
        walletId: String(walletId),
        ...(authoritySelection.kind === 'exact'
          ? { walletAuthMethodId: authoritySelection.walletAuthMethodId }
          : {}),
        routePlan: args.routePlan,
        otpChannel: EMAIL_OTP_CHANNEL,
        ...(args.operationFingerprintDigest
          ? { operationFingerprintDigest: args.operationFingerprintDigest }
          : {}),
      },
    },
  });
  const challengeId = String(response.challengeId || '').trim();
  if (!challengeId) {
    throw new Error('Email OTP signing challenge response did not include challengeId');
  }
  const delivery: EmailOtpChallengeDelivery = response.delivery;
  return {
    challengeId,
    emailHint: delivery.emailHint,
    delivery,
  };
}

export async function requestTransactionSigningChallenge(
  ports: EmailOtpWorkerPorts,
  args: RequestEmailOtpChallengeArgs,
): Promise<EmailOtpTransactionSigningChallenge> {
  const routePlan = buildTransactionSigningChallengeRoutePlan(ports, args);
  const challenge =
    args.kind === 'near_account_challenge'
      ? await requestEmailOtpChallengeWithRoutePlan(ports, {
          kind: 'near_account',
          walletSession: args.walletSession,
          nearAccountId: args.nearAccountId,
          routePlan,
          ...(args.operationFingerprintDigest
            ? { operationFingerprintDigest: args.operationFingerprintDigest }
            : {}),
        })
      : args.kind === 'wallet_export_challenge'
        ? await requestEmailOtpChallengeWithRoutePlan(ports, {
            kind: 'wallet_session',
            walletId: args.walletId,
            routePlan,
          })
        : await requestEmailOtpChallengeWithRoutePlan(ports, {
            kind: 'wallet_session',
            walletId: args.walletSession.walletId,
            routePlan,
            ...(args.operationFingerprintDigest
              ? { operationFingerprintDigest: args.operationFingerprintDigest }
              : {}),
          });
  return challenge;
}

function buildTransactionSigningChallengeRoutePlan(
  ports: EmailOtpWorkerPorts,
  args: RequestEmailOtpChallengeArgs,
): EmailOtpRoutePlan {
  switch (args.kind) {
    case 'wallet_login_challenge':
      return buildEmailOtpRoutePlan({
        routeFamily: 'login',
        operation: WALLET_EMAIL_OTP_TRANSACTION_SIGN_OPERATION,
      });
    case 'wallet_session_challenge':
    case 'near_account_challenge':
      return ports.buildSigningSessionRoutePlan({
        authLane: requireProvidedEmailOtpSigningSessionAuthLane({
          authLane: args.authLane,
          chain: args.chain,
        }),
        operation: WALLET_EMAIL_OTP_TRANSACTION_SIGN_OPERATION,
      });
    case 'wallet_export_challenge':
      throw new Error('Email OTP export challenge cannot authorize transaction signing');
  }
}

export async function requestExportChallenge(
  ports: EmailOtpWorkerPorts,
  args: RequestEmailOtpExportChallengeArgs,
): Promise<EmailOtpTransactionSigningChallenge> {
  const routePlan = buildExportChallengeRoutePlan(ports, args);
  const challenge =
    args.kind === 'near_account_challenge'
      ? await requestEmailOtpChallengeWithRoutePlan(ports, {
          kind: 'near_account',
          walletSession: args.walletSession,
          nearAccountId: args.nearAccountId,
          routePlan,
        })
      : args.kind === 'wallet_export_challenge'
        ? await requestEmailOtpChallengeWithRoutePlan(ports, {
            kind: 'wallet_session',
            walletId: args.walletId,
            routePlan,
          })
        : await requestEmailOtpChallengeWithRoutePlan(ports, {
            kind: 'wallet_session',
            walletId: args.walletSession.walletId,
            routePlan,
          });
  return challenge;
}

function buildExportChallengeRoutePlan(
  ports: EmailOtpWorkerPorts,
  args: RequestEmailOtpExportChallengeArgs,
): EmailOtpRoutePlan {
  switch (args.kind) {
    case 'wallet_login_challenge':
      return buildEmailOtpRoutePlan({
        routeFamily: 'login',
        operation: WALLET_EMAIL_OTP_EXPORT_OPERATION,
      });
    case 'wallet_session_challenge':
    case 'near_account_challenge':
      return ports.buildSigningSessionRoutePlan({
        authLane: requireProvidedEmailOtpSigningSessionAuthLane({
          authLane: args.authLane,
          chain: args.chain,
        }),
        operation: WALLET_EMAIL_OTP_EXPORT_OPERATION,
      });
    case 'wallet_export_challenge':
      return buildEmailOtpRoutePlan({
        routeFamily: 'login',
        operation: WALLET_EMAIL_OTP_EXPORT_OPERATION,
      });
  }
}

function buildEcdsaExportVerificationRoutePlan(
  authorization: EcdsaExplicitExportOperationAuthorization,
): EmailOtpRoutePlan {
  return buildEmailOtpRoutePlan({
    routeFamily: 'login',
    operation: WALLET_EMAIL_OTP_EXPORT_OPERATION,
  });
}

function emailOtpEd25519WorkerExportMaterial(
  context: ResolvedWalletCustodyEd25519ExportV1,
): EmailOtpEd25519YaoExportMaterialV1 {
  switch (context.material.kind) {
    case 'active_capability':
      return context.material;
    case 'sealed_custody':
      return {
        kind: 'sealed_custody',
        materialActivation: context.material.materialActivation,
        walletCustodyEd25519Material: context.material.walletCustodyEd25519Material,
        bootstrap: context.material.bootstrap,
      };
    case 'sealed_export_root':
      return {
        kind: 'sealed_export_root',
        materialActivation: context.material.materialActivation,
        capability: context.material.capability,
        exportRootEnvelope: context.material.exportRootEnvelope,
      };
    default:
      context.material satisfies never;
      throw new Error('Email OTP Ed25519 export material is invalid');
  }
}

export async function exportEd25519YaoSeedWithFreshEmailOtpLane(
  ports: Pick<EmailOtpWorkerPorts, 'getSignerWorkerContext' | 'requireRelayUrl'>,
  args: {
    challengeId: string;
    otpCode: string;
    exportContext: ResolvedWalletCustodyEd25519ExportV1;
  },
): Promise<{ artifactKind: 'near-ed25519-seed-v1'; publicKey: string; privateKey: string }> {
  const workerCtx = ports.getSignerWorkerContext();
  if (!workerCtx) {
    throw new Error('Email OTP Ed25519 Yao export requires the dedicated emailOtp worker');
  }
  const relayUrl = ports.requireRelayUrl();
  const walletId = args.exportContext.lane.signer.account.wallet.walletId;
  const result = await workerCtx.requestWorkerOperation({
    kind: 'emailOtp',
    request: {
      type: 'exportEmailOtpEd25519YaoSeed',
      timeoutMs: 60_000,
      payload: {
        relayUrl,
        challengeId: args.challengeId,
        otpCode: args.otpCode,
        lane: {
          walletId: String(walletId),
          providerSubjectId: args.exportContext.lane.auth.providerSubjectId,
          walletAuthMethodId: String(args.exportContext.authorization.record.authMethodId),
          nearAccountId: String(args.exportContext.lane.signer.account.nearAccountId),
          nearEd25519SigningKeyId: String(args.exportContext.lane.signer.nearEd25519SigningKeyId),
          signerSlot: args.exportContext.lane.signer.signerSlot,
        },
        material: emailOtpEd25519WorkerExportMaterial(args.exportContext),
      },
    },
  });
  switch (result.kind) {
    case 'exported':
      return result;
    case 'exported_and_rehydrated':
      if (args.exportContext.material.kind !== 'sealed_custody') {
        await disposeWalletCustodyEd25519ActiveClientV1({
          workerContext: workerCtx,
          activeClientHandle: result.activeClientHandle,
        }).catch(() => undefined);
        throw new Error('Email OTP Ed25519 export returned unexpected recovered material');
      }
      try {
        await args.exportContext.material.activateRecoveredCapability({
          activation: {
            activeClientHandle: result.activeClientHandle,
            metadata: result.metadata,
            bootstrap: result.bootstrap,
          },
          operationCredential: args.exportContext.authorization.operationCredential,
        });
      } catch (error) {
        await disposeWalletCustodyEd25519ActiveClientV1({
          workerContext: workerCtx,
          activeClientHandle: result.activeClientHandle,
        }).catch(() => undefined);
        throw error;
      }
      return result;
    default:
      result satisfies never;
      throw new Error('Email OTP Ed25519 export returned an invalid result');
  }
}

export async function exportEcdsaKeyWithDurableAuthorization(
  ports: Pick<EmailOtpWorkerPorts, 'getSignerWorkerContext' | 'requireRelayUrl'>,
  args: {
    walletSession: WalletSessionRef;
    chainTarget: ThresholdEcdsaChainTarget;
    challengeId: string;
    otpCode: string;
    publicFacts: VerifiedEcdsaPublicFacts;
    runtimePolicyScope: ThresholdRuntimePolicyScope;
    authority: EmailOtpWalletAuthAuthority;
    persistedMaterial: PersistedEcdsaRoleLocalMaterial;
    explicitExportAuthorization: EcdsaExplicitExportOperationAuthorization;
    prepareEcdsaExportCapability: EmailOtpEcdsaExportLogin;
  },
): Promise<EmailOtpEcdsaExportArtifact> {
  const routePlan = buildEcdsaExportVerificationRoutePlan(args.explicitExportAuthorization);
  return await exportEcdsaKeyWithFreshLoginAuthorization({
    walletSession: args.walletSession,
    authority: await walletAuthAuthorityRef({ authority: args.authority }),
    chainTarget: args.chainTarget,
    challengeId: args.challengeId,
    otpCode: args.otpCode,
    routePlan,
    keyHandle: String(args.publicFacts.keyHandle),
    participantIds: args.publicFacts.participantIds.map(Number),
    emailHashHex: args.authority.verifier.emailHashHex,
    provider: args.authority.factor.provider,
    providerUserId: args.authority.factor.providerUserId,
    runtimePolicyScope: args.runtimePolicyScope,
    relayUrl: ports.requireRelayUrl(),
    getSignerWorkerContext: ports.getSignerWorkerContext,
    prepareEcdsaExportCapability: args.prepareEcdsaExportCapability,
    persistedMaterial: args.persistedMaterial,
    explicitExportAuthorization: args.explicitExportAuthorization,
  });
}

type ExportEcdsaKeyWithFreshLoginAuthorizationArgs = {
  walletSession: WalletSessionRef;
  authority: WalletAuthAuthorityRef;
  chainTarget: ThresholdEcdsaChainTarget;
  challengeId: string;
  otpCode: string;
  routePlan: EmailOtpRoutePlan;
  keyHandle: string;
  participantIds: number[];
  emailHashHex: string;
  provider: 'google' | 'email';
  providerUserId: string;
  runtimePolicyScope: ThresholdRuntimePolicyScope;
  relayUrl: string;
  getSignerWorkerContext: EmailOtpWorkerPorts['getSignerWorkerContext'];
  prepareEcdsaExportCapability: EmailOtpEcdsaExportLogin;
  persistedMaterial: PersistedEcdsaRoleLocalMaterial;
  explicitExportAuthorization: EcdsaExplicitExportOperationAuthorization;
};

async function exportEcdsaKeyWithFreshLoginAuthorization(
  args: ExportEcdsaKeyWithFreshLoginAuthorizationArgs,
): Promise<EmailOtpEcdsaExportArtifact> {
  const result = await args.prepareEcdsaExportCapability({
    walletSession: args.walletSession,
    authoritySelector: {
      kind: 'wallet_auth_method',
      walletAuthMethodId: String(args.authority.walletAuthMethodId),
    },
    chainTarget: args.chainTarget,
    relayUrl: args.relayUrl,
    emailOtpAuthPolicy: 'per_operation',
    emailOtpAuthReason: 'sign',
    challengeId: args.challengeId,
    otpCode: args.otpCode,
    operation: WALLET_EMAIL_OTP_EXPORT_OPERATION,
    routePlan: args.routePlan,
    ecdsaBootstrapAuthorization: { kind: 'route_plan_auth' },
    keyHandle: args.keyHandle,
    participantIds: args.participantIds,
    remainingUses: 1,
    emailHashHex: args.emailHashHex,
    providerIdentity: {
      kind: 'explicit_provider_user',
      provider: args.provider,
      providerUserId: args.providerUserId,
    },
    runtimePolicyScope: args.runtimePolicyScope,
    ed25519YaoRecovery: { kind: 'not_requested' },
    persistedExportMaterial: args.persistedMaterial,
    explicitExportAuthorization: args.explicitExportAuthorization,
  });
  const workerCtx = args.getSignerWorkerContext();
  if (!workerCtx) {
    throw new Error('Email OTP ECDSA export requires the dedicated signer worker');
  }
  return await exportEcdsaDerivationKey(
    { getSignerWorkerContext: () => workerCtx },
    {
      walletSessionUserId: args.walletSession.walletSessionUserId,
      exportProvision: result.bootstrap,
      factorAuthorization: { kind: 'email_otp_verified' },
    },
  );
}
