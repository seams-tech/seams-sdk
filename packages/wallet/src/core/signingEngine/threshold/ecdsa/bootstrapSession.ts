import { base64UrlDecode } from '@shared/utils/base64';
import type { ThresholdEcdsaDerivationRouteAuth } from '@/core/rpcClients/relayer/thresholdEcdsa';
import type { WorkerOperationContext } from '../../workerManager/executeWorkerOperation';
import type { ThresholdWebAuthnPromptPort } from '../crypto/webauthn';
import {
  normalizeThresholdRuntimePolicyScope,
  type ThresholdRuntimePolicyScope,
} from '../sessionPolicy';
import type {
  EvmFamilyEcdsaKeyHandle,
  EvmFamilyEcdsaKeyIdentity,
  EvmFamilyEcdsaActivationLanePolicy,
} from '../../session/identity/evmFamilyEcdsaIdentity';
import type {
  RouterAbEcdsaDerivationPublicCapabilityV1,
  RouterAbEcdsaPostRegistrationSessionActivationResponseV1,
} from '@shared/utils/routerAbEcdsaDerivation';
import {
  adoptStrictEcdsaPostRegistrationSession,
  activateStrictEcdsaPostRegistrationSession,
  type ExistingEcdsaRoleLocalActivation,
} from './postRegistrationSessionActivation';
import { bytesToHex } from '../../chains/evm/bytes';
import { secureRandomId } from '@shared/utils/secureRandomId';
import type { PersistedEcdsaRoleLocalMaterial } from '../../session/material/ecdsaRoleLocalMaterialResolver';
import { computeEcdsaDerivationRoleLocalRelayerKeyId } from '@shared/threshold/ecdsaDerivationRoleLocalBootstrap';
import type {
  MpcWalletSigningQuotaId,
  EcdsaAuthorizationSessionId,
  WalletSessionAuthorizationId,
  WalletSessionId,
} from '@shared/authorization/capabilityKinds';
import { parseWalletSessionMintId } from '@shared/authorization/capabilityKinds';
import type {
  ActiveWalletSessionV1,
  WalletSessionOperationCredentialV1,
} from '@shared/device-linking/contracts';

type BootstrapEcdsaSessionBaseArgs = {
  touchIdPrompt: Pick<ThresholdWebAuthnPromptPort, 'getRpId'>;
  relayerUrl: string;
  requestId?: string;
  workerCtx: WorkerOperationContext;
};

type BootstrapEcdsaExactSessionArgsBase = BootstrapEcdsaSessionBaseArgs & {
  keyHandle: EvmFamilyEcdsaKeyHandle;
  key: EvmFamilyEcdsaKeyIdentity;
  lanePolicy: EvmFamilyEcdsaActivationLanePolicy;
  publicCapability: RouterAbEcdsaDerivationPublicCapabilityV1;
  existingRoleLocalMaterial: PersistedEcdsaRoleLocalMaterial;
  evmFamilySigningKeySlotId?: never;
  ecdsaThresholdKeyId?: never;
};

type BootstrapEcdsaExactSessionArgs = BootstrapEcdsaExactSessionArgsBase &
  (
    | {
        bootstrapAuth: Extract<
          ThresholdEcdsaDerivationRouteAuth,
          { kind: 'opaque_wallet_session' }
        >;
        sessionActivation?: never;
      }
    | {
        sessionActivation: RouterAbEcdsaPostRegistrationSessionActivationResponseV1;
        bootstrapAuth?: never;
      }
  );

type BootstrapEcdsaSessionFailure = {
  ok: false;
  code: string;
  message: string;
};

type BootstrapEcdsaSessionSuccessCommon = {
  ok: true;
  bootstrapKind: 'strict_post_registration';
  keygenSessionId: string;
  rpId: string;
  keyHandle: string;
  ecdsaThresholdKeyId: string;
  clientVerifyingShareB64u: string;
  thresholdEcdsaPublicKeyB64u: string;
  ethereumAddress: string;
  relayerKeyId: string;
  relayerVerifyingShareB64u: string;
  clientShareRetryCounter: number;
  relayerShareRetryCounter: number;
  participantIds: number[];
  chainId: number;
  thresholdSessionId: string;
  authorizationSessionId: EcdsaAuthorizationSessionId;
  authorizationId: WalletSessionAuthorizationId;
  walletSessionId: WalletSessionId;
  quotaId: MpcWalletSigningQuotaId;
  expiresAtMs: number;
  remainingUses: number;
  runtimePolicyScope: ThresholdRuntimePolicyScope;
  signingRootId: string;
  signingRootVersion: string;
  walletSession: ActiveWalletSessionV1;
  operationCredential: WalletSessionOperationCredentialV1;
  walletSessionToken: string;
  roleLocalActivation: ExistingEcdsaRoleLocalActivation;
  routerAbEcdsaDerivationNormalSigning: Awaited<
    ReturnType<typeof activateStrictEcdsaPostRegistrationSession>
  >['sessionActivation']['normal_signing'];
};

type BootstrapEcdsaPersistedRoleLocalSessionSuccess = BootstrapEcdsaSessionSuccessCommon & {
  secretSourceKind: 'persisted_role_local';
};

export type BootstrapEcdsaSessionResult =
  | BootstrapEcdsaPersistedRoleLocalSessionSuccess
  | BootstrapEcdsaSessionFailure;

async function bootstrapStrictExistingEcdsaSession(
  args: BootstrapEcdsaExactSessionArgs,
  rpId: string,
): Promise<BootstrapEcdsaPersistedRoleLocalSessionSuccess> {
  const runtimePolicyScope = normalizeThresholdRuntimePolicyScope(
    args.lanePolicy.runtimePolicyScope,
  );
  if (!runtimePolicyScope) {
    throw new Error('Strict ECDSA session activation requires runtimePolicyScope');
  }
  const strictInput = {
    workerCtx: args.workerCtx,
    publicCapability: args.publicCapability,
    persistedRoleLocalMaterial: args.existingRoleLocalMaterial,
    walletId: String(args.key.walletId),
    thresholdSessionId: args.lanePolicy.thresholdSessionId,
    ttlMs: args.lanePolicy.ttlMs,
    remainingUses: args.lanePolicy.remainingUses,
    runtimePolicyScope,
  };
  const strict = args.sessionActivation
    ? await adoptStrictEcdsaPostRegistrationSession({
        ...strictInput,
        sessionActivation: args.sessionActivation,
      })
    : await activateStrictEcdsaPostRegistrationSession({
        ...strictInput,
        walletSessionMintId: requireFreshWalletSessionMintId(),
        relayerUrl: args.relayerUrl,
        routeAuth: args.bootstrapAuth,
      });
  const capability = strict.sessionActivation.public_capability;
  const publicIdentity = capability.public_identity;
  const relayerKeyId = await computeEcdsaDerivationRoleLocalRelayerKeyId({
    walletId: String(args.key.walletId),
    signingRootId: args.key.signingRootId,
    signingRootVersion: args.key.signingRootVersion,
  });
  const common: BootstrapEcdsaSessionSuccessCommon = {
    ok: true,
    bootstrapKind: 'strict_post_registration',
    keygenSessionId:
      String(args.requestId || '').trim() ||
      secureRandomId('tecdsa-keygen', 32, 'threshold ECDSA session IDs'),
    rpId,
    keyHandle: String(args.keyHandle),
    ecdsaThresholdKeyId: String(args.key.ecdsaThresholdKeyId),
    clientVerifyingShareB64u: publicIdentity.derivation_client_share_public_key33_b64u,
    thresholdEcdsaPublicKeyB64u: publicIdentity.threshold_public_key33_b64u,
    ethereumAddress: bytesToHex(base64UrlDecode(publicIdentity.ethereum_address20_b64u)),
    relayerKeyId,
    relayerVerifyingShareB64u: publicIdentity.server_public_key33_b64u,
    clientShareRetryCounter: publicIdentity.client_share_retry_counter,
    relayerShareRetryCounter: publicIdentity.server_share_retry_counter,
    participantIds: args.key.participantIds.map(Number),
    chainId: args.lanePolicy.chainTarget.chainId,
    thresholdSessionId: strict.sessionActivation.session.threshold_session_id,
    authorizationSessionId: strict.sessionActivation.session.authorization_session_id,
    authorizationId: strict.sessionActivation.session.authorization_id,
    walletSessionId: strict.sessionActivation.session.wallet_session_id,
    quotaId: strict.sessionActivation.session.quota_id,
    expiresAtMs: strict.sessionActivation.session.expires_at_ms,
    remainingUses: strict.sessionActivation.session.remaining_uses,
    runtimePolicyScope,
    signingRootId: String(args.key.signingRootId),
    signingRootVersion: String(args.key.signingRootVersion),
    walletSession: strict.sessionActivation.session.wallet_session,
    operationCredential: strict.sessionActivation.session.operation_credential,
    walletSessionToken: strict.sessionActivation.session.operation_credential.token,
    roleLocalActivation: strict.roleLocalActivation,
    routerAbEcdsaDerivationNormalSigning: strict.sessionActivation.normal_signing,
  };
  return {
    ...common,
    secretSourceKind: 'persisted_role_local',
  };
}

function requireFreshWalletSessionMintId() {
  const parsed = parseWalletSessionMintId(
    secureRandomId('wallet-session-mint', 32, 'Wallet Session mint IDs'),
  );
  if (!parsed.ok) throw new Error('Failed to create Wallet Session mint identity');
  return parsed.value;
}

export async function bootstrapEcdsaSession(
  args: BootstrapEcdsaExactSessionArgs,
): Promise<BootstrapEcdsaSessionResult> {
  const rpId = args.touchIdPrompt.getRpId();
  if (!rpId) {
    return { ok: false, code: 'invalid_args', message: 'Missing rpId for WebAuthn' };
  }
  try {
    return await bootstrapStrictExistingEcdsaSession(args, rpId);
  } catch (error: unknown) {
    return {
      ok: false,
      code: 'strict_post_registration_failed',
      message: error instanceof Error ? error.message : String(error),
    };
  }
}
