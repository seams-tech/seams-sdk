import { base64UrlDecode, base64UrlEncode } from '@shared/utils/base64';
import type { WebAuthnAuthenticationCredential } from '@/core/types/webauthn';
import type { ThresholdEcdsaDerivationRouteAuth } from '@/core/rpcClients/relayer/thresholdEcdsa';
import type { WorkerOperationContext } from '../../workerManager/executeWorkerOperation';
import type { ThresholdCredentialStorePort, ThresholdWebAuthnPromptPort } from '../crypto/webauthn';
import {
  normalizeThresholdRuntimePolicyScope,
  type ThresholdRuntimePolicyScope,
} from '../sessionPolicy';
import type {
  EvmFamilyEcdsaKeyHandle,
  EvmFamilyEcdsaKeyIdentity,
  EvmFamilyEcdsaSessionLanePolicy,
} from '../../session/identity/evmFamilyEcdsaIdentity';
import type { ThresholdEcdsaChainTarget } from '../../interfaces/ecdsaChainTarget';
import type { EmailOtpWorkerIssuedSessionHandle } from '@/core/platform/types';
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
  SeamsSessionId,
  WalletSessionId,
} from '@shared/authorization/capabilityKinds';
import { parseReusableWalletSessionMintId } from '@shared/authorization/capabilityKinds';

type BootstrapEcdsaSessionBaseArgs = {
  credentialStore: ThresholdCredentialStorePort;
  touchIdPrompt: ThresholdWebAuthnPromptPort;
  relayerUrl: string;
  userId: string;
  chainTarget: ThresholdEcdsaChainTarget;
  participantIds?: number[];
  sessionKind?: 'jwt';
  requestId?: string;
  runtimePolicyScope?: ThresholdRuntimePolicyScope;
  runtimeScopeBootstrap?: {
    projectEnvironmentId: string;
    publishableKey: string;
  };
  ttlMs?: number;
  remainingUses?: number;
  workerCtx: WorkerOperationContext;
};

type BootstrapEcdsaPasskeyPromptAuthArgs = {
  authKind: 'passkey_prompt';
  passkeyPrfFirst32?: never;
  passkeyPrfFirstB64u?: never;
  passkeyCredentialIdB64u?: never;
  emailOtpWorkerSessionHandle?: never;
  webauthnAuthentication?: never;
};

type BootstrapEcdsaPasskeyWebAuthnAuthArgs = {
  authKind: 'passkey_webauthn';
  webauthnAuthentication: WebAuthnAuthenticationCredential;
  passkeyPrfFirst32?: never;
  passkeyPrfFirstB64u?: never;
  passkeyCredentialIdB64u?: never;
  emailOtpWorkerSessionHandle?: never;
};

type BootstrapEcdsaPasskeyWebAuthnPrfB64uAuthArgs = {
  authKind: 'passkey_webauthn_prf_b64u';
  webauthnAuthentication: WebAuthnAuthenticationCredential;
  passkeyPrfFirstB64u: string;
  passkeyPrfFirst32?: never;
  passkeyCredentialIdB64u?: never;
  emailOtpWorkerSessionHandle?: never;
};

type BootstrapEcdsaPasskeyPrfB64uAuthArgs = {
  authKind: 'passkey_prf_b64u';
  passkeyPrfFirstB64u: string;
  passkeyCredentialIdB64u: string;
  passkeyPrfFirst32?: never;
  emailOtpWorkerSessionHandle?: never;
  webauthnAuthentication?: never;
};

type BootstrapEcdsaPasskeyPrfBytesAuthArgs = {
  authKind: 'passkey_prf_bytes';
  passkeyPrfFirst32: Uint8Array;
  passkeyCredentialIdB64u: string;
  passkeyPrfFirstB64u?: never;
  emailOtpWorkerSessionHandle?: never;
  webauthnAuthentication?: never;
};

type BootstrapEcdsaEmailOtpAuthArgs = {
  authKind: 'email_otp';
  emailOtpWorkerSessionHandle: Extract<
    EmailOtpWorkerIssuedSessionHandle,
    { action: 'threshold_ecdsa_bootstrap' }
  >;
  passkeyPrfFirst32?: never;
  passkeyPrfFirstB64u?: never;
  passkeyCredentialIdB64u?: never;
  webauthnAuthentication?: never;
};

export type BootstrapEcdsaSessionAuthArgs =
  | BootstrapEcdsaPasskeyPromptAuthArgs
  | BootstrapEcdsaPasskeyWebAuthnAuthArgs
  | BootstrapEcdsaPasskeyWebAuthnPrfB64uAuthArgs
  | BootstrapEcdsaPasskeyPrfB64uAuthArgs
  | BootstrapEcdsaPasskeyPrfBytesAuthArgs
  | BootstrapEcdsaEmailOtpAuthArgs;

type BootstrapEcdsaExactSessionArgsBase = BootstrapEcdsaSessionBaseArgs &
  BootstrapEcdsaSessionAuthArgs & {
    keyHandle: EvmFamilyEcdsaKeyHandle;
    key: EvmFamilyEcdsaKeyIdentity;
    lanePolicy: EvmFamilyEcdsaSessionLanePolicy;
    publicCapability: RouterAbEcdsaDerivationPublicCapabilityV1;
    existingRoleLocalMaterial: PersistedEcdsaRoleLocalMaterial;
    evmFamilySigningKeySlotId?: never;
    ecdsaThresholdKeyId?: never;
    sessionId?: never;
    signingGrantId?: never;
  };

type BootstrapEcdsaExactSessionArgs = BootstrapEcdsaExactSessionArgsBase &
  (
    | {
        bootstrapAuth: Extract<ThresholdEcdsaDerivationRouteAuth, { kind: 'wallet_session' }>;
        sessionActivation?: never;
      }
    | {
        sessionActivation: RouterAbEcdsaPostRegistrationSessionActivationResponseV1;
        bootstrapAuth?: never;
      }
  );

type BootstrapEcdsaSessionArgs = BootstrapEcdsaExactSessionArgs;

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
  sessionId: string;
  signingGrantId: string;
  authorizationSessionId: SeamsSessionId;
  walletSessionId: WalletSessionId;
  quotaId: MpcWalletSigningQuotaId;
  expiresAtMs: number;
  remainingUses: number;
  runtimePolicyScope: ThresholdRuntimePolicyScope;
  signingRootId: string;
  signingRootVersion: string;
  jwt: string;
  roleLocalActivation: ExistingEcdsaRoleLocalActivation;
  routerAbEcdsaDerivationNormalSigning: Awaited<
    ReturnType<typeof activateStrictEcdsaPostRegistrationSession>
  >['sessionActivation']['normal_signing'];
};

type BootstrapEcdsaPasskeySessionSuccess = BootstrapEcdsaSessionSuccessCommon & {
  secretSourceKind: 'passkey';
  passkeyPrfFirstB64u: string;
  passkeyCredentialIdB64u: string;
};

type BootstrapEcdsaEmailOtpSessionSuccess = BootstrapEcdsaSessionSuccessCommon & {
  secretSourceKind: 'email_otp';
  passkeyPrfFirstB64u?: never;
  passkeyCredentialIdB64u?: never;
};

export type BootstrapEcdsaSessionResult =
  | BootstrapEcdsaPasskeySessionSuccess
  | BootstrapEcdsaEmailOtpSessionSuccess
  | BootstrapEcdsaSessionFailure;

function credentialIdFromCredential(credential: WebAuthnAuthenticationCredential): string {
  const credentialId = String(credential.rawId || credential.id || '').trim();
  if (!credentialId) {
    throw new Error('Strict passkey ECDSA activation requires a credential id');
  }
  return credentialId;
}

function strictPasskeyMaterial(
  args: BootstrapEcdsaExactSessionArgs,
): { passkeyPrfFirstB64u: string; passkeyCredentialIdB64u: string } | null {
  switch (args.authKind) {
    case 'passkey_prf_bytes':
      return {
        passkeyPrfFirstB64u: base64UrlEncode(args.passkeyPrfFirst32),
        passkeyCredentialIdB64u: args.passkeyCredentialIdB64u,
      };
    case 'passkey_prf_b64u':
      return {
        passkeyPrfFirstB64u: args.passkeyPrfFirstB64u,
        passkeyCredentialIdB64u: args.passkeyCredentialIdB64u,
      };
    case 'passkey_webauthn_prf_b64u':
      return {
        passkeyPrfFirstB64u: args.passkeyPrfFirstB64u,
        passkeyCredentialIdB64u: credentialIdFromCredential(args.webauthnAuthentication),
      };
    case 'passkey_prompt':
    case 'passkey_webauthn':
      throw new Error('Strict passkey ECDSA activation requires PRF.first material');
    case 'email_otp':
      return null;
  }
  args satisfies never;
  throw new Error('Strict ECDSA activation auth kind is invalid');
}

async function bootstrapStrictExistingEcdsaSession(
  args: BootstrapEcdsaExactSessionArgs,
  rpId: string,
): Promise<BootstrapEcdsaPasskeySessionSuccess | BootstrapEcdsaEmailOtpSessionSuccess> {
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
        walletSessionMintId: requireFreshReusableWalletSessionMintId(),
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
    sessionId: strict.sessionActivation.session.threshold_session_id,
    signingGrantId: strict.sessionActivation.session.signing_grant_id,
    authorizationSessionId: strict.sessionActivation.session.authorization_session_id,
    walletSessionId: strict.sessionActivation.session.wallet_session_id,
    quotaId: strict.sessionActivation.session.quota_id,
    expiresAtMs: strict.sessionActivation.session.expires_at_ms,
    remainingUses: strict.sessionActivation.session.remaining_uses,
    runtimePolicyScope,
    signingRootId: String(args.key.signingRootId),
    signingRootVersion: String(args.key.signingRootVersion),
    jwt: strict.sessionActivation.session.wallet_session_jwt,
    roleLocalActivation: strict.roleLocalActivation,
    routerAbEcdsaDerivationNormalSigning: strict.sessionActivation.normal_signing,
  };
  const passkeyMaterial = strictPasskeyMaterial(args);
  return passkeyMaterial
    ? {
        ...common,
        secretSourceKind: 'passkey',
        passkeyPrfFirstB64u: passkeyMaterial.passkeyPrfFirstB64u,
        passkeyCredentialIdB64u: passkeyMaterial.passkeyCredentialIdB64u,
      }
    : {
        ...common,
        secretSourceKind: 'email_otp',
      };
}

function requireFreshReusableWalletSessionMintId() {
  const parsed = parseReusableWalletSessionMintId(
    secureRandomId('wallet-session-mint', 32, 'reusable Wallet Session mint IDs'),
  );
  if (!parsed.ok) throw new Error('Failed to create reusable Wallet Session mint identity');
  return parsed.value;
}

export async function bootstrapEcdsaSession(
  args: BootstrapEcdsaSessionArgs,
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
