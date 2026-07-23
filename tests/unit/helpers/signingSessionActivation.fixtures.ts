import {
  buildEmailOtpWorkerIssuedSessionHandle,
  buildRelayerKeyId,
  type EcdsaRoleLocalReadyRecord,
  type EmailOtpWorkerIssuedSessionHandle,
} from '@/core/platform';
import type {
  ThresholdEcdsaChainTarget,
  WalletId,
} from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import type { EmailOtpAuthSubjectId } from '@/core/signingEngine/session/identity/emailOtpEcdsaDerivationIdentity';
import type { RpId } from '@/core/signingEngine/session/identity/evmFamilyEcdsaIdentity';
import { SigningSessionIds } from '@/core/signingEngine/session/operationState/types';
import { buildEcdsaRoleLocalPasskeyAuthMethod } from '@/core/signingEngine/session/persistence/ecdsaRoleLocalRecords';
import type { ThresholdEcdsaActivationChain } from '@/core/signingEngine/threshold/ecdsa/activation';
import type {
  Ed25519RelayerKeyId,
  SigningSessionActivationEmailOtpEcdsaAuth,
  SigningSessionActivationEmailOtpEd25519Auth,
  SigningSessionActivationMaterial,
  SigningSessionActivationPasskeyAuth,
} from '@/core/signingEngine/useCases/lifecycle';
import type { EvmFamilySigningKeySlotId } from '@shared/signing-lanes';
import { createThresholdEcdsaBootstrapFixture } from './ecdsaBootstrap.fixtures';

type EmailOtpWorkerSessionOperation = 'registration' | 'wallet_unlock' | 'sign' | 'export';

export type Ed25519SigningSessionActivationMaterial = Extract<
  SigningSessionActivationMaterial,
  { kind: 'ed25519_session' }
>;

export type EcdsaSigningSessionActivationMaterial = Extract<
  SigningSessionActivationMaterial,
  { kind: 'ecdsa_session' }
>;

function ed25519WorkerHandle(
  handle: EmailOtpWorkerIssuedSessionHandle,
): Extract<EmailOtpWorkerIssuedSessionHandle, { action: 'threshold_ed25519_session' }> {
  if (handle.action !== 'threshold_ed25519_session') {
    throw new Error('Activation fixture expected an Ed25519 worker handle');
  }
  return handle;
}

function ecdsaWorkerHandle(
  handle: EmailOtpWorkerIssuedSessionHandle,
): Extract<EmailOtpWorkerIssuedSessionHandle, { action: 'threshold_ecdsa_bootstrap' }> {
  if (handle.action !== 'threshold_ecdsa_bootstrap') {
    throw new Error('Activation fixture expected an ECDSA worker handle');
  }
  return handle;
}

export function seedSigningSessionActivationPasskeyAuth(args: {
  walletId: WalletId;
  rpId: RpId;
  credentialIdB64u?: string;
}): SigningSessionActivationPasskeyAuth {
  const authMethod = buildEcdsaRoleLocalPasskeyAuthMethod({
    credentialIdB64u: args.credentialIdB64u || 'credential-passkey',
    rpId: args.rpId,
  });
  return {
    kind: 'passkey',
    walletId: args.walletId,
    rpId: args.rpId,
    credentialIdB64u: authMethod.credentialIdB64u,
  };
}

export function seedSigningSessionActivationEmailOtpEd25519Auth(args: {
  walletId: WalletId;
  rpId: RpId;
  authSubjectId: EmailOtpAuthSubjectId;
  sessionId?: string;
  operation?: EmailOtpWorkerSessionOperation;
}): SigningSessionActivationEmailOtpEd25519Auth {
  return {
    kind: 'email_otp',
    walletId: args.walletId,
    rpId: args.rpId,
    authSubjectId: args.authSubjectId,
    workerHandle: ed25519WorkerHandle(
      buildEmailOtpWorkerIssuedSessionHandle({
        sessionId: args.sessionId || 'email-ed25519-session',
        walletId: args.walletId,
        rpId: args.rpId,
        authSubjectId: args.authSubjectId,
        action: 'threshold_ed25519_session',
        operation: args.operation || 'wallet_unlock',
      }),
    ),
  };
}

export function seedSigningSessionActivationEmailOtpEcdsaAuth(args: {
  walletId: WalletId;
  evmFamilySigningKeySlotId: EvmFamilySigningKeySlotId;
  authSubjectId: EmailOtpAuthSubjectId;
  chainTarget: ThresholdEcdsaChainTarget;
  sessionId?: string;
  operation?: EmailOtpWorkerSessionOperation;
}): SigningSessionActivationEmailOtpEcdsaAuth {
  return {
    kind: 'email_otp',
    walletId: args.walletId,
    evmFamilySigningKeySlotId: args.evmFamilySigningKeySlotId,
    authSubjectId: args.authSubjectId,
    workerHandle: ecdsaWorkerHandle(
      buildEmailOtpWorkerIssuedSessionHandle({
        sessionId: args.sessionId || 'email-ecdsa-session',
        walletId: args.walletId,
        evmFamilySigningKeySlotId: args.evmFamilySigningKeySlotId,
        authSubjectId: args.authSubjectId,
        action: 'threshold_ecdsa_bootstrap',
        operation: args.operation || 'wallet_unlock',
        chainTarget: args.chainTarget,
      }),
    ),
  };
}

export function seedEd25519SigningSessionActivationMaterial(
  overrides: Partial<Ed25519SigningSessionActivationMaterial> = {},
): Ed25519SigningSessionActivationMaterial {
  return {
    kind: 'ed25519_session',
    thresholdSessionId: SigningSessionIds.thresholdEd25519Session('threshold-ed25519-session'),
    signingGrantId: SigningSessionIds.signingGrant('signing-grant'),
    relayerKeyId: buildRelayerKeyId('ed25519-relayer') as Ed25519RelayerKeyId,
    ...overrides,
  };
}

export function seedEcdsaSigningSessionActivationMaterial(
  args: { record: EcdsaRoleLocalReadyRecord } & Partial<
    Pick<EcdsaSigningSessionActivationMaterial, 'thresholdSessionId' | 'signingGrantId'>
  >,
): EcdsaSigningSessionActivationMaterial {
  return {
    kind: 'ecdsa_session',
    thresholdSessionId:
      args.thresholdSessionId ?? SigningSessionIds.thresholdEcdsaSession('threshold-ecdsa-session'),
    signingGrantId: args.signingGrantId ?? SigningSessionIds.signingGrant('signing-grant'),
    record: args.record,
  };
}

/**
 * ECDSA role-local ready record for signing-session activation, built through
 * the shared bootstrap fixture (production `buildEcdsaRoleLocalReadyRecord` /
 * `buildEcdsaRoleLocalPublicFacts` paths). The record's
 * `evmFamilySigningKeySlotId` derives from walletId + signingRootId +
 * signingRootVersion exactly as production derives it.
 */
export function seedActivationEcdsaRoleLocalReadyRecord(args: {
  walletId: WalletId;
  authMethod: 'passkey' | 'email_otp';
  signingRootId?: string;
  signingRootVersion?: string;
  credentialIdB64u?: string;
  rpId?: RpId;
  authSubjectId?: EmailOtpAuthSubjectId;
  chain?: ThresholdEcdsaActivationChain;
}): EcdsaRoleLocalReadyRecord {
  const bootstrap = createThresholdEcdsaBootstrapFixture({
    nearAccountId: String(args.walletId),
    chain: args.chain || 'tempo',
    signingRootId: args.signingRootId ?? 'root',
    signingRootVersion: args.signingRootVersion ?? 'v1',
    roleLocalAuthMethod: args.authMethod,
    ...(args.authMethod === 'passkey'
      ? {
          passkeyCredentialIdB64u: args.credentialIdB64u || 'credential-passkey',
          rpId: String(args.rpId || 'wallet.example'),
        }
      : {
          emailOtpAuthSubjectId: String(args.authSubjectId || 'google:alice'),
        }),
  });
  const backendBinding = bootstrap.thresholdEcdsaKeyRef.backendBinding;
  if (backendBinding?.materialKind !== 'role_local_ready_state_blob') {
    throw new Error('Activation fixture requires a role-local ready ECDSA backend binding');
  }
  return backendBinding.ecdsaRoleLocalReadyRecord;
}
