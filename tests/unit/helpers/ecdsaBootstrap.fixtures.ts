import type {
  ThresholdEcdsaActivationChain,
  ThresholdEcdsaSessionBootstrapResult,
} from '@/core/signingEngine/threshold/ecdsa/activation';
import { parseEcdsaThresholdKeyId } from '@/core/signingEngine/session/keyMaterialBrands';
import {
  toWalletId,
  type ThresholdEcdsaChainTarget,
} from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import {
  buildEcdsaRoleLocalEmailOtpAuthMethod,
  buildEcdsaRoleLocalPasskeyAuthMethod,
  buildEcdsaRoleLocalPublicFacts,
  buildEcdsaRoleLocalReadyRecord,
} from '@/core/signingEngine/session/persistence/ecdsaRoleLocalRecords';
import type { ThresholdRuntimePolicyScope } from '@/core/signingEngine/threshold/sessionPolicy';
import { deriveEvmFamilySigningKeySlotId } from '@shared/signing-lanes';
import { ROUTER_AB_ECDSA_DERIVATION_WALLET_SESSION_JWT_KIND } from '@shared/utils/sessionTokens';
import {
  parseRouterAbEcdsaDerivationPublicCapabilityV1,
  ROUTER_AB_ECDSA_DERIVATION_NORMAL_SIGNING_STATE_KIND_V1,
  type RouterAbEcdsaDerivationPublicCapabilityV1,
  type RouterAbEcdsaDerivationNormalSigningStateV1,
} from '@shared/utils/routerAbEcdsaDerivation';
import { testEcdsaChainId, testEcdsaChainTarget } from './ecdsaChainTarget.fixtures';

const VALID_ECDSA_PUBLIC_KEY_B64U = 'AgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA';
const VALID_ECDSA_RELAYER_PUBLIC_KEY_B64U = 'AwAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA';
const VALID_ECDSA_SHARE32_B64U = 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA';

function hexAddressToBase64Url(address: string): string {
  return Buffer.from(address.replace(/^0x/i, ''), 'hex').toString('base64url');
}

function fixtureRouterAbEcdsaDerivationNormalSigning(args: {
  walletId: string;
  walletKeyId: string;
  ecdsaThresholdKeyId: string;
  signingRootId: string;
  signingRootVersion: string;
  sessionId: string;
  clientVerifyingShareB64u: string;
  thresholdEcdsaPublicKeyB64u: string;
  ethereumAddress: string;
}): RouterAbEcdsaDerivationNormalSigningStateV1 {
  return {
    kind: ROUTER_AB_ECDSA_DERIVATION_NORMAL_SIGNING_STATE_KIND_V1,
    scope: {
      wallet_key_id: args.walletKeyId,
      wallet_id: args.walletId,
      ecdsa_threshold_key_id: args.ecdsaThresholdKeyId,
      signing_root_id: args.signingRootId,
      signing_root_version: args.signingRootVersion,
      context: {
        application_binding_digest_b64u: VALID_ECDSA_SHARE32_B64U,
      },
      public_identity: {
        context_binding_b64u: VALID_ECDSA_SHARE32_B64U,
        derivation_client_share_public_key33_b64u: args.clientVerifyingShareB64u,
        server_public_key33_b64u: VALID_ECDSA_RELAYER_PUBLIC_KEY_B64U,
        threshold_public_key33_b64u: args.thresholdEcdsaPublicKeyB64u,
        ethereum_address20_b64u: hexAddressToBase64Url(args.ethereumAddress),
        client_share_retry_counter: 0,
        server_share_retry_counter: 0,
      },
      signing_worker: {
        server_id: 'signing-worker-warm-session-fixture',
        key_epoch: 'epoch-warm-session-fixture',
        recipient_encryption_key:
          'x25519:1111111111111111111111111111111111111111111111111111111111111111',
      },
      activation_epoch: args.sessionId,
    },
  };
}

export function fixtureRouterAbEcdsaDerivationPublicCapability(args: {
  walletId: string;
  sessionId: string;
  normalSigning: RouterAbEcdsaDerivationNormalSigningStateV1;
}): RouterAbEcdsaDerivationPublicCapabilityV1 {
  return parseRouterAbEcdsaDerivationPublicCapabilityV1({
    kind: 'router_ab_ecdsa_derivation_public_capability_v1',
    context: args.normalSigning.scope.context,
    public_identity: args.normalSigning.scope.public_identity,
    signer_set: {
      signer_set_id: 'signer-set-warm-session-fixture',
      policy: 'all_2',
      signer_a: {
        role: 'signer_a',
        signer_id: 'signer-a-warm-session-fixture',
        key_epoch: 'epoch-warm-session-fixture',
      },
      signer_b: {
        role: 'signer_b',
        signer_id: 'signer-b-warm-session-fixture',
        key_epoch: 'epoch-warm-session-fixture',
      },
      selected_server: args.normalSigning.scope.signing_worker,
    },
    deriver_recipient_keys: {
      deriver_a: {
        role: 'signer_a',
        key_epoch: 'epoch-warm-session-fixture',
        public_key: 'x25519:2222222222222222222222222222222222222222222222222222222222222222',
      },
      deriver_b: {
        role: 'signer_b',
        key_epoch: 'epoch-warm-session-fixture',
        public_key: 'x25519:3333333333333333333333333333333333333333333333333333333333333333',
      },
    },
    router_id: 'router-warm-session-fixture',
    client_id: args.walletId,
    activation_epoch: args.sessionId,
    registration_request_digest_b64u: VALID_ECDSA_SHARE32_B64U,
    proof_transcript_digest_b64u: VALID_ECDSA_SHARE32_B64U,
  });
}

export function fixtureRuntimePolicyScopeFromSigningRoot(
  signingRootId: string,
  signingRootVersion: string,
): ThresholdRuntimePolicyScope | undefined {
  const delimiter = signingRootId.lastIndexOf(':');
  if (delimiter <= 0 || delimiter >= signingRootId.length - 1) return undefined;
  return {
    orgId: 'org-test',
    projectId: signingRootId.slice(0, delimiter),
    envId: signingRootId.slice(delimiter + 1),
    signingRootVersion,
  };
}

export function createThresholdEcdsaBootstrapFixture(args: {
  nearAccountId: string;
  chain: ThresholdEcdsaActivationChain;
  rpId?: string;
  keyHandle?: string;
  ecdsaThresholdKeyId?: string;
  sessionId?: string;
  walletSessionJwt?: string;
  sessionKind?: 'jwt' | 'cookie';
  relayerUrl?: string;
  relayerKeyId?: string;
  clientVerifyingShareB64u?: string;
  passkeyCredentialIdB64u?: string;
  participantIds?: number[];
  ethereumAddress?: string;
  signingGrantId?: string;
  signingRootId?: string;
  signingRootVersion?: string;
  expiresAtMs?: number;
  remainingUses?: number;
  runtimePolicyScope?: ThresholdRuntimePolicyScope;
  roleLocalAuthMethod?: 'passkey' | 'email_otp';
  emailOtpAuthSubjectId?: string;
}): ThresholdEcdsaSessionBootstrapResult {
  const chainLabel = args.chain;
  const ecdsaThresholdKeyId = parseEcdsaThresholdKeyId(
    String(args.ecdsaThresholdKeyId || 'ek-shared-1').trim(),
  );
  const keyHandle = String(args.keyHandle || `ederivation-key-${ecdsaThresholdKeyId}`).trim();
  const sessionId = String(args.sessionId || `sess-${chainLabel}-1`).trim();
  const sessionKind = args.sessionKind || 'jwt';
  const relayerUrl = String(args.relayerUrl || 'https://relay.example').trim();
  const rpId = String(args.rpId || 'localhost').trim();
  const relayerKeyId = String(args.relayerKeyId || `rk-${chainLabel}-1`).trim();
  const clientVerifyingShareB64u = String(
    args.clientVerifyingShareB64u || VALID_ECDSA_PUBLIC_KEY_B64U,
  ).trim();
  const passkeyCredentialIdB64u = String(
    args.passkeyCredentialIdB64u || `passkey-credential-${ecdsaThresholdKeyId}`,
  ).trim();
  const participantIds = args.participantIds || [1, 2];
  const ethereumAddress = args.ethereumAddress || `0x${'11'.repeat(20)}`;
  const signingGrantId = String(args.signingGrantId || `wsess-${sessionId}`).trim();
  const signingRootId = String(args.signingRootId || 'sr-test:dev').trim();
  const signingRootVersion = String(args.signingRootVersion || 'default').trim();
  const evmFamilySigningKeySlotId = deriveEvmFamilySigningKeySlotId({
    walletId: args.nearAccountId,
    signingRootId,
    signingRootVersion,
  });
  const runtimePolicyScope =
    args.runtimePolicyScope ||
    fixtureRuntimePolicyScopeFromSigningRoot(signingRootId, signingRootVersion);
  const chainTarget = testEcdsaChainTarget(args.chain);
  const roleLocalAuthMethod =
    args.roleLocalAuthMethod === 'email_otp'
      ? buildEcdsaRoleLocalEmailOtpAuthMethod({
          authSubjectId: args.emailOtpAuthSubjectId || `google:${args.nearAccountId}`,
        })
      : buildEcdsaRoleLocalPasskeyAuthMethod({
          credentialIdB64u: passkeyCredentialIdB64u,
          rpId,
        });
  const normalSigning = fixtureRouterAbEcdsaDerivationNormalSigning({
    walletId: args.nearAccountId,
    walletKeyId: evmFamilySigningKeySlotId,
    ecdsaThresholdKeyId,
    signingRootId,
    signingRootVersion,
    sessionId,
    clientVerifyingShareB64u,
    thresholdEcdsaPublicKeyB64u: VALID_ECDSA_PUBLIC_KEY_B64U,
    ethereumAddress,
  });
  const ecdsaRoleLocalReadyRecord = buildEcdsaRoleLocalReadyRecord({
    stateBlob: {
      kind: 'ecdsa_role_local_state_blob_v1',
      curve: 'secp256k1',
      encoding: 'base64url',
      producer: 'signer_core',
      stateBlobB64u: VALID_ECDSA_SHARE32_B64U,
    },
    publicFacts: buildEcdsaRoleLocalPublicFacts({
      walletId: toWalletId(args.nearAccountId),
      evmFamilySigningKeySlotId,
      chainTarget,
      keyHandle,
      ecdsaThresholdKeyId,
      signingRootId,
      signingRootVersion,
      clientParticipantId: 1,
      relayerParticipantId: 2,
      participantIds,
      contextBinding32B64u: VALID_ECDSA_SHARE32_B64U,
      applicationBindingDigestB64u: VALID_ECDSA_SHARE32_B64U,
      derivationClientSharePublicKey33B64u: clientVerifyingShareB64u,
      relayerPublicKey33B64u: VALID_ECDSA_RELAYER_PUBLIC_KEY_B64U,
      groupPublicKey33B64u: VALID_ECDSA_PUBLIC_KEY_B64U,
      ethereumAddress,
      publicCapability: fixtureRouterAbEcdsaDerivationPublicCapability({
        walletId: args.nearAccountId,
        sessionId,
        normalSigning,
      }),
    }),
    authMethod: roleLocalAuthMethod,
  });
  const walletSessionJwt =
    sessionKind === 'jwt'
      ? toFixtureWalletSessionJwt(String(args.walletSessionJwt || `jwt:${sessionId}`).trim(), {
          nearAccountId: args.nearAccountId,
          sessionId,
          signingGrantId,
          relayerKeyId,
          ecdsaThresholdKeyId,
          participantIds,
          chainTarget,
          ...(runtimePolicyScope ? { runtimePolicyScope } : {}),
        })
      : '';

  return {
    thresholdEcdsaKeyRef: {
      type: 'threshold-ecdsa-secp256k1',
      userId: args.nearAccountId,
      chainTarget,
      relayerUrl,
      keyHandle,
      evmFamilySigningKeySlotId,
      ecdsaThresholdKeyId,
      participantIds: [...participantIds],
      backendBinding: {
        materialKind: 'role_local_ready_state_blob',
        relayerKeyId,
        clientVerifyingShareB64u,
        stateBlob: ecdsaRoleLocalReadyRecord.stateBlob,
        ecdsaRoleLocalReadyRecord,
      },
      thresholdSessionKind: sessionKind,
      thresholdSessionId: sessionId,
      signingGrantId,
      ...(walletSessionJwt ? { walletSessionJwt } : {}),
      routerAbEcdsaDerivationNormalSigning: normalSigning,
      ethereumAddress,
      thresholdEcdsaPublicKeyB64u: VALID_ECDSA_PUBLIC_KEY_B64U,
      relayerVerifyingShareB64u: VALID_ECDSA_RELAYER_PUBLIC_KEY_B64U,
    },
    passkeyCredentialIdB64u,
    keygen: {
      ok: true,
      walletKeyId: evmFamilySigningKeySlotId,
      evmFamilySigningKeySlotId,
      ecdsaThresholdKeyId,
      clientVerifyingShareB64u,
      relayerKeyId,
      participantIds: [...participantIds],
      chainId: testEcdsaChainId(args.chain),
      ethereumAddress,
      thresholdEcdsaPublicKeyB64u: VALID_ECDSA_PUBLIC_KEY_B64U,
      relayerVerifyingShareB64u: VALID_ECDSA_RELAYER_PUBLIC_KEY_B64U,
    },
    session: {
      ok: true,
      thresholdSessionId: sessionId,
      signingGrantId,
      expiresAtMs: args.expiresAtMs ?? Date.now() + 120_000,
      remainingUses: args.remainingUses ?? 5,
      ...(runtimePolicyScope ? { runtimePolicyScope } : {}),
      ...(walletSessionJwt ? { jwt: walletSessionJwt } : {}),
      clientVerifyingShareB64u,
    },
  };
}

function toFixtureWalletSessionJwt(
  token: string,
  args: {
    nearAccountId: string;
    sessionId: string;
    signingGrantId: string;
    relayerKeyId: string;
    ecdsaThresholdKeyId: string;
    participantIds: number[];
    chainTarget: ThresholdEcdsaChainTarget;
    runtimePolicyScope?: ThresholdRuntimePolicyScope;
  },
): string {
  if (token.split('.').length === 3) return token;
  const header = Buffer.from(JSON.stringify({ alg: 'none', typ: 'JWT' })).toString('base64url');
  const payload = Buffer.from(
    JSON.stringify({
      sub: args.nearAccountId,
      walletId: args.nearAccountId,
      kind: ROUTER_AB_ECDSA_DERIVATION_WALLET_SESSION_JWT_KIND,
      thresholdSessionId: args.sessionId,
      signingGrantId: args.signingGrantId,
      subjectId: args.nearAccountId,
      chainTarget: args.chainTarget,
      ecdsaThresholdKeyId: args.ecdsaThresholdKeyId,
      relayerKeyId: args.relayerKeyId,
      rpId: 'localhost',
      thresholdExpiresAtMs: Date.now() + 120_000,
      participantIds: args.participantIds,
      ...(args.runtimePolicyScope ? { runtimePolicyScope: args.runtimePolicyScope } : {}),
    }),
  ).toString('base64url');
  return `${header}.${payload}.fixture`;
}
