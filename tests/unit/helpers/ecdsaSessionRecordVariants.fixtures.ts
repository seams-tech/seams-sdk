import { deriveEvmFamilySigningKeySlotId } from '@shared/signing-lanes';
import {
  parseRootShareEpoch,
  type RootShareEpoch,
  type WalletId,
} from '@shared/utils/domainIds';
import type { RouterAbEcdsaDerivationNormalSigningStateV1 } from '@shared/utils/routerAbEcdsaDerivation';
import {
  toWalletId,
  type ThresholdEcdsaChainTarget,
} from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import { toEvmFamilyEcdsaKeyHandle } from '@/core/signingEngine/session/identity/evmFamilyEcdsaIdentity';
import {
  buildEcdsaRoleLocalPasskeyAuthMethod,
  buildEcdsaRoleLocalPublicFacts,
  buildEcdsaRoleLocalReadyRecord,
} from '@/core/signingEngine/session/persistence/ecdsaRoleLocalRecords';
import { fixtureRouterAbEcdsaDerivationPublicCapability } from './ecdsaBootstrap.fixtures';

const FIXTURE_WALLET_ID = toWalletId('alice.testnet');

function fixtureRootShareEpoch(value: string): RootShareEpoch {
  const parsed = parseRootShareEpoch(value);
  if (!parsed.ok) {
    throw new Error(`invalid fixture activation epoch: ${value}`);
  }
  return parsed.value;
}

const FIXTURE_RP_ID = 'localhost';
const FIXTURE_OWNER_ADDRESS = '0x1111111111111111111111111111111111111111';
const FIXTURE_PUBLIC_KEY_B64U = 'AgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA';
const FIXTURE_RELAYER_PUBLIC_KEY_B64U = 'AwAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA';
const FIXTURE_SHARE_32_B64U = 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA';
const FIXTURE_APPLICATION_BINDING_DIGEST_32_B64U = 'CAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAg';
const FIXTURE_RUNTIME_POLICY_SCOPE = {
  projectId: 'project',
  envId: 'dev',
  signingRootVersion: 'default',
};
const FIXTURE_SIGNING_ROOT_ID = `${FIXTURE_RUNTIME_POLICY_SCOPE.projectId}:${FIXTURE_RUNTIME_POLICY_SCOPE.envId}`;
const FIXTURE_SIGNING_ROOT_VERSION = FIXTURE_RUNTIME_POLICY_SCOPE.signingRootVersion;

const FIXTURE_EVM_TARGET: ThresholdEcdsaChainTarget = {
  kind: 'evm',
  namespace: 'eip155',
  chainId: 5042002,
  networkSlug: 'arc-testnet',
};

function ethereumAddress20B64u(address: string): string {
  return Buffer.from(address.replace(/^0x/i, ''), 'hex').toString('base64url');
}

export function makeRouterAbEcdsaDerivationNormalSigningStateFixture(
  input: {
    walletId?: string;
    walletKeyId?: string;
    ecdsaThresholdKeyId?: string;
    signingRootId?: string;
    signingRootVersion?: string;
    clientPublicKey33B64u?: string;
    serverPublicKey33B64u?: string;
    thresholdPublicKey33B64u?: string;
    ethereumAddress?: string;
    activationEpoch?: string;
  } = {},
): RouterAbEcdsaDerivationNormalSigningStateV1 {
  const signingRootId = input.signingRootId ?? FIXTURE_SIGNING_ROOT_ID;
  const signingRootVersion = input.signingRootVersion ?? FIXTURE_SIGNING_ROOT_VERSION;
  const walletId = input.walletId ?? FIXTURE_WALLET_ID;
  return {
    kind: 'router_ab_ecdsa_derivation_normal_signing_v1',
    scope: {
      wallet_id: walletId,
      ecdsa_threshold_key_id: input.ecdsaThresholdKeyId ?? 'ederivation-shared-key',
      signing_root_id: signingRootId,
      signing_root_version: signingRootVersion,
      context: {
        application_binding_digest_b64u: FIXTURE_APPLICATION_BINDING_DIGEST_32_B64U,
      },
      public_identity: {
        context_binding_b64u: FIXTURE_SHARE_32_B64U,
        derivation_client_share_public_key33_b64u:
          input.clientPublicKey33B64u ?? FIXTURE_PUBLIC_KEY_B64U,
        server_public_key33_b64u:
          input.serverPublicKey33B64u ?? FIXTURE_RELAYER_PUBLIC_KEY_B64U,
        threshold_public_key33_b64u:
          input.thresholdPublicKey33B64u ?? FIXTURE_PUBLIC_KEY_B64U,
        ethereum_address20_b64u: ethereumAddress20B64u(
          input.ethereumAddress ?? FIXTURE_OWNER_ADDRESS,
        ),
        client_share_retry_counter: 0,
        server_share_retry_counter: 0,
      },
      signing_worker: {
        server_id: 'signing-worker-1',
        key_epoch: 'worker-epoch-1',
        recipient_encryption_key:
          'x25519:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
      },
      activation_epoch: fixtureRootShareEpoch(input.activationEpoch ?? 'activation-1'),
    },
  };
}

export function makeEcdsaRoleLocalReadyRecordFixture(
  args: {
    walletId?: WalletId;
    walletKeyId?: string;
    keyHandle?: string;
    chainTarget?: ThresholdEcdsaChainTarget;
    ecdsaThresholdKeyId?: string;
    signingRootId?: string;
    signingRootVersion?: string;
    ethereumAddress?: string;
    authMethod?: Parameters<typeof buildEcdsaRoleLocalReadyRecord>[0]['authMethod'];
    normalSigning?: RouterAbEcdsaDerivationNormalSigningStateV1;
  } = {},
) {
  const recordWalletId = args.walletId ?? FIXTURE_WALLET_ID;
  const signingRootId = args.signingRootId ?? FIXTURE_SIGNING_ROOT_ID;
  const signingRootVersion = args.signingRootVersion ?? FIXTURE_SIGNING_ROOT_VERSION;
  const recordKeyHandle = args.keyHandle ?? toEvmFamilyEcdsaKeyHandle('key-handle-shared');
  const recordChainTarget = args.chainTarget ?? FIXTURE_EVM_TARGET;
  const recordWalletKeyId =
    args.walletKeyId ??
    deriveEvmFamilySigningKeySlotId({
      walletId: recordWalletId,
      signingRootId,
      signingRootVersion,
    });
  const ecdsaThresholdKeyId = args.ecdsaThresholdKeyId ?? 'ederivation-shared-key';
  const ethereumAddress = args.ethereumAddress ?? FIXTURE_OWNER_ADDRESS;
  const normalSigning =
    args.normalSigning ??
    makeRouterAbEcdsaDerivationNormalSigningStateFixture({
      walletId: recordWalletId,
      walletKeyId: recordWalletKeyId,
      ecdsaThresholdKeyId,
      signingRootId,
      signingRootVersion,
      ethereumAddress,
    });
  return buildEcdsaRoleLocalReadyRecord({
    stateBlob: {
      kind: 'ecdsa_role_local_state_blob_v1',
      curve: 'secp256k1',
      encoding: 'base64url',
      producer: 'signer_core',
      stateBlobB64u: FIXTURE_SHARE_32_B64U,
    },
    publicFacts: buildEcdsaRoleLocalPublicFacts({
      walletId: recordWalletId,
      evmFamilySigningKeySlotId: recordWalletKeyId,
      chainTarget: recordChainTarget,
      keyHandle: recordKeyHandle,
      ecdsaThresholdKeyId,
      signingRootId,
      signingRootVersion,
      clientParticipantId: 1,
      relayerParticipantId: 2,
      participantIds: [1, 2],
      applicationBindingDigestB64u: FIXTURE_APPLICATION_BINDING_DIGEST_32_B64U,
      contextBinding32B64u: FIXTURE_SHARE_32_B64U,
      derivationClientSharePublicKey33B64u:
        normalSigning.scope.public_identity.derivation_client_share_public_key33_b64u,
      relayerPublicKey33B64u: normalSigning.scope.public_identity.server_public_key33_b64u,
      groupPublicKey33B64u: FIXTURE_PUBLIC_KEY_B64U,
      ethereumAddress,
      publicCapability: fixtureRouterAbEcdsaDerivationPublicCapability({
        walletId: String(recordWalletId),
        sessionId: normalSigning.scope.activation_epoch,
        normalSigning,
      }),
    }),
    authMethod:
      args.authMethod ??
      buildEcdsaRoleLocalPasskeyAuthMethod({
        credentialIdB64u: recordKeyHandle,
        rpId: FIXTURE_RP_ID,
      }),
  });
}
