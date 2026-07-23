import { buildWalletEcdsaSignerRecord } from '../../../packages/sdk-server-ts/src/core/d1WalletStore';
import type { WalletEcdsaSignerRecord } from '../../../packages/sdk-server-ts/src/core/WalletStore';
import type { WalletRegistrationEcdsaWalletKey } from '../../../packages/sdk-server-ts/src/core/registrationContracts';
import { derivationClientSharePublicKey33B64uFromString } from '../../../packages/shared-ts/src/threshold/ecdsaDerivationRoleLocalBootstrap';
import type { WalletId } from '../../../packages/shared-ts/src/utils/registrationIntent';
import {
  parseRouterAbEcdsaDerivationPublicCapabilityV1,
  type RouterAbEcdsaDerivationPublicCapabilityV1,
} from '../../../packages/shared-ts/src/utils/routerAbEcdsaDerivation';

const VALID_ECDSA_CLIENT_SHARE_PUBLIC_KEY33_B64U = 'AgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA';
const VALID_ECDSA_RELAYER_PUBLIC_KEY33_B64U = 'AwAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA';
const VALID_ECDSA_DIGEST32_B64U = 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA';
const FIXTURE_THRESHOLD_OWNER_ADDRESS = '0x0000000000000000000000000000000000000001';

function hexAddressToBase64Url(address: string): string {
  return Buffer.from(address.replace(/^0x/i, ''), 'hex').toString('base64url');
}

/** Public capability built through the production capability parser so the
 * fixture cannot drift from the current wire shape. (Near-duplicate of the
 * warm-session capability fixture in ecdsaBootstrap.fixtures.ts, whose
 * normal-signing input builder is not exported; noted as owned duplication.) */
function fixtureRegistrationEcdsaPublicCapability(args: {
  walletId: string;
  ecdsaThresholdKeyId: string;
}): RouterAbEcdsaDerivationPublicCapabilityV1 {
  return parseRouterAbEcdsaDerivationPublicCapabilityV1({
    kind: 'router_ab_ecdsa_derivation_public_capability_v1',
    context: {
      application_binding_digest_b64u: VALID_ECDSA_DIGEST32_B64U,
    },
    public_identity: {
      context_binding_b64u: VALID_ECDSA_DIGEST32_B64U,
      derivation_client_share_public_key33_b64u: VALID_ECDSA_CLIENT_SHARE_PUBLIC_KEY33_B64U,
      server_public_key33_b64u: VALID_ECDSA_RELAYER_PUBLIC_KEY33_B64U,
      threshold_public_key33_b64u: VALID_ECDSA_CLIENT_SHARE_PUBLIC_KEY33_B64U,
      ethereum_address20_b64u: hexAddressToBase64Url(FIXTURE_THRESHOLD_OWNER_ADDRESS),
      client_share_retry_counter: 0,
      server_share_retry_counter: 0,
    },
    signer_set: {
      signer_set_id: 'signer-set-registration-signer-fixture',
      policy: 'all_2',
      signer_a: {
        role: 'signer_a',
        signer_id: 'signer-a-registration-signer-fixture',
        key_epoch: 'epoch-registration-signer-fixture',
      },
      signer_b: {
        role: 'signer_b',
        signer_id: 'signer-b-registration-signer-fixture',
        key_epoch: 'epoch-registration-signer-fixture',
      },
      selected_server: {
        server_id: 'signing-worker-registration-signer-fixture',
        key_epoch: 'epoch-registration-signer-fixture',
        recipient_encryption_key:
          'x25519:1111111111111111111111111111111111111111111111111111111111111111',
      },
    },
    deriver_recipient_keys: {
      deriver_a: {
        role: 'signer_a',
        key_epoch: 'epoch-registration-signer-fixture',
        public_key: 'x25519:2222222222222222222222222222222222222222222222222222222222222222',
      },
      deriver_b: {
        role: 'signer_b',
        key_epoch: 'epoch-registration-signer-fixture',
        public_key: 'x25519:3333333333333333333333333333333333333333333333333333333333333333',
      },
    },
    router_id: 'router-registration-signer-fixture',
    client_id: args.walletId,
    activation_epoch: args.ecdsaThresholdKeyId,
    registration_request_digest_b64u: VALID_ECDSA_DIGEST32_B64U,
    proof_transcript_digest_b64u: VALID_ECDSA_DIGEST32_B64U,
  });
}

export type WalletEcdsaSignerRecordSeedArgs = {
  walletId: WalletId;
  now: number;
  walletKeyOverrides?: Partial<Omit<WalletRegistrationEcdsaWalletKey, 'walletId' | 'keyScope'>>;
};

/** Valid current-domain ECDSA wallet signer record, constructed through the
 * production `buildWalletEcdsaSignerRecord` builder. Rejection-path tests must
 * corrupt the returned record with a visible override at the call site. */
export function createWalletEcdsaSignerRecord(
  args: WalletEcdsaSignerRecordSeedArgs,
): WalletEcdsaSignerRecord {
  const ecdsaThresholdKeyId = String(
    args.walletKeyOverrides?.ecdsaThresholdKeyId || 'ecdsa-threshold-key-1',
  );
  const walletKey: WalletRegistrationEcdsaWalletKey = {
    keyScope: 'evm-family',
    chainTarget: { kind: 'evm', namespace: 'eip155', chainId: 8453 },
    walletId: args.walletId,
    evmFamilySigningKeySlotId: 'ecdsa-slot-1',
    keyHandle: 'ecdsa-key-handle-1',
    ecdsaThresholdKeyId,
    signingRootId: 'project-a:env-a',
    signingRootVersion: 'root-v1',
    thresholdEcdsaPublicKeyB64u: VALID_ECDSA_CLIENT_SHARE_PUBLIC_KEY33_B64U,
    thresholdOwnerAddress: FIXTURE_THRESHOLD_OWNER_ADDRESS,
    relayerKeyId: 'ecdsa-relayer-a',
    relayerVerifyingShareB64u: VALID_ECDSA_RELAYER_PUBLIC_KEY33_B64U,
    contextBinding32B64u: VALID_ECDSA_DIGEST32_B64U,
    derivationClientSharePublicKey33B64u: derivationClientSharePublicKey33B64uFromString(
      VALID_ECDSA_CLIENT_SHARE_PUBLIC_KEY33_B64U,
    ),
    clientShareRetryCounter: 0,
    relayerShareRetryCounter: 0,
    participantIds: [1, 2],
    publicCapability: fixtureRegistrationEcdsaPublicCapability({
      walletId: String(args.walletId),
      ecdsaThresholdKeyId,
    }),
    ...args.walletKeyOverrides,
  };
  return buildWalletEcdsaSignerRecord({
    walletId: args.walletId,
    walletKey,
    createdAtMs: args.now,
    updatedAtMs: args.now,
  });
}
