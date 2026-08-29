import {
  NEAR_ED25519_YAO_KEY_VERSION_V1,
  implicitNearAccountProvisioning,
  registrationEvmFamilyEcdsaBranchKey,
  registrationNearEd25519BranchKey,
} from '../../../packages/shared-ts/src/utils/registrationIntent';
import { buildStoredWalletRegistrationPreparedContext } from '../../../packages/wallet-server/src/core/RegistrationCeremonyStore';
import { parseD1WalletRegistrationCommittedInstallationProjection } from '../../../packages/wallet-server/src/router/cloudflare/d1/registration/d1RegistrationCeremonyRecords';
import { buildFixtureRespondEd25519DeferredWork } from '../../helpers/ed25519YaoAdmissionFixtures';

export const REGISTRATION_COMMITTED_INSTALLATION_PROJECTION_FIXTURE_IDS = {
  registrationCeremonyId: 'registration-projection-fixture',
  walletId: 'projection-wallet.testnet',
  orgId: 'org-projection',
  signingRootId: 'project-projection:env-projection',
  signingRootVersion: 'root-projection-v1',
} as const;

const ECDSA_CHAIN_TARGET = { kind: 'evm', namespace: 'eip155', chainId: 8453 } as const;

/**
 * Build a raw persisted projection through the production parser's current
 * nested shapes. Callers should mutate only the field under test.
 */
export function buildRegistrationCommittedInstallationProjectionFixture(): Record<string, unknown> {
  const { registrationCeremonyId, walletId, orgId, signingRootId, signingRootVersion } =
    REGISTRATION_COMMITTED_INSTALLATION_PROJECTION_FIXTURE_IDS;
  const near = buildFixtureRespondEd25519DeferredWork({
    lifecycleId: registrationCeremonyId,
    rootShareEpoch: signingRootVersion,
    walletId,
    signerSetId: String(registrationNearEd25519BranchKey(1)),
    signingRootId,
    participantIds: [1, 2],
    signerSlot: 1,
  });
  const preparedContext = buildStoredWalletRegistrationPreparedContext({
    signingRootId,
    signingRootVersion,
    runtimePolicyScope: {
      orgId,
      projectId: 'project-projection',
      envId: 'env-projection',
      signingRootVersion,
    },
    ecdsaChainTargets: [ECDSA_CHAIN_TARGET],
  });
  const projection: Record<string, unknown> = {
    kind: 'wallet_registration_committed_installation_projection_v1',
    registrationCeremonyId,
    walletId,
    orgId,
    registrationAuthority: {
      kind: 'passkey',
      walletId,
      rpId: 'example.com',
      credentialIdB64u: 'credential-id',
      credentialPublicKeyB64u: 'credential-public-key',
      counter: 0,
      device: {
        label: 'Unknown device',
        browser: 'other',
        os: 'other',
        synced: false,
        transports: [],
      },
      registrationIntentDigestB64u: 'registration-digest',
    },
    signerPlan: {
      kind: 'signer_set',
      branches: [
        {
          kind: 'near_ed25519',
          branchKey: String(registrationNearEd25519BranchKey(1)),
          accountProvisioning: implicitNearAccountProvisioning(),
          signerSlot: 1,
          participantIds: [1, 2],
          keyPurpose: 'near_tx',
          keyVersion: NEAR_ED25519_YAO_KEY_VERSION_V1,
          derivationVersion: 1,
        },
        {
          kind: 'evm_family_ecdsa',
          branchKey: String(registrationEvmFamilyEcdsaBranchKey([ECDSA_CHAIN_TARGET])),
          participantIds: [1, 2],
          chainTargets: [ECDSA_CHAIN_TARGET],
        },
      ],
    },
    preparedContext,
    nearEd25519: {
      kind: 'near_ed25519_yao_authorized',
      branchKey: String(registrationNearEd25519BranchKey(1)),
      admissionRequest: near.admissionRequest,
      admissionReceipt: near.admissionReceipt,
    },
  };
  if (!parseD1WalletRegistrationCommittedInstallationProjection(projection)) {
    throw new Error('registration installation projection fixture is invalid');
  }
  return projection;
}
