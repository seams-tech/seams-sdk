import type {
  WalletRegistrationCommittedInstallationProjectionV1,
  WalletRegistrationSessionCommitReceiptV2,
} from '../../packages/wallet-server/src/core/threeRouteRegistrationContracts';

type EcdsaReadyReceipt = Extract<
  WalletRegistrationSessionCommitReceiptV2,
  { readonly committed: { readonly kind: 'ecdsa_ready' } }
>;
type EcdsaReadyCommit = EcdsaReadyReceipt['committed'];
type MixedEcdsaReadyCommit = Extract<
  EcdsaReadyCommit,
  { readonly nearProvisioning: { readonly status: 'near_pending' } }
>;

declare const ecdsa: EcdsaReadyCommit['ecdsa'];
declare const session: EcdsaReadyCommit['session'];
declare const installation: WalletRegistrationCommittedInstallationProjectionV1;
declare const mixedCommit: MixedEcdsaReadyCommit;

const requiredInstallation: WalletRegistrationCommittedInstallationProjectionV1 =
  mixedCommit.installation;
void requiredInstallation;

const nearPending = { status: 'near_pending' } as const;
const missingInstallation = {
  kind: 'ecdsa_ready' as const,
  ecdsa,
  session,
  nearProvisioning: nearPending,
};
// @ts-expect-error A mixed ECDSA receipt cannot carry near_pending without its installation projection.
const rejectedMissingInstallation: EcdsaReadyCommit = missingInstallation;
void rejectedMissingInstallation;

const invalidEcdsaOnlyProjection = {
  kind: 'ecdsa_ready' as const,
  ecdsa,
  session,
  installation,
};
// @ts-expect-error An ECDSA-only receipt cannot carry a mixed installation projection.
const rejectedEcdsaOnlyProjection: EcdsaReadyCommit = invalidEcdsaOnlyProjection;
void rejectedEcdsaOnlyProjection;
