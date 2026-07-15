import { walletIdFromString, type WalletId } from '@shared/utils/registrationIntent';
import type {
  WalletEd25519SignerRecord,
  WalletEd25519YaoActiveCapabilityRecord,
  WalletRecord,
} from './WalletStore';

const walletId: WalletId = walletIdFromString('wallet_alice');
const runtimePolicyScope = {
  orgId: 'org-a',
  projectId: 'project-a',
  envId: 'env-a',
  signingRootVersion: 'root-v1',
} as const;
declare const activeYaoCapability: WalletEd25519YaoActiveCapabilityRecord;

void ({
  version: 'wallet_v1',
  walletId,
  createdAtMs: 1,
  updatedAtMs: 1,
} satisfies WalletRecord);

void ({
  version: 'wallet_v1',
  walletId,
  createdAtMs: 1,
  updatedAtMs: 1,
  // @ts-expect-error RP ID belongs to passkey auth-method records; wallet identity rejects it.
  rpId: 'wallet.example.test',
} satisfies WalletRecord);

void ({
  version: 'wallet_signer_ed25519_v1',
  walletId,
  signerId: 'ed25519:alice.testnet:1',
  nearAccountId: 'alice.testnet',
  nearEd25519SigningKeyId: 'alice.testnet',
  thresholdSessionId: 'threshold-session-1',
  signerSlot: 1,
  publicKey: 'ed25519-public-key',
  signingWorkerId: 'signing-worker-a',
  keyVersion: 'router-ab-ed25519-yao-v1',
  recoveryExportCapable: true,
  participantIds: [1, 2],
  signingRootId: 'project-a:env-a',
  signingRootVersion: 'root-v1',
  runtimePolicyScope,
  activeYaoCapability,
  createdAtMs: 1,
  updatedAtMs: 1,
} satisfies WalletEd25519SignerRecord);

void ({
  version: 'wallet_signer_ed25519_v1',
  walletId,
  signerId: 'ed25519:alice.testnet:1',
  nearAccountId: 'alice.testnet',
  nearEd25519SigningKeyId: 'alice.testnet',
  thresholdSessionId: 'threshold-session-1',
  // @ts-expect-error Signing grants are mutable budget authority, not durable signer identity.
  signingGrantId: 'signing-grant-1',
  signerSlot: 1,
  publicKey: 'ed25519-public-key',
  signingWorkerId: 'signing-worker-a',
  keyVersion: 'router-ab-ed25519-yao-v1',
  recoveryExportCapable: true,
  participantIds: [1, 2],
  signingRootId: 'project-a:env-a',
  signingRootVersion: 'root-v1',
  runtimePolicyScope,
  activeYaoCapability,
  createdAtMs: 1,
  updatedAtMs: 1,
} satisfies WalletEd25519SignerRecord);

const ed25519SignerWithRpId: WalletEd25519SignerRecord = {
  version: 'wallet_signer_ed25519_v1',
  walletId,
  signerId: 'ed25519:alice.testnet:1',
  nearAccountId: 'alice.testnet',
  nearEd25519SigningKeyId: 'alice.testnet',
  thresholdSessionId: 'threshold-session-1',
  signerSlot: 1,
  publicKey: 'ed25519-public-key',
  signingWorkerId: 'signing-worker-a',
  keyVersion: 'router-ab-ed25519-yao-v1',
  recoveryExportCapable: true,
  participantIds: [1, 2],
  signingRootId: 'project-a:env-a',
  signingRootVersion: 'root-v1',
  runtimePolicyScope,
  activeYaoCapability,
  // @ts-expect-error RP ID belongs to WebAuthn/session authority; durable Ed25519 signer identity rejects it.
  rpId: 'wallet.example.test',
  createdAtMs: 1,
  updatedAtMs: 1,
};
void ed25519SignerWithRpId;
