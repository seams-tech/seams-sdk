import { walletIdFromString, type WalletId } from '@shared/utils/registrationIntent';
import type { WalletEd25519SignerRecord, WalletRecord } from './WalletStore';

const walletId: WalletId = walletIdFromString('wallet_alice');

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
  signerSlot: 1,
  publicKey: 'ed25519-public-key',
  relayerKeyId: 'relayer-key',
  keyVersion: 'threshold-ed25519-hss-v1',
  recoveryExportCapable: true,
  createdAtMs: 1,
  updatedAtMs: 1,
} satisfies WalletEd25519SignerRecord);

const ed25519SignerWithRpId: WalletEd25519SignerRecord = {
  version: 'wallet_signer_ed25519_v1',
  walletId,
  signerId: 'ed25519:alice.testnet:1',
  nearAccountId: 'alice.testnet',
  nearEd25519SigningKeyId: 'alice.testnet',
  signerSlot: 1,
  publicKey: 'ed25519-public-key',
  relayerKeyId: 'relayer-key',
  keyVersion: 'threshold-ed25519-hss-v1',
  recoveryExportCapable: true,
  // @ts-expect-error RP ID belongs to WebAuthn/session authority; durable Ed25519 signer identity rejects it.
  rpId: 'wallet.example.test',
  createdAtMs: 1,
  updatedAtMs: 1,
};
void ed25519SignerWithRpId;
