import { alphabetizeStringify } from '@shared/utils/digests';
import { parseWalletId } from '@shared/utils/domainIds';
import type { WalletEd25519YaoActiveCapabilityRecord } from '../../core/WalletStore';
import type { D1WalletStore } from '../../core/d1WalletStore';
import type {
  RouterAbEd25519YaoCapabilityPersistenceResultV1,
  RouterAbEd25519YaoCapabilityPersistenceV1,
} from '../routerAbEd25519YaoRecovery';
import {
  ed25519NearPublicKeyFromBytes,
  replaceYaoEd25519WalletSignerActiveCapability,
} from './d1Ed25519YaoWalletSigner';

function activeCapabilityApplication(
  capability: WalletEd25519YaoActiveCapabilityRecord,
) {
  return capability.admissionRequest.application_binding;
}

function activeCapabilityParticipants(
  capability: WalletEd25519YaoActiveCapabilityRecord,
): readonly [number, number] {
  return capability.admissionRequest.participant_ids;
}

function activeCapabilitySigningWorkerId(
  capability: WalletEd25519YaoActiveCapabilityRecord,
): string {
  return capability.admissionRequest.scope.signing_worker_id;
}

function activeCapabilityPublicKey(capability: WalletEd25519YaoActiveCapabilityRecord): string {
  return ed25519NearPublicKeyFromBytes(
    capability.activationResult.public_receipt.registered_public_key,
  );
}

function capabilityBindingMatches(
  left: WalletEd25519YaoActiveCapabilityRecord,
  right: WalletEd25519YaoActiveCapabilityRecord,
): boolean {
  return alphabetizeStringify(left.activeCapabilityBinding) ===
    alphabetizeStringify(right.activeCapabilityBinding);
}

function persistenceFailure(
  code: string,
  message: string,
): RouterAbEd25519YaoCapabilityPersistenceResultV1 {
  return { ok: false, code, message };
}

export class CloudflareD1RouterAbEd25519YaoCapabilityPersistence
  implements RouterAbEd25519YaoCapabilityPersistenceV1
{
  constructor(private readonly walletStore: D1WalletStore) {}

  async replaceActiveCapability(input: {
    readonly previous: WalletEd25519YaoActiveCapabilityRecord;
    readonly next: WalletEd25519YaoActiveCapabilityRecord;
  }): Promise<RouterAbEd25519YaoCapabilityPersistenceResultV1> {
    const application = activeCapabilityApplication(input.next);
    const walletId = parseWalletId(application.wallet_id);
    if (!walletId.ok) {
      return persistenceFailure('invalid_wallet', 'promoted Yao capability wallet ID is invalid');
    }
    const signer = await this.walletStore.getEd25519SignerBySlot({
      walletId: walletId.value,
      signerSlot: application.key_creation_signer_slot,
    });
    if (!signer) {
      return persistenceFailure('signer_not_found', 'promoted Yao capability signer was not found');
    }
    if (!capabilityBindingMatches(signer.activeYaoCapability, input.previous)) {
      return persistenceFailure(
        'capability_conflict',
        'durable Yao capability changed before recovery promotion',
      );
    }
    if (
      signer.walletId !== application.wallet_id ||
      signer.nearAccountId !== input.next.nearAccountId ||
      signer.nearEd25519SigningKeyId !== application.near_ed25519_signing_key_id ||
      signer.signerSlot !== application.key_creation_signer_slot ||
      signer.signingRootId !== application.signing_root_id ||
      signer.signingRootVersion !== input.next.admissionRequest.scope.root_share_epoch ||
      signer.signingWorkerId !== activeCapabilitySigningWorkerId(input.next) ||
      signer.publicKey !== activeCapabilityPublicKey(input.next) ||
      alphabetizeStringify(signer.participantIds) !==
        alphabetizeStringify(activeCapabilityParticipants(input.next)) ||
      alphabetizeStringify(signer.runtimePolicyScope) !==
        alphabetizeStringify(input.next.runtimePolicyScope)
    ) {
      return persistenceFailure(
        'identity_mismatch',
        'promoted Yao capability does not match its durable signer',
      );
    }
    await this.walletStore.putSigner(
      replaceYaoEd25519WalletSignerActiveCapability({
        signer,
        activeYaoCapability: input.next,
        now: Date.now(),
      }),
    );
    return { ok: true };
  }
}
