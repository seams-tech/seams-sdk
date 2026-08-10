import type { WalletId } from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import type { NearEd25519YaoOperationMaterial } from '@/core/signingEngine/interfaces/near';
import type { ExactEd25519ExportMaterialIdentity } from '@/core/signingEngine/session/identity/exactSigningLaneIdentity';
import type { SigningLaneAuthBinding } from '@/core/signingEngine/session/identity/signingLaneAuthBinding';
import type { EmailOtpEd25519YaoActiveCapabilityDescriptorV1 } from '@/core/signingEngine/workerManager/workerTypes';
import type { AccountId } from '@/core/types/accountIds';
import {
  type ActiveWalletSessionAuthorizationProjection,
  type WalletSessionAuthorizationReadResult,
} from '@/core/indexedDB/seamsWalletDB/walletSessionAuthorizationStore';
import {
  mpcMaterialActivationRefsEqual,
  parseThresholdEd25519SessionId,
  type MpcMaterialActivationRef,
} from '@shared/utils/domainIds';

type EmailOtpEd25519LaneAuth = Extract<SigningLaneAuthBinding, { kind: 'email_otp' }>;

export type ResolvedWalletCustodyEd25519ExportV1 = {
  readonly kind: 'wallet_custody_ed25519_export_context_v1';
  readonly lane: ExactEd25519ExportMaterialIdentity<EmailOtpEd25519LaneAuth>;
  readonly authorization: ActiveWalletSessionAuthorizationProjection;
  readonly material: {
    readonly materialActivation: MpcMaterialActivationRef;
    readonly capability: EmailOtpEd25519YaoActiveCapabilityDescriptorV1;
  };
};

function resolveActiveEmailOtpAuthorization(args: {
  walletId: WalletId;
  result: WalletSessionAuthorizationReadResult<ActiveWalletSessionAuthorizationProjection>;
}): ActiveWalletSessionAuthorizationProjection {
  if (args.result.kind !== 'found') {
    throw new Error('[SigningEngine][ed25519-export] active Wallet Session authorization is unavailable');
  }
  const authorization = args.result.projection;
  if (
    authorization.status !== 'active' ||
    authorization.walletId !== args.walletId ||
    authorization.authority.walletId !== args.walletId ||
    authorization.authMethod !== 'email_otp' ||
    authorization.expiresAtMs <= Date.now()
  ) {
    throw new Error('[SigningEngine][ed25519-export] Email OTP Wallet Session authorization is invalid');
  }
  return authorization;
}

function capabilityFromActiveMaterial(args: {
  subject: ExactEd25519ExportMaterialIdentity<EmailOtpEd25519LaneAuth>;
  expectedMaterialActivation: MpcMaterialActivationRef;
  material: NearEd25519YaoOperationMaterial;
}): EmailOtpEd25519YaoActiveCapabilityDescriptorV1 {
  if (args.material.activeClient.status().kind !== 'active') {
    throw new Error('[SigningEngine][ed25519-export] wallet custody client is inactive');
  }
  const metadata = args.material.activeClient.metadata();
  const signer = args.subject.signer;
  if (
    !mpcMaterialActivationRefsEqual(metadata.materialActivation, args.expectedMaterialActivation) ||
    args.material.facts.signer.account.wallet.walletId !== signer.account.wallet.walletId ||
    String(args.material.facts.signer.account.nearAccountId) !== String(signer.account.nearAccountId) ||
    args.material.facts.signer.nearEd25519SigningKeyId !== signer.nearEd25519SigningKeyId ||
    args.material.facts.signer.signerSlot !== signer.signerSlot ||
    metadata.applicationBinding.wallet_id !== signer.account.wallet.walletId ||
    metadata.applicationBinding.near_ed25519_signing_key_id !== signer.nearEd25519SigningKeyId ||
    metadata.applicationBinding.key_creation_signer_slot !== signer.signerSlot
  ) {
    throw new Error('[SigningEngine][ed25519-export] wallet custody client changed the exact lane');
  }
  const thresholdSessionId = parseThresholdEd25519SessionId(metadata.scope.threshold_session_id);
  if (!thresholdSessionId.ok) {
    throw new Error(
      `[SigningEngine][ed25519-export] threshold session id is invalid: ${thresholdSessionId.error.message}`,
    );
  }
  return {
    kind: 'router_ab_ed25519_yao_active_capability_v1',
    materialActivation: metadata.materialActivation,
    activeCapabilityBinding: metadata.activeCapabilityBinding,
    registeredPublicKey: [...metadata.registeredPublicKey],
    nearAccountId: String(signer.account.nearAccountId),
    applicationBinding: metadata.applicationBinding,
    runtimePolicyScope: args.material.facts.runtimePolicyScope,
    participantIds: metadata.participantIds,
    lifecycle: {
      lifecycleId: metadata.scope.lifecycle_id,
      rootShareEpoch: metadata.scope.root_share_epoch,
      accountId: metadata.scope.account_id,
      thresholdSessionId: thresholdSessionId.value,
      signerSetId: metadata.scope.signer_set_id,
      signingWorkerId: metadata.scope.signing_worker_id,
    },
    stateEpoch: Number(metadata.stateEpoch),
    registrationContinuity: { kind: 'recovery' },
  };
}

export async function resolveWalletCustodyEd25519ExportContextV1(input: {
  subject: ExactEd25519ExportMaterialIdentity<EmailOtpEd25519LaneAuth>;
  expectedMaterialActivation: MpcMaterialActivationRef;
  readActiveWalletSessionAuthorization: (
    walletId: WalletId,
  ) => Promise<WalletSessionAuthorizationReadResult<ActiveWalletSessionAuthorizationProjection>>;
  resolveActiveCapability: (
    walletId: WalletId,
    nearAccountId: AccountId,
    materialActivation: MpcMaterialActivationRef,
  ) => NearEd25519YaoOperationMaterial | null;
}): Promise<ResolvedWalletCustodyEd25519ExportV1> {
  const walletId = input.subject.signer.account.wallet.walletId;
  const authorization = resolveActiveEmailOtpAuthorization({
    walletId,
    result: await input.readActiveWalletSessionAuthorization(walletId),
  });
  const material = input.resolveActiveCapability(
    walletId,
    input.subject.signer.account.nearAccountId,
    input.expectedMaterialActivation,
  );
  if (!material) {
    throw new Error('[SigningEngine][ed25519-export] active wallet custody material is unavailable');
  }
  return {
    kind: 'wallet_custody_ed25519_export_context_v1',
    lane: input.subject,
    authorization,
    material: {
      materialActivation: input.expectedMaterialActivation,
      capability: capabilityFromActiveMaterial({
        subject: input.subject,
        expectedMaterialActivation: input.expectedMaterialActivation,
        material,
      }),
    },
  };
}
