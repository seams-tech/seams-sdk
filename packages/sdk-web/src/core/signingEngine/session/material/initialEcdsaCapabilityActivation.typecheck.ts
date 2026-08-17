import { parseWalletAuthMethodId } from '@shared/utils/domainIds';
import type {
  SigningRootId,
  SigningRootVersion,
} from '@shared/threshold/ecdsaDerivationRoleLocalBootstrap';
import type { WalletAuthorityBindingDigest, WalletId } from '@shared/utils/domainIds';
import type {
  CanonicalEcdsaServerActivationRequest,
  EcdsaCapabilityManifestId,
} from '@shared/utils/ecdsaCapabilityActivation';
import type { CorrelationId, DigestB64u, IsoTimestamp } from '@shared/utils/canonicalPrimitives';
import type { WalletAuthAuthorityRef } from '@shared/utils/walletAuthAuthority';
import type { ThresholdEcdsaChainTarget } from '@/core/platform/types';
import type { EvmFamilySigningKeySlotId } from '@shared/signing-lanes';
import type { RuntimePolicyScope } from '@shared/threshold/signingRootScope';
import type { ParticipantId } from '../identity/evmFamilyEcdsaIdentity';
import type {
  EcdsaClientVerifyingPublicKey33B64u,
  EcdsaRelayerKeyId,
  EcdsaRoleLocalBindingDigest,
  EcdsaThresholdKeyId,
} from '../keyMaterialBrands';
import {
  buildInitialEcdsaCapabilityActivationPlan,
  type InitialEcdsaCapabilityActivationPlan,
  type InitialEcdsaCapabilityActivationPlanInput,
} from './initialEcdsaCapabilityActivation';

declare const walletId: WalletId;
declare const authorityDigest: WalletAuthorityBindingDigest;
declare const evmFamilySigningKeySlotId: EvmFamilySigningKeySlotId;
declare const ecdsaThresholdKeyId: EcdsaThresholdKeyId;
declare const signingRootId: SigningRootId;
declare const signingRootVersion: SigningRootVersion;
declare const runtimePolicyScope: RuntimePolicyScope;
declare const clientVerifyingPublicKey33B64u: EcdsaClientVerifyingPublicKey33B64u;
declare const participantId: ParticipantId;
declare const relayerKeyId: EcdsaRelayerKeyId;
declare const bindingDigest: EcdsaRoleLocalBindingDigest;
declare const journalId: CorrelationId;
declare const requestDigest: DigestB64u;
declare const canonicalRequest: CanonicalEcdsaServerActivationRequest;
declare const createdAt: IsoTimestamp;
declare const callerManifestId: EcdsaCapabilityManifestId;
declare const plan: InitialEcdsaCapabilityActivationPlan;

const walletAuthMethodId = parseWalletAuthMethodId('passkey:wallet.example.test:typecheck');
if (!walletAuthMethodId.ok) {
  throw new Error('type fixture requires a valid wallet auth-method identity');
}
const authority: WalletAuthAuthorityRef = {
  kind: 'wallet_auth_authority_ref',
    walletAuthMethodId: walletAuthMethodId.value,
  walletId,
  authorityDigest,
};

const chainTarget: ThresholdEcdsaChainTarget = {
  kind: 'evm',
  namespace: 'eip155',
  chainId: 1,
  networkSlug: 'ethereum',
};

const validInput = {
  authority,
  targetMemberships: [chainTarget],
  evmFamilySigningKeySlotId,
  ecdsaThresholdKeyId,
  signingRootId,
  signingRootVersion,
  runtimePolicyScope,
  clientVerifyingPublicKey33B64u,
  participantIds: [participantId],
  relayerKeyId,
  bindingDigest,
  journalId,
  requestDigest,
  canonicalRequest,
  createdAt,
} satisfies InitialEcdsaCapabilityActivationPlanInput;

void buildInitialEcdsaCapabilityActivationPlan(validInput);

// @ts-expect-error The worker must add pending plaintext after planning.
const persistenceInput: { readonly pendingPayloadB64u: string } = plan;
void persistenceInput;

buildInitialEcdsaCapabilityActivationPlan({
  ...validInput,
  // @ts-expect-error The worker owns the pending protocol payload.
  pendingPayloadB64u: 'worker-owned-pending-payload',
});

buildInitialEcdsaCapabilityActivationPlan({
  ...validInput,
  // @ts-expect-error The retired state-blob field is not a compatibility alias.
  pendingStateBlobB64u: 'retired-pending-state-blob',
});

buildInitialEcdsaCapabilityActivationPlan({
  ...validInput,
  // @ts-expect-error Ceremony/session identities cannot become activation identities.
  thresholdSessionId: journalId,
});

buildInitialEcdsaCapabilityActivationPlan({
  ...validInput,
  // @ts-expect-error Worker material handles cannot become durable material identities.
  materialHandle: 'worker-material-handle',
});

buildInitialEcdsaCapabilityActivationPlan({
  ...validInput,
  // @ts-expect-error Caller-supplied manifest identities cannot bypass fresh generation.
  manifestId: callerManifestId,
});

buildInitialEcdsaCapabilityActivationPlan({
  ...validInput,
  authority: {
    kind: 'wallet_auth_authority_ref',
    walletAuthMethodId: walletAuthMethodId.value,
    walletId,
    // @ts-expect-error Exact authority references require their authority digest.
    authorityDigest: undefined,
  },
});

buildInitialEcdsaCapabilityActivationPlan({
  ...validInput,
  // @ts-expect-error Threshold-key identity cannot be substituted by a signing-root identity.
  ecdsaThresholdKeyId: signingRootId,
});
