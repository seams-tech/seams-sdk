import { parseWalletAuthMethodId } from '@shared/utils/domainIds';
import type {
  CapabilityInstanceRef,
  MpcCapabilityRuntimeRef,
  MpcKeyBindingRef,
  MpcLifecycleBindingRef,
  MpcMaterialActivationId,
  MpcMaterialActivationRef,
  MpcMaterialOwnerRef,
  MpcReauthorizationPolicyRef,
  MpcRegisteredPublicKeyBindingRef,
  MpcSigningWorkerRef,
  WalletAuthorityBindingDigest,
  WalletId,
} from '@shared/utils/domainIds';
import { buildMpcMaterialActivationRef } from '@shared/utils/domainIds';
import type { WalletAuthAuthorityRef } from '@shared/utils/walletAuthAuthority';
import type { EcdsaCapabilityManifestLookup } from '@/core/indexedDB/seamsWalletDB/ecdsaCapabilityManifestStore';
import { resolveEcdsaCapabilityHydration } from './ecdsaCapabilityHydration';
import {
  resolveNearEd25519YaoCapabilityHydrationV1,
  type NearEd25519YaoPublicLocatorObservationV1,
  type NearEd25519YaoRuntimeObservationV1,
  type NearEd25519YaoSealedMaterialObservationV1,
  type NearEd25519YaoUnlockSourceObservationV1,
} from './nearEd25519YaoMaterialActivation';
import {
  buildBlockedMpcCapabilityHydrationPlan,
  buildMpcCapabilityPublicReauthAnchor,
  buildReauthorizePublicAnchorHydrationPlan,
  buildRehydrateMaterialActivationHydrationPlan,
  buildUseLiveRuntimeHydrationPlan,
  type MpcCapabilityHydrationPlan,
  type MpcCapabilityPublicReauthAnchor,
  type RestorableMpcMaterialRef,
} from './mpcCapabilityHydration';

declare const capability: CapabilityInstanceRef;
declare const otherCapability: CapabilityInstanceRef;
declare const materialOwner: MpcMaterialOwnerRef;
declare const runtime: MpcCapabilityRuntimeRef;
declare const activationId: MpcMaterialActivationId;
declare const signingWorker: MpcSigningWorkerRef;
declare const keyBinding: MpcKeyBindingRef;
declare const lifecycleBinding: MpcLifecycleBindingRef;
declare const sealedMaterial: RestorableMpcMaterialRef;
declare const reauthorizationPolicy: MpcReauthorizationPolicyRef;
declare const registeredPublicKeyBinding: MpcRegisteredPublicKeyBindingRef;
declare const walletId: WalletId;
declare const authorityDigest: WalletAuthorityBindingDigest;
declare const ecdsaLookup: EcdsaCapabilityManifestLookup;
declare const nearPublicLocator: NearEd25519YaoPublicLocatorObservationV1;
declare const nearSealedMaterial: NearEd25519YaoSealedMaterialObservationV1;
declare const nearRuntime: NearEd25519YaoRuntimeObservationV1;
declare const nearUnlockSource: NearEd25519YaoUnlockSourceObservationV1;

// @ts-expect-error Restorable material is constructed only by protocol hydration adapters.
const rawRestorableMaterial: RestorableMpcMaterialRef = 'raw-material-ref';

// @ts-expect-error Structural lookalikes cannot forge protocol-owned restorable material.
const structuralRestorableMaterial: RestorableMpcMaterialRef = {
  kind: 'restorable_mpc_material_ref',
  durableMaterialRef: 'raw-material-ref',
};

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

const materialActivation = buildMpcMaterialActivationRef({
  activationId,
  capability,
  materialOwner,
  keyBinding,
  lifecycleBinding,
  signingWorker,
});

const publicReauthAnchor = buildMpcCapabilityPublicReauthAnchor({
  capability,
  materialOwner,
  authority,
  keyBinding,
  lifecycleBinding,
  reauthorizationPolicy,
  registeredPublicKeyBinding,
});

const livePlan = buildUseLiveRuntimeHydrationPlan({
  authority,
  runtime,
  materialActivation,
});

const sealedPlan = buildRehydrateMaterialActivationHydrationPlan({
  authority,
  materialActivation,
  sealedMaterial,
});

const reauthPlan = buildReauthorizePublicAnchorHydrationPlan({
  retirement: 'expired',
  publicReauthAnchor,
});

const blockedPlan = buildBlockedMpcCapabilityHydrationPlan({
  capability: null,
  reason: 'missing_capability',
});

resolveEcdsaCapabilityHydration({
  // @ts-expect-error Hydration decisions cannot vary by registration, unlock, or refresh provenance.
  entryPoint: 'post_page_refresh',
  lookup: ecdsaLookup,
  runtime: { kind: 'absent' },
});

resolveEcdsaCapabilityHydration({
  // @ts-expect-error Diagnostic provenance cannot enter the ECDSA hydration decision.
  provenance: { entryPoint: 'post_registration' },
  lookup: ecdsaLookup,
  runtime: { kind: 'absent' },
});

resolveNearEd25519YaoCapabilityHydrationV1({
  // @ts-expect-error Hydration decisions cannot vary by registration, unlock, or refresh provenance.
  entryPoint: 'post_wallet_unlock',
  publicLocator: nearPublicLocator,
  sealed: nearSealedMaterial,
  runtime: nearRuntime,
  unlockSource: nearUnlockSource,
});

resolveNearEd25519YaoCapabilityHydrationV1({
  // @ts-expect-error Diagnostic provenance cannot enter the Near hydration decision.
  provenance: { entryPoint: 'post_page_refresh' },
  publicLocator: nearPublicLocator,
  sealed: nearSealedMaterial,
  runtime: nearRuntime,
  unlockSource: nearUnlockSource,
});

// @ts-expect-error Blocked plans can only be constructed by their branch builder.
const directBlockedPlan: MpcCapabilityHydrationPlan = {
  kind: 'blocked',
  capability: null,
  reason: 'missing_capability',
};

// @ts-expect-error Missing-capability failures carry no capability reference.
buildBlockedMpcCapabilityHydrationPlan({
  capability,
  reason: 'missing_capability',
});

// @ts-expect-error Known-capability failures require the exact capability reference.
buildBlockedMpcCapabilityHydrationPlan({
  capability: null,
  reason: 'corrupt',
});

// @ts-expect-error Activation references can only be constructed by their proof builder.
const directActivation: MpcMaterialActivationRef = {
  kind: 'mpc_material_activation_ref',
  activationId,
  capability,
  materialOwner,
  keyBinding,
  lifecycleBinding,
  signingWorker,
};

// @ts-expect-error Public reauthorization anchors can only be constructed by their builder.
const directAnchor: MpcCapabilityPublicReauthAnchor = {
  kind: 'mpc_capability_public_reauth_anchor',
  capability,
  materialOwner,
  authority,
  keyBinding,
  lifecycleBinding,
  reauthorizationPolicy,
  registeredPublicKeyBinding,
};

const spreadLivePlan = {
  ...livePlan,
  capability: otherCapability,
};

// @ts-expect-error Spreading a proof loses opacity even when replacement fields are branded.
const broadSpreadPlan: MpcCapabilityHydrationPlan = spreadLivePlan;

// @ts-expect-error Derived capability fields cannot be supplied through broad builder inputs.
buildUseLiveRuntimeHydrationPlan(spreadLivePlan);

const reauthWithDuplicateAuthority = {
  retirement: 'expired' as const,
  publicReauthAnchor,
  authority,
};

// @ts-expect-error Reauthorization authority is derived from the public anchor.
buildReauthorizePublicAnchorHydrationPlan(reauthWithDuplicateAuthority);

buildUseLiveRuntimeHydrationPlan({
  authority,
  runtime,
  materialActivation,
  // @ts-expect-error Live-runtime hydration cannot also carry sealed material.
  sealedMaterial,
});

// @ts-expect-error Live-runtime hydration requires an exact runtime proof.
buildUseLiveRuntimeHydrationPlan({
  authority,
  materialActivation,
});

// @ts-expect-error Sealed-material hydration requires the exact material activation.
buildRehydrateMaterialActivationHydrationPlan({
  authority,
  sealedMaterial,
});

// @ts-expect-error Retired reauthorization requires a public reauthorization anchor.
buildReauthorizePublicAnchorHydrationPlan({
  retirement: 'exhausted',
});

buildMpcCapabilityPublicReauthAnchor({
  capability,
  materialOwner,
  authority,
  keyBinding,
  lifecycleBinding,
  reauthorizationPolicy,
  registeredPublicKeyBinding,
  // @ts-expect-error Public anchors cannot carry bearer credentials.
  bearerSessionCredential: 'jwt',
});

void directActivation;
void directAnchor;
void directBlockedPlan;
void broadSpreadPlan;
void rawRestorableMaterial;
void structuralRestorableMaterial;
