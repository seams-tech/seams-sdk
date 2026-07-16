import {
  buildBlockedMpcCapabilityHydrationPlan,
  buildMpcCapabilityHydrationResolution,
  buildMpcCapabilityPublicReauthAnchor,
  buildReauthorizeMpcCapabilityPublicAnchorPlan,
  buildRehydrateActiveMpcMaterialSessionPlan,
  buildUseLiveMpcCapabilityRuntimePlan,
  type ActiveMpcMaterialSessionRef,
  type CapabilityInstanceRef,
  type MpcCapabilityHydrationPlan,
  type MpcCapabilityPublicReauthAnchor,
  type MpcCapabilityRuntimeRef,
  type MpcKeyBindingRef,
  type MpcLifecycleBindingRef,
  type MpcMaterialOwnerRef,
  type MpcPolicyBindingRef,
  type MpcRegisteredPublicKeyBindingRef,
  type RestorableMpcMaterialRef,
  type WalletAuthAuthorityRef,
} from './mpcCapabilityHydration';

declare const capability: CapabilityInstanceRef;
declare const materialOwner: MpcMaterialOwnerRef;
declare const authority: WalletAuthAuthorityRef;
declare const runtime: MpcCapabilityRuntimeRef;
declare const activeMaterialSession: ActiveMpcMaterialSessionRef;
declare const sealedMaterial: RestorableMpcMaterialRef;
declare const keyBinding: MpcKeyBindingRef;
declare const lifecycleBinding: MpcLifecycleBindingRef;
declare const policyBinding: MpcPolicyBindingRef;
declare const registeredPublicKeyBinding: MpcRegisteredPublicKeyBindingRef;

const publicReauthAnchor = buildMpcCapabilityPublicReauthAnchor({
  capability,
  materialOwner,
  authority,
  keyBinding,
  lifecycleBinding,
  policyBinding,
  registeredPublicKeyBinding,
});
const livePlan = buildUseLiveMpcCapabilityRuntimePlan({
  capability,
  materialOwner,
  authority,
  runtime,
  activeMaterialSession,
});
const sealedPlan = buildRehydrateActiveMpcMaterialSessionPlan({
  capability,
  materialOwner,
  authority,
  activeMaterialSession,
  sealedMaterial,
});
const retiredPlan = buildReauthorizeMpcCapabilityPublicAnchorPlan({
  retirement: 'exhausted',
  publicReauthAnchor,
});
const blockedPlan = buildBlockedMpcCapabilityHydrationPlan({
  capability,
  reason: 'persistence_unavailable',
});

const plans = [
  livePlan,
  sealedPlan,
  retiredPlan,
  blockedPlan,
] satisfies readonly MpcCapabilityHydrationPlan[];
void plans;
void buildMpcCapabilityHydrationResolution({ entryPoint: 'post_page_refresh', plan: sealedPlan });

const mixedLivePlan = { ...livePlan, sealedMaterial };
// @ts-expect-error live runtime and sealed material branches are mutually exclusive
mixedLivePlan satisfies MpcCapabilityHydrationPlan;

const mixedRetiredPlan = { ...retiredPlan, activeMaterialSession };
// @ts-expect-error retired public-anchor branches cannot carry active sessions
mixedRetiredPlan satisfies MpcCapabilityHydrationPlan;

const anchorWithSecret = { ...publicReauthAnchor, secretMaterial: new Uint8Array(32) };
// @ts-expect-error public reauthorization anchors cannot carry secret material
anchorWithSecret satisfies MpcCapabilityPublicReauthAnchor;

buildUseLiveMpcCapabilityRuntimePlan({
  // @ts-expect-error builders reject raw identity strings
  capability: 'capability:raw',
  materialOwner,
  authority,
  runtime,
  activeMaterialSession,
});

// @ts-expect-error sealed material requires an exact active material session
buildRehydrateActiveMpcMaterialSessionPlan({
  capability,
  materialOwner,
  authority,
  sealedMaterial,
});

// @ts-expect-error retired material requires an exact public anchor
buildReauthorizeMpcCapabilityPublicAnchorPlan({ retirement: 'expired' });
