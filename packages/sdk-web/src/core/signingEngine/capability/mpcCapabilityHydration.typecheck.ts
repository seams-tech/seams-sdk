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

const rehydratePlan = buildRehydrateActiveMpcMaterialSessionPlan({
  capability,
  materialOwner,
  authority,
  activeMaterialSession,
  sealedMaterial,
});

const reauthorizePlan = buildReauthorizeMpcCapabilityPublicAnchorPlan({
  retirement: 'exhausted',
  publicReauthAnchor,
});

const blockedPlan = buildBlockedMpcCapabilityHydrationPlan({
  capability,
  reason: 'persistence_unavailable',
});

void buildMpcCapabilityHydrationResolution({
  entryPoint: 'post_page_refresh',
  plan: rehydratePlan,
});

function consumeHydrationPlan(plan: MpcCapabilityHydrationPlan): void {
  void plan;
}

consumeHydrationPlan(livePlan);
consumeHydrationPlan(rehydratePlan);
consumeHydrationPlan(reauthorizePlan);
consumeHydrationPlan(blockedPlan);

const mixedLivePlan = {
  ...livePlan,
  sealedMaterial,
};
// @ts-expect-error a live runtime plan cannot also carry sealed material
mixedLivePlan satisfies MpcCapabilityHydrationPlan;

const mixedReauthorizePlan = {
  ...reauthorizePlan,
  activeMaterialSession,
};
// @ts-expect-error a public-anchor plan cannot carry an active material session
mixedReauthorizePlan satisfies MpcCapabilityHydrationPlan;

const blockedWithAuthority = {
  ...blockedPlan,
  authority,
};
// @ts-expect-error a blocked plan cannot carry an authorization authority
blockedWithAuthority satisfies MpcCapabilityHydrationPlan;

const anchorWithSecret = {
  ...publicReauthAnchor,
  secretMaterial: new Uint8Array(32),
};
// @ts-expect-error a public reauthorization anchor cannot contain secret material
anchorWithSecret satisfies MpcCapabilityPublicReauthAnchor;

const directLivePlan = {
  kind: 'use_live_runtime',
  capability,
  materialOwner,
  authority,
  runtime,
  activeMaterialSession,
};
// @ts-expect-error lifecycle plans must be constructed by their branch builder
directLivePlan satisfies MpcCapabilityHydrationPlan;

const rawStringIdentity = {
  capability: 'capability:raw',
  materialOwner,
  authority,
  runtime,
  activeMaterialSession,
};
// @ts-expect-error branch builders reject raw identity strings
buildUseLiveMpcCapabilityRuntimePlan(rawStringIdentity);

const sealedPlanWithoutActiveSession = {
  capability,
  materialOwner,
  authority,
  sealedMaterial,
};
// @ts-expect-error sealed material is unusable without an exact active material session
buildRehydrateActiveMpcMaterialSessionPlan(sealedPlanWithoutActiveSession);

const livePlanWithoutRuntime = {
  capability,
  materialOwner,
  authority,
  activeMaterialSession,
};
// @ts-expect-error a live branch requires capability-local runtime readiness proof
buildUseLiveMpcCapabilityRuntimePlan(livePlanWithoutRuntime);

const retiredPlanWithoutPublicAnchor = {
  retirement: 'expired' as const,
};
// @ts-expect-error retired material cannot be reauthorized without its exact public anchor
buildReauthorizeMpcCapabilityPublicAnchorPlan(retiredPlanWithoutPublicAnchor);

const resolution = buildMpcCapabilityHydrationResolution({
  entryPoint: 'post_registration',
  plan: livePlan,
});
// @ts-expect-error executors consume the plan without entry-point provenance
consumeHydrationPlan(resolution);
