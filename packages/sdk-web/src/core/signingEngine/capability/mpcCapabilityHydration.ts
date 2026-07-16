const hydrationPlanBrand: unique symbol = Symbol('mpc-capability-hydration-plan');
const publicReauthAnchorBrand: unique symbol = Symbol('mpc-capability-public-reauth-anchor');
declare const lifecycleReferenceBrand: unique symbol;

export const MPC_CAPABILITY_HYDRATION_OBSERVATION_VERSION =
  'mpc_capability_hydration_observation_v1' as const;

export type MpcCapabilityLifecycleReferenceKind =
  | 'capability_instance'
  | 'material_owner'
  | 'wallet_auth_authority'
  | 'capability_runtime'
  | 'active_material_session'
  | 'restorable_material'
  | 'key_binding'
  | 'lifecycle_binding'
  | 'policy_binding'
  | 'registered_public_key_binding';

export type MpcCapabilityLifecycleReference<Kind extends MpcCapabilityLifecycleReferenceKind> =
  string & {
    readonly [lifecycleReferenceBrand]: Kind;
  };

export type CapabilityInstanceRef = MpcCapabilityLifecycleReference<'capability_instance'>;
export type MpcMaterialOwnerRef = MpcCapabilityLifecycleReference<'material_owner'>;
export type WalletAuthAuthorityRef = MpcCapabilityLifecycleReference<'wallet_auth_authority'>;
export type MpcCapabilityRuntimeRef = MpcCapabilityLifecycleReference<'capability_runtime'>;
export type ActiveMpcMaterialSessionRef =
  MpcCapabilityLifecycleReference<'active_material_session'>;
export type RestorableMpcMaterialRef = MpcCapabilityLifecycleReference<'restorable_material'>;
export type MpcKeyBindingRef = MpcCapabilityLifecycleReference<'key_binding'>;
export type MpcLifecycleBindingRef = MpcCapabilityLifecycleReference<'lifecycle_binding'>;
export type MpcPolicyBindingRef = MpcCapabilityLifecycleReference<'policy_binding'>;
export type MpcRegisteredPublicKeyBindingRef =
  MpcCapabilityLifecycleReference<'registered_public_key_binding'>;

export type MpcCapabilityHydrationEntryPoint =
  | 'post_registration'
  | 'post_wallet_unlock'
  | 'post_page_refresh';

export type MpcCapabilityRetirement = 'expired' | 'exhausted';

export type MpcCapabilityHydrationBlockedReason =
  | 'missing_capability'
  | 'missing_material'
  | 'revoked'
  | 'ambiguous_authority'
  | 'binding_mismatch'
  | 'corrupt_persistence'
  | 'persistence_unavailable';

export type MpcCapabilityPublicReauthAnchor = {
  readonly [publicReauthAnchorBrand]: true;
  readonly kind: 'mpc_capability_public_reauth_anchor_v1';
  readonly capability: CapabilityInstanceRef;
  readonly materialOwner: MpcMaterialOwnerRef;
  readonly authority: WalletAuthAuthorityRef;
  readonly keyBinding: MpcKeyBindingRef;
  readonly lifecycleBinding: MpcLifecycleBindingRef;
  readonly policyBinding: MpcPolicyBindingRef;
  readonly registeredPublicKeyBinding: MpcRegisteredPublicKeyBindingRef;
  readonly secretMaterial?: never;
  readonly sealedMaterial?: never;
  readonly bearerSessionCredential?: never;
  readonly runtime?: never;
  readonly activeMaterialSession?: never;
  readonly operationGrant?: never;
  readonly quotaState?: never;
  readonly nonceState?: never;
};

export type UseLiveMpcCapabilityRuntimePlan = {
  readonly [hydrationPlanBrand]: true;
  readonly kind: 'use_live_runtime';
  readonly capability: CapabilityInstanceRef;
  readonly materialOwner: MpcMaterialOwnerRef;
  readonly authority: WalletAuthAuthorityRef;
  readonly runtime: MpcCapabilityRuntimeRef;
  readonly activeMaterialSession: ActiveMpcMaterialSessionRef;
  readonly sealedMaterial?: never;
  readonly retirement?: never;
  readonly publicReauthAnchor?: never;
};

export type RehydrateActiveMpcMaterialSessionPlan = {
  readonly [hydrationPlanBrand]: true;
  readonly kind: 'rehydrate_active_session';
  readonly capability: CapabilityInstanceRef;
  readonly materialOwner: MpcMaterialOwnerRef;
  readonly authority: WalletAuthAuthorityRef;
  readonly activeMaterialSession: ActiveMpcMaterialSessionRef;
  readonly sealedMaterial: RestorableMpcMaterialRef;
  readonly runtime?: never;
  readonly retirement?: never;
  readonly publicReauthAnchor?: never;
};

export type ReauthorizeMpcCapabilityPublicAnchorPlan = {
  readonly [hydrationPlanBrand]: true;
  readonly kind: 'reauthorize_public_anchor';
  readonly capability: CapabilityInstanceRef;
  readonly materialOwner: MpcMaterialOwnerRef;
  readonly authority: WalletAuthAuthorityRef;
  readonly retirement: MpcCapabilityRetirement;
  readonly publicReauthAnchor: MpcCapabilityPublicReauthAnchor;
  readonly runtime?: never;
  readonly activeMaterialSession?: never;
  readonly sealedMaterial?: never;
};

export type BlockedMpcCapabilityHydrationPlan = {
  readonly [hydrationPlanBrand]: true;
  readonly kind: 'blocked';
  readonly capability: CapabilityInstanceRef | null;
  readonly reason: MpcCapabilityHydrationBlockedReason;
  readonly materialOwner?: never;
  readonly authority?: never;
  readonly runtime?: never;
  readonly activeMaterialSession?: never;
  readonly sealedMaterial?: never;
  readonly retirement?: never;
  readonly publicReauthAnchor?: never;
};

export type MpcCapabilityHydrationPlan =
  | UseLiveMpcCapabilityRuntimePlan
  | RehydrateActiveMpcMaterialSessionPlan
  | ReauthorizeMpcCapabilityPublicAnchorPlan
  | BlockedMpcCapabilityHydrationPlan;

export type MpcCapabilityHydrationResolution = {
  readonly provenance: {
    readonly entryPoint: MpcCapabilityHydrationEntryPoint;
  };
  readonly plan: MpcCapabilityHydrationPlan;
};

export type MpcCapabilityLifecycleParseFailure = {
  readonly ok: false;
  readonly code: 'invalid_mpc_capability_hydration_observation';
  readonly path: string;
  readonly message: string;
  readonly value?: never;
};

export type MpcCapabilityLifecycleParseSuccess<Value> = {
  readonly ok: true;
  readonly value: Value;
  readonly code?: never;
  readonly path?: never;
  readonly message?: never;
};

export type MpcCapabilityLifecycleParseResult<Value> =
  | MpcCapabilityLifecycleParseSuccess<Value>
  | MpcCapabilityLifecycleParseFailure;

type ParsedRecord = Readonly<Record<string, unknown>>;

function parseFailure(path: string, message: string): MpcCapabilityLifecycleParseFailure {
  return {
    ok: false,
    code: 'invalid_mpc_capability_hydration_observation',
    path,
    message,
  };
}

function isPlainObject(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function parseExactRecord(
  value: unknown,
  expectedKeys: readonly string[],
  path: string,
): MpcCapabilityLifecycleParseResult<ParsedRecord> {
  if (!isPlainObject(value)) {
    return parseFailure(path, 'must be an object');
  }
  const actualKeys = Object.keys(value);
  for (const expectedKey of expectedKeys) {
    if (!Object.hasOwn(value, expectedKey)) {
      return parseFailure(`${path}.${expectedKey}`, 'is required');
    }
  }
  for (const actualKey of actualKeys) {
    if (!expectedKeys.includes(actualKey)) {
      return parseFailure(`${path}.${actualKey}`, 'is not allowed');
    }
  }
  return { ok: true, value };
}

function parseLifecycleReference<Kind extends MpcCapabilityLifecycleReferenceKind>(
  value: unknown,
  kind: Kind,
  path: string,
): MpcCapabilityLifecycleParseResult<MpcCapabilityLifecycleReference<Kind>> {
  if (typeof value !== 'string') {
    return parseFailure(path, `${kind} reference must be a string`);
  }
  const normalized = value.trim();
  if (!normalized) {
    return parseFailure(path, `${kind} reference must be non-empty`);
  }
  return {
    ok: true,
    value: normalized as MpcCapabilityLifecycleReference<Kind>,
  };
}

export function parseMpcCapabilityLifecycleReference<
  Kind extends MpcCapabilityLifecycleReferenceKind,
>(input: {
  readonly kind: Kind;
  readonly value: unknown;
}): MpcCapabilityLifecycleParseResult<MpcCapabilityLifecycleReference<Kind>> {
  return parseLifecycleReference(input.value, input.kind, 'reference');
}

export function buildMpcCapabilityPublicReauthAnchor(input: {
  readonly capability: CapabilityInstanceRef;
  readonly materialOwner: MpcMaterialOwnerRef;
  readonly authority: WalletAuthAuthorityRef;
  readonly keyBinding: MpcKeyBindingRef;
  readonly lifecycleBinding: MpcLifecycleBindingRef;
  readonly policyBinding: MpcPolicyBindingRef;
  readonly registeredPublicKeyBinding: MpcRegisteredPublicKeyBindingRef;
}): MpcCapabilityPublicReauthAnchor {
  return {
    [publicReauthAnchorBrand]: true,
    kind: 'mpc_capability_public_reauth_anchor_v1',
    capability: input.capability,
    materialOwner: input.materialOwner,
    authority: input.authority,
    keyBinding: input.keyBinding,
    lifecycleBinding: input.lifecycleBinding,
    policyBinding: input.policyBinding,
    registeredPublicKeyBinding: input.registeredPublicKeyBinding,
  };
}

export function buildUseLiveMpcCapabilityRuntimePlan(input: {
  readonly capability: CapabilityInstanceRef;
  readonly materialOwner: MpcMaterialOwnerRef;
  readonly authority: WalletAuthAuthorityRef;
  readonly runtime: MpcCapabilityRuntimeRef;
  readonly activeMaterialSession: ActiveMpcMaterialSessionRef;
}): UseLiveMpcCapabilityRuntimePlan {
  return {
    [hydrationPlanBrand]: true,
    kind: 'use_live_runtime',
    capability: input.capability,
    materialOwner: input.materialOwner,
    authority: input.authority,
    runtime: input.runtime,
    activeMaterialSession: input.activeMaterialSession,
  };
}

export function buildRehydrateActiveMpcMaterialSessionPlan(input: {
  readonly capability: CapabilityInstanceRef;
  readonly materialOwner: MpcMaterialOwnerRef;
  readonly authority: WalletAuthAuthorityRef;
  readonly activeMaterialSession: ActiveMpcMaterialSessionRef;
  readonly sealedMaterial: RestorableMpcMaterialRef;
}): RehydrateActiveMpcMaterialSessionPlan {
  return {
    [hydrationPlanBrand]: true,
    kind: 'rehydrate_active_session',
    capability: input.capability,
    materialOwner: input.materialOwner,
    authority: input.authority,
    activeMaterialSession: input.activeMaterialSession,
    sealedMaterial: input.sealedMaterial,
  };
}

export function buildReauthorizeMpcCapabilityPublicAnchorPlan(input: {
  readonly retirement: MpcCapabilityRetirement;
  readonly publicReauthAnchor: MpcCapabilityPublicReauthAnchor;
}): ReauthorizeMpcCapabilityPublicAnchorPlan {
  return {
    [hydrationPlanBrand]: true,
    kind: 'reauthorize_public_anchor',
    capability: input.publicReauthAnchor.capability,
    materialOwner: input.publicReauthAnchor.materialOwner,
    authority: input.publicReauthAnchor.authority,
    retirement: input.retirement,
    publicReauthAnchor: input.publicReauthAnchor,
  };
}

export function buildBlockedMpcCapabilityHydrationPlan(input: {
  readonly capability: CapabilityInstanceRef | null;
  readonly reason: MpcCapabilityHydrationBlockedReason;
}): BlockedMpcCapabilityHydrationPlan {
  return {
    [hydrationPlanBrand]: true,
    kind: 'blocked',
    capability: input.capability,
    reason: input.reason,
  };
}

export function buildMpcCapabilityHydrationResolution(input: {
  readonly entryPoint: MpcCapabilityHydrationEntryPoint;
  readonly plan: MpcCapabilityHydrationPlan;
}): MpcCapabilityHydrationResolution {
  return {
    provenance: {
      entryPoint: input.entryPoint,
    },
    plan: input.plan,
  };
}

function parseEntryPoint(
  value: unknown,
  path: string,
): MpcCapabilityLifecycleParseResult<MpcCapabilityHydrationEntryPoint> {
  switch (value) {
    case 'post_registration':
    case 'post_wallet_unlock':
    case 'post_page_refresh':
      return { ok: true, value };
    default:
      return parseFailure(path, 'is not a supported hydration entry point');
  }
}

function parseRetirement(
  value: unknown,
  path: string,
): MpcCapabilityLifecycleParseResult<MpcCapabilityRetirement> {
  switch (value) {
    case 'expired':
    case 'exhausted':
      return { ok: true, value };
    default:
      return parseFailure(path, 'must be expired or exhausted');
  }
}

function parseBlockedReason(
  value: unknown,
  path: string,
): MpcCapabilityLifecycleParseResult<MpcCapabilityHydrationBlockedReason> {
  switch (value) {
    case 'missing_capability':
    case 'missing_material':
    case 'revoked':
    case 'ambiguous_authority':
    case 'binding_mismatch':
    case 'corrupt_persistence':
    case 'persistence_unavailable':
      return { ok: true, value };
    default:
      return parseFailure(path, 'is not a supported blocked reason');
  }
}

function parsePublicReauthAnchor(
  value: unknown,
  path: string,
): MpcCapabilityLifecycleParseResult<MpcCapabilityPublicReauthAnchor> {
  const recordResult = parseExactRecord(
    value,
    [
      'kind',
      'capability',
      'materialOwner',
      'authority',
      'keyBinding',
      'lifecycleBinding',
      'policyBinding',
      'registeredPublicKeyBinding',
    ],
    path,
  );
  if (!recordResult.ok) return recordResult;
  const record = recordResult.value;
  if (record.kind !== 'mpc_capability_public_reauth_anchor_v1') {
    return parseFailure(`${path}.kind`, 'is not a supported public reauthorization anchor');
  }
  const capability = parseLifecycleReference(
    record.capability,
    'capability_instance',
    `${path}.capability`,
  );
  if (!capability.ok) return capability;
  const materialOwner = parseLifecycleReference(
    record.materialOwner,
    'material_owner',
    `${path}.materialOwner`,
  );
  if (!materialOwner.ok) return materialOwner;
  const authority = parseLifecycleReference(
    record.authority,
    'wallet_auth_authority',
    `${path}.authority`,
  );
  if (!authority.ok) return authority;
  const keyBinding = parseLifecycleReference(
    record.keyBinding,
    'key_binding',
    `${path}.keyBinding`,
  );
  if (!keyBinding.ok) return keyBinding;
  const lifecycleBinding = parseLifecycleReference(
    record.lifecycleBinding,
    'lifecycle_binding',
    `${path}.lifecycleBinding`,
  );
  if (!lifecycleBinding.ok) return lifecycleBinding;
  const policyBinding = parseLifecycleReference(
    record.policyBinding,
    'policy_binding',
    `${path}.policyBinding`,
  );
  if (!policyBinding.ok) return policyBinding;
  const registeredPublicKeyBinding = parseLifecycleReference(
    record.registeredPublicKeyBinding,
    'registered_public_key_binding',
    `${path}.registeredPublicKeyBinding`,
  );
  if (!registeredPublicKeyBinding.ok) return registeredPublicKeyBinding;
  return {
    ok: true,
    value: buildMpcCapabilityPublicReauthAnchor({
      capability: capability.value,
      materialOwner: materialOwner.value,
      authority: authority.value,
      keyBinding: keyBinding.value,
      lifecycleBinding: lifecycleBinding.value,
      policyBinding: policyBinding.value,
      registeredPublicKeyBinding: registeredPublicKeyBinding.value,
    }),
  };
}

function parseUseLiveRuntimePlan(
  value: unknown,
  path: string,
): MpcCapabilityLifecycleParseResult<UseLiveMpcCapabilityRuntimePlan> {
  const recordResult = parseExactRecord(
    value,
    ['kind', 'capability', 'materialOwner', 'authority', 'runtime', 'activeMaterialSession'],
    path,
  );
  if (!recordResult.ok) return recordResult;
  const record = recordResult.value;
  const capability = parseLifecycleReference(
    record.capability,
    'capability_instance',
    `${path}.capability`,
  );
  if (!capability.ok) return capability;
  const materialOwner = parseLifecycleReference(
    record.materialOwner,
    'material_owner',
    `${path}.materialOwner`,
  );
  if (!materialOwner.ok) return materialOwner;
  const authority = parseLifecycleReference(
    record.authority,
    'wallet_auth_authority',
    `${path}.authority`,
  );
  if (!authority.ok) return authority;
  const runtime = parseLifecycleReference(record.runtime, 'capability_runtime', `${path}.runtime`);
  if (!runtime.ok) return runtime;
  const activeMaterialSession = parseLifecycleReference(
    record.activeMaterialSession,
    'active_material_session',
    `${path}.activeMaterialSession`,
  );
  if (!activeMaterialSession.ok) return activeMaterialSession;
  return {
    ok: true,
    value: buildUseLiveMpcCapabilityRuntimePlan({
      capability: capability.value,
      materialOwner: materialOwner.value,
      authority: authority.value,
      runtime: runtime.value,
      activeMaterialSession: activeMaterialSession.value,
    }),
  };
}

function parseRehydrateActiveSessionPlan(
  value: unknown,
  path: string,
): MpcCapabilityLifecycleParseResult<RehydrateActiveMpcMaterialSessionPlan> {
  const recordResult = parseExactRecord(
    value,
    ['kind', 'capability', 'materialOwner', 'authority', 'activeMaterialSession', 'sealedMaterial'],
    path,
  );
  if (!recordResult.ok) return recordResult;
  const record = recordResult.value;
  const capability = parseLifecycleReference(
    record.capability,
    'capability_instance',
    `${path}.capability`,
  );
  if (!capability.ok) return capability;
  const materialOwner = parseLifecycleReference(
    record.materialOwner,
    'material_owner',
    `${path}.materialOwner`,
  );
  if (!materialOwner.ok) return materialOwner;
  const authority = parseLifecycleReference(
    record.authority,
    'wallet_auth_authority',
    `${path}.authority`,
  );
  if (!authority.ok) return authority;
  const activeMaterialSession = parseLifecycleReference(
    record.activeMaterialSession,
    'active_material_session',
    `${path}.activeMaterialSession`,
  );
  if (!activeMaterialSession.ok) return activeMaterialSession;
  const sealedMaterial = parseLifecycleReference(
    record.sealedMaterial,
    'restorable_material',
    `${path}.sealedMaterial`,
  );
  if (!sealedMaterial.ok) return sealedMaterial;
  return {
    ok: true,
    value: buildRehydrateActiveMpcMaterialSessionPlan({
      capability: capability.value,
      materialOwner: materialOwner.value,
      authority: authority.value,
      activeMaterialSession: activeMaterialSession.value,
      sealedMaterial: sealedMaterial.value,
    }),
  };
}

function parseReauthorizePublicAnchorPlan(
  value: unknown,
  path: string,
): MpcCapabilityLifecycleParseResult<ReauthorizeMpcCapabilityPublicAnchorPlan> {
  const recordResult = parseExactRecord(value, ['kind', 'retirement', 'publicReauthAnchor'], path);
  if (!recordResult.ok) return recordResult;
  const record = recordResult.value;
  const retirement = parseRetirement(record.retirement, `${path}.retirement`);
  if (!retirement.ok) return retirement;
  const publicReauthAnchor = parsePublicReauthAnchor(
    record.publicReauthAnchor,
    `${path}.publicReauthAnchor`,
  );
  if (!publicReauthAnchor.ok) return publicReauthAnchor;
  return {
    ok: true,
    value: buildReauthorizeMpcCapabilityPublicAnchorPlan({
      retirement: retirement.value,
      publicReauthAnchor: publicReauthAnchor.value,
    }),
  };
}

function parseBlockedPlan(
  value: unknown,
  path: string,
): MpcCapabilityLifecycleParseResult<BlockedMpcCapabilityHydrationPlan> {
  const recordResult = parseExactRecord(value, ['kind', 'capability', 'reason'], path);
  if (!recordResult.ok) return recordResult;
  const record = recordResult.value;
  const reason = parseBlockedReason(record.reason, `${path}.reason`);
  if (!reason.ok) return reason;
  if (record.capability === null) {
    return {
      ok: true,
      value: buildBlockedMpcCapabilityHydrationPlan({
        capability: null,
        reason: reason.value,
      }),
    };
  }
  const capability = parseLifecycleReference(
    record.capability,
    'capability_instance',
    `${path}.capability`,
  );
  if (!capability.ok) return capability;
  return {
    ok: true,
    value: buildBlockedMpcCapabilityHydrationPlan({
      capability: capability.value,
      reason: reason.value,
    }),
  };
}

function parseHydrationPlan(
  value: unknown,
  path: string,
): MpcCapabilityLifecycleParseResult<MpcCapabilityHydrationPlan> {
  if (!isPlainObject(value)) {
    return parseFailure(path, 'must be an object');
  }
  switch (value.kind) {
    case 'use_live_runtime':
      return parseUseLiveRuntimePlan(value, path);
    case 'rehydrate_active_session':
      return parseRehydrateActiveSessionPlan(value, path);
    case 'reauthorize_public_anchor':
      return parseReauthorizePublicAnchorPlan(value, path);
    case 'blocked':
      return parseBlockedPlan(value, path);
    default:
      return parseFailure(`${path}.kind`, 'is not a supported hydration state');
  }
}

export function parseMpcCapabilityHydrationObservation(
  value: unknown,
): MpcCapabilityLifecycleParseResult<MpcCapabilityHydrationResolution> {
  const observation = parseExactRecord(value, ['version', 'entryPoint', 'state'], 'observation');
  if (!observation.ok) return observation;
  if (observation.value.version !== MPC_CAPABILITY_HYDRATION_OBSERVATION_VERSION) {
    return parseFailure('observation.version', 'is not a supported lifecycle observation version');
  }
  const entryPoint = parseEntryPoint(observation.value.entryPoint, 'observation.entryPoint');
  if (!entryPoint.ok) return entryPoint;
  const plan = parseHydrationPlan(observation.value.state, 'observation.state');
  if (!plan.ok) return plan;
  return {
    ok: true,
    value: buildMpcCapabilityHydrationResolution({
      entryPoint: entryPoint.value,
      plan: plan.value,
    }),
  };
}
