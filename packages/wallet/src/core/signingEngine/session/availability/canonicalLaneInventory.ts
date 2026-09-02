export type ServerIssuedGeneration = string & { readonly __brand: 'ServerIssuedGeneration' };

export type CanonicalFactExactness = 'exact_target' | 'shared_projection';

export type CanonicalTieBreakOrder = -1 | 0 | 1;

export type CanonicalFactSupersession<TFact extends object> = {
  isOperationUsable(fact: TFact): boolean;
  generation(fact: TFact): ServerIssuedGeneration | null;
  exactness(fact: TFact): CanonicalFactExactness;
  tieBreak(left: TFact, right: TFact): CanonicalTieBreakOrder;
};

export type CanonicalLaneInventoryAdapter<TFact extends object, TGroupKey, TConflict> = {
  groupKey(fact: TFact): TGroupKey;
  groupKeyString(groupKey: TGroupKey): string;
  groupConflicts(facts: readonly TFact[]): readonly TConflict[];
  supersession: CanonicalFactSupersession<TFact>;
};

export type CanonicalLaneSelection<TFact extends object, TConflict> =
  | {
      kind: 'selected';
      selectedFact: TFact;
      supersededFacts: readonly TFact[];
    }
  | {
      kind: 'no_current_lane';
      unusableFacts: readonly TFact[];
    }
  | {
      kind: 'conflicting_key_material';
      conflicts: readonly TConflict[];
    }
  | {
      kind: 'ambiguous_material';
      candidates: readonly TFact[];
    };

type CanonicalFactGroup<TFact extends object, TGroupKey> = {
  groupKey: TGroupKey;
  facts: readonly TFact[];
};

type CanonicalFactPreference<TFact extends object> =
  | { kind: 'left' }
  | { kind: 'right' }
  | { kind: 'ambiguous'; candidates: readonly TFact[] };

export function serverIssuedGenerationFromNumber(
  value: number | null | undefined,
): ServerIssuedGeneration | null {
  const normalized = Math.floor(Number(value));
  if (!Number.isFinite(normalized) || normalized <= 0) return null;
  return normalized.toString(10).padStart(20, '0') as ServerIssuedGeneration;
}

export function canonicalizeLaneFacts<TFact extends object, TGroupKey, TConflict>(
  facts: readonly TFact[],
  adapter: CanonicalLaneInventoryAdapter<TFact, TGroupKey, TConflict>,
): CanonicalLaneSelection<TFact, TConflict> {
  if (facts.length === 0) return { kind: 'no_current_lane', unusableFacts: [] };
  const groups = canonicalFactGroups(facts, adapter);
  const conflicts = canonicalFactGroupConflicts(groups, adapter);
  if (conflicts.length) return { kind: 'conflicting_key_material', conflicts };
  if (groups.length !== 1) return { kind: 'ambiguous_material', candidates: facts };
  const group = groups[0];
  if (!group) return { kind: 'no_current_lane', unusableFacts: [] };
  return canonicalizeSingleLaneFactGroup(group, adapter.supersession);
}

function canonicalizeSingleLaneFactGroup<TFact extends object, TGroupKey, TConflict>(
  group: CanonicalFactGroup<TFact, TGroupKey>,
  supersession: CanonicalFactSupersession<TFact>,
): CanonicalLaneSelection<TFact, TConflict> {
  const usableFacts = group.facts.filter(supersession.isOperationUsable);
  if (usableFacts.length === 0) {
    return { kind: 'no_current_lane', unusableFacts: group.facts };
  }
  const selected = selectCanonicalFact(usableFacts, supersession);
  if (selected.kind === 'ambiguous') {
    return { kind: 'ambiguous_material', candidates: selected.candidates };
  }
  return {
    kind: 'selected',
    selectedFact: selected.fact,
    supersededFacts: group.facts.filter((fact) => fact !== selected.fact),
  };
}

function canonicalFactGroups<TFact extends object, TGroupKey, TConflict>(
  facts: readonly TFact[],
  adapter: CanonicalLaneInventoryAdapter<TFact, TGroupKey, TConflict>,
): CanonicalFactGroup<TFact, TGroupKey>[] {
  const groupsByKey = new Map<string, CanonicalFactGroup<TFact, TGroupKey>>();
  for (const fact of facts) {
    const groupKey = adapter.groupKey(fact);
    const encodedGroupKey = adapter.groupKeyString(groupKey);
    const existingGroup = groupsByKey.get(encodedGroupKey);
    groupsByKey.set(
      encodedGroupKey,
      existingGroup
        ? { groupKey: existingGroup.groupKey, facts: [...existingGroup.facts, fact] }
        : { groupKey, facts: [fact] },
    );
  }
  return [...groupsByKey.values()];
}

function canonicalFactGroupConflicts<TFact extends object, TGroupKey, TConflict>(
  groups: readonly CanonicalFactGroup<TFact, TGroupKey>[],
  adapter: CanonicalLaneInventoryAdapter<TFact, TGroupKey, TConflict>,
): TConflict[] {
  return groups.flatMap((group) => adapter.groupConflicts(group.facts));
}

function selectCanonicalFact<TFact extends object>(
  facts: readonly TFact[],
  supersession: CanonicalFactSupersession<TFact>,
): { kind: 'selected'; fact: TFact } | { kind: 'ambiguous'; candidates: readonly TFact[] } {
  const firstFact = facts[0];
  if (firstFact === undefined) return { kind: 'ambiguous', candidates: [] };
  let selectedFact = firstFact;
  for (const candidateFact of facts.slice(1)) {
    const preference = canonicalFactPreference(selectedFact, candidateFact, supersession);
    switch (preference.kind) {
      case 'left':
        break;
      case 'right':
        selectedFact = candidateFact;
        break;
      case 'ambiguous':
        return { kind: 'ambiguous', candidates: preference.candidates };
      default: {
        const exhaustive: never = preference;
        return exhaustive;
      }
    }
  }
  return { kind: 'selected', fact: selectedFact };
}

function canonicalFactPreference<TFact extends object>(
  left: TFact,
  right: TFact,
  supersession: CanonicalFactSupersession<TFact>,
): CanonicalFactPreference<TFact> {
  const generationPreference = canonicalGenerationPreference(left, right, supersession);
  if (generationPreference.kind !== 'equal') return generationPreference;
  const exactnessPreference = canonicalExactnessPreference(left, right, supersession);
  if (exactnessPreference.kind !== 'equal') return exactnessPreference;
  const tieBreakPreference = supersession.tieBreak(left, right);
  switch (tieBreakPreference) {
    case 1:
      return { kind: 'left' };
    case -1:
      return { kind: 'right' };
    case 0:
      return { kind: 'ambiguous', candidates: [left, right] };
    default: {
      const exhaustive: never = tieBreakPreference;
      return exhaustive;
    }
  }
}

function canonicalGenerationPreference<TFact extends object>(
  left: TFact,
  right: TFact,
  supersession: CanonicalFactSupersession<TFact>,
): CanonicalFactPreference<TFact> | { kind: 'equal' } {
  const leftGeneration = supersession.generation(left);
  const rightGeneration = supersession.generation(right);
  if (!leftGeneration || !rightGeneration) {
    return { kind: 'ambiguous', candidates: [left, right] };
  }
  if (leftGeneration > rightGeneration) return { kind: 'left' };
  if (rightGeneration > leftGeneration) return { kind: 'right' };
  return { kind: 'equal' };
}

function canonicalExactnessPreference<TFact extends object>(
  left: TFact,
  right: TFact,
  supersession: CanonicalFactSupersession<TFact>,
): CanonicalFactPreference<TFact> | { kind: 'equal' } {
  const leftExactness = supersession.exactness(left);
  const rightExactness = supersession.exactness(right);
  if (leftExactness === rightExactness) return { kind: 'equal' };
  if (leftExactness === 'exact_target') return { kind: 'left' };
  return { kind: 'right' };
}
