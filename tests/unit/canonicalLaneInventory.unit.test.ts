import { expect, test } from '@playwright/test';
import {
  canonicalizeLaneFacts,
  serverIssuedGenerationFromNumber,
  type CanonicalFactExactness,
  type CanonicalLaneInventoryAdapter,
  type CanonicalTieBreakOrder,
  type ServerIssuedGeneration,
} from '@/core/signingEngine/session/availability/canonicalLaneInventory';

type TestFact = {
  id: string;
  groupKey: string;
  usable: boolean;
  generation: ServerIssuedGeneration | null;
  exactness: CanonicalFactExactness;
  materialId: string;
};

type TestConflict = {
  kind: 'material_mismatch';
  materialIds: readonly string[];
};

function generation(value: number): ServerIssuedGeneration {
  const parsed = serverIssuedGenerationFromNumber(value);
  if (!parsed) throw new Error(`invalid test generation ${value}`);
  return parsed;
}

function fact(args: {
  id: string;
  generation?: ServerIssuedGeneration | null;
  exactness?: CanonicalFactExactness;
  usable?: boolean;
  groupKey?: string;
  materialId?: string;
}): TestFact {
  return {
    id: args.id,
    groupKey: args.groupKey || 'wallet-authority-key',
    usable: args.usable ?? true,
    generation: args.generation === undefined ? generation(100) : args.generation,
    exactness: args.exactness || 'exact_target',
    materialId: args.materialId || 'material-a',
  };
}

function testGroupKey(record: TestFact): string {
  return record.groupKey;
}

function testGroupKeyString(groupKey: string): string {
  return groupKey;
}

function testGroupConflicts(facts: readonly TestFact[]): readonly TestConflict[] {
  const materialIds = [...new Set(facts.map((record) => record.materialId))].sort();
  return materialIds.length > 1 ? [{ kind: 'material_mismatch', materialIds }] : [];
}

function testIsOperationUsable(record: TestFact): boolean {
  return record.usable;
}

function testGeneration(record: TestFact): ServerIssuedGeneration | null {
  return record.generation;
}

function testExactness(record: TestFact): CanonicalFactExactness {
  return record.exactness;
}

function testTieBreak(left: TestFact, right: TestFact): CanonicalTieBreakOrder {
  const comparison = left.id.localeCompare(right.id);
  if (comparison > 0) return 1;
  if (comparison < 0) return -1;
  return 0;
}

const adapter: CanonicalLaneInventoryAdapter<TestFact, string, TestConflict> = {
  groupKey: testGroupKey,
  groupKeyString: testGroupKeyString,
  groupConflicts: testGroupConflicts,
  supersession: {
    isOperationUsable: testIsOperationUsable,
    generation: testGeneration,
    exactness: testExactness,
    tieBreak: testTieBreak,
  },
};

test.describe('canonical lane inventory kernel', () => {
  test('selects the usable fact with the higher server-issued generation', () => {
    const stale = fact({ id: 'stale', generation: generation(100) });
    const current = fact({ id: 'current', generation: generation(200) });

    const selection = canonicalizeLaneFacts([stale, current], adapter);

    expect(selection).toMatchObject({
      kind: 'selected',
      selectedFact: current,
      supersededFacts: [stale],
    });
  });

  test('prefers exact target over shared projection at the same generation', () => {
    const shared = fact({ id: 'shared', exactness: 'shared_projection' });
    const exact = fact({ id: 'exact', exactness: 'exact_target' });

    const selection = canonicalizeLaneFacts([shared, exact], adapter);

    expect(selection).toMatchObject({
      kind: 'selected',
      selectedFact: exact,
      supersededFacts: [shared],
    });
  });

  test('returns ambiguous_material for usable facts without comparable generations', () => {
    const left = fact({ id: 'left', generation: null });
    const right = fact({ id: 'right', generation: null });

    const selection = canonicalizeLaneFacts([left, right], adapter);

    expect(selection).toMatchObject({
      kind: 'ambiguous_material',
      candidates: [left, right],
    });
  });

  test('returns no_current_lane with unusable facts', () => {
    const unusable = fact({ id: 'unusable', usable: false });

    const selection = canonicalizeLaneFacts([unusable], adapter);

    expect(selection).toMatchObject({
      kind: 'no_current_lane',
      unusableFacts: [unusable],
    });
  });

  test('checks full-group conflicts before supersession filters stale facts', () => {
    const current = fact({ id: 'current', generation: generation(200), materialId: 'material-a' });
    const stalePoisoned = fact({
      id: 'stale-poisoned',
      generation: generation(100),
      usable: false,
      materialId: 'material-b',
    });

    const selection = canonicalizeLaneFacts([current, stalePoisoned], adapter);

    expect(selection).toMatchObject({
      kind: 'conflicting_key_material',
      conflicts: [
        {
          kind: 'material_mismatch',
          materialIds: ['material-a', 'material-b'],
        },
      ],
    });
  });
});
