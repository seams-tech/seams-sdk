import type { EcdsaLaneGroup, EcdsaLaneRecordFact } from './availableSigningLanes';
import type {
  CanonicalFactExactness,
  CanonicalFactSupersession,
  CanonicalLaneInventoryAdapter,
  CanonicalLaneSelection,
  CanonicalTieBreakOrder,
  ServerIssuedGeneration,
} from './canonicalLaneInventory';
import type { EcdsaCommittedLane } from '../../flows/signEvmFamily/ecdsaSelection';

declare const recordFact: EcdsaLaneRecordFact;
declare const laneGroup: EcdsaLaneGroup;
declare const diagnosticSelection: CanonicalLaneSelection<EcdsaLaneRecordFact, never>;

declare function requireCommittedEcdsaLane(lane: EcdsaCommittedLane): void;

// @ts-expect-error ECDSA record facts are read-model inputs, not committed lanes.
requireCommittedEcdsaLane(recordFact);

// @ts-expect-error ECDSA lane groups are read-model inputs, not committed lanes.
requireCommittedEcdsaLane(laneGroup);

// @ts-expect-error Generic inventory selections are read-model outputs, not committed lanes.
requireCommittedEcdsaLane(diagnosticSelection);

type FixtureFact = {
  id: string;
  groupKey: FixtureGroupKey;
  generation: ServerIssuedGeneration | null;
  exactness: CanonicalFactExactness;
};

type FixtureGroupKey = {
  value: string;
};

type FixtureConflict = {
  kind: 'fixture_conflict';
};

declare function fixtureGroupKey(fact: FixtureFact): FixtureGroupKey;
declare function nullableFixtureGroupKey(fact: FixtureFact): FixtureGroupKey | null;
declare function fixtureGroupKeyString(groupKey: FixtureGroupKey): string;
declare function fixtureGroupConflicts(facts: readonly FixtureFact[]): readonly FixtureConflict[];
declare function fixtureIsOperationUsable(fact: FixtureFact): boolean;
declare function fixtureGeneration(fact: FixtureFact): ServerIssuedGeneration | null;
declare function fixtureExactness(fact: FixtureFact): CanonicalFactExactness;
declare function fixtureTieBreak(left: FixtureFact, right: FixtureFact): CanonicalTieBreakOrder;
declare function fixtureCompareCurrent(left: FixtureFact, right: FixtureFact): number;

const fixtureSupersession: CanonicalFactSupersession<FixtureFact> = {
  isOperationUsable: fixtureIsOperationUsable,
  generation: fixtureGeneration,
  exactness: fixtureExactness,
  tieBreak: fixtureTieBreak,
};
void fixtureSupersession;

const validAdapter: CanonicalLaneInventoryAdapter<FixtureFact, FixtureGroupKey, FixtureConflict> =
  {
    groupKey: fixtureGroupKey,
    groupKeyString: fixtureGroupKeyString,
    groupConflicts: fixtureGroupConflicts,
    supersession: fixtureSupersession,
  };
void validAdapter;

const nullableGroupKeyAdapter: CanonicalLaneInventoryAdapter<
  FixtureFact,
  FixtureGroupKey,
  FixtureConflict
> = {
  // @ts-expect-error Canonical inventory adapters must expose a total groupKey.
  groupKey: nullableFixtureGroupKey,
  groupKeyString: fixtureGroupKeyString,
  groupConflicts: fixtureGroupConflicts,
  supersession: fixtureSupersession,
};
void nullableGroupKeyAdapter;

const comparatorAdapter: CanonicalLaneInventoryAdapter<
  FixtureFact,
  FixtureGroupKey,
  FixtureConflict
> = {
  groupKey: fixtureGroupKey,
  groupKeyString: fixtureGroupKeyString,
  groupConflicts: fixtureGroupConflicts,
  supersession: fixtureSupersession,
  // @ts-expect-error Adapters supply supersession ingredients, not comparator policy.
  compareCurrent: fixtureCompareCurrent,
};
void comparatorAdapter;
