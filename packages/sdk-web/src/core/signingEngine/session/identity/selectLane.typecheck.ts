import type {
  Ed25519LaneAuthorityKey,
  NearEd25519TransactionReadyAvailableLane,
  NearEd25519TransactionReadyLane,
} from './selectLane';
import type { Ed25519LaneCandidate, SelectedEd25519Lane } from './laneIdentity';

declare const candidate: Ed25519LaneCandidate;
declare const availableLane: NearEd25519TransactionReadyAvailableLane;
declare const selectedLane: SelectedEd25519Lane;
declare const authorityKey: Ed25519LaneAuthorityKey;

const validReadyLane: NearEd25519TransactionReadyLane = {
  kind: 'near_ed25519_transaction_ready_lane',
  candidate,
  availableLane,
  selectedLane,
  authorityKey,
};
void validReadyLane;

// @ts-expect-error transaction-ready available lanes cannot carry provenance source.
const invalidReadyAvailableLaneSource = availableLane.source;
void invalidReadyAvailableLaneSource;

// @ts-expect-error transaction-ready available lanes cannot carry flat material fields.
const invalidReadyAvailableLaneFlatMaterial = availableLane.materialKeyId;
void invalidReadyAvailableLaneFlatMaterial;

const invalidMaterial: NearEd25519TransactionReadyLane = {
  kind: 'near_ed25519_transaction_ready_lane',
  candidate,
  availableLane,
  selectedLane,
  authorityKey,
  // @ts-expect-error Yao-backed transaction lanes reject worker material.
  material: { kind: 'loaded_worker_material' },
};
void invalidMaterial;

// @ts-expect-error transaction-ready Ed25519 lanes require an authority key.
const missingAuthorityKey: NearEd25519TransactionReadyLane = {
  kind: 'near_ed25519_transaction_ready_lane',
  candidate,
  availableLane,
  selectedLane,
};
void missingAuthorityKey;

// @ts-expect-error transaction-ready Ed25519 lanes require the selected exact lane.
const missingSelectedLane: NearEd25519TransactionReadyLane = {
  kind: 'near_ed25519_transaction_ready_lane',
  candidate,
  availableLane,
  authorityKey,
};
void missingSelectedLane;
