import type {
  BuildThresholdEd25519SeedExportArtifactResult,
  CompleteThresholdEd25519HssClientCeremonyResult,
  OpenThresholdEd25519HssSeedOutputResult,
  PrepareThresholdEd25519HssServerCeremonyWithSessionResult,
} from './hssLifecycle';
import type {
  ThresholdEd25519HssFinalizedReportEnvelope,
  ThresholdEd25519HssOpenedClientOutput,
  ThresholdEd25519HssOpenedSeedOutput,
  ThresholdEd25519HssPreparedSessionEnvelope,
  ThresholdEd25519SeedExportArtifact,
} from '../crypto/hssClientSignerWasm';

declare const preparedSession: ThresholdEd25519HssPreparedSessionEnvelope;
declare const finalizedReport: ThresholdEd25519HssFinalizedReportEnvelope;
declare const clientOutput: ThresholdEd25519HssOpenedClientOutput;
declare const seedOutput: ThresholdEd25519HssOpenedSeedOutput;
declare const artifact: ThresholdEd25519SeedExportArtifact;

const completedHss: CompleteThresholdEd25519HssClientCeremonyResult = {
  ok: true,
  contextBindingB64u: 'ctx',
  preparedSession,
  finalizedReport,
  clientOutput,
};
void completedHss;

// @ts-expect-error HSS client ceremony success requires opened client output.
const completedHssWithoutClientOutput: CompleteThresholdEd25519HssClientCeremonyResult = {
  ok: true,
  contextBindingB64u: 'ctx',
  preparedSession,
  finalizedReport,
};
void completedHssWithoutClientOutput;

// @ts-expect-error failed HSS client ceremony rejects success-only output.
const failedHssWithClientOutput: CompleteThresholdEd25519HssClientCeremonyResult = {
  ok: false,
  contextBindingB64u: 'ctx',
  code: 'complete_client_ceremony_failed',
  message: 'failed',
  clientOutput,
};
void failedHssWithClientOutput;

const preparedServerCeremony: PrepareThresholdEd25519HssServerCeremonyWithSessionResult = {
  ok: true,
  contextBindingB64u: 'ctx',
  ceremonyHandle: 'ceremony-1',
  preparedSession,
  clientOtOfferMessageB64u: 'ot-offer',
};
void preparedServerCeremony;

// @ts-expect-error server prepare success requires a ceremony handle.
const preparedServerCeremonyWithoutHandle: PrepareThresholdEd25519HssServerCeremonyWithSessionResult =
  {
    ok: true,
    contextBindingB64u: 'ctx',
    preparedSession,
    clientOtOfferMessageB64u: 'ot-offer',
  };
void preparedServerCeremonyWithoutHandle;

const openedSeedOutput: OpenThresholdEd25519HssSeedOutputResult = {
  ok: true,
  contextBindingB64u: 'ctx',
  seedOutput,
};
void openedSeedOutput;

// @ts-expect-error failed seed open rejects seed output.
const failedSeedOpenWithSeedOutput: OpenThresholdEd25519HssSeedOutputResult = {
  ok: false,
  contextBindingB64u: 'ctx',
  code: 'open_seed_output_failed',
  message: 'failed',
  seedOutput,
};
void failedSeedOpenWithSeedOutput;

const seedExportArtifact: BuildThresholdEd25519SeedExportArtifactResult = {
  ok: true,
  contextBindingB64u: 'ctx',
  seedOutput,
  artifact,
};
void seedExportArtifact;

// @ts-expect-error seed export success requires the artifact.
const seedExportArtifactWithoutArtifact: BuildThresholdEd25519SeedExportArtifactResult = {
  ok: true,
  contextBindingB64u: 'ctx',
  seedOutput,
};
void seedExportArtifactWithoutArtifact;

// @ts-expect-error failed seed export rejects artifact material.
const failedSeedExportWithArtifact: BuildThresholdEd25519SeedExportArtifactResult = {
  ok: false,
  contextBindingB64u: 'ctx',
  code: 'build_seed_export_artifact_failed',
  message: 'failed',
  artifact,
};
void failedSeedExportWithArtifact;

export {};
