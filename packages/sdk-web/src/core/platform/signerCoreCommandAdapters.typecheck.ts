import type {
  BuildEcdsaRoleLocalExportArtifactCommand as RawBuildEcdsaRoleLocalExportArtifactCommand,
  BuildEcdsaRoleLocalExportArtifactOutput as RawBuildEcdsaRoleLocalExportArtifactOutput,
  FinalizeEcdsaClientBootstrapCommand as RawFinalizeEcdsaClientBootstrapCommand,
  FinalizeEcdsaClientBootstrapOutput as RawFinalizeEcdsaClientBootstrapOutput,
  PrepareEcdsaClientBootstrapCommand as RawPrepareEcdsaClientBootstrapCommand,
  PrepareEcdsaClientBootstrapOutput as RawPrepareEcdsaClientBootstrapOutput,
} from './generated/signerCoreCommands';
import {
  parseGeneratedBuildEcdsaRoleLocalExportArtifactOutput,
  parseGeneratedFinalizeEcdsaClientBootstrapOutput,
  parseGeneratedPrepareEcdsaClientBootstrapOutput,
  toGeneratedBuildEcdsaRoleLocalExportArtifactCommand,
  toGeneratedFinalizeEcdsaClientBootstrapCommand,
  toGeneratedPrepareEcdsaClientBootstrapCommand,
} from './signerCoreCommandAdapters';
import type {
  BuildEcdsaRoleLocalExportArtifactInput,
  BuildEcdsaRoleLocalExportArtifactOutput,
  FinalizeEcdsaClientBootstrapInput,
  FinalizeEcdsaClientBootstrapOutput,
  PrepareEcdsaClientBootstrapInput,
  PrepareEcdsaClientBootstrapOutput,
  WebAuthnPrfFirstSecretSource,
} from './types';

type StringKeys<T> = Extract<keyof T, string>;
type AssertNever<T extends never> = T;
declare function expectNoExtraKeys<T extends never>(): void;

type _PrepareInputNoExtraTopLevel = AssertNever<
  Exclude<
    StringKeys<PrepareEcdsaClientBootstrapInput>,
    StringKeys<RawPrepareEcdsaClientBootstrapCommand>
  >
>;
type _PrepareInputNoMissingTopLevel = AssertNever<
  Exclude<
    StringKeys<RawPrepareEcdsaClientBootstrapCommand>,
    StringKeys<PrepareEcdsaClientBootstrapInput>
  >
>;
type _PrepareContextNoExtra = AssertNever<
  Exclude<
    StringKeys<PrepareEcdsaClientBootstrapInput['context']>,
    StringKeys<RawPrepareEcdsaClientBootstrapCommand['context']>
  >
>;
type _PrepareContextNoMissing = AssertNever<
  Exclude<
    StringKeys<RawPrepareEcdsaClientBootstrapCommand['context']>,
    StringKeys<PrepareEcdsaClientBootstrapInput['context']>
  >
>;
type _PrepareParticipantsNoExtra = AssertNever<
  Exclude<
    StringKeys<PrepareEcdsaClientBootstrapInput['participants']>,
    StringKeys<RawPrepareEcdsaClientBootstrapCommand['participants']>
  >
>;
type _PrepareParticipantsNoMissing = AssertNever<
  Exclude<
    StringKeys<RawPrepareEcdsaClientBootstrapCommand['participants']>,
    StringKeys<PrepareEcdsaClientBootstrapInput['participants']>
  >
>;
type _WebAuthnSecretSourceNoExtra = AssertNever<
  Exclude<
    StringKeys<WebAuthnPrfFirstSecretSource>,
    StringKeys<
      Extract<RawPrepareEcdsaClientBootstrapCommand['secretSource'], { kind: 'webauthn_prf_first' }>
    >
  >
>;
type _WebAuthnSecretSourceNoMissing = AssertNever<
  Exclude<
    StringKeys<
      Extract<RawPrepareEcdsaClientBootstrapCommand['secretSource'], { kind: 'webauthn_prf_first' }>
    >,
    StringKeys<WebAuthnPrfFirstSecretSource>
  >
>;
type _GeneratedPrepareSecretSourceDoesNotExposeEmailOtp = AssertNever<
  Extract<
    RawPrepareEcdsaClientBootstrapCommand['secretSource'],
    { kind: 'email_otp_worker_session' }
  >
>;

type _PrepareOutputNoExtraTopLevel = AssertNever<
  Exclude<
    StringKeys<PrepareEcdsaClientBootstrapOutput>,
    StringKeys<RawPrepareEcdsaClientBootstrapOutput>
  >
>;
type _PrepareOutputNoMissingTopLevel = AssertNever<
  Exclude<
    StringKeys<RawPrepareEcdsaClientBootstrapOutput>,
    StringKeys<PrepareEcdsaClientBootstrapOutput>
  >
>;
type _FinalizeInputNoExtraTopLevel = AssertNever<
  Exclude<
    StringKeys<FinalizeEcdsaClientBootstrapInput>,
    StringKeys<RawFinalizeEcdsaClientBootstrapCommand>
  >
>;
type _FinalizeInputNoMissingTopLevel = AssertNever<
  Exclude<
    StringKeys<RawFinalizeEcdsaClientBootstrapCommand>,
    StringKeys<FinalizeEcdsaClientBootstrapInput>
  >
>;
type _FinalizeOutputNoExtraTopLevel = AssertNever<
  Exclude<
    StringKeys<FinalizeEcdsaClientBootstrapOutput>,
    StringKeys<RawFinalizeEcdsaClientBootstrapOutput>
  >
>;
type _FinalizeOutputNoMissingTopLevel = AssertNever<
  Exclude<
    StringKeys<RawFinalizeEcdsaClientBootstrapOutput>,
    StringKeys<FinalizeEcdsaClientBootstrapOutput>
  >
>;
type _ExportInputNoExtraTopLevel = AssertNever<
  Exclude<
    StringKeys<BuildEcdsaRoleLocalExportArtifactInput>,
    StringKeys<RawBuildEcdsaRoleLocalExportArtifactCommand>
  >
>;
type _ExportInputNoMissingTopLevel = AssertNever<
  Exclude<
    StringKeys<RawBuildEcdsaRoleLocalExportArtifactCommand>,
    StringKeys<BuildEcdsaRoleLocalExportArtifactInput>
  >
>;
type _ExportOutputNoExtraTopLevel = AssertNever<
  Exclude<
    StringKeys<BuildEcdsaRoleLocalExportArtifactOutput>,
    StringKeys<RawBuildEcdsaRoleLocalExportArtifactOutput>
  >
>;
type _ExportOutputNoMissingTopLevel = AssertNever<
  Exclude<
    StringKeys<RawBuildEcdsaRoleLocalExportArtifactOutput>,
    StringKeys<BuildEcdsaRoleLocalExportArtifactOutput>
  >
>;

expectNoExtraKeys<
  // @ts-expect-error generated command fields must be represented by the wrapper shape.
  Exclude<
    StringKeys<RawPrepareEcdsaClientBootstrapCommand & { rustOnlyField: string }>,
    StringKeys<PrepareEcdsaClientBootstrapInput>
  >
>();

expectNoExtraKeys<
  // @ts-expect-error wrapper command fields must be represented by the generated shape.
  Exclude<
    StringKeys<PrepareEcdsaClientBootstrapInput & { wrapperOnlyField: string }>,
    StringKeys<RawPrepareEcdsaClientBootstrapCommand>
  >
>();

declare const prepareInput: PrepareEcdsaClientBootstrapInput;
declare const prepareOutput: RawPrepareEcdsaClientBootstrapOutput;
declare const finalizeInput: FinalizeEcdsaClientBootstrapInput;
declare const finalizeOutput: RawFinalizeEcdsaClientBootstrapOutput;
declare const exportInput: BuildEcdsaRoleLocalExportArtifactInput;
declare const exportOutput: RawBuildEcdsaRoleLocalExportArtifactOutput;

toGeneratedPrepareEcdsaClientBootstrapCommand(
  prepareInput,
) satisfies RawPrepareEcdsaClientBootstrapCommand;
parseGeneratedPrepareEcdsaClientBootstrapOutput(
  prepareOutput,
) satisfies PrepareEcdsaClientBootstrapOutput;
toGeneratedFinalizeEcdsaClientBootstrapCommand(
  finalizeInput,
) satisfies RawFinalizeEcdsaClientBootstrapCommand;
parseGeneratedFinalizeEcdsaClientBootstrapOutput(
  finalizeOutput,
) satisfies FinalizeEcdsaClientBootstrapOutput;
toGeneratedBuildEcdsaRoleLocalExportArtifactCommand(
  exportInput,
) satisfies RawBuildEcdsaRoleLocalExportArtifactCommand;
parseGeneratedBuildEcdsaRoleLocalExportArtifactOutput(
  exportOutput,
) satisfies BuildEcdsaRoleLocalExportArtifactOutput;
