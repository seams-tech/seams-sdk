import type {
  FinalizeEcdsaClientBootstrapCommand as RawFinalizeEcdsaClientBootstrapCommand,
  FinalizeEcdsaClientBootstrapOutput as RawFinalizeEcdsaClientBootstrapOutput,
  PrepareEcdsaClientBootstrapCommand as RawPrepareEcdsaClientBootstrapCommand,
  PrepareEcdsaClientBootstrapOutput as RawPrepareEcdsaClientBootstrapOutput,
} from './generated/signerCoreCommands';
import {
  parseGeneratedFinalizeEcdsaClientBootstrapOutput,
  parseGeneratedPrepareEcdsaClientBootstrapOutput,
  toGeneratedFinalizeEcdsaClientBootstrapCommand,
  toGeneratedPrepareEcdsaClientBootstrapCommand,
} from './signerCoreCommandAdapters';
import type {
  FinalizeEcdsaClientBootstrapInput,
  FinalizeEcdsaClientBootstrapOutput,
  PrepareEcdsaClientBootstrapInput,
  PrepareEcdsaClientBootstrapOutput,
  ThresholdPrfXClientBaseSecretSource,
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
type _ThresholdPrfSecretSourceNoExtra = AssertNever<
  Exclude<
    StringKeys<ThresholdPrfXClientBaseSecretSource>,
    StringKeys<
      Extract<
        RawPrepareEcdsaClientBootstrapCommand['secretSource'],
        { kind: 'threshold_prf_x_client_base' }
      >
    >
  >
>;
type _ThresholdPrfSecretSourceNoMissing = AssertNever<
  Exclude<
    StringKeys<
      Extract<
        RawPrepareEcdsaClientBootstrapCommand['secretSource'],
        { kind: 'threshold_prf_x_client_base' }
      >
    >,
    StringKeys<ThresholdPrfXClientBaseSecretSource>
  >
>;
type _GeneratedPrepareSecretSourceIsOnlyThresholdPrf = AssertNever<
  Extract<
    RawPrepareEcdsaClientBootstrapCommand['secretSource'],
    {
      kind:
        | 'email_otp_worker_session'
        | 'webauthn_prf_first'
        | 'secure_enclave_wrapped_secret'
        | 'fido2_hmac_secret';
    }
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
