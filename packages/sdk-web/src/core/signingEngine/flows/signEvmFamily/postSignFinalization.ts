import {
  SigningSessionPlanKind,
  type SigningSessionPlan,
} from '../../session/operationState/types';
import type { OperationTransitionObserver } from '../shared/operationPorts';
import {
  SigningOperationCommandKind,
  buildSigningPostSignOperationSteps,
  createSigningPostSignOperationPlan,
  runSigningOperationSteps,
  type SigningOperationCommand,
  type SigningOperationTransitionEvent,
} from '../shared/signingStateMachine';

export async function runSuccessfulEvmFamilyPostSignCommands(args: {
  signingSessionPlan?: SigningSessionPlan;
  onTransition?: OperationTransitionObserver<SigningOperationTransitionEvent>;
  recordSuccessfulSigningGrantSpend: () => Promise<void>;
  applySuccessfulEcdsaPostSignPolicy: () => Promise<void>;
}): Promise<void> {
  // EVM/Tempo touch-confirm flows return a signed raw transaction before broadcast.
  // Consume budget and cleanup policy before the caller dispatches the transaction.
  if (
    !args.signingSessionPlan ||
    args.signingSessionPlan.kind === SigningSessionPlanKind.NotReady
  ) {
    await args.recordSuccessfulSigningGrantSpend();
    await args.applySuccessfulEcdsaPostSignPolicy();
    return;
  }

  const operationPlan = createSigningPostSignOperationPlan({
    sessionPlan: args.signingSessionPlan,
    operation: null,
    commands: [SigningOperationCommandKind.SpendBudget, SigningOperationCommandKind.Cleanup],
  });
  const result = await runSigningOperationSteps({
    steps: buildSigningPostSignOperationSteps(operationPlan),
    onTransition: args.onTransition,
    executor: {
      async execute(command: SigningOperationCommand) {
        if (command.kind === SigningOperationCommandKind.SpendBudget) {
          await args.recordSuccessfulSigningGrantSpend();
          return;
        }
        if (command.kind === SigningOperationCommandKind.Cleanup) {
          await args.applySuccessfulEcdsaPostSignPolicy();
          return;
        }
        throw new Error(`[SigningEngine] unexpected post-sign command: ${command.kind}`);
      },
    },
  });
  if (!result.ok) {
    throw result.error;
  }
}
