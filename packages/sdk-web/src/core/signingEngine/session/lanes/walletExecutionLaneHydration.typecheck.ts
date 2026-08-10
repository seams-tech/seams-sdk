import type {
  WalletExecutionLaneHydrationInput,
  WalletExecutionLaneHydrationResult,
} from './walletExecutionLaneHydration';

declare const input: WalletExecutionLaneHydrationInput;
declare const result: WalletExecutionLaneHydrationResult;

const parsedInput: WalletExecutionLaneHydrationInput = input;
const parsedResult: WalletExecutionLaneHydrationResult = result;

function consumeHydrationResult(value: WalletExecutionLaneHydrationResult): void {
  switch (value.kind) {
    case 'active_wallet_execution_lane_v1':
      value.lane.materialActivation;
      value.holderParticipant.participantBindingDigestB64u;
      value.serverParticipant.participantBindingDigestB64u;
      value.publicIdentity.keyFamily;
      return;
    case 'wallet_execution_lane_refused_v1':
      if (value.reason === 'invalid_boundary_record') {
        // @ts-expect-error Boundary parse failures never expose identity fields.
        const walletId: string = value.walletId;
        void walletId;
      } else {
        value.walletId;
        value.walletKeyId;
        value.laneId;
      }
      return;
    default:
      value satisfies never;
  }
}

consumeHydrationResult(parsedResult);
void parsedInput;
