import { expect, test } from '@playwright/test';
import {
  activateSigningSessionAllowedTransitions,
  activateSigningSessionTerminalStates,
  ecdsaProvisioningAllowedTransitions,
  ecdsaProvisioningTerminalStates,
  exportKeysAllowedTransitions,
  exportKeysTerminalStates,
  registerWalletAllowedTransitions,
  registerWalletTerminalStates,
  restorePersistedSessionsAllowedTransitions,
  restorePersistedSessionsTerminalStates,
  signEvmFamilyAllowedTransitions,
  signEvmFamilyTerminalStates,
  signNearAllowedTransitions,
  signNearTerminalStates,
  unlockWalletAllowedTransitions,
  unlockWalletTerminalStates,
} from '@/core/signingEngine/useCases/lifecycle';

type TransitionTable = Record<string, readonly string[]>;

const lifecycleTables: readonly {
  name: string;
  transitions: TransitionTable;
  terminalStates: readonly string[];
}[] = [
  {
    name: 'ecdsa provisioning',
    transitions: ecdsaProvisioningAllowedTransitions,
    terminalStates: ecdsaProvisioningTerminalStates,
  },
  {
    name: 'register wallet',
    transitions: registerWalletAllowedTransitions,
    terminalStates: registerWalletTerminalStates,
  },
  {
    name: 'unlock wallet',
    transitions: unlockWalletAllowedTransitions,
    terminalStates: unlockWalletTerminalStates,
  },
  {
    name: 'activate signing session',
    transitions: activateSigningSessionAllowedTransitions,
    terminalStates: activateSigningSessionTerminalStates,
  },
  {
    name: 'sign EVM family',
    transitions: signEvmFamilyAllowedTransitions,
    terminalStates: signEvmFamilyTerminalStates,
  },
  {
    name: 'sign NEAR',
    transitions: signNearAllowedTransitions,
    terminalStates: signNearTerminalStates,
  },
  {
    name: 'export keys',
    transitions: exportKeysAllowedTransitions,
    terminalStates: exportKeysTerminalStates,
  },
  {
    name: 'restore persisted sessions',
    transitions: restorePersistedSessionsAllowedTransitions,
    terminalStates: restorePersistedSessionsTerminalStates,
  },
];

function reachesTerminal(args: {
  transitions: TransitionTable;
  terminalStates: ReadonlySet<string>;
  state: string;
  seen?: ReadonlySet<string>;
}): boolean {
  if (args.terminalStates.has(args.state)) return true;
  if (args.seen?.has(args.state)) return false;
  const seen = new Set(args.seen || []);
  seen.add(args.state);
  return (args.transitions[args.state] || []).some((next) =>
    reachesTerminal({
      transitions: args.transitions,
      terminalStates: args.terminalStates,
      state: next,
      seen,
    }),
  );
}

test.describe('use-case lifecycle transition tables', () => {
  for (const lifecycle of lifecycleTables) {
    test(`${lifecycle.name} has closed transitions and terminal paths`, () => {
      const stateKinds = new Set(Object.keys(lifecycle.transitions));
      const terminalStates = new Set(lifecycle.terminalStates);

      for (const terminalState of terminalStates) {
        expect(
          lifecycle.transitions[terminalState],
          `${lifecycle.name}: terminal state ${terminalState} must have no outgoing transitions`,
        ).toEqual([]);
      }

      for (const [state, targets] of Object.entries(lifecycle.transitions)) {
        for (const target of targets) {
          expect(
            stateKinds.has(target),
            `${lifecycle.name}: ${state} targets unknown state ${target}`,
          ).toBe(true);
        }
        expect(
          reachesTerminal({
            transitions: lifecycle.transitions,
            terminalStates,
            state,
          }),
          `${lifecycle.name}: ${state} must reach a terminal state`,
        ).toBe(true);
      }
    });
  }

  test('ECDSA provisioning preserves the storage-first service path', () => {
    expect(ecdsaProvisioningAllowedTransitions).toEqual({
      needs_secret_source: ['preparing_client_bootstrap', 'failed'],
      preparing_client_bootstrap: ['awaiting_relayer_identity', 'failed'],
      awaiting_relayer_identity: ['finalizing_ready_state', 'failed'],
      finalizing_ready_state: ['persisting_ready_record', 'failed'],
      persisting_ready_record: ['ready', 'failed'],
      ready: [],
      failed: [],
    });
  });
});
