import {
  ActionType,
  type AddKeyAction,
  type CreateAccountAction,
  type DeleteAccountAction,
  type DeleteKeyAction,
  type DeployContractAction,
  type FunctionCallAction,
  type StakeAction,
  type TransferAction,
} from '@/core/types/actions';

/**
 * Action builders.
 *
 * `{ type: ActionType.FunctionCall, methodName, args }` is the shape the wire
 * needs; it is not the shape a call site wants to read. These builders produce
 * the same objects with the discriminant filled in, so a transaction reads as
 * what it does.
 *
 * `gas` and `deposit` are optional — omit them to take the SDK defaults.
 *
 * @example
 * await wallet.near.signAndSendTransaction({
 *   receiverId: 'guest-book.testnet',
 *   actions: [functionCall({ method: 'set_greeting', args: { greeting: 'hi' } })],
 * });
 */
export function functionCall(args: {
  method: string;
  args?: Record<string, unknown>;
  gas?: string;
  deposit?: string;
}): FunctionCallAction {
  return {
    type: ActionType.FunctionCall,
    methodName: args.method,
    args: args.args ?? {},
    ...(args.gas !== undefined ? { gas: args.gas } : {}),
    ...(args.deposit !== undefined ? { deposit: args.deposit } : {}),
  };
}

/** Transfer NEAR. `amount` is in yoctoNEAR. */
export function transfer(amount: string): TransferAction {
  return { type: ActionType.Transfer, amount };
}

export function createAccount(): CreateAccountAction {
  return { type: ActionType.CreateAccount };
}

export function deployContract(code: Uint8Array | string): DeployContractAction {
  return { type: ActionType.DeployContract, code };
}

export function stake(args: { amount: string; publicKey: string }): StakeAction {
  return { type: ActionType.Stake, stake: args.amount, publicKey: args.publicKey };
}

export function addKey(args: {
  publicKey: string;
  accessKey: AddKeyAction['accessKey'];
}): AddKeyAction {
  return { type: ActionType.AddKey, publicKey: args.publicKey, accessKey: args.accessKey };
}

export function deleteKey(publicKey: string): DeleteKeyAction {
  return { type: ActionType.DeleteKey, publicKey };
}

export function deleteAccount(beneficiaryId: string): DeleteAccountAction {
  return { type: ActionType.DeleteAccount, beneficiaryId };
}
