import type { DelegateAction, Signature } from './delegate';
import { isObject } from '../utils/validation';

export interface TransactionInput {
  receiverId: string;
  actions: ActionArgs[];
}

export interface TransactionInputWasm {
  receiverId: string;
  actions: ActionArgsWasm[];
  nonce?: string;
}

export enum ActionType {
  CreateAccount = 'CreateAccount',
  DeployContract = 'DeployContract',
  FunctionCall = 'FunctionCall',
  Transfer = 'Transfer',
  Stake = 'Stake',
  AddKey = 'AddKey',
  DeleteKey = 'DeleteKey',
  DeleteAccount = 'DeleteAccount',
  SignedDelegate = 'SignedDelegate',
  DeployGlobalContract = 'DeployGlobalContract',
  UseGlobalContract = 'UseGlobalContract',
}

export enum TxExecutionStatus {
  NONE = 'NONE',
  INCLUDED = 'INCLUDED',
  INCLUDED_FINAL = 'INCLUDED_FINAL',
  EXECUTED = 'EXECUTED',
  FINAL = 'FINAL',
  EXECUTED_OPTIMISTIC = 'EXECUTED_OPTIMISTIC',
}

export interface FunctionCallAction {
  type: ActionType.FunctionCall;
  methodName: string;
  args: Record<string, any>;
  gas?: string;
  deposit?: string;
}

export interface TransferAction {
  type: ActionType.Transfer;
  amount: string;
}

export interface CreateAccountAction {
  type: ActionType.CreateAccount;
}

export interface DeployContractAction {
  type: ActionType.DeployContract;
  code: Uint8Array | string;
}

export interface DeployGlobalContractAction {
  type: ActionType.DeployGlobalContract;
  code: Uint8Array | string;
  deployMode: 'CodeHash' | 'AccountId';
}

export interface UseGlobalContractAction {
  type: ActionType.UseGlobalContract;
  accountId?: string;
  codeHash?: string;
}

export interface StakeAction {
  type: ActionType.Stake;
  stake: string;
  publicKey: string;
}

export interface AddKeyAction {
  type: ActionType.AddKey;
  publicKey: string;
  accessKey: {
    nonce?: number;
    permission:
      | 'FullAccess'
      | {
          FunctionCall: {
            allowance?: string;
            receiverId?: string;
            methodNames?: string[];
          };
        };
  };
}

export interface DeleteKeyAction {
  type: ActionType.DeleteKey;
  publicKey: string;
}

export interface DeleteAccountAction {
  type: ActionType.DeleteAccount;
  beneficiaryId: string;
}

export type ActionArgs =
  | FunctionCallAction
  | TransferAction
  | CreateAccountAction
  | DeployContractAction
  | StakeAction
  | AddKeyAction
  | DeleteKeyAction
  | DeleteAccountAction
  | DeployGlobalContractAction
  | UseGlobalContractAction;

export type ActionArgsWasm =
  | { action_type: ActionType.CreateAccount }
  | { action_type: ActionType.DeployContract; code: number[] }
  | {
      action_type: ActionType.FunctionCall;
      method_name: string;
      args: string;
      gas: string;
      deposit: string;
    }
  | { action_type: ActionType.Transfer; deposit: string }
  | { action_type: ActionType.Stake; stake: string; public_key: string }
  | { action_type: ActionType.AddKey; public_key: string; access_key: string }
  | { action_type: ActionType.DeleteKey; public_key: string }
  | { action_type: ActionType.DeleteAccount; beneficiary_id: string }
  | {
      action_type: ActionType.SignedDelegate;
      delegate_action: DelegateAction;
      signature: Signature;
    }
  | {
      action_type: ActionType.DeployGlobalContract;
      code: number[];
      deploy_mode: 'CodeHash' | 'AccountId';
    }
  | { action_type: ActionType.UseGlobalContract; account_id?: string; code_hash?: string };

export function isActionArgsWasm(a?: any): a is ActionArgsWasm {
  return isObject(a) && 'action_type' in a;
}

export function toActionArgsWasm(action: ActionArgs): ActionArgsWasm {
  switch (action.type) {
    case ActionType.Transfer:
      return { action_type: ActionType.Transfer, deposit: action.amount };
    case ActionType.FunctionCall:
      return {
        action_type: ActionType.FunctionCall,
        method_name: action.methodName,
        args: JSON.stringify(action.args),
        gas: action.gas || '30000000000000',
        deposit: action.deposit || '0',
      };
    case ActionType.AddKey: {
      const rawPermission = action.accessKey.permission;
      const permission = rawPermission === 'FullAccess' ? { FullAccess: {} } : rawPermission;
      return {
        action_type: ActionType.AddKey,
        public_key: action.publicKey,
        access_key: JSON.stringify({
          nonce: action.accessKey.nonce || 0,
          permission,
        }),
      };
    }
    case ActionType.DeleteKey:
      return { action_type: ActionType.DeleteKey, public_key: action.publicKey };
    case ActionType.CreateAccount:
      return { action_type: ActionType.CreateAccount };
    case ActionType.DeleteAccount:
      return { action_type: ActionType.DeleteAccount, beneficiary_id: action.beneficiaryId };
    case ActionType.DeployContract:
      return {
        action_type: ActionType.DeployContract,
        code:
          typeof action.code === 'string'
            ? Array.from(new TextEncoder().encode(action.code))
            : Array.from(action.code),
      };
    case ActionType.DeployGlobalContract:
      return {
        action_type: ActionType.DeployGlobalContract,
        code:
          typeof action.code === 'string'
            ? Array.from(new TextEncoder().encode(action.code))
            : Array.from(action.code),
        deploy_mode: action.deployMode,
      };
    case ActionType.UseGlobalContract:
      return {
        action_type: ActionType.UseGlobalContract,
        account_id: action.accountId,
        code_hash: action.codeHash,
      };
    case ActionType.Stake:
      return { action_type: ActionType.Stake, stake: action.stake, public_key: action.publicKey };
    default:
      throw new Error(`Action type ${(action as any).type} is not supported`);
  }
}

export function validateActionArgsWasm(actionArgsWasm: ActionArgsWasm): void {
  switch (actionArgsWasm.action_type) {
    case ActionType.FunctionCall:
      if (!actionArgsWasm.method_name) throw new Error('method_name required for FunctionCall');
      if (!actionArgsWasm.args) throw new Error('args required for FunctionCall');
      if (!actionArgsWasm.gas) throw new Error('gas required for FunctionCall');
      if (!actionArgsWasm.deposit) throw new Error('deposit required for FunctionCall');
      if (typeof actionArgsWasm.args !== 'string') {
        throw new Error('FunctionCall action args must be a valid JSON string');
      }
      try {
        JSON.parse(actionArgsWasm.args);
      } catch {
        throw new Error('FunctionCall action args must be valid JSON string');
      }
      break;
    case ActionType.Transfer:
      if (!actionArgsWasm.deposit) throw new Error('deposit required for Transfer');
      break;
    case ActionType.CreateAccount:
      break;
    case ActionType.DeployContract:
      if (!actionArgsWasm.code || actionArgsWasm.code.length === 0) {
        throw new Error('code required for DeployContract');
      }
      break;
    case ActionType.Stake:
      if (!actionArgsWasm.stake) throw new Error('stake amount required for Stake');
      if (!actionArgsWasm.public_key) throw new Error('public_key required for Stake');
      break;
    case ActionType.AddKey:
      if (!actionArgsWasm.public_key) throw new Error('public_key required for AddKey');
      if (!actionArgsWasm.access_key) throw new Error('access_key required for AddKey');
      if (typeof actionArgsWasm.access_key !== 'string') {
        throw new Error('AddKey action access_key must be a valid JSON string');
      }
      try {
        JSON.parse(actionArgsWasm.access_key);
      } catch {
        throw new Error('AddKey action access_key must be valid JSON string');
      }
      break;
    case ActionType.DeleteKey:
      if (!actionArgsWasm.public_key) throw new Error('public_key required for DeleteKey');
      break;
    case ActionType.DeleteAccount:
      if (!actionArgsWasm.beneficiary_id) {
        throw new Error('beneficiary_id required for DeleteAccount');
      }
      break;
    case ActionType.SignedDelegate:
      if (!actionArgsWasm.delegate_action || typeof actionArgsWasm.delegate_action !== 'object') {
        throw new Error('delegate_action required for SignedDelegate');
      }
      if (!actionArgsWasm.signature || typeof actionArgsWasm.signature !== 'object') {
        throw new Error('signature required for SignedDelegate');
      }
      break;
    case ActionType.DeployGlobalContract:
      if (!actionArgsWasm.code || actionArgsWasm.code.length === 0) {
        throw new Error('code required for DeployGlobalContract');
      }
      if (
        !actionArgsWasm.deploy_mode ||
        (actionArgsWasm.deploy_mode !== 'CodeHash' && actionArgsWasm.deploy_mode !== 'AccountId')
      ) {
        throw new Error('deploy_mode must be CodeHash or AccountId for DeployGlobalContract');
      }
      break;
    case ActionType.UseGlobalContract: {
      const hasAccountId = !!actionArgsWasm.account_id;
      const hasCodeHash = !!actionArgsWasm.code_hash;
      if (hasAccountId === hasCodeHash) {
        throw new Error('UseGlobalContract requires exactly one of account_id or code_hash');
      }
      break;
    }
    default:
      throw new Error(`Unsupported action type: ${(actionArgsWasm as any).action_type}`);
  }
}

interface FunctionCallPermissionView {
  FunctionCall: {
    allowance: string;
    receiver_id: string;
    method_names: string[];
  };
}

export function fromActionArgsWasm(a: ActionArgsWasm): ActionArgs {
  switch (a.action_type) {
    case ActionType.FunctionCall: {
      let parsedArgs: Record<string, any> = {};
      try {
        parsedArgs = typeof a.args === 'string' ? (a.args ? JSON.parse(a.args) : {}) : a.args || {};
      } catch {
        parsedArgs = {};
      }
      return {
        type: ActionType.FunctionCall,
        methodName: a.method_name,
        args: parsedArgs,
        gas: a.gas,
        deposit: a.deposit,
      };
    }
    case ActionType.Transfer:
      return { type: ActionType.Transfer, amount: a.deposit };
    case ActionType.CreateAccount:
      return { type: ActionType.CreateAccount };
    case ActionType.DeployContract:
      return {
        type: ActionType.DeployContract,
        code: Array.isArray(a.code) ? new Uint8Array(a.code) : new Uint8Array(),
      };
    case ActionType.DeployGlobalContract:
      return {
        type: ActionType.DeployGlobalContract,
        code: Array.isArray(a.code) ? new Uint8Array(a.code) : new Uint8Array(),
        deployMode: a.deploy_mode,
      };
    case ActionType.Stake:
      return { type: ActionType.Stake, stake: a.stake, publicKey: a.public_key };
    case ActionType.AddKey: {
      let accessKey: { nonce: bigint; permission: 'FullAccess' | FunctionCallPermissionView };
      try {
        accessKey = JSON.parse(a.access_key);
      } catch {
        accessKey = { nonce: BigInt(0), permission: 'FullAccess' };
      }
      const permission = accessKey?.permission;
      let normalizedPermission: 'FullAccess' | FunctionCallPermissionView = 'FullAccess';
      if (isObject(permission)) {
        if ('FullAccess' in permission) {
          normalizedPermission = 'FullAccess';
        } else if ('FunctionCall' in permission) {
          const fc = (permission as FunctionCallPermissionView).FunctionCall;
          normalizedPermission = {
            FunctionCall: {
              allowance: fc.allowance,
              receiver_id: fc.receiver_id,
              method_names: fc.method_names,
            },
          };
        }
      }
      return {
        type: ActionType.AddKey,
        publicKey: a.public_key,
        accessKey: {
          nonce: typeof accessKey?.nonce === 'number' ? accessKey.nonce : 0,
          permission: normalizedPermission,
        },
      };
    }
    case ActionType.DeleteKey:
      return { type: ActionType.DeleteKey, publicKey: a.public_key };
    case ActionType.DeleteAccount:
      return { type: ActionType.DeleteAccount, beneficiaryId: a.beneficiary_id };
    case ActionType.UseGlobalContract:
      return { type: ActionType.UseGlobalContract, accountId: a.account_id, codeHash: a.code_hash };
    default:
      throw new Error(`Unsupported wasm action_type: ${(a as any)?.action_type}`);
  }
}

export function fromTransactionInputWasm(tx: TransactionInputWasm): TransactionInput {
  return {
    receiverId: tx.receiverId,
    actions: tx.actions.map(fromActionArgsWasm),
  };
}

export function fromTransactionInputsWasm(txs: TransactionInputWasm[]): TransactionInput[] {
  return (txs || []).map(fromTransactionInputWasm);
}
