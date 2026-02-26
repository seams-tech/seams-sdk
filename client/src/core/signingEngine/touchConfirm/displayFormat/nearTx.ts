import { ActionType, type ActionArgsWasm, type TransactionInputWasm } from '@/core/types/actions';
import type {
  TxDisplayField,
  TxDisplayModel,
  TxDisplayOperation,
  NearActionOperation,
  GenericContractCallOperation,
} from '@/core/signingEngine/touchConfirm/shared/displayModel';

export type BuildNearDisplayModelArgs = {
  txSigningRequests: TransactionInputWasm[];
  intentDigest?: string;
  signerAccount?: string;
  title?: string;
  subtitle?: string;
};

function toSafeJson(value: unknown): string {
  try {
    return JSON.stringify(
      value,
      (_key, fieldValue) => (typeof fieldValue === 'bigint' ? fieldValue.toString() : fieldValue),
      2,
    );
  } catch {
    return String(value);
  }
}

function makeField(
  label: string,
  value: string | undefined,
  copyValue?: string,
): TxDisplayField | undefined {
  const normalized = String(value ?? '').trim();
  if (!normalized) return undefined;
  return {
    label,
    value: normalized,
    ...(typeof copyValue === 'string' && copyValue.trim() ? { copyValue } : {}),
  };
}

function totalAttachedValueForAction(action: ActionArgsWasm): bigint {
  switch (action.action_type) {
    case ActionType.Transfer:
    case ActionType.FunctionCall:
      return BigInt(action.deposit || '0');
    case ActionType.Stake:
      return BigInt(action.stake || '0');
    default:
      return BigInt(0);
  }
}

function parseAccessKeyPermission(rawAccessKey: string): string {
  try {
    const parsed = JSON.parse(rawAccessKey) as {
      permission?: 'FullAccess' | { FunctionCall?: unknown } | { FullAccess?: unknown };
    };
    const permission = parsed?.permission;
    if (permission === 'FullAccess') return 'FullAccess';
    if (permission && typeof permission === 'object') {
      if ('FullAccess' in permission) return 'FullAccess';
      if ('FunctionCall' in permission) return 'FunctionCall';
    }
  } catch {
    return 'Unknown';
  }
  return 'Unknown';
}

function buildActionOperation(args: {
  action: ActionArgsWasm;
  txIndex: number;
  actionIndex: number;
  receiverId: string;
}): TxDisplayOperation {
  const { action, txIndex, actionIndex, receiverId } = args;
  const id = `near.tx.${txIndex}.action.${actionIndex}`;

  switch (action.action_type) {
    case ActionType.CreateAccount:
      return {
        id,
        kind: 'near.action',
        actionType: 'createAccount',
        label: `Action ${actionIndex + 1}: CreateAccount`,
        fields: [makeField('Receiver', receiverId)].filter(Boolean) as TxDisplayField[],
      } as NearActionOperation;

    case ActionType.Transfer:
      return {
        id,
        kind: 'near.action',
        actionType: 'transfer',
        label: `Action ${actionIndex + 1}: Transfer`,
        fields: [
          makeField('Receiver', receiverId),
          makeField('Amount (yoctoNEAR)', action.deposit),
        ].filter(Boolean) as TxDisplayField[],
      } as NearActionOperation;

    case ActionType.FunctionCall: {
      const argsRaw = String(action.args || '');
      const children: TxDisplayOperation[] = argsRaw
        ? [
            {
              id: `${id}.args`,
              kind: 'raw.fallback',
              label: 'Function Arguments',
              raw: argsRaw,
            },
          ]
        : [];
      return {
        id,
        kind: 'near.action',
        actionType: 'functionCall',
        label: `Action ${actionIndex + 1}: FunctionCall`,
        fields: [
          makeField('Receiver', receiverId),
          makeField('Method', action.method_name),
          makeField('Gas', action.gas),
          makeField('Deposit (yoctoNEAR)', action.deposit),
        ].filter(Boolean) as TxDisplayField[],
        ...(children.length ? { children } : {}),
      } as NearActionOperation;
    }

    case ActionType.Stake:
      return {
        id,
        kind: 'near.action',
        actionType: 'stake',
        label: `Action ${actionIndex + 1}: Stake`,
        fields: [
          makeField('Receiver', receiverId),
          makeField('Stake (yoctoNEAR)', action.stake),
          makeField('Validator Key', action.public_key, action.public_key),
        ].filter(Boolean) as TxDisplayField[],
      } as NearActionOperation;

    case ActionType.AddKey:
      return {
        id,
        kind: 'near.action',
        actionType: 'addKey',
        label: `Action ${actionIndex + 1}: AddKey`,
        fields: [
          makeField('Receiver', receiverId),
          makeField('Public Key', action.public_key, action.public_key),
          makeField('Permission', parseAccessKeyPermission(action.access_key)),
        ].filter(Boolean) as TxDisplayField[],
      } as NearActionOperation;

    case ActionType.DeleteKey:
      return {
        id,
        kind: 'near.action',
        actionType: 'deleteKey',
        label: `Action ${actionIndex + 1}: DeleteKey`,
        fields: [
          makeField('Receiver', receiverId),
          makeField('Public Key', action.public_key, action.public_key),
        ].filter(Boolean) as TxDisplayField[],
      } as NearActionOperation;

    case ActionType.DeployContract:
      return {
        id,
        kind: 'near.action',
        actionType: 'deployContract',
        label: `Action ${actionIndex + 1}: DeployContract`,
        fields: [
          makeField('Receiver', receiverId),
          makeField('Code Bytes', String(action.code?.length ?? 0)),
        ].filter(Boolean) as TxDisplayField[],
      } as NearActionOperation;

    case ActionType.DeployGlobalContract:
      return {
        id,
        kind: 'near.action',
        actionType: 'deployGlobalContract',
        label: `Action ${actionIndex + 1}: DeployGlobalContract`,
        fields: [
          makeField('Receiver', receiverId),
          makeField('Deploy Mode', action.deploy_mode),
          makeField('Code Bytes', String(action.code?.length ?? 0)),
        ].filter(Boolean) as TxDisplayField[],
      } as NearActionOperation;

    case ActionType.UseGlobalContract:
      return {
        id,
        kind: 'near.action',
        actionType: 'useGlobalContract',
        label: `Action ${actionIndex + 1}: UseGlobalContract`,
        fields: [
          makeField('Receiver', receiverId),
          makeField('By Account', action.account_id),
          makeField('By Code Hash', action.code_hash, action.code_hash),
        ].filter(Boolean) as TxDisplayField[],
      } as NearActionOperation;

    case ActionType.DeleteAccount:
      return {
        id,
        kind: 'near.action',
        actionType: 'deleteAccount',
        label: `Action ${actionIndex + 1}: DeleteAccount`,
        fields: [
          makeField('Receiver', receiverId),
          makeField('Beneficiary', action.beneficiary_id),
        ].filter(Boolean) as TxDisplayField[],
      } as NearActionOperation;

    case ActionType.SignedDelegate:
      return {
        id,
        kind: 'near.action',
        actionType: 'signedDelegate',
        label: `Action ${actionIndex + 1}: SignedDelegate`,
        children: [
          {
            id: `${id}.delegate`,
            kind: 'raw.fallback',
            label: 'Signed Delegate Payload',
            raw: toSafeJson(action),
          },
        ],
      } as NearActionOperation;

    default:
      return {
        id,
        kind: 'raw.fallback',
        label: `Action ${actionIndex + 1}: Unsupported`,
        raw: toSafeJson(action),
      };
  }
}

function buildTransactionOperation(
  tx: TransactionInputWasm,
  txIndex: number,
  txCount: number,
): GenericContractCallOperation {
  const receiverId = String(tx.receiverId || '').trim() || '(unknown receiver)';
  const actions = Array.isArray(tx.actions) ? tx.actions : [];
  const txAttachedValue = actions.reduce(
    (sum, action) => sum + totalAttachedValueForAction(action),
    BigInt(0),
  );

  const fields: TxDisplayField[] = [
    makeField('Receiver', receiverId),
    makeField('Action Count', String(actions.length)),
    makeField(
      'Attached Value (yoctoNEAR)',
      txAttachedValue > 0 ? txAttachedValue.toString() : undefined,
    ),
  ].filter(Boolean) as TxDisplayField[];

  return {
    id: `near.tx.${txIndex}`,
    kind: 'generic.contractCall',
    label: txCount > 1 ? `Transaction ${txIndex + 1}` : 'Transaction',
    to: receiverId,
    value: txAttachedValue > 0 ? txAttachedValue.toString() : undefined,
    fields,
    children: actions.map((action, actionIndex) =>
      buildActionOperation({
        action,
        txIndex,
        actionIndex,
        receiverId,
      }),
    ),
  };
}

export function buildNearDisplayModel(args: BuildNearDisplayModelArgs): TxDisplayModel {
  const txSigningRequests = Array.isArray(args.txSigningRequests) ? args.txSigningRequests : [];
  const operations = txSigningRequests.map((tx, txIndex) =>
    buildTransactionOperation(tx, txIndex, txSigningRequests.length),
  );
  const totalAttachedValue = txSigningRequests.reduce(
    (sum, tx) =>
      sum +
      (Array.isArray(tx.actions)
        ? tx.actions.reduce(
            (actionSum, action) => actionSum + totalAttachedValueForAction(action),
            BigInt(0),
          )
        : BigInt(0)),
    BigInt(0),
  );

  return {
    chain: 'near',
    intentDigest: args.intentDigest,
    signerAccount: args.signerAccount,
    title: args.title || 'NEAR Transaction',
    subtitle: args.subtitle,
    operations,
    ...(totalAttachedValue > 0
      ? {
          totals: {
            nativeValue: totalAttachedValue.toString(),
            nativeSymbol: 'yoctoNEAR',
          },
        }
      : {}),
  };
}
