export type DisplayChain = 'near' | 'evm' | 'tempo' | 'unknown';

export type DisplaySeverity = 'info' | 'warning' | 'critical';

export interface TxDisplayModel {
  chain: DisplayChain;
  chainId?: string;
  intentDigest?: string;
  signerAccount?: string;
  title?: string;
  subtitle?: string;
  operations: TxDisplayOperation[];
  warnings?: TxDisplayWarning[];
  totals?: TxDisplayTotals;
  raw?: { format: string; value: string };
}

export interface TxDisplayWarning {
  code: string;
  severity: DisplaySeverity;
  message: string;
}

export interface TxDisplayTotals {
  nativeValue?: string;
  nativeSymbol?: string;
  estimatedFee?: string;
  feeSymbol?: string;
}

export interface TxDisplayField {
  label: string;
  value: string;
  copyValue?: string;
}

export interface BaseDisplayOperation {
  id: string;
  kind: string;
  label: string;
  description?: string;
  risk?: DisplaySeverity;
  fields?: TxDisplayField[];
  children?: TxDisplayOperation[];
}

export interface NearActionOperation extends BaseDisplayOperation {
  kind: 'near.action';
  actionType:
    | 'createAccount'
    | 'transfer'
    | 'functionCall'
    | 'stake'
    | 'addKey'
    | 'deleteKey'
    | 'deployContract'
    | 'deployGlobalContract'
    | 'useGlobalContract'
    | 'deleteAccount'
    | 'signedDelegate';
}

export interface Erc4337Operation extends BaseDisplayOperation {
  kind: 'evm.erc4337';
  entryPoint?: string;
  smartAccount?: string;
  callType?: 'execute' | 'executeBatch' | 'custom';
}

export interface TempoTypedOperation extends BaseDisplayOperation {
  kind: 'tempo.eip2718';
  txTypeHex?: string;
  txTypeName?: string;
}

export interface GenericContractCallOperation extends BaseDisplayOperation {
  kind: 'generic.contractCall';
  to?: string;
  value?: string;
  selector?: string;
}

export interface RawFallbackOperation extends BaseDisplayOperation {
  kind: 'raw.fallback';
  raw: string;
}

export type TxDisplayOperation =
  | NearActionOperation
  | Erc4337Operation
  | TempoTypedOperation
  | GenericContractCallOperation
  | RawFallbackOperation;
