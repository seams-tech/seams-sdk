export type DisplayChain = 'near' | 'evm' | 'tempo' | 'unknown';

export type DisplaySeverity = 'info' | 'warning' | 'critical';

export interface TxDisplayModel {
  chain: DisplayChain;
  chainId?: number;
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
  renderAs?: 'inline' | 'file-content';
  hideLabel?: boolean;
  hideChevron?: boolean;
  contentVariants?: TxDisplayFileContentVariants;
}

export type TxDisplayFileContentMode = 'decoded' | 'raw';

export interface TxDisplayFileContentVariants {
  decoded: string;
  raw: string;
  defaultMode?: TxDisplayFileContentMode;
}

export interface TxDisplayAbiDecodeHint {
  dataHex: string;
  abi?: readonly Record<string, unknown>[];
}

export interface BaseDisplayOperation {
  id: string;
  kind: string;
  label: string;
  description?: string;
  risk?: DisplaySeverity;
  fields?: TxDisplayField[];
  children?: TxDisplayOperation[];
  abiDecodeHint?: TxDisplayAbiDecodeHint;
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

export interface TempoTypedOperation extends BaseDisplayOperation {
  kind: 'tempo.eip2718';
  txTypeHex?: string;
  txTypeName?: string;
  to?: string;
  selector?: string;
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
  | TempoTypedOperation
  | GenericContractCallOperation
  | RawFallbackOperation;
