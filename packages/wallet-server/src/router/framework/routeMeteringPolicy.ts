export type RouteEventMeteringAction = 'wallet_created';
export type RouteGasLedger = 'evm' | 'near_delegate';

export type RouteMeteringPolicy =
  | { kind: 'none' }
  | {
      kind: 'event';
      action: RouteEventMeteringAction;
    }
  | {
      kind: 'gas';
      ledger: RouteGasLedger;
    };

export interface RouteUsageData {
  gasUsed?: number | string;
  transactionHash?: string;
  walletId?: string;
}
