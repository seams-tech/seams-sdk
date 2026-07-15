import type { TempoSignedResult } from '@/core/signingEngine/chains/tempo/tempoAdapter';
import type { WalletSessionRef } from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import type { ReportTempoBroadcastAcceptedArgs } from './publicApi/types';
import type { PMReportTempoBroadcastAcceptedPayload } from './walletIframe/shared/messages';

declare const walletSession: WalletSessionRef;
declare const signedResult: TempoSignedResult;

const acceptedBroadcast: ReportTempoBroadcastAcceptedArgs = {
  walletSession,
  signedResult,
  txHash: `0x${'11'.repeat(32)}`,
};
void acceptedBroadcast;

// @ts-expect-error Public broadcast acceptance requires the network transaction identity.
const acceptedBroadcastWithoutTxHash: ReportTempoBroadcastAcceptedArgs = {
  walletSession,
  signedResult,
};
void acceptedBroadcastWithoutTxHash;

// @ts-expect-error Iframe broadcast acceptance requires the network transaction identity.
const iframeAcceptedBroadcastWithoutTxHash: PMReportTempoBroadcastAcceptedPayload = {
  walletSession,
  signedResult,
};
void iframeAcceptedBroadcastWithoutTxHash;

export {};
