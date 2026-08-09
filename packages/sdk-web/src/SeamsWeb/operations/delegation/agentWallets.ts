import type { DelegatedAgentSigningLaneRecord } from '@shared/signing-lanes';

export type AgentWalletSummary = {
  kind: 'agent_wallet_summary_v1';
  lane: DelegatedAgentSigningLaneRecord;
  signingState: 'active' | 'suspended' | 'expired' | 'revoked';
};
