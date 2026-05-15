import type {
  ThresholdEcdsaBootstrapSessionPolicy,
  ThresholdEcdsaChainTarget,
  ThresholdEcdsaHssPrepareRequest,
} from '../types';

const chainTarget: ThresholdEcdsaChainTarget = {
  kind: 'evm',
  namespace: 'eip155',
  chainId: 11155111,
  networkSlug: 'ethereum-sepolia',
};

const bootstrapSessionPolicy: ThresholdEcdsaBootstrapSessionPolicy = {
  version: 'threshold_session_v1',
  walletSessionUserId: 'wallet-session-user-1',
  subjectId: 'wallet-subject-1',
  rpId: 'example.localhost',
  chainTarget,
  ecdsaThresholdKeyId: 'ecdsa-key-1',
  sessionId: 'threshold-session-1',
  walletSigningSessionId: 'wallet-signing-session-1',
  ttlMs: 60_000,
  remainingUses: 1,
};
void bootstrapSessionPolicy;

const validSessionBootstrapHssRequest: ThresholdEcdsaHssPrepareRequest = {
  walletSessionUserId: 'wallet-session-user-1',
  rpId: 'example.localhost',
  operation: 'session_bootstrap',
  keygenSessionId: 'keygen-session-1',
  sessionPolicy: bootstrapSessionPolicy,
  ecdsaThresholdKeyId: 'ecdsa-key-1',
};
void validSessionBootstrapHssRequest;

const missingSessionBootstrapLaneIdentity: ThresholdEcdsaHssPrepareRequest = {
  walletSessionUserId: 'wallet-session-user-1',
  rpId: 'example.localhost',
  operation: 'session_bootstrap',
  keygenSessionId: 'keygen-session-1',
  // @ts-expect-error ECDSA HSS session bootstrap must carry subjectId and chainTarget in sessionPolicy.
  sessionPolicy: {
    version: 'threshold_session_v1',
    walletSessionUserId: 'wallet-session-user-1',
    rpId: 'example.localhost',
    ecdsaThresholdKeyId: 'ecdsa-key-1',
    sessionId: 'threshold-session-1',
    walletSigningSessionId: 'wallet-signing-session-1',
    ttlMs: 60_000,
    remainingUses: 1,
  },
  ecdsaThresholdKeyId: 'ecdsa-key-1',
};
void missingSessionBootstrapLaneIdentity;

// @ts-expect-error explicit ECDSA HSS export must carry subjectId and chainTarget directly.
const missingExplicitExportLaneIdentity: ThresholdEcdsaHssPrepareRequest = {
  walletSessionUserId: 'wallet-session-user-1',
  rpId: 'example.localhost',
  operation: 'explicit_key_export',
  ecdsaThresholdKeyId: 'ecdsa-key-1',
  ecdsaSessionClaims: {},
};
void missingExplicitExportLaneIdentity;

export {};
