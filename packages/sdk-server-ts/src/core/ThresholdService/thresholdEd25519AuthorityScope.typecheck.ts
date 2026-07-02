import type { Ed25519SessionPolicy, ThresholdEd25519AuthorityScope } from '../types';
import type { WebAuthnRpId } from '@shared/utils/domainIds';
import type {
  RouterAbEd25519PresignExpectedScope,
  RouterAbEd25519PresignRecord,
  ThresholdEd25519MpcSessionRecord,
} from './stores/SessionStore';
import type {
  ThresholdEd25519KeyRecord,
  ThresholdEd25519ReadyKeyRecord,
} from './stores/KeyStore';
import type { Ed25519WalletSessionRecord } from './stores/WalletSessionStore';

declare const rpId: WebAuthnRpId;

const authorityScope: ThresholdEd25519AuthorityScope = { kind: 'passkey_rp', rpId };

const sessionPolicy: Ed25519SessionPolicy = {
  version: 'threshold_session_v1',
  walletId: 'wallet_alice',
  nearAccountId: 'alice.near',
  nearEd25519SigningKeyId: 'ed25519:wallet_alice:1',
  authorityScope,
  relayerKeyId: 'ed25519:relayer',
  thresholdSessionId: 'threshold-session-1',
  ttlMs: 60_000,
  remainingUses: 1,
};

const walletSession: Ed25519WalletSessionRecord = {
  expiresAtMs: 1,
  relayerKeyId: 'ed25519:relayer',
  userId: 'wallet_alice',
  walletId: 'wallet_alice',
  nearAccountId: 'alice.near',
  nearEd25519SigningKeyId: 'ed25519:wallet_alice:1',
  authorityScope,
  participantIds: [1, 2],
};

const mpcSession: ThresholdEd25519MpcSessionRecord = {
  expiresAtMs: 1,
  relayerKeyId: 'ed25519:relayer',
  purpose: 'near_tx',
  intentDigestB64u: 'intent',
  signingDigestB64u: 'digest',
  userId: 'wallet_alice',
  authorityScope,
  participantIds: [1, 2],
};

declare function requireReadyKeyRecord(record: ThresholdEd25519ReadyKeyRecord): void;

const keyRecord: ThresholdEd25519ReadyKeyRecord = {
  kind: 'ready',
  walletId: 'wallet_alice',
  nearAccountId: 'alice.near',
  nearEd25519SigningKeyId: 'ed25519:wallet_alice:1',
  authorityScope,
  publicKey: 'ed25519:relayer',
  routerMaterial: {
    signingShareB64u: 'signing-share',
    verifyingShareB64u: 'verifying-share',
  },
  keyVersion: 'key-v1',
  recoveryExportCapable: true,
};

const broadKeyRecord: ThresholdEd25519KeyRecord = keyRecord;

const presignRecord: RouterAbEd25519PresignRecord = {
  kind: 'router_ab_ed25519_presign_record_v2',
  expiresAtMs: 1,
  thresholdSessionId: 'threshold-session-1',
  signingGrantId: 'grant-1',
  relayerKeyId: 'ed25519:relayer',
  nearAccountId: 'alice.near',
  nearNetworkId: 'testnet',
  signerPublicKey: 'ed25519:public',
  rpcPolicyId: 'policy',
  authorityScope,
  runtimePolicyScope: {
    orgId: 'org',
    projectId: 'project',
    envId: 'env',
    signingRootVersion: 'root-v1',
  },
  protocolVersion: 'ed25519_frost_2p_presign_v1',
  participantIds: [1, 2],
  groupPublicKey: 'ed25519:group',
  clientVerifyingShareB64u: 'client-share',
  clientCommitments: { hiding: 'hiding', binding: 'binding' },
  relayerCommitments: { hiding: 'hiding', binding: 'binding' },
  relayerVerifyingShareB64u: 'relayer-share',
  relayerNoncesB64u: 'relayer-nonces',
};

const expectedScope: RouterAbEd25519PresignExpectedScope = {
  thresholdSessionId: presignRecord.thresholdSessionId,
  signingGrantId: presignRecord.signingGrantId,
  relayerKeyId: presignRecord.relayerKeyId,
  nearAccountId: presignRecord.nearAccountId,
  nearNetworkId: presignRecord.nearNetworkId,
  signerPublicKey: presignRecord.signerPublicKey,
  rpcPolicyId: presignRecord.rpcPolicyId,
  authorityScope,
  runtimePolicyScope: presignRecord.runtimePolicyScope,
  participantIds: presignRecord.participantIds,
  groupPublicKey: presignRecord.groupPublicKey,
};

void sessionPolicy;
void walletSession;
void mpcSession;
void keyRecord;
void broadKeyRecord;
void expectedScope;
requireReadyKeyRecord(keyRecord);

const invalidSessionPolicy = {
  ...sessionPolicy,
  // @ts-expect-error Ed25519 session policy carries authorityScope, never root rpId.
  rpId: 'wallet.example.test',
} satisfies Ed25519SessionPolicy;

const invalidWalletSession = {
  ...walletSession,
  // @ts-expect-error Ed25519 wallet-session records carry authorityScope, never root rpId.
  rpId: 'wallet.example.test',
} satisfies Ed25519WalletSessionRecord;

const invalidMpcSession = {
  ...mpcSession,
  // @ts-expect-error Ed25519 MPC session records carry authorityScope, never root rpId.
  rpId: 'wallet.example.test',
} satisfies ThresholdEd25519MpcSessionRecord;

const invalidKeyRecord = {
  ...keyRecord,
  // @ts-expect-error Ed25519 key-store records carry authorityScope, never root rpId.
  rpId: 'wallet.example.test',
} satisfies ThresholdEd25519KeyRecord;

// @ts-expect-error ready Ed25519 key records require router material.
const invalidReadyKeyRecordMissingRouterMaterial: ThresholdEd25519ReadyKeyRecord = {
  kind: 'ready',
  walletId: 'wallet_alice',
  nearAccountId: 'alice.near',
  nearEd25519SigningKeyId: 'ed25519:wallet_alice:1',
  authorityScope,
  publicKey: 'ed25519:relayer',
  keyVersion: 'key-v1',
  recoveryExportCapable: true,
};

// @ts-expect-error provisioning Ed25519 key records cannot carry router material.
const invalidProvisioningKeyRecordWithRouterMaterial: ThresholdEd25519KeyRecord = {
  kind: 'provisioning',
  walletId: 'wallet_alice',
  nearAccountId: 'alice.near',
  nearEd25519SigningKeyId: 'ed25519:wallet_alice:1',
  authorityScope,
  publicKey: 'ed25519:relayer',
  keyVersion: 'key-v1',
  routerMaterial: {
    signingShareB64u: 'signing-share',
    verifyingShareB64u: 'verifying-share',
  },
};

// @ts-expect-error core signing/session code must receive a ready key record.
requireReadyKeyRecord({} as ThresholdEd25519KeyRecord);

const invalidPresignScope = {
  ...expectedScope,
  // @ts-expect-error Ed25519 presign scopes carry authorityScope, never root rpId.
  rpId: 'wallet.example.test',
} satisfies RouterAbEd25519PresignExpectedScope;

void invalidSessionPolicy;
void invalidWalletSession;
void invalidMpcSession;
void invalidKeyRecord;
void invalidReadyKeyRecordMissingRouterMaterial;
void invalidProvisioningKeyRecordWithRouterMaterial;
void invalidPresignScope;
