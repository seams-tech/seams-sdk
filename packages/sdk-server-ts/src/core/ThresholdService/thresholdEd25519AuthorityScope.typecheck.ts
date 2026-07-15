import type { Ed25519SessionPolicy, ThresholdEd25519AuthorityScope } from '../types';
import type { WebAuthnRpId } from '@shared/utils/domainIds';
import { buildPasskeyWalletAuthAuthority } from '@shared/utils/walletAuthAuthority';
import type {
  ThresholdEd25519MpcSessionRecord,
  ThresholdEd25519SigningSessionRecord,
} from './stores/SessionStore';
import type {
  ThresholdEd25519KeyRecord,
  ThresholdEd25519ReadyKeyRecord,
} from './stores/KeyStore';
import type { Ed25519WalletSessionRecord } from './stores/WalletSessionStore';

declare const rpId: WebAuthnRpId;

const authorityScope: ThresholdEd25519AuthorityScope = { kind: 'passkey_rp', rpId };
const passkeyAuthority = buildPasskeyWalletAuthAuthority({
  walletId: 'wallet_alice',
  rpId,
  credentialIdB64u: 'Y3JlZGVudGlhbC0x',
});

const sessionPolicy: Ed25519SessionPolicy = {
  version: 'threshold_session_v1',
  nearAccountId: 'alice.near',
  nearEd25519SigningKeyId: 'ed25519:wallet_alice:1',
  authority: passkeyAuthority,
  relayerKeyId: 'ed25519:relayer',
  thresholdSessionId: 'threshold-session-1',
  signingGrantId: 'signing-grant-1',
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

const keyStoreShareSigningSession: ThresholdEd25519SigningSessionRecord = {
  expiresAtMs: 1,
  mpcSessionId: 'mpc-session-1',
  relayerKeyId: 'ed25519:relayer',
  signingDigestB64u: 'digest',
  userId: 'wallet_alice',
  authorityScope,
  commitmentsById: { '1': { hiding: 'hiding', binding: 'binding' } },
  signingShare: { kind: 'key_store' },
  relayerNoncesB64u: 'nonces',
  participantIds: [1, 2],
};

const embeddedShareSigningSession: ThresholdEd25519SigningSessionRecord = {
  expiresAtMs: 1,
  mpcSessionId: 'mpc-session-1',
  relayerKeyId: 'ed25519:relayer',
  signingDigestB64u: 'digest',
  userId: 'wallet_alice',
  authorityScope,
  commitmentsById: { '1': { hiding: 'hiding', binding: 'binding' } },
  signingShare: { kind: 'embedded_cosigner_share', relayerSigningShareB64u: 'signing-share' },
  relayerNoncesB64u: 'nonces',
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


void sessionPolicy;
void walletSession;
void mpcSession;
void keyStoreShareSigningSession;
void embeddedShareSigningSession;
void keyRecord;
void broadKeyRecord;
requireReadyKeyRecord(keyRecord);

const invalidSessionPolicy = {
  ...sessionPolicy,
  // @ts-expect-error Ed25519 session policy carries bound authority, never root rpId.
  rpId: 'wallet.example.test',
} satisfies Ed25519SessionPolicy;

const invalidSessionPolicyWithWalletId = {
  ...sessionPolicy,
  // @ts-expect-error Ed25519 session policy gets wallet binding from authority.
  walletId: 'wallet_alice',
} satisfies Ed25519SessionPolicy;

const invalidSessionPolicyWithAuthorityScope = {
  ...sessionPolicy,
  // @ts-expect-error Ed25519 session policy carries bound authority, never authorityScope.
  authorityScope,
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

const invalidKeyStoreShareSigningSession = {
  ...keyStoreShareSigningSession,
  signingShare: {
    kind: 'key_store',
    // @ts-expect-error key-store Ed25519 signing sessions cannot embed router share material.
    relayerSigningShareB64u: 'signing-share',
  },
} satisfies ThresholdEd25519SigningSessionRecord;

const invalidEmbeddedShareSigningSession: ThresholdEd25519SigningSessionRecord = {
  expiresAtMs: 1,
  mpcSessionId: 'mpc-session-1',
  relayerKeyId: 'ed25519:relayer',
  signingDigestB64u: 'digest',
  userId: 'wallet_alice',
  authorityScope,
  commitmentsById: { '1': { hiding: 'hiding', binding: 'binding' } },
  // @ts-expect-error embedded-share Ed25519 signing sessions require router share material.
  signingShare: { kind: 'embedded_cosigner_share' },
  relayerNoncesB64u: 'nonces',
  participantIds: [1, 2],
};

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


const invalidEmailOtpAuthorityScopeWithProofKind = {
  kind: 'email_otp',
  provider: 'google',
  providerUserId: 'google:alice',
  // @ts-expect-error Ed25519 Email OTP authority scopes carry stable provider identity, never one-time proof kind.
  proofKind: 'otp_challenge',
} satisfies ThresholdEd25519AuthorityScope;

const invalidEmailOtpAuthorityScopeWithChallengeId = {
  kind: 'email_otp',
  provider: 'google',
  providerUserId: 'google:alice',
  // @ts-expect-error Ed25519 Email OTP authority scopes cannot carry one-time challenge IDs.
  challengeId: 'challenge-1',
} satisfies ThresholdEd25519AuthorityScope;

void invalidSessionPolicy;
void invalidSessionPolicyWithWalletId;
void invalidSessionPolicyWithAuthorityScope;
void invalidWalletSession;
void invalidMpcSession;
void invalidKeyStoreShareSigningSession;
void invalidEmbeddedShareSigningSession;
void invalidKeyRecord;
void invalidReadyKeyRecordMissingRouterMaterial;
void invalidProvisioningKeyRecordWithRouterMaterial;
void invalidEmailOtpAuthorityScopeWithProofKind;
void invalidEmailOtpAuthorityScopeWithChallengeId;
