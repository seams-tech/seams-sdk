import {
  toWalletId,
  walletSessionRefFromSession,
  type EcdsaCommandSubject,
  type NearCommandSubject,
  type WalletSessionRef,
} from './ecdsaChainTarget';

const walletSession = walletSessionRefFromSession({
  walletId: 'wallet.testnet',
  walletSessionUserId: 'wallet-user',
});

const ecdsaSubject = {
  walletSession,
} satisfies EcdsaCommandSubject;

const nearSubject = {
  walletSession,
  nearAccount: { kind: 'named', accountId: 'wallet.testnet' },
} satisfies NearCommandSubject;

void ecdsaSubject;
void nearSubject;

const invalidRawWalletSession: WalletSessionRef = {
  // @ts-expect-error wallet session refs must come from the boundary constructor.
  walletId: 'wallet.testnet',
  walletSessionUserId: 'wallet-user',
};

const invalidEcdsaSubjectWithNearAccount = {
  walletSession,
  // @ts-expect-error ECDSA subjects carry protocol-neutral subject identity.
  nearAccount: { kind: 'named', accountId: 'wallet.testnet' },
} satisfies EcdsaCommandSubject;

const invalidNearSubjectWithEcdsaSubject = {
  walletSession,
  nearAccount: { kind: 'named', accountId: 'wallet.testnet' },
  // @ts-expect-error NEAR command subjects carry NEAR account identity, not ECDSA subject identity.
  subjectId: 'wallet-subject',
} satisfies NearCommandSubject;

void invalidRawWalletSession;
void invalidEcdsaSubjectWithNearAccount;
void invalidNearSubjectWithEcdsaSubject;

const explicitWalletSession = {
  walletId: toWalletId('wallet.testnet'),
  walletSessionUserId: 'wallet-user',
} satisfies WalletSessionRef;

void explicitWalletSession;
