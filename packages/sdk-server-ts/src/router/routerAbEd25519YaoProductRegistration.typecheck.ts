import type { RouterAbEd25519YaoWalletSessionMintInputV1 } from './routerAbEd25519YaoProductRegistration';

type SharedRegistrationWalletSessionMintInput = Extract<
  RouterAbEd25519YaoWalletSessionMintInputV1,
  { readonly kind: 'shared_registration_wallet_session_v1' }
>;

type SharedRegistrationWalletSessionIdentity = Omit<
  SharedRegistrationWalletSessionMintInput,
  'kind' | 'signingGrantId' | 'expiresAtMs' | 'remainingUses'
>;

declare const identity: SharedRegistrationWalletSessionIdentity;

type AddSignerWalletSessionMintInput = Extract<
  RouterAbEd25519YaoWalletSessionMintInputV1,
  { readonly kind: 'add_signer_wallet_session_v1' }
>;

const validSharedRegistrationWalletSessionMintInput: SharedRegistrationWalletSessionMintInput = {
  ...identity,
  kind: 'shared_registration_wallet_session_v1',
  signingGrantId: 'signing-grant-1',
  expiresAtMs: 1_900_000_000_000,
  remainingUses: 3,
};

// @ts-expect-error A shared registration mint must carry the authoritative ECDSA grant.
const missingGrantSharedRegistrationWalletSessionMintInput: SharedRegistrationWalletSessionMintInput =
  {
    ...identity,
    kind: 'shared_registration_wallet_session_v1',
    expiresAtMs: 1_900_000_000_000,
    remainingUses: 3,
  };

// @ts-expect-error A generated registration mint cannot accept shared-budget terms.
const generatedRegistrationWalletSessionWithGrant: RouterAbEd25519YaoWalletSessionMintInputV1 = {
  ...identity,
  kind: 'registration_wallet_session_v1',
  signingGrantId: 'signing-grant-1',
  expiresAtMs: 1_900_000_000_000,
  remainingUses: 3,
};

const validAddSignerWalletSessionMintInput: AddSignerWalletSessionMintInput = {
  ...identity,
  kind: 'add_signer_wallet_session_v1',
  signingGrantId: 'add-signer-grant-1',
  expiresAtMs: 1_900_000_000_000,
  remainingUses: 3,
};

// @ts-expect-error An add-signer mint must carry its durable pre-claim session terms.
const missingTermsAddSignerWalletSessionMintInput: AddSignerWalletSessionMintInput = {
  ...identity,
  kind: 'add_signer_wallet_session_v1',
};

void validSharedRegistrationWalletSessionMintInput;
void missingGrantSharedRegistrationWalletSessionMintInput;
void generatedRegistrationWalletSessionWithGrant;
void validAddSignerWalletSessionMintInput;
void missingTermsAddSignerWalletSessionMintInput;
