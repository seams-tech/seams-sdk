import { expect, test } from '@playwright/test';
import {
  registrationIntentGrantFromString,
  walletIdFromString,
  type PasskeyRegistrationAuthMethodInput,
  type RegistrationSignerSetSelection,
} from '@shared/utils/registrationIntent';
import { parseWebAuthnRpId } from '@shared/utils/domainIds';
import {
  prepareVerifiedPasskeyEd25519YaoRegistrationV1,
  registerVerifiedPasskeyEd25519YaoV1,
  type PasskeyRegistrationIntentV1,
  type VerifiedPasskeyEd25519YaoRegistrationInputV1,
} from '../../packages/sdk-web/src/core/signingEngine/flows/registration/services/passkeyEd25519YaoRegistration';

const UNUSED_FETCH: typeof fetch = async (): Promise<Response> => {
  throw new Error('fetch is not expected in this test');
};

function passkeyAuthMethod(): PasskeyRegistrationAuthMethodInput {
  const rpId = parseWebAuthnRpId('wallet.example.test');
  if (!rpId.ok) throw new Error(rpId.error.message);
  return { kind: 'passkey', rpId: rpId.value };
}

function signerSelection(
  participantIds: readonly number[] = [11, 29],
): RegistrationSignerSetSelection {
  return {
    kind: 'signer_set',
    signers: [
      {
        kind: 'near_ed25519',
        accountProvisioning: {
          kind: 'implicit_account',
          accountIdSource: 'ed25519_public_key',
        },
        signerSlot: 3,
        participantIds,
        derivationVersion: 1,
      },
    ],
  };
}

function passkeyIntent(
  selection: RegistrationSignerSetSelection = signerSelection(),
): PasskeyRegistrationIntentV1 {
  return {
    version: 'registration_intent_v1',
    walletId: walletIdFromString('wallet-yao-local'),
    authMethod: passkeyAuthMethod(),
    signerSelection: selection,
    nonceB64u: 'registration-intent-nonce',
  };
}

function registrationInput(args: {
  intentDigest: string;
  authorityDigest: string;
  participantIds: readonly [number, number];
  ownedPasskeyPrfFirst: Uint8Array;
  routerOrigin: string;
}): VerifiedPasskeyEd25519YaoRegistrationInputV1 {
  const walletId = walletIdFromString('wallet-yao-local');
  return {
    kind: 'verified_passkey_ed25519_yao_registration_input_v1',
    verifiedIntent: {
      kind: 'verified_passkey_registration_intent_v1',
      intent: passkeyIntent(),
      registrationIntentDigestB64u: args.intentDigest,
      registrationIntentGrant: registrationIntentGrantFromString('registration-yao-grant'),
      registrationCeremonyId: 'registration-ceremony-42',
    },
    verifiedAuthority: {
      kind: 'verified_passkey_registration_authority_v1',
      walletId,
      registrationIntentDigestB64u: args.authorityDigest,
      credentialIdB64u: 'credential-42',
      ownedPasskeyPrfFirst: args.ownedPasskeyPrfFirst,
    },
    admissionRequest: {
      scope: {
        lifecycle_id: 'registration-ceremony-42',
        root_share_epoch: 'root-share-epoch-9',
        account_id: 'near-account.testnet',
        wallet_session_id: 'wallet-session-42',
        signer_set_id: 'signer-set-42',
        signing_worker_id: 'signing-worker-a',
      },
      application_binding: {
        wallet_id: 'wallet-yao-local',
        near_ed25519_signing_key_id: 'ed25519ks_wallet_yao_local',
        signing_root_id: 'project-local:development',
        key_creation_signer_slot: 3,
      },
      participant_ids: args.participantIds,
    },
    httpTransport: {
      kind: 'passkey_ed25519_yao_http_transport_v1',
      routerOrigin: args.routerOrigin,
      fetch: UNUSED_FETCH,
    },
  };
}

test.describe('verified passkey Ed25519 Yao registration orchestration', () => {
  test('builds the exact admission and HTTP transport from verified facts', () => {
    const ownedPasskeyPrfFirst = new Uint8Array(32).fill(7);
    const prepared = prepareVerifiedPasskeyEd25519YaoRegistrationV1(
      registrationInput({
        intentDigest: 'intent-digest-42',
        authorityDigest: 'intent-digest-42',
        participantIds: [11, 29],
        ownedPasskeyPrfFirst,
        routerOrigin: 'http://127.0.0.1:8787',
      }),
    );

    expect(prepared).toEqual({
      kind: 'prepared_passkey_ed25519_yao_registration_v1',
      request: {
        scope: {
          lifecycle_id: 'registration-ceremony-42',
          root_share_epoch: 'root-share-epoch-9',
          account_id: 'near-account.testnet',
          wallet_session_id: 'wallet-session-42',
          signer_set_id: 'signer-set-42',
          signing_worker_id: 'signing-worker-a',
        },
        application_binding: {
          wallet_id: 'wallet-yao-local',
          near_ed25519_signing_key_id: 'ed25519ks_wallet_yao_local',
          signing_root_id: 'project-local:development',
          key_creation_signer_slot: 3,
        },
        participant_ids: [11, 29],
      },
      transportConfig: {
        routerOrigin: 'http://127.0.0.1:8787',
        authorization: 'Bearer registration-yao-grant',
        fetch: UNUSED_FETCH,
      },
    });
    expect(ownedPasskeyPrfFirst).toEqual(new Uint8Array(32).fill(7));
  });

  test('rejects authority substitution and consumes owned PRF.first', async () => {
    const ownedPasskeyPrfFirst = new Uint8Array(32).fill(9);
    await expect(
      registerVerifiedPasskeyEd25519YaoV1(
        registrationInput({
          intentDigest: 'intent-digest-42',
          authorityDigest: 'substituted-intent-digest',
          participantIds: [11, 29],
          ownedPasskeyPrfFirst,
          routerOrigin: 'http://127.0.0.1:8787',
        }),
      ),
    ).rejects.toThrow('Passkey authority intent digest does not match');
    expect(ownedPasskeyPrfFirst).toEqual(new Uint8Array(32));
  });

  test('rejects participant substitution before Yao execution', () => {
    const input = registrationInput({
      intentDigest: 'intent-digest-42',
      authorityDigest: 'intent-digest-42',
      participantIds: [11, 31],
      ownedPasskeyPrfFirst: new Uint8Array(32).fill(5),
      routerOrigin: 'http://127.0.0.1:8787',
    });
    expect(() => prepareVerifiedPasskeyEd25519YaoRegistrationV1(input)).toThrow(
      'Yao participant IDs do not match',
    );
  });

  test('rejects a server admission from another registration ceremony', () => {
    const input = registrationInput({
      intentDigest: 'intent-digest-42',
      authorityDigest: 'intent-digest-42',
      participantIds: [11, 29],
      ownedPasskeyPrfFirst: new Uint8Array(32).fill(6),
      routerOrigin: 'http://127.0.0.1:8787',
    });
    input.admissionRequest.scope.lifecycle_id = 'registration-ceremony-substituted';
    expect(() => prepareVerifiedPasskeyEd25519YaoRegistrationV1(input)).toThrow(
      'Yao lifecycle ID does not match',
    );
  });

  test('rejects invalid transport configuration and consumes owned PRF.first', async () => {
    const ownedPasskeyPrfFirst = new Uint8Array(32).fill(4);
    await expect(
      registerVerifiedPasskeyEd25519YaoV1(
        registrationInput({
          intentDigest: 'intent-digest-42',
          authorityDigest: 'intent-digest-42',
          participantIds: [11, 29],
          ownedPasskeyPrfFirst,
          routerOrigin: 'file:///tmp/router',
        }),
      ),
    ).rejects.toThrow('Router origin must be an HTTP origin');
    expect(ownedPasskeyPrfFirst).toEqual(new Uint8Array(32));
  });
});
