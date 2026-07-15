import { expect, test } from '@playwright/test';
import {
  addSignerIntentGrantFromString,
  computeAddSignerNearEd25519SigningKeyId,
  registrationNearEd25519BranchKey,
  walletIdFromString,
} from '../../packages/shared-ts/src/utils/registrationIntent';
import {
  prepareVerifiedPasskeyEd25519YaoAddSignerV1,
  registerVerifiedPasskeyEd25519YaoAddSignerV1,
  type VerifiedPasskeyEd25519AddSignerIntentV1,
  type VerifiedPasskeyEd25519YaoAddSignerInputV1,
} from '../../packages/sdk-web/src/core/signingEngine/flows/registration/services/passkeyEd25519YaoAddSigner';

const UNUSED_FETCH: typeof fetch = async (): Promise<Response> => {
  throw new Error('fetch is not expected in this test');
};

const WALLET_ID = walletIdFromString('wallet-yao-add-signer');
const CEREMONY_ID = 'add-signer-ceremony-42';
const INTENT_DIGEST = 'add-signer-intent-digest-42';

function addSignerIntent(): VerifiedPasskeyEd25519AddSignerIntentV1['intent'] {
  return {
    version: 'add_signer_intent_v1',
    walletId: WALLET_ID,
    signerSelection: {
      mode: 'ed25519',
      ed25519: {
        mode: 'create_implicit_near_account',
        signerSlot: 3,
        participantIds: [11, 29],
        keyPurpose: 'near_tx',
        keyVersion: 'router-ab-ed25519-yao-v1',
        derivationVersion: 1,
      },
    },
    runtimePolicyScope: {
      orgId: 'org-local',
      projectId: 'project-local',
      envId: 'development',
      signingRootVersion: 'root-share-epoch-9',
    },
    nonceB64u: 'add-signer-intent-nonce',
  };
}

async function addSignerInput(
  ownedPasskeyPrfFirst: Uint8Array,
): Promise<VerifiedPasskeyEd25519YaoAddSignerInputV1> {
  const intent = addSignerIntent();
  const selection = intent.signerSelection.ed25519;
  const nearEd25519SigningKeyId = await computeAddSignerNearEd25519SigningKeyId({
    kind: 'wallet_add_signer_implicit_near_ed25519_key_v1',
    walletId: intent.walletId,
    signingRootId: 'project-local:development',
    signingRootVersion: intent.runtimePolicyScope.signingRootVersion,
    signerSlot: selection.signerSlot,
    participantIds: selection.participantIds,
    keyPurpose: selection.keyPurpose,
    keyVersion: selection.keyVersion,
    derivationVersion: selection.derivationVersion,
  });
  return {
    kind: 'verified_passkey_ed25519_yao_add_signer_input_v1',
    verifiedIntent: {
      kind: 'verified_passkey_ed25519_add_signer_intent_v1',
      intent,
      addSignerIntentDigestB64u: INTENT_DIGEST,
      addSignerIntentGrant: addSignerIntentGrantFromString('add-signer-yao-grant'),
      addSignerCeremonyId: CEREMONY_ID,
    },
    verifiedAuthority: {
      kind: 'verified_passkey_ed25519_add_signer_authority_v1',
      walletId: WALLET_ID,
      addSignerIntentDigestB64u: INTENT_DIGEST,
      credentialIdB64u: 'credential-42',
      ownedPasskeyPrfFirst,
    },
    admissionRequest: {
      scope: {
        lifecycle_id: CEREMONY_ID,
        root_share_epoch: 'root-share-epoch-9',
        account_id: WALLET_ID,
        wallet_session_id: CEREMONY_ID,
        signer_set_id: registrationNearEd25519BranchKey(selection.signerSlot),
        signing_worker_id: 'signing-worker-a',
      },
      application_binding: {
        wallet_id: WALLET_ID,
        near_ed25519_signing_key_id: nearEd25519SigningKeyId,
        signing_root_id: 'project-local:development',
        key_creation_signer_slot: 3,
      },
      participant_ids: [11, 29],
    },
    httpTransport: {
      kind: 'passkey_ed25519_yao_http_transport_v1',
      routerOrigin: 'http://127.0.0.1:8787',
      fetch: UNUSED_FETCH,
    },
  };
}

type AdmissionMutation = {
  label: string;
  expectedError: RegExp;
  mutate(input: VerifiedPasskeyEd25519YaoAddSignerInputV1): void;
};

const ADMISSION_MUTATIONS: readonly AdmissionMutation[] = [
  {
    label: 'lifecycle',
    expectedError: /Yao lifecycle ID does not match/,
    mutate(input) {
      input.admissionRequest.scope.lifecycle_id = 'substituted-ceremony';
    },
  },
  {
    label: 'Wallet Session',
    expectedError: /Yao Wallet Session ID does not match/,
    mutate(input) {
      input.admissionRequest.scope.wallet_session_id = 'substituted-wallet-session';
    },
  },
  {
    label: 'account',
    expectedError: /Yao account ID does not match/,
    mutate(input) {
      input.admissionRequest.scope.account_id = 'wallet-substituted';
    },
  },
  {
    label: 'signer set',
    expectedError: /Yao signer-set ID does not match/,
    mutate(input) {
      input.admissionRequest.scope.signer_set_id = 'near_ed25519:slot:4';
    },
  },
  {
    label: 'root epoch',
    expectedError: /Yao root-share epoch does not match/,
    mutate(input) {
      input.admissionRequest.scope.root_share_epoch = 'root-share-epoch-substituted';
    },
  },
  {
    label: 'application wallet',
    expectedError: /Yao application wallet ID does not match/,
    mutate(input) {
      input.admissionRequest.application_binding.wallet_id = 'wallet-substituted';
    },
  },
  {
    label: 'signing root',
    expectedError: /Yao signing-root ID does not match/,
    mutate(input) {
      input.admissionRequest.application_binding.signing_root_id = 'project-other:development';
    },
  },
  {
    label: 'NEAR signing key',
    expectedError: /Yao NEAR signing-key ID does not match/,
    mutate(input) {
      input.admissionRequest.application_binding.near_ed25519_signing_key_id =
        'near-ed25519-signing-key-substituted';
    },
  },
  {
    label: 'signer slot',
    expectedError: /Yao signer slot does not match/,
    mutate(input) {
      input.admissionRequest.application_binding.key_creation_signer_slot = 4;
    },
  },
  {
    label: 'participants',
    expectedError: /Yao participant IDs do not match/,
    mutate(input) {
      input.admissionRequest.participant_ids = [11, 31];
    },
  },
];

test.describe('verified passkey Ed25519 Yao add-signer authorization', () => {
  test('builds the exact admission and HTTP transport from verified add-signer facts', async () => {
    const ownedPasskeyPrfFirst = new Uint8Array(32).fill(7);
    const input = await addSignerInput(ownedPasskeyPrfFirst);
    const prepared = await prepareVerifiedPasskeyEd25519YaoAddSignerV1(input);

    expect(prepared).toEqual({
      kind: 'prepared_passkey_ed25519_yao_add_signer_v1',
      request: input.admissionRequest,
      transportConfig: {
        routerOrigin: 'http://127.0.0.1:8787',
        authorization: 'Bearer add-signer-yao-grant',
        fetch: UNUSED_FETCH,
      },
    });
    expect(ownedPasskeyPrfFirst).toEqual(new Uint8Array(32).fill(7));
  });

  for (const mutation of ADMISSION_MUTATIONS) {
    test(`rejects ${mutation.label} substitution before Yao execution`, async () => {
      const input = await addSignerInput(new Uint8Array(32).fill(5));
      mutation.mutate(input);
      await expect(prepareVerifiedPasskeyEd25519YaoAddSignerV1(input)).rejects.toThrow(
        mutation.expectedError,
      );
    });
  }

  test('rejects authority substitution and consumes owned PRF.first', async () => {
    const ownedPasskeyPrfFirst = new Uint8Array(32).fill(9);
    const input = await addSignerInput(ownedPasskeyPrfFirst);
    input.verifiedAuthority.addSignerIntentDigestB64u = 'substituted-intent-digest';

    await expect(registerVerifiedPasskeyEd25519YaoAddSignerV1(input)).rejects.toThrow(
      'Passkey authority intent digest does not match',
    );
    expect(ownedPasskeyPrfFirst).toEqual(new Uint8Array(32));
  });

  test('rejects invalid transport configuration and consumes owned PRF.first', async () => {
    const ownedPasskeyPrfFirst = new Uint8Array(32).fill(4);
    const input = await addSignerInput(ownedPasskeyPrfFirst);
    input.httpTransport.routerOrigin = 'file:///tmp/router';

    await expect(registerVerifiedPasskeyEd25519YaoAddSignerV1(input)).rejects.toThrow(
      'Router origin must be an HTTP origin',
    );
    expect(ownedPasskeyPrfFirst).toEqual(new Uint8Array(32));
  });
});
