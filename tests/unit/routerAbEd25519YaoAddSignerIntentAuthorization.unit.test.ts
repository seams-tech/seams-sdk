import { expect, test } from '@playwright/test';
import { deriveSigningRootId } from '@shared/threshold/signingRootScope';
import { parseWebAuthnRpId } from '@shared/utils/domainIds';
import type { RouterAbEd25519YaoRegistrationAdmissionRequestV1 } from '@shared/utils/routerAbEd25519Yao';
import {
  addSignerIntentGrantFromString,
  computeAddSignerNearEd25519SigningKeyId,
  registrationIntentGrantFromString,
  registrationNearEd25519BranchKey,
  walletIdFromString,
  type AddSignerIntentV1,
  type RegistrationIntentV1,
} from '@shared/utils/registrationIntent';
import { InMemoryRouterAbEd25519YaoRegistrationIntentAuthorizationAdapter } from '../../packages/sdk-server-ts/src/router/routerAbEd25519YaoRegistrationIntentAuthorization';

const WALLET_ID = walletIdFromString('wallet-add-signer');
const ADD_SIGNER_GRANT = addSignerIntentGrantFromString(
  'asig_authorized-add-signer-intent-credential-00000001',
);
const REGISTRATION_GRANT = registrationIntentGrantFromString(String(ADD_SIGNER_GRANT));
const EXPIRES_AT_MS = 4_102_444_800_000;
const RUNTIME_POLICY_SCOPE = {
  orgId: 'organization-1',
  projectId: 'project-1',
  envId: 'environment-1',
  signingRootVersion: 'root-version-1',
} as const;

function webAuthnRpId(value: string) {
  const parsed = parseWebAuthnRpId(value);
  if (!parsed.ok) throw new Error(parsed.error.message);
  return parsed.value;
}

function addSignerIntent(input?: {
  readonly keyPurpose?: string;
  readonly participantIds?: readonly [number, number];
}): AddSignerIntentV1 & {
  readonly signerSelection: Extract<AddSignerIntentV1['signerSelection'], { mode: 'ed25519' }>;
} {
  return {
    version: 'add_signer_intent_v1',
    walletId: WALLET_ID,
    signerSelection: {
      mode: 'ed25519',
      ed25519: {
        mode: 'create_implicit_near_account',
        signerSlot: 2,
        participantIds: [...(input?.participantIds ?? [1, 2])],
        keyPurpose: input?.keyPurpose ?? 'near_tx',
        keyVersion: 'router-ab-ed25519-yao-v1',
        derivationVersion: 1,
      },
    },
    runtimePolicyScope: RUNTIME_POLICY_SCOPE,
    nonceB64u: 'add-signer-intent-nonce',
  };
}

async function admissionRequest(
  intent: ReturnType<typeof addSignerIntent>,
): Promise<RouterAbEd25519YaoRegistrationAdmissionRequestV1> {
  const selection = intent.signerSelection.ed25519;
  const signingRootId = deriveSigningRootId(RUNTIME_POLICY_SCOPE);
  const nearEd25519SigningKeyId = await computeAddSignerNearEd25519SigningKeyId({
    kind: 'wallet_add_signer_implicit_near_ed25519_key_v1',
    walletId: intent.walletId,
    signingRootId,
    signingRootVersion: RUNTIME_POLICY_SCOPE.signingRootVersion,
    signerSlot: selection.signerSlot,
    participantIds: selection.participantIds,
    keyPurpose: selection.keyPurpose,
    keyVersion: selection.keyVersion,
    derivationVersion: selection.derivationVersion,
  });
  return {
    scope: {
      lifecycle_id: 'wallet-add-signer-ceremony-1',
      root_share_epoch: RUNTIME_POLICY_SCOPE.signingRootVersion,
      account_id: String(intent.walletId),
      wallet_session_id: 'wallet-add-signer-ceremony-1',
      signer_set_id: registrationNearEd25519BranchKey(selection.signerSlot),
      signing_worker_id: 'signing-worker-1',
    },
    application_binding: {
      wallet_id: String(intent.walletId),
      near_ed25519_signing_key_id: nearEd25519SigningKeyId,
      signing_root_id: signingRootId,
      key_creation_signer_slot: selection.signerSlot,
    },
    participant_ids: [selection.participantIds[0]!, selection.participantIds[1]!],
  };
}

function registrationIntent(): RegistrationIntentV1 {
  return {
    version: 'registration_intent_v1',
    walletId: WALLET_ID,
    authMethod: { kind: 'passkey', rpId: webAuthnRpId('wallet.local') },
    signerSelection: {
      kind: 'signer_set',
      signers: [
        {
          kind: 'near_ed25519',
          accountProvisioning: {
            kind: 'implicit_account',
            accountIdSource: 'ed25519_public_key',
          },
          signerSlot: 2,
          participantIds: [1, 2],
          derivationVersion: 1,
        },
      ],
    },
    nonceB64u: 'registration-intent-nonce',
  };
}

function authorizedRequest(credential: string): Request {
  return new Request('http://router.local/router-ab/ed25519/yao/registration/admit', {
    method: 'POST',
    headers: { authorization: `Bearer ${credential}` },
  });
}

test.describe('Router A/B Ed25519 Yao add-signer intent authorization', () => {
  test('binds and admits the exact deterministic add-signer identity', async () => {
    const adapter = new InMemoryRouterAbEd25519YaoRegistrationIntentAuthorizationAdapter();
    const intent = addSignerIntent();
    const admission = await admissionRequest(intent);

    await expect(
      adapter.bindVerifiedIntent({
        kind: 'verified_add_signer_intent',
        addSignerIntentGrant: ADD_SIGNER_GRANT,
        intent,
        admissionRequest: admission,
        expiresAtMs: EXPIRES_AT_MS,
      }),
    ).resolves.toEqual({ ok: true });
    await expect(
      adapter.authorize({
        kind: 'admit',
        request: authorizedRequest(String(ADD_SIGNER_GRANT)),
        body: admission,
      }),
    ).resolves.toEqual({ ok: true });
    expect(JSON.stringify(adapter)).not.toContain(String(ADD_SIGNER_GRANT));
    expect(JSON.stringify(adapter)).not.toContain(intent.nonceB64u);
  });

  test('rejects key-purpose, participant, and deterministic-key substitutions', async () => {
    const exactIntent = addSignerIntent();
    const exactAdmission = await admissionRequest(exactIntent);
    const substitutions = [
      { intent: addSignerIntent({ keyPurpose: 'recovery' }), admission: exactAdmission },
      { intent: addSignerIntent({ participantIds: [1, 3] }), admission: exactAdmission },
      {
        intent: exactIntent,
        admission: {
          ...exactAdmission,
          application_binding: {
            ...exactAdmission.application_binding,
            near_ed25519_signing_key_id: 'ed25519ks_substituted',
          },
        },
      },
    ];

    for (const substitution of substitutions) {
      const adapter = new InMemoryRouterAbEd25519YaoRegistrationIntentAuthorizationAdapter();
      await expect(
        adapter.bindVerifiedIntent({
          kind: 'verified_add_signer_intent',
          addSignerIntentGrant: ADD_SIGNER_GRANT,
          intent: substitution.intent,
          admissionRequest: substitution.admission,
          expiresAtMs: EXPIRES_AT_MS,
        }),
      ).resolves.toMatchObject({ ok: false, code: 'invalid_registration_intent' });
    }
  });

  test('rejects registration and add-signer cross-purpose credential reuse', async () => {
    const adapter = new InMemoryRouterAbEd25519YaoRegistrationIntentAuthorizationAdapter();
    const intent = addSignerIntent();
    const admission = await admissionRequest(intent);
    await adapter.bindVerifiedIntent({
      kind: 'verified_add_signer_intent',
      addSignerIntentGrant: ADD_SIGNER_GRANT,
      intent,
      admissionRequest: admission,
      expiresAtMs: EXPIRES_AT_MS,
    });

    await expect(
      adapter.bindVerifiedIntent({
        kind: 'verified_registration_intent',
        registrationIntentGrant: REGISTRATION_GRANT,
        intent: registrationIntent(),
        admissionRequest: admission,
        expiresAtMs: EXPIRES_AT_MS,
      }),
    ).resolves.toMatchObject({ ok: false, code: 'registration_intent_conflict' });
  });
});
