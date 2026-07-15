import { expect, test } from '@playwright/test';
import { parseWebAuthnRpId } from '@shared/utils/domainIds';
import {
  deriveRouterAbEd25519YaoStableContextBindingV1,
  type RouterAbEd25519YaoActivationBindingV1,
  type RouterAbEd25519YaoActivationExecuteRequestV1,
  type RouterAbEd25519YaoRegistrationAdmissionRequestV1,
} from '@shared/utils/routerAbEd25519Yao';
import {
  registrationIntentGrantFromString,
  walletIdFromString,
  type RegistrationIntentV1,
} from '@shared/utils/registrationIntent';
import { InMemoryRouterAbEd25519YaoRegistrationIntentAuthorizationAdapter } from '../../packages/sdk-server-ts/src/router/routerAbEd25519YaoRegistrationIntentAuthorization';

type RouterAbEd25519YaoRegistrationBindingV1 =
  RouterAbEd25519YaoActivationBindingV1<'registration'>;
type RouterAbEd25519YaoRegistrationExecuteRequestV1 =
  RouterAbEd25519YaoActivationExecuteRequestV1<'registration'>;

const GRANT = registrationIntentGrantFromString(
  'rig_authorized-registration-intent-credential-00000001',
);
const OTHER_GRANT = registrationIntentGrantFromString(
  'rig_substituted-registration-intent-credential-00000002',
);
const EXPIRES_AT_MS = 4_102_444_800_000;

function webAuthnRpId(value: string) {
  const parsed = parseWebAuthnRpId(value);
  if (!parsed.ok) throw new Error(parsed.error.message);
  return parsed.value;
}

function bytes(seed: number): number[] {
  return new Array<number>(32).fill(seed);
}

function registrationIntent(input: {
  walletId: string;
  firstParticipantId: number;
  secondParticipantId: number;
}): RegistrationIntentV1 {
  return {
    version: 'registration_intent_v1',
    walletId: walletIdFromString(input.walletId),
    authMethod: {
      kind: 'passkey',
      rpId: webAuthnRpId('wallet.local'),
    },
    signerSelection: {
      kind: 'signer_set',
      signers: [
        {
          kind: 'near_ed25519',
          accountProvisioning: {
            kind: 'implicit_account',
            accountIdSource: 'ed25519_public_key',
          },
          signerSlot: 1,
          participantIds: [input.firstParticipantId, input.secondParticipantId],
          derivationVersion: 1,
        },
      ],
    },
    nonceB64u: 'registration-intent-nonce',
  };
}

function admissionRequest(input: {
  lifecycleId: string;
  walletId: string;
  firstParticipantId: number;
  secondParticipantId: number;
}): RouterAbEd25519YaoRegistrationAdmissionRequestV1 {
  return {
    scope: {
      lifecycle_id: input.lifecycleId,
      root_share_epoch: 'root-share-epoch-1',
      account_id: 'account-1',
      wallet_session_id: 'wallet-session-1',
      signer_set_id: 'signer-set-1',
      signing_worker_id: 'signing-worker-1',
    },
    application_binding: {
      wallet_id: input.walletId,
      near_ed25519_signing_key_id: 'ed25519ks_wallet-1',
      signing_root_id: 'project-1:environment-1',
      key_creation_signer_slot: 1,
    },
    participant_ids: [input.firstParticipantId, input.secondParticipantId],
  };
}

function authorizedIntent(input: {
  grant: ReturnType<typeof registrationIntentGrantFromString>;
  intent: RegistrationIntentV1;
  admissionRequest: RouterAbEd25519YaoRegistrationAdmissionRequestV1;
}) {
  return {
    kind: 'verified_registration_intent' as const,
    registrationIntentGrant: input.grant,
    intent: input.intent,
    admissionRequest: input.admissionRequest,
    expiresAtMs: EXPIRES_AT_MS,
  };
}

function requestWithAuthorization(authorization: string): Request {
  return new Request('http://router.local/router-ab/ed25519/yao/registration', {
    method: 'POST',
    headers: { authorization },
  });
}

function requestWithoutAuthorization(): Request {
  return new Request('http://router.local/router-ab/ed25519/yao/registration', {
    method: 'POST',
  });
}

async function registrationBinding(
  request: RouterAbEd25519YaoRegistrationAdmissionRequestV1,
): Promise<RouterAbEd25519YaoRegistrationBindingV1> {
  return {
    lifecycle: {
      lifecycle_id: request.scope.lifecycle_id,
      work_kind: 'registration_prepare',
      primitive_request_kind: 'registration',
      root_share_epoch: request.scope.root_share_epoch,
      account_id: request.scope.account_id,
      session_id: request.scope.wallet_session_id,
      signer_set_id: request.scope.signer_set_id,
      selected_server_id: request.scope.signing_worker_id,
    },
    operation: 'registration',
    session_id: bytes(7),
    stable_key_context_binding: await deriveRouterAbEd25519YaoStableContextBindingV1(
      request.application_binding,
      request.participant_ids,
    ),
  };
}

function executeRequest(
  binding: RouterAbEd25519YaoRegistrationBindingV1,
): RouterAbEd25519YaoRegistrationExecuteRequestV1 {
  return {
    binding,
    deriver_a_input: {
      kind: 'activation',
      deriver: 'deriver_a',
      operation: 'registration',
      session: binding.session_id,
      stable_context_binding: binding.stable_key_context_binding,
      encapsulated_key: bytes(8),
      ciphertext: bytes(9),
    },
    deriver_b_input: {
      kind: 'activation',
      deriver: 'deriver_b',
      operation: 'registration',
      session: binding.session_id,
      stable_context_binding: binding.stable_key_context_binding,
      encapsulated_key: bytes(10),
      ciphertext: bytes(11),
    },
  };
}

function admittedAuthorizationInput(input: {
  request: Request;
  body: RouterAbEd25519YaoRegistrationAdmissionRequestV1;
}) {
  return {
    kind: 'admit' as const,
    request: input.request,
    body: input.body,
  };
}

function executionAuthorizationInput(input: {
  request: Request;
  body: RouterAbEd25519YaoRegistrationExecuteRequestV1;
}) {
  return {
    kind: 'execute' as const,
    request: input.request,
    body: input.body,
  };
}

test.describe('Router A/B Ed25519 Yao registration-intent authorization', () => {
  test('binds one verified intent and retains no raw credential', async () => {
    const adapter = new InMemoryRouterAbEd25519YaoRegistrationIntentAuthorizationAdapter();
    const request = admissionRequest({
      lifecycleId: 'registration-lifecycle-1',
      walletId: 'wallet-1',
      firstParticipantId: 1,
      secondParticipantId: 2,
    });
    const intent = registrationIntent({
      walletId: 'wallet-1',
      firstParticipantId: 1,
      secondParticipantId: 2,
    });
    const verified = authorizedIntent({ grant: GRANT, intent, admissionRequest: request });

    await expect(adapter.bindVerifiedIntent(verified)).resolves.toEqual({ ok: true });
    await expect(adapter.bindVerifiedIntent(verified)).resolves.toEqual({ ok: true });
    request.scope.wallet_session_id = 'mutated-after-binding';
    const exactRequest = admissionRequest({
      lifecycleId: 'registration-lifecycle-1',
      walletId: 'wallet-1',
      firstParticipantId: 1,
      secondParticipantId: 2,
    });
    await expect(
      adapter.authorize(
        admittedAuthorizationInput({
          request: requestWithAuthorization(`Bearer ${GRANT}`),
          body: exactRequest,
        }),
      ),
    ).resolves.toEqual({ ok: true });
    expect(JSON.stringify(adapter)).not.toContain(String(GRANT));
    expect(JSON.stringify(adapter)).not.toContain('registration-intent-nonce');
  });

  test('rejects an intent subject or participant substitution before binding', async () => {
    const adapter = new InMemoryRouterAbEd25519YaoRegistrationIntentAuthorizationAdapter();
    const request = admissionRequest({
      lifecycleId: 'registration-lifecycle-1',
      walletId: 'wallet-1',
      firstParticipantId: 1,
      secondParticipantId: 2,
    });
    const wrongWalletIntent = registrationIntent({
      walletId: 'wallet-2',
      firstParticipantId: 1,
      secondParticipantId: 2,
    });
    const wrongParticipantsIntent = registrationIntent({
      walletId: 'wallet-1',
      firstParticipantId: 1,
      secondParticipantId: 3,
    });

    await expect(
      adapter.bindVerifiedIntent(
        authorizedIntent({ grant: GRANT, intent: wrongWalletIntent, admissionRequest: request }),
      ),
    ).resolves.toMatchObject({ ok: false, code: 'invalid_registration_intent' });
    await expect(
      adapter.bindVerifiedIntent(
        authorizedIntent({
          grant: GRANT,
          intent: wrongParticipantsIntent,
          admissionRequest: request,
        }),
      ),
    ).resolves.toMatchObject({ ok: false, code: 'invalid_registration_intent' });
  });

  test('requires one canonical Bearer credential and denies unknown credentials', async () => {
    const adapter = new InMemoryRouterAbEd25519YaoRegistrationIntentAuthorizationAdapter();
    const body = admissionRequest({
      lifecycleId: 'registration-lifecycle-1',
      walletId: 'wallet-1',
      firstParticipantId: 1,
      secondParticipantId: 2,
    });
    const malformed = [
      requestWithoutAuthorization(),
      requestWithAuthorization(`bearer ${GRANT}`),
      requestWithAuthorization(`Bearer  ${GRANT}`),
      requestWithAuthorization(`Bearer ${GRANT}, Bearer ${OTHER_GRANT}`),
    ];

    for (const request of malformed) {
      await expect(
        adapter.authorize(admittedAuthorizationInput({ request, body })),
      ).resolves.toMatchObject({
        ok: false,
        status: 401,
      });
    }
    await expect(
      adapter.authorize(
        admittedAuthorizationInput({
          request: requestWithAuthorization(`Bearer ${OTHER_GRANT}`),
          body,
        }),
      ),
    ).resolves.toMatchObject({
      ok: false,
      status: 403,
      code: 'registration_intent_credential_rejected',
    });
  });

  test('authorizes only the exact admitted scope, application, and participants', async () => {
    const adapter = new InMemoryRouterAbEd25519YaoRegistrationIntentAuthorizationAdapter();
    const exact = admissionRequest({
      lifecycleId: 'registration-lifecycle-1',
      walletId: 'wallet-1',
      firstParticipantId: 1,
      secondParticipantId: 2,
    });
    const intent = registrationIntent({
      walletId: 'wallet-1',
      firstParticipantId: 1,
      secondParticipantId: 2,
    });
    await adapter.bindVerifiedIntent(
      authorizedIntent({ grant: GRANT, intent, admissionRequest: exact }),
    );
    const bearer = requestWithAuthorization(`Bearer ${GRANT}`);

    await expect(
      adapter.authorize(admittedAuthorizationInput({ request: bearer, body: exact })),
    ).resolves.toEqual({ ok: true });
    await expect(
      adapter.authorize(
        admittedAuthorizationInput({
          request: requestWithAuthorization(`Bearer ${GRANT}`),
          body: exact,
        }),
      ),
    ).resolves.toEqual({ ok: true });

    const substitutedScope = admissionRequest({
      lifecycleId: 'registration-lifecycle-substituted',
      walletId: 'wallet-1',
      firstParticipantId: 1,
      secondParticipantId: 2,
    });
    const substitutedApplication = admissionRequest({
      lifecycleId: 'registration-lifecycle-1',
      walletId: 'wallet-1',
      firstParticipantId: 1,
      secondParticipantId: 2,
    });
    substitutedApplication.application_binding.signing_root_id =
      'substituted-project:environment-1';
    const substitutedParticipants = admissionRequest({
      lifecycleId: 'registration-lifecycle-1',
      walletId: 'wallet-1',
      firstParticipantId: 1,
      secondParticipantId: 3,
    });
    for (const body of [substitutedScope, substitutedApplication, substitutedParticipants]) {
      await expect(
        adapter.authorize(
          admittedAuthorizationInput({
            request: requestWithAuthorization(`Bearer ${GRANT}`),
            body,
          }),
        ),
      ).resolves.toMatchObject({
        ok: false,
        status: 403,
        code: 'registration_intent_subject_mismatch',
      });
    }
  });

  test('authorizes execution retries only for the admitted lifecycle and credential', async () => {
    const adapter = new InMemoryRouterAbEd25519YaoRegistrationIntentAuthorizationAdapter();
    const admission = admissionRequest({
      lifecycleId: 'registration-lifecycle-1',
      walletId: 'wallet-1',
      firstParticipantId: 1,
      secondParticipantId: 2,
    });
    const intent = registrationIntent({
      walletId: 'wallet-1',
      firstParticipantId: 1,
      secondParticipantId: 2,
    });
    await adapter.bindVerifiedIntent(
      authorizedIntent({ grant: GRANT, intent, admissionRequest: admission }),
    );
    const binding = await registrationBinding(admission);
    const execution = executeRequest(binding);

    await expect(
      adapter.authorize(
        executionAuthorizationInput({
          request: requestWithAuthorization(`Bearer ${GRANT}`),
          body: execution,
        }),
      ),
    ).resolves.toMatchObject({
      ok: false,
      code: 'registration_intent_admission_required',
    });
    await adapter.authorize(
      admittedAuthorizationInput({
        request: requestWithAuthorization(`Bearer ${GRANT}`),
        body: admission,
      }),
    );

    const exactExecution = executionAuthorizationInput({
      request: requestWithAuthorization(`Bearer ${GRANT}`),
      body: execution,
    });
    await expect(adapter.authorize(exactExecution)).resolves.toEqual({ ok: true });
    await expect(adapter.authorize(exactExecution)).resolves.toEqual({ ok: true });
    await expect(
      adapter.authorize(
        executionAuthorizationInput({
          request: requestWithAuthorization(`Bearer ${OTHER_GRANT}`),
          body: execution,
        }),
      ),
    ).resolves.toMatchObject({
      ok: false,
      code: 'registration_intent_subject_mismatch',
    });

    const substitutedLifecycle = await registrationBinding(
      admissionRequest({
        lifecycleId: 'registration-lifecycle-2',
        walletId: 'wallet-1',
        firstParticipantId: 1,
        secondParticipantId: 2,
      }),
    );
    await expect(
      adapter.authorize(
        executionAuthorizationInput({
          request: requestWithAuthorization(`Bearer ${GRANT}`),
          body: executeRequest(substitutedLifecycle),
        }),
      ),
    ).resolves.toMatchObject({
      ok: false,
      code: 'registration_intent_admission_required',
    });

    const substitutedContext: RouterAbEd25519YaoRegistrationBindingV1 = {
      lifecycle: binding.lifecycle,
      operation: 'registration',
      session_id: binding.session_id,
      stable_key_context_binding: bytes(29),
    };
    await expect(
      adapter.authorize(
        executionAuthorizationInput({
          request: requestWithAuthorization(`Bearer ${GRANT}`),
          body: executeRequest(substitutedContext),
        }),
      ),
    ).resolves.toMatchObject({
      ok: false,
      code: 'registration_intent_binding_mismatch',
    });
  });

  test('rejects credential and lifecycle rebinding', async () => {
    const adapter = new InMemoryRouterAbEd25519YaoRegistrationIntentAuthorizationAdapter();
    const intent = registrationIntent({
      walletId: 'wallet-1',
      firstParticipantId: 1,
      secondParticipantId: 2,
    });
    const first = admissionRequest({
      lifecycleId: 'registration-lifecycle-1',
      walletId: 'wallet-1',
      firstParticipantId: 1,
      secondParticipantId: 2,
    });
    const second = admissionRequest({
      lifecycleId: 'registration-lifecycle-2',
      walletId: 'wallet-1',
      firstParticipantId: 1,
      secondParticipantId: 2,
    });
    await adapter.bindVerifiedIntent(
      authorizedIntent({ grant: GRANT, intent, admissionRequest: first }),
    );

    await expect(
      adapter.bindVerifiedIntent(
        authorizedIntent({ grant: GRANT, intent, admissionRequest: second }),
      ),
    ).resolves.toMatchObject({ ok: false, code: 'registration_intent_conflict' });
    await expect(
      adapter.bindVerifiedIntent(
        authorizedIntent({ grant: OTHER_GRANT, intent, admissionRequest: first }),
      ),
    ).resolves.toMatchObject({ ok: false, code: 'registration_intent_conflict' });
  });
});
