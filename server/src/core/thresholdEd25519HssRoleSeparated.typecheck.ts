import type {
  ThresholdEd25519HssRoleSeparatedRespondForRegistrationRequest,
  ThresholdEd25519HssRoleSeparatedRespondResponse,
  ThresholdEd25519HssRoleSeparatedRespondWithSessionRequest,
  ThresholdEd25519HssServerVisibleClientRequestEnvelope,
  WalletRegistrationFinalizeRequest,
  WalletRegistrationHssRespondRequest,
} from './types';

const serverVisibleClientRequest = {
  clientRequestMessageB64u: 'client-request-message',
} satisfies ThresholdEd25519HssServerVisibleClientRequestEnvelope;
void serverVisibleClientRequest;

void ({
  clientRequestMessageB64u: 'client-request-message',
  // @ts-expect-error role-separated HSS server routes must not receive evaluator OT state
  evaluatorOtStateB64u: 'evaluator-ot-state',
} satisfies ThresholdEd25519HssServerVisibleClientRequestEnvelope);

void ({
  clientRequestMessageB64u: 'client-request-message',
  // @ts-expect-error role-separated HSS server routes must not receive client y input
  yClientB64u: 'client-y',
} satisfies ThresholdEd25519HssServerVisibleClientRequestEnvelope);

void ({
  clientRequestMessageB64u: 'client-request-message',
  // @ts-expect-error role-separated HSS server routes must not receive client tau input
  tauClientB64u: 'client-tau',
} satisfies ThresholdEd25519HssServerVisibleClientRequestEnvelope);

void ({
  clientRequestMessageB64u: 'client-request-message',
  // @ts-expect-error role-separated HSS server routes must not receive client output mask
  rClientB64u: 'client-mask',
} satisfies ThresholdEd25519HssServerVisibleClientRequestEnvelope);

void ({
  clientRequestMessageB64u: 'client-request-message',
  // @ts-expect-error role-separated HSS server routes must not receive client output mask
  clientOutputMaskB64u: 'client-output-mask',
} satisfies ThresholdEd25519HssServerVisibleClientRequestEnvelope);

void ({
  clientRequestMessageB64u: 'client-request-message',
  // @ts-expect-error role-separated HSS server routes must not receive PRF material
  prfFirstB64u: 'prf-first',
} satisfies ThresholdEd25519HssServerVisibleClientRequestEnvelope);

void ({
  clientRequestMessageB64u: 'client-request-message',
  // @ts-expect-error role-separated HSS server routes must not receive recovered client secret material
  clientSecret32B64u: 'client-secret',
} satisfies ThresholdEd25519HssServerVisibleClientRequestEnvelope);

void ({
  ceremonyHandle: 'ceremony',
  clientRequest: serverVisibleClientRequest,
} satisfies ThresholdEd25519HssRoleSeparatedRespondWithSessionRequest);

void ({
  ceremonyHandle: 'ceremony',
  clientRequest: {
    clientRequestMessageB64u: 'client-request-message',
    // @ts-expect-error role-separated session respond rejects client-retained evaluator state
    evaluatorOtStateB64u: 'evaluator-ot-state',
  },
} satisfies ThresholdEd25519HssRoleSeparatedRespondWithSessionRequest);

void ({
  new_account_id: 'alice.near',
  rp_id: 'wallet.example.test',
  ceremonyHandle: 'ceremony',
  clientRequest: serverVisibleClientRequest,
} satisfies ThresholdEd25519HssRoleSeparatedRespondForRegistrationRequest);

void ({
  new_account_id: 'alice.near',
  rp_id: 'wallet.example.test',
  ceremonyHandle: 'ceremony',
  clientRequest: {
    clientRequestMessageB64u: 'client-request-message',
    // @ts-expect-error role-separated registration respond rejects client-retained evaluator state
    evaluatorOtStateB64u: 'evaluator-ot-state',
  },
} satisfies ThresholdEd25519HssRoleSeparatedRespondForRegistrationRequest);

const roleSeparatedRespondResponse = {
  ok: true,
  contextBindingB64u: 'context-binding',
  serverStageResponses: {
    serverAssistInitMessageB64u: 'server-assist-init',
    addStageResponseMessageB64u: 'add-stage-response',
    messageScheduleResponseMessagesB64u: ['message-schedule-response'],
    roundCoreResponseMessagesB64u: ['round-core-response'],
    outputProjectionResponseMessageB64u: 'output-projection-response',
  },
  outputDelivery: {
    clientOutputDeliveryMessageB64u: 'client-output-delivery',
    outputCommitmentB64u: 'output-commitment',
    clientMaskCommitmentB64u: 'client-mask-commitment',
  },
} satisfies ThresholdEd25519HssRoleSeparatedRespondResponse;
void roleSeparatedRespondResponse;

void ({
  ok: true,
  contextBindingB64u: 'context-binding',
  serverStageResponses: {
    serverAssistInitMessageB64u: 'server-assist-init',
    addStageResponseMessageB64u: 'add-stage-response',
    messageScheduleResponseMessagesB64u: [],
    roundCoreResponseMessagesB64u: [],
    outputProjectionResponseMessageB64u: 'output-projection-response',
    // @ts-expect-error role-separated server responses must not return evaluator state
    evaluatorDriverStateB64u: 'evaluator-driver-state',
  },
  outputDelivery: {
    clientOutputDeliveryMessageB64u: 'client-output-delivery',
    outputCommitmentB64u: 'output-commitment',
    clientMaskCommitmentB64u: 'client-mask-commitment',
  },
} satisfies ThresholdEd25519HssRoleSeparatedRespondResponse);

void ({
  ok: true,
  contextBindingB64u: 'context-binding',
  serverStageResponses: {
    serverAssistInitMessageB64u: 'server-assist-init',
    addStageResponseMessageB64u: 'add-stage-response',
    messageScheduleResponseMessagesB64u: [],
    roundCoreResponseMessagesB64u: [],
    outputProjectionResponseMessageB64u: 'output-projection-response',
  },
  outputDelivery: {
    clientOutputDeliveryMessageB64u: 'client-output-delivery',
    outputCommitmentB64u: 'output-commitment',
    clientMaskCommitmentB64u: 'client-mask-commitment',
    // @ts-expect-error role-separated output delivery must not return the raw client output
    xClientBaseB64u: 'client-output',
  },
} satisfies ThresholdEd25519HssRoleSeparatedRespondResponse);

void ({
  ok: true,
  contextBindingB64u: 'context-binding',
  serverStageResponses: {
    serverAssistInitMessageB64u: 'server-assist-init',
    addStageResponseMessageB64u: 'add-stage-response',
    messageScheduleResponseMessagesB64u: [],
    roundCoreResponseMessagesB64u: [],
    outputProjectionResponseMessageB64u: 'output-projection-response',
  },
  outputDelivery: {
    clientOutputDeliveryMessageB64u: 'client-output-delivery',
    outputCommitmentB64u: 'output-commitment',
    clientMaskCommitmentB64u: 'client-mask-commitment',
  },
  // @ts-expect-error role-separated respond must not return client mask material
  rClientB64u: 'client-mask',
} satisfies ThresholdEd25519HssRoleSeparatedRespondResponse);

void ({
  registrationCeremonyId: 'wallet-registration-ceremony',
  ed25519: {
    clientRequest: serverVisibleClientRequest,
  },
} satisfies WalletRegistrationHssRespondRequest);

void ({
  registrationCeremonyId: 'wallet-registration-ceremony',
  ed25519: {
    clientRequest: {
      clientRequestMessageB64u: 'client-request-message',
      // @ts-expect-error wallet registration respond rejects client-retained evaluator state
      evaluatorOtStateB64u: 'evaluator-ot-state',
    },
  },
} satisfies WalletRegistrationHssRespondRequest);

void ({
  registrationCeremonyId: 'wallet-registration-ceremony',
  ed25519: {
    clientRequest: {
      clientRequestMessageB64u: 'client-request-message',
      // @ts-expect-error wallet registration respond rejects PRF material
      prfOutputB64u: 'prf-output',
    },
  },
} satisfies WalletRegistrationHssRespondRequest);

void ({
  registrationCeremonyId: 'wallet-registration-ceremony',
  ed25519: {
    clientRequest: {
      clientRequestMessageB64u: 'client-request-message',
      // @ts-expect-error wallet registration respond rejects client output masks
      clientOutputMaskB64u: 'client-output-mask',
    },
  },
} satisfies WalletRegistrationHssRespondRequest);

void ({
  registrationCeremonyId: 'wallet-registration-ceremony',
  ed25519: {
    evaluationResult: {
      contextBindingB64u: 'context-binding',
      stagedEvaluatorArtifactB64u: 'staged-artifact',
    },
  },
} satisfies WalletRegistrationFinalizeRequest);

void ({
  registrationCeremonyId: 'wallet-registration-ceremony',
  ed25519: {
    evaluationResult: {
      contextBindingB64u: 'context-binding',
      stagedEvaluatorArtifactB64u: 'staged-artifact',
      // @ts-expect-error wallet registration finalize rejects raw opened client output
      xClientBaseB64u: 'client-output',
    },
  },
} satisfies WalletRegistrationFinalizeRequest);

void ({
  registrationCeremonyId: 'wallet-registration-ceremony',
  ed25519: {
    evaluationResult: {
      contextBindingB64u: 'context-binding',
      stagedEvaluatorArtifactB64u: 'staged-artifact',
      // @ts-expect-error wallet registration finalize rejects seed output
      seedOutputMessageB64u: 'seed-output',
    },
  },
} satisfies WalletRegistrationFinalizeRequest);

export {};
