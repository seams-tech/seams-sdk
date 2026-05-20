import {
  thresholdEcdsaHssFinalize,
  thresholdEcdsaHssPrepare,
  thresholdEcdsaHssRespond,
} from '@/core/rpcClients/relayer/thresholdEcdsa';
import {
  finalizeThresholdEcdsaHssClientRequestWasm,
  prepareThresholdEcdsaHssClientRequestWasm,
  prepareThresholdEcdsaHssSessionWasm,
} from '../../threshold/crypto/hssClientSignerWasm';
import {
  createThresholdEcdsaHssHiddenEvalFinalizeMessage,
  encodeThresholdEcdsaHssHiddenEvalRequestMessage,
  parseThresholdEcdsaHssHiddenEvalServerResponseMessage,
} from '../../threshold/ecdsa/hssTransport';
import {
  walletSubjectIdFromWalletProfile,
  type ThresholdEcdsaChainTarget,
} from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import type { WorkerOperationContext } from '../../workerManager/executeWorkerOperation';
import { toWalletSessionUserId } from '../../session/identity/emailOtpHssIdentity';
import type { ReadyEcdsaSignerSession } from '../../session/identity/evmFamilyEcdsaIdentity';

export type EcdsaHssExplicitExportDeps = {
  getSignerWorkerContext: () => WorkerOperationContext;
};

export async function exportEcdsaHssKeyWithThresholdSession(
  deps: EcdsaHssExplicitExportDeps,
  args: {
    walletSessionUserId: string;
    chainTarget: ThresholdEcdsaChainTarget;
    rpId: string;
    signerSession: ReadyEcdsaSignerSession;
    clientRootShare32B64u: string;
  },
): Promise<{
  publicKeyHex: string;
  privateKeyHex: string;
  ethereumAddress: string;
}> {
  const currentThresholdSessionId = String(
    args.signerSession.session.thresholdSessionId || '',
  ).trim();
  const signerTransport = args.signerSession.transport;
  const signerTransportAuth = signerTransport.auth;
  const currentThresholdSessionAuthToken =
    signerTransportAuth.kind === 'jwt_threshold_session_auth'
      ? String(signerTransportAuth.thresholdSessionAuthToken || '').trim()
      : '';
  const currentRelayerUrl = String(signerTransport.relayerUrl || '').trim();
  const currentKeyHandle = String(args.signerSession.publicFacts.keyHandle || '').trim();
  const walletSessionUserId = toWalletSessionUserId(args.walletSessionUserId);
  const subjectId = walletSubjectIdFromWalletProfile({
    walletId: args.walletSessionUserId,
  });
  const sessionKind =
    signerTransportAuth.kind === 'cookie_threshold_session_auth' ? 'cookie' : 'jwt';
  if (
    !currentThresholdSessionId ||
    !currentThresholdSessionAuthToken ||
    !currentRelayerUrl ||
    !currentKeyHandle
  ) {
    throw new Error(
      '[SigningEngine][ecdsa-export] ready export signer session is missing canonical transport',
    );
  }

  const signerWorkerCtx = deps.getSignerWorkerContext();
  const prepare = await thresholdEcdsaHssPrepare(currentRelayerUrl, {
    walletSessionUserId,
    subjectId,
    rpId: args.rpId,
    chainTarget: args.chainTarget,
    operation: 'explicit_key_export',
    keySelector: {
      kind: 'key_handle',
      keyHandle: currentKeyHandle,
    },
    auth: { kind: 'threshold_session', jwt: currentThresholdSessionAuthToken },
    sessionKind,
  });
  if (!prepare.ok) {
    throw new Error(prepare.error || prepare.message || 'Threshold explicit export prepare failed');
  }
  const ceremonyId = String(prepare.ceremonyId || '').trim();
  const preparedServerSessionB64u = String(prepare.preparedServerSessionB64u || '').trim();
  const serverAssistInitB64u = String(prepare.serverAssistInitB64u || '').trim();
  if (!ceremonyId || !preparedServerSessionB64u || !serverAssistInitB64u || !prepare.hssContext) {
    throw new Error(
      'Threshold explicit export prepare response missing staged transport inputs or HSS context',
    );
  }

  const preparedClientSession = await prepareThresholdEcdsaHssSessionWasm({
    context: prepare.hssContext,
    clientRootShare32B64u: args.clientRootShare32B64u,
    workerCtx: signerWorkerCtx,
  });
  const evaluatorDriverStateB64u = String(
    preparedClientSession.evaluatorDriverStateB64u || '',
  ).trim();
  if (!evaluatorDriverStateB64u) {
    throw new Error(
      'Threshold explicit export client session preparation returned incomplete staged transport data',
    );
  }

  const clientRequest = await prepareThresholdEcdsaHssClientRequestWasm({
    evaluatorDriverStateB64u,
    serverAssistInitMessageB64u: serverAssistInitB64u,
    clientRootShare32B64u: args.clientRootShare32B64u,
    workerCtx: signerWorkerCtx,
  });
  const clientEvalRequestB64u = String(clientRequest.clientEvalRequestB64u || '').trim();
  if (!clientEvalRequestB64u) {
    throw new Error(
      'Threshold explicit export client request preparation returned incomplete staged transport data',
    );
  }

  const requestMessageB64u = encodeThresholdEcdsaHssHiddenEvalRequestMessage({
    ceremonyId,
    preparedServerSessionB64u,
    serverAssistInitB64u,
    clientEvalRequestB64u,
  });

  const respond = await thresholdEcdsaHssRespond(currentRelayerUrl, {
    ceremonyId,
    requestMessageB64u,
    auth: { kind: 'threshold_session', jwt: currentThresholdSessionAuthToken },
    sessionKind,
  });
  if (!respond.ok) {
    throw new Error(respond.error || respond.message || 'Threshold explicit export respond failed');
  }
  const responseMessageB64u = String(respond.responseMessageB64u || '').trim();
  if (!responseMessageB64u) {
    throw new Error('Threshold explicit export respond response missing responseMessageB64u');
  }
  const responseEnvelope =
    parseThresholdEcdsaHssHiddenEvalServerResponseMessage(responseMessageB64u);
  if (!responseEnvelope) {
    throw new Error(
      'Threshold explicit export respond response did not contain a valid hidden-eval staged payload',
    );
  }
  const serverEvalResponseB64u = String(responseEnvelope.serverEvalResponseB64u || '').trim();
  if (!serverEvalResponseB64u) {
    throw new Error(
      'Threshold explicit export respond response missing hidden-eval serverEvalResponseB64u',
    );
  }

  const clientFinalize = await finalizeThresholdEcdsaHssClientRequestWasm({
    evaluatorDriverStateB64u,
    serverEvalResponseB64u,
    workerCtx: signerWorkerCtx,
  });
  const clientEvalFinalizeB64u = String(clientFinalize.clientEvalFinalizeB64u || '').trim();
  if (!clientEvalFinalizeB64u) {
    throw new Error(
      'Threshold explicit export client finalize preparation returned incomplete staged transport data',
    );
  }

  const clientFinalizeMessageB64u = await createThresholdEcdsaHssHiddenEvalFinalizeMessage({
    ceremonyId,
    requestMessageB64u,
    responseMessageB64u,
    clientEvalFinalizeB64u,
  });

  const finalized = await thresholdEcdsaHssFinalize(currentRelayerUrl, {
    ceremonyId,
    clientFinalizeMessageB64u,
    auth: { kind: 'threshold_session', jwt: currentThresholdSessionAuthToken },
    sessionKind,
  });
  if (!finalized.ok) {
    throw new Error(finalized.error || finalized.message || 'Threshold explicit export finalize failed');
  }
  const publicKeyHex = String(finalized.canonicalPublicKeyHex || '').trim();
  const privateKeyHex = String(finalized.privateKeyHex || '').trim();
  const ethereumAddress = String(finalized.canonicalEthereumAddress || '').trim();
  if (!publicKeyHex || !privateKeyHex || !ethereumAddress) {
    throw new Error('Threshold explicit export finalize returned incomplete export material');
  }
  return { publicKeyHex, privateKeyHex, ethereumAddress };
}
