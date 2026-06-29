import type { Page } from '@playwright/test';
import { readFileSync } from 'node:fs';
import {
  createInMemoryConsoleApiKeyService,
  createInMemoryConsoleBootstrapTokenService,
  createInMemoryConsoleOrgProjectEnvService,
  createInMemoryRouterAbNormalSigningAdmissionStore,
  createRouterApiBootstrapGrantBroker,
  createRouterApiPublishableKeyAuthAdapter,
  createRouterApiRouter,
  createRouterAbNormalSigningAdmissionAdapter,
} from '@server/router/express-adaptor';
import { deriveThresholdEd25519RegistrationMaterialFromHssFinalize } from '@server/core/ThresholdService/ed25519HssWasm';
import {
  createSigningSessionSealPolicyFromWalletSessionStores,
  createSigningSessionSealRoutesOptions,
  createSigningSessionSealShamir3PassCipherAdapter,
} from '@server/threshold/session/signingSessionSeal';
import { walletSigningBudgetSessionId } from '@server/core/ThresholdService/walletSigningBudget';
import type { SessionAdapter } from '@server/router/routerApi';
import {
  computeEcdsaHssRoleLocalRelayerKeyId,
  computeEcdsaHssRoleLocalThresholdKeyId,
} from '@shared/threshold/ecdsaHssRoleLocalBootstrap';
import { signingRootScopeFromRuntimePolicyScope } from '@shared/threshold/signingRootScope';
import {
  parseRouterAbPublicKeysetV2,
  ROUTER_AB_PUBLIC_KEYSET_VERSION_V2,
} from '@shared/utils/routerAbPublicKeyset';
import {
  ROUTER_AB_ECDSA_HSS_WALLET_SESSION_JWT_KIND,
  ROUTER_AB_ED25519_WALLET_SESSION_JWT_KIND,
} from '@shared/utils/sessionTokens';
import { initSync as initHssClientSignerWasmSync } from '../../wasm/hss_client_signer/pkg/hss_client_signer.js';
import { preparePasskeyPrfEcdsaClientBootstrapForTest } from './thresholdEcdsaClientBootstrap';
import { startExpressRouter } from '../relayer/helpers';
import { DEFAULT_TEST_CONFIG } from '../setup/config';
import {
  corsHeadersForRoute,
  createInMemoryJwtSessionAdapter,
  installFastNearRpcMock,
  makeAuthServiceForThreshold,
  setupThresholdE2ePage,
  setupRouterAbEcdsaHssPrivateSigningWorker,
  TEST_ROUTER_AB_INTERNAL_SERVICE_AUTH_SECRET,
} from '../e2e/thresholdEd25519.testUtils';
import { autoConfirmWalletIframeUntil } from '../setup/flows';
import { installRouterApiProxyShim } from '../setup/cross-origin-headers';

export const TEST_KEY_VERSION = 'signing-session-seal-kek-test-r1';
export const TEST_SHAMIR_PRIME_B64U = '_____________________________________v___C8';
const TEST_SERVER_ENCRYPT_EXPONENT_B64U = 'AQAB';
const TEST_SERVER_DECRYPT_EXPONENT_B64U = '6LQXS-i0F0votBdL6LQXS-i0F0votBdL6LQXSv___Ic';
export const TEST_WEBAUTHN_GET_COUNTER_KEY = '__w3a_test_webauthn_get_calls';
const TEST_SESSION_COOKIE_NAME =
  String(process.env.SESSION_COOKIE_NAME || 'seams-jwt').trim() || 'seams-jwt';
const TEST_ROUTER_AB_PUBLIC_KEYSET = parseRouterAbPublicKeysetV2({
  keyset_version: ROUTER_AB_PUBLIC_KEYSET_VERSION_V2,
  signer_envelope_hpke: {
    current: {
      deriver_a: {
        role: 'signer_a',
        key_epoch: 'epoch-a',
        public_key: 'x25519:1111111111111111111111111111111111111111111111111111111111111111',
      },
      deriver_b: {
        role: 'signer_b',
        key_epoch: 'epoch-b',
        public_key: 'x25519:2222222222222222222222222222222222222222222222222222222222222222',
      },
    },
  },
  signer_peer_verifying_keys: {
    deriver_a: {
      role: 'signer_a',
      verifying_key_hex: '5afa80b305e72e02615ed1f580144a40a42a71dfcac175809ceb5d79e740d015',
    },
    deriver_b: {
      role: 'signer_b',
      verifying_key_hex: '0c700dd63695221e508f3164b528f190bed63a4437d38e882308f9a57acc1bc3',
    },
  },
  signing_worker_server_output_hpke: {
    key_epoch: 'epoch-server',
    public_key: 'x25519:3333333333333333333333333333333333333333333333333333333333333333',
  },
});
const HSS_CLIENT_SIGNER_WASM_URL = new URL(
  '../../wasm/hss_client_signer/pkg/hss_client_signer_bg.wasm',
  import.meta.url,
);
let hssClientSignerWasmInitialized = false;

function hexAddress20ToB64u(address: string): string {
  const normalized = address.trim().toLowerCase().replace(/^0x/, '');
  return Buffer.from(normalized, 'hex').toString('base64url');
}

function ensureHssClientSignerWasm(): void {
  if (hssClientSignerWasmInitialized) return;
  initHssClientSignerWasmSync({ module: readFileSync(HSS_CLIENT_SIGNER_WASM_URL) });
  hssClientSignerWasmInitialized = true;
}

export type SealedRefreshHarness = {
  baseUrl: string;
  relayerUrl: string;
  managedRegistration: {
    environmentId: string;
    publishableKey: string;
  };
  signingSessionSealRouteCounts: {
    applyServerSealCalls: number;
    removeServerSealCalls: number;
  };
  attachPage: (page: Page) => Promise<void>;
  close: () => Promise<void>;
};

function createThresholdAwareSealedRefreshSessionAdapter(): ReturnType<
  typeof createInMemoryJwtSessionAdapter
> {
  const base = createInMemoryJwtSessionAdapter();
  const readBearerToken = (headers: Record<string, string | string[] | undefined>): string => {
    const raw = headers.authorization ?? headers.Authorization;
    const header = Array.isArray(raw) ? raw[0] : raw;
    return typeof header === 'string' ? header.replace(/^Bearer\s+/i, '').trim() : '';
  };
  const decodeUnsignedJwtClaims = (token: string): Record<string, unknown> | null => {
    const payload = String(token || '').split('.')[1];
    if (!payload) return null;
    try {
      const decoded = JSON.parse(Buffer.from(payload, 'base64url').toString('utf8'));
      return decoded && typeof decoded === 'object' && !Array.isArray(decoded) ? decoded : null;
    } catch {
      return null;
    }
  };
  return {
    ...base,
    buildSetCookie: (token: string) =>
      `${TEST_SESSION_COOKIE_NAME}=${token}; Path=/; HttpOnly; Secure; SameSite=None`,
    parse: async (headers) => {
      const parsed = await base.parse(headers);
      if (parsed.ok) return parsed;
      const claims = decodeUnsignedJwtClaims(readBearerToken(headers));
      const kind = String(claims?.kind || '').trim();
      if (
        kind === ROUTER_AB_ED25519_WALLET_SESSION_JWT_KIND ||
        kind === ROUTER_AB_ECDSA_HSS_WALLET_SESSION_JWT_KIND
      ) {
        return { ok: true as const, claims: claims as Record<string, unknown> };
      }
      return parsed;
    },
  };
}

async function installThresholdRegistrationBootstrapMock(
  page: Page,
  input: {
    relayerBaseUrl: string;
    threshold: unknown;
    session: SessionAdapter;
    runtimePolicyScope: {
      orgId: string;
      projectId: string;
      envId: string;
      signingRootVersion: string;
    };
    onNewPublicKey: (publicKey: string) => void;
    onNewAccountId?: (accountId: string) => void;
  },
): Promise<void> {
  const threshold = input.threshold as {
    ecdsaHssRoleLocalBootstrap?: (request: Record<string, unknown>) => Promise<{
      ok: boolean;
      code?: string;
      message?: string;
      value?: Record<string, unknown>;
    }>;
    walletSessionStore?: {
      putSession: (
        id: string,
        record: {
          expiresAtMs: number;
          relayerKeyId: string;
          userId: string;
          rpId: string;
          participantIds: number[];
          walletBudgetBinding?: {
            curve: 'ed25519' | 'ecdsa';
            thresholdSessionId: string;
          };
        },
        opts: { ttlMs: number; remainingUses: number },
      ) => Promise<void>;
    };
  };
  if (typeof threshold.ecdsaHssRoleLocalBootstrap !== 'function') {
    throw new Error('Missing threshold-ecdsa role-local bootstrap hook');
  }

  const positiveInt = (value: unknown, fallback: number): number => {
    const n = Number(value);
    return Number.isFinite(n) && n > 0 ? Math.floor(n) : fallback;
  };
  const asParticipantIds = (value: unknown, fallback: number[]): number[] => {
    if (!Array.isArray(value)) return [...fallback];
    const normalized = value
      .map((id) => Number(id))
      .filter((id) => Number.isFinite(id) && id > 0)
      .map((id) => Math.floor(id));
    return normalized.length >= 2 ? normalized : [...fallback];
  };

  await page.route(`${input.relayerBaseUrl}/registration/bootstrap`, async (route) => {
    const req = route.request();
    const method = req.method().toUpperCase();
    if (method === 'OPTIONS') {
      await route.fallback();
      return;
    }

    const corsHeaders = corsHeadersForRoute(route);
    try {
      const payload = JSON.parse(req.postData() || '{}');
      const accountId = String(payload?.new_account_id || '').trim();
      const rpId = String(payload?.rp_id || '').trim() || 'example.localhost';
      const nowMs = Date.now();

      if (accountId) input.onNewAccountId?.(accountId);

      const resolveRuntimePolicyScope = (
        policy: Record<string, unknown>,
      ): typeof input.runtimePolicyScope => {
        const scope =
          policy.runtimePolicyScope && typeof policy.runtimePolicyScope === 'object'
            ? (policy.runtimePolicyScope as Partial<typeof input.runtimePolicyScope>)
            : {};
        const orgId = String(scope.orgId || input.runtimePolicyScope.orgId || '').trim();
        const projectId = String(
          scope.projectId || input.runtimePolicyScope.projectId || '',
        ).trim();
        const envId = String(scope.envId || input.runtimePolicyScope.envId || '').trim();
        const signingRootVersion = String(
          scope.signingRootVersion || input.runtimePolicyScope.signingRootVersion || 'default',
        ).trim();
        return { orgId, projectId, envId, signingRootVersion };
      };

      const signWalletSessionJwt = async (args: {
        kind:
          | typeof ROUTER_AB_ED25519_WALLET_SESSION_JWT_KIND
          | typeof ROUTER_AB_ECDSA_HSS_WALLET_SESSION_JWT_KIND;
        thresholdSessionId: string;
        signingGrantId: string;
        relayerKeyId: string;
        participantIds: number[];
        expiresAtMs: number;
        runtimePolicyScope: typeof input.runtimePolicyScope;
        keyHandle?: string;
        extraClaims?: Record<string, unknown>;
      }): Promise<string> => {
        const nowSec = Math.floor(nowMs / 1000);
        const expSec = Math.floor(args.expiresAtMs / 1000);
        return await input.session.signJwt(accountId, {
          kind: args.kind,
          walletId: accountId,
          thresholdSessionId: args.thresholdSessionId,
          signingGrantId: args.signingGrantId,
          relayerKeyId: args.relayerKeyId,
          rpId,
          participantIds: args.participantIds,
          thresholdExpiresAtMs: args.expiresAtMs,
          runtimePolicyScope: args.runtimePolicyScope,
          ...(args.extraClaims || {}),
          ...(args.keyHandle ? { keyHandle: args.keyHandle } : {}),
          iat: nowSec,
          exp: expSec,
        });
      };

      const thresholdEd = payload?.threshold_ed25519 || null;
      const thresholdEdPublicKey = String(thresholdEd?.public_key || '').trim();
      const thresholdEdKeyVersion = String(thresholdEd?.key_version || '').trim();
      // The finalized threshold Ed25519 record is keyed by the derived public key.
      // Keep the mocked registration/bootstrap response on that same seam.
      const thresholdEdRelayerKeyId = thresholdEdPublicKey;
      const thresholdEdRecoveryExportCapable = thresholdEd?.recovery_export_capable === true;
      let thresholdEdResponse: Record<string, unknown> | undefined;
      if (thresholdEdPublicKey && thresholdEdKeyVersion && thresholdEdRecoveryExportCapable) {
        if (thresholdEdPublicKey) input.onNewPublicKey(thresholdEdPublicKey);

        const policy = thresholdEd?.session_policy || {};
        const sessionId = String(policy?.sessionId || policy?.session_id || `ed-session-${nowMs}`);
        const signingGrantId = String(
          policy?.signingGrantId || policy?.signing_grant_id || sessionId,
        ).trim();
        const ttlMs = positiveInt(policy?.ttlMs || policy?.ttl_ms, 60_000);
        const remainingUses = positiveInt(policy?.remainingUses || policy?.remaining_uses, 10_000);
        const expiresAtMs = nowMs + ttlMs;
        const participantIds = asParticipantIds(policy?.participantIds, [1, 2]);
        const runtimePolicyScope = resolveRuntimePolicyScope(policy);
        const jwt = await signWalletSessionJwt({
          kind: ROUTER_AB_ED25519_WALLET_SESSION_JWT_KIND,
          thresholdSessionId: sessionId,
          signingGrantId,
          relayerKeyId: thresholdEdRelayerKeyId,
          participantIds,
          expiresAtMs,
          runtimePolicyScope,
          extraClaims: {
            routerAbNormalSigning: {
              kind: 'router_ab_ed25519_normal_signing_v1',
              signingWorkerId: 'signing-worker-sealed-refresh',
            },
          },
        });
        if (threshold.walletSessionStore) {
          const sessionRecord = {
            expiresAtMs,
            relayerKeyId: thresholdEdRelayerKeyId,
            userId: accountId,
            rpId,
            participantIds,
          };
          await threshold.walletSessionStore.putSession(sessionId, sessionRecord, {
            ttlMs,
            remainingUses,
          });
          await threshold.walletSessionStore.putSession(
            walletSigningBudgetSessionId({ curve: 'ed25519', signingGrantId }),
            {
              ...sessionRecord,
              walletBudgetBinding: {
                curve: 'ed25519',
                thresholdSessionId: sessionId,
              },
            },
            {
              ttlMs,
              remainingUses,
            },
          );
        }
        thresholdEdResponse = {
          keyVersion: thresholdEdKeyVersion,
          recoveryExportCapable: true,
          publicKey: thresholdEdPublicKey,
          relayerKeyId: thresholdEdRelayerKeyId,
          clientParticipantId: 1,
          relayerParticipantId: 2,
          participantIds,
          session: {
            sessionKind: 'jwt',
            sessionId,
            signingGrantId,
            expiresAtMs,
            participantIds,
            remainingUses,
            runtimePolicyScope,
            jwt,
          },
        };
      }

      const thresholdEcdsa = payload?.threshold_ecdsa || null;
      const thresholdEcdsaPasskeyPrfFirstB64u = String(
        thresholdEcdsa?.client_root_share32_b64u || '',
      ).trim();
      let thresholdEcdsaResponse: Record<string, unknown> | undefined;
      if (thresholdEcdsaPasskeyPrfFirstB64u) {
        const policy = thresholdEcdsa?.session_policy || {};
        const sessionId = String(
          policy?.sessionId || policy?.session_id || `ecdsa-session-${nowMs}`,
        );
        const signingGrantId = String(
          policy?.signingGrantId || policy?.signing_grant_id || sessionId,
        ).trim();
        const ttlMs = positiveInt(policy?.ttlMs || policy?.ttl_ms, 60_000);
        const remainingUses = positiveInt(policy?.remainingUses || policy?.remaining_uses, 10_000);
        const participantIds = asParticipantIds(policy?.participantIds, [1, 2]);
        const runtimePolicyScope = resolveRuntimePolicyScope(policy);
        const signingRootScope = signingRootScopeFromRuntimePolicyScope(runtimePolicyScope);
        const signingRootVersion = String(signingRootScope.signingRootVersion || '').trim();
        const walletKeyId = String(
          thresholdEcdsa?.walletKeyId || thresholdEcdsa?.wallet_key_id || `wallet-key-${accountId}`,
        ).trim();
        const ecdsaThresholdKeyId = await computeEcdsaHssRoleLocalThresholdKeyId({
          walletId: accountId,
          walletKeyId,
          signingRootId: signingRootScope.signingRootId,
          signingRootVersion,
        });
        const relayerKeyId = await computeEcdsaHssRoleLocalRelayerKeyId({
          walletId: accountId,
          walletKeyId,
        });
        ensureHssClientSignerWasm();
        const clientBootstrap = preparePasskeyPrfEcdsaClientBootstrapForTest({
          context: {
            walletId: accountId,
            rpId,
            ecdsaThresholdKeyId,
            signingRootId: signingRootScope.signingRootId,
            signingRootVersion,
          },
          passkeyPrfFirstB64u: thresholdEcdsaPasskeyPrfFirstB64u,
        });
        const bootstrapResult = await threshold.ecdsaHssRoleLocalBootstrap!({
          formatVersion: 'ecdsa-hss-role-local',
          walletId: accountId,
          walletKeyId,
          ecdsaThresholdKeyId,
          signingRootId: signingRootScope.signingRootId,
          signingRootVersion,
          keyScope: 'evm-family',
          relayerKeyId,
          hssClientSharePublicKey33B64u: clientBootstrap.hssClientSharePublicKey33B64u,
          clientShareRetryCounter: clientBootstrap.clientShareRetryCounter,
          contextBinding32B64u: clientBootstrap.contextBinding32B64u,
          requestId: `threshold-ecdsa-registration-${nowMs}`,
          sessionId,
          signingGrantId,
          ttlMs,
          remainingUses,
          participantIds,
        });
        if (!bootstrapResult.ok) {
          await route.fulfill({
            status: 400,
            headers: { 'Content-Type': 'application/json', ...corsHeaders },
            body: JSON.stringify({
              success: false,
              error: String(bootstrapResult.message || 'ecdsa bootstrap'),
            }),
          });
          return;
        }
        const bootstrap = bootstrapResult.value || {};
        const expiresAtMs = Number(bootstrap.expiresAtMs || nowMs + ttlMs);
        const bootstrapParticipantIds = Array.isArray(bootstrap.participantIds)
          ? (bootstrap.participantIds as number[])
          : participantIds;
        const bootstrapSessionId = String(bootstrap.sessionId || sessionId);
        const bootstrapRelayerKeyId = String(bootstrap.relayerKeyId || relayerKeyId);
        const jwt = await signWalletSessionJwt({
          kind: ROUTER_AB_ECDSA_HSS_WALLET_SESSION_JWT_KIND,
          thresholdSessionId: bootstrapSessionId,
          signingGrantId,
          relayerKeyId: bootstrapRelayerKeyId,
          participantIds: bootstrapParticipantIds,
          expiresAtMs,
          runtimePolicyScope,
          keyHandle: String(bootstrap.keyHandle || ''),
          extraClaims: {
            routerAbEcdsaHssNormalSigning: {
              kind: 'router_ab_ecdsa_hss_normal_signing_v1',
              scope: {
                wallet_key_id: rpId,
                context: {
                  wallet_id: accountId,
                  ecdsa_threshold_key_id: String(bootstrap.ecdsaThresholdKeyId || ''),
                  signing_root_id: String(bootstrap.signingRootId || ''),
                  signing_root_version: String(bootstrap.signingRootVersion || ''),
                },
                public_identity: {
                  context_binding_b64u: String(bootstrap.contextBinding32B64u || ''),
                  client_public_key33_b64u: clientBootstrap.hssClientSharePublicKey33B64u,
                  server_public_key33_b64u: String(
                    (bootstrap.publicIdentity as { relayerPublicKey33B64u?: unknown })
                      ?.relayerPublicKey33B64u || '',
                  ),
                  threshold_public_key33_b64u: String(
                    (bootstrap.publicIdentity as { groupPublicKey33B64u?: unknown })
                      ?.groupPublicKey33B64u || '',
                  ),
                  ethereum_address20_b64u: hexAddress20ToB64u(
                    String(bootstrap.ethereumAddress || ''),
                  ),
                  client_share_retry_counter: Number(clientBootstrap.clientShareRetryCounter || 0),
                  server_share_retry_counter: Number(
                    (bootstrap as { relayerShareRetryCounter?: unknown })
                      .relayerShareRetryCounter || 0,
                  ),
                },
                signing_worker: {
                  server_id: 'signing-worker-sealed-refresh',
                  key_epoch: 'signing-worker-output-epoch',
                  recipient_encryption_key: `x25519:${'33'.repeat(32)}`,
                },
                activation_epoch: bootstrapSessionId,
              },
            },
          },
        });

        thresholdEcdsaResponse = {
          walletId: accountId,
          rpId,
          keyHandle: String(bootstrap.keyHandle || ''),
          ecdsaThresholdKeyId: String(bootstrap.ecdsaThresholdKeyId || ''),
          relayerKeyId: bootstrapRelayerKeyId,
          contextBinding32B64u: String(bootstrap.contextBinding32B64u || ''),
          publicIdentity: bootstrap.publicIdentity,
          signingRootId: String(bootstrap.signingRootId || ''),
          signingRootVersion: String(bootstrap.signingRootVersion || ''),
          thresholdEcdsaPublicKeyB64u: String(bootstrap.thresholdEcdsaPublicKeyB64u || ''),
          ethereumAddress: String(bootstrap.ethereumAddress || ''),
          relayerVerifyingShareB64u: String(bootstrap.relayerVerifyingShareB64u || ''),
          participantIds: bootstrapParticipantIds,
          thresholdSessionId: bootstrapSessionId,
          signingGrantId,
          expiresAtMs,
          remainingUses: Number(bootstrap.remainingUses || remainingUses),
          jwt,
          session: {
            sessionKind: 'jwt',
            sessionId: bootstrapSessionId,
            thresholdSessionId: bootstrapSessionId,
            signingGrantId,
            expiresAtMs,
            participantIds: bootstrapParticipantIds,
            remainingUses: Number(bootstrap.remainingUses || remainingUses),
            runtimePolicyScope,
            jwt,
          },
        };
      }

      await route.fulfill({
        status: 200,
        headers: { 'Content-Type': 'application/json', ...corsHeaders },
        body: JSON.stringify({
          success: true,
          transactionHash: `mock_atomic_tx_${Date.now()}`,
          ...(thresholdEdResponse ? { thresholdEd25519: thresholdEdResponse } : {}),
          ...(thresholdEcdsaResponse ? { thresholdEcdsa: thresholdEcdsaResponse } : {}),
        }),
      });
    } catch (error) {
      await route.fulfill({
        status: 500,
        headers: { 'Content-Type': 'application/json', ...corsHeaders },
        body: JSON.stringify({
          success: false,
          error: error instanceof Error ? error.message : String(error),
        }),
      });
    }
  });
}

async function installThresholdRegistrationFinalizeRelayKeyMaterialCapture(
  page: Page,
  input: {
    relayerBaseUrl: string;
    relayUpstreamBaseUrl: string;
    threshold: unknown;
  },
): Promise<void> {
  await page.route(
    `${input.relayerBaseUrl}/registration/threshold-ed25519/hss/finalize`,
    async (route) => {
      const req = route.request();
      const method = req.method().toUpperCase();
      if (method === 'OPTIONS') {
        await route.fallback();
        return;
      }
      if (method !== 'POST') {
        await route.fallback();
        return;
      }

      const upstreamUrl = req.url().replace(input.relayerBaseUrl, input.relayUpstreamBaseUrl);
      const upstreamResponse = await fetch(upstreamUrl, {
        method,
        headers: req.headers(),
        body: req.postData(),
      });
      const upstreamText = await upstreamResponse.text();
      const payload = JSON.parse(req.postData() || '{}');
      const responseJson = JSON.parse(upstreamText || '{}');

      if (
        upstreamResponse.ok &&
        responseJson?.ok === true &&
        responseJson?.finalizedReport &&
        responseJson?.serverOutput
      ) {
        const preparedSession = payload?.preparedSession;
        const finalizedReport = responseJson.finalizedReport;
        if (Object.prototype.hasOwnProperty.call(responseJson, 'keyVersion')) {
          throw new Error('threshold Ed25519 HSS finalize response must not echo keyVersion');
        }
        const registrationMaterial =
          await deriveThresholdEd25519RegistrationMaterialFromHssFinalize({
            preparedSession,
            preparedServerSession: { preparedSessionHandle: '' },
            finalizedReport,
            serverOutput: responseJson.serverOutput,
          });
        const keyVersion = TEST_KEY_VERSION;
        const keyStore = (
          input.threshold as {
            keyStore?: {
              put: (
                relayerKeyId: string,
                record: {
                  walletId: string;
                  nearAccountId: string;
                  authorityScope: { kind: 'passkey_rp'; rpId: string };
                  publicKey: string;
                  relayerSigningShareB64u: string;
                  relayerVerifyingShareB64u: string;
                  keyVersion: string;
                  recoveryExportCapable: true;
                },
              ) => Promise<void>;
            };
          }
        ).keyStore;
        if (keyStore?.put) {
          await keyStore.put(registrationMaterial.relayerKeyId, {
            walletId: String(payload?.new_account_id || '').trim(),
            nearAccountId: String(payload?.new_account_id || '').trim(),
            authorityScope: {
              kind: 'passkey_rp',
              rpId: String(payload?.rp_id || '').trim(),
            },
            publicKey: registrationMaterial.publicKey,
            relayerSigningShareB64u: registrationMaterial.relayerSigningShareB64u,
            relayerVerifyingShareB64u: registrationMaterial.relayerVerifyingShareB64u,
            keyVersion,
            recoveryExportCapable: true,
          });
        }
      }

      await route.fulfill({
        status: upstreamResponse.status,
        headers: {
          ...corsHeadersForRoute(route),
          ...Object.fromEntries(upstreamResponse.headers.entries()),
        },
        body: upstreamText,
      });
    },
  );
}

export async function setupThresholdEcdsaSealedRefreshHarness(
  page: Page,
  options: { injectWalletServiceImportMap?: boolean } = {},
): Promise<SealedRefreshHarness> {
  const keysOnChain = new Set<string>();
  const nonceByPublicKey = new Map<string, number>();
  const accountsOnChain = new Set<string>(
    [DEFAULT_TEST_CONFIG.relayerAccount].filter((value): value is string => !!value),
  );
  const signingSessionSealRouteCounts = {
    applyServerSealCalls: 0,
    removeServerSealCalls: 0,
  };

  const signingWorker = await setupRouterAbEcdsaHssPrivateSigningWorker();
  const { service, threshold } = makeAuthServiceForThreshold(keysOnChain, {
    ROUTER_AB_SIGNING_WORKER_URL: signingWorker.baseUrl,
    ROUTER_AB_INTERNAL_SERVICE_AUTH_SECRET: TEST_ROUTER_AB_INTERNAL_SERVICE_AUTH_SECRET,
  });
  await service.getRelayerAccount();
  const bootstrapTokenStore = createInMemoryConsoleBootstrapTokenService();
  const orgProjectEnv = createInMemoryConsoleOrgProjectEnvService();
  const apiKeys = createInMemoryConsoleApiKeyService();
  const bootstrapAdminCtx = {
    orgId: 'org_threshold_sealed_refresh',
    actorUserId: 'user_threshold_sealed_refresh',
    roles: ['admin'],
  } as const;
  const bootstrapProjectId = 'proj_threshold_sealed_refresh';
  const bootstrapEnvId = 'dev';
  const runtimePolicyScope = {
    orgId: bootstrapAdminCtx.orgId,
    projectId: bootstrapProjectId,
    envId: bootstrapEnvId,
    signingRootVersion: 'default',
  } as const;
  const managedRegistrationEnvironmentId = `${bootstrapProjectId}:${bootstrapEnvId}`;
  await orgProjectEnv.upsertOrganization(bootstrapAdminCtx, {
    name: 'Threshold Sealed Refresh Org',
    slug: 'threshold-sealed-refresh-org',
  });
  await orgProjectEnv.createProject(bootstrapAdminCtx, {
    id: bootstrapProjectId,
    name: 'Threshold Sealed Refresh Project',
    liveEnvironmentsEnabled: true,
  });
  const frontendOrigin = new URL(DEFAULT_TEST_CONFIG.frontendUrl).origin;
  const createdPublishableKey = await apiKeys.createApiKey(bootstrapAdminCtx, {
    kind: 'publishable_key',
    name: 'threshold-sealed-refresh-browser',
    environmentId: managedRegistrationEnvironmentId,
    allowedOrigins: [
      frontendOrigin,
      'https://example.localhost',
      'https://wallet.example.localhost',
    ],
    rateLimitBucket: 'default_web_v1',
    quotaBucket: 'free_registrations_v1',
  });
  const managedRegistration = {
    environmentId: managedRegistrationEnvironmentId,
    publishableKey: createdPublishableKey.secret,
  } as const;

  const session = createThresholdAwareSealedRefreshSessionAdapter();
  const routerAbNormalSigningAdmission = createRouterAbNormalSigningAdmissionAdapter(
    createInMemoryRouterAbNormalSigningAdmissionStore(),
  );
  const relayerUrl = DEFAULT_TEST_CONFIG.relayer?.url ?? 'https://router-api.localhost';
  const thresholdWalletSessionStores = threshold as unknown as {
    walletSessionStore?: unknown;
    ecdsaWalletSessionStore?: unknown;
    walletBudgetSessionStore?: unknown;
  };
  if (
    !thresholdWalletSessionStores.walletSessionStore ||
    !thresholdWalletSessionStores.ecdsaWalletSessionStore ||
    !thresholdWalletSessionStores.walletBudgetSessionStore
  ) {
    throw new Error('Missing Wallet Session stores for signing-session seal policy');
  }

  const router = createRouterApiRouter(service, {
    corsOrigins: [frontendOrigin, 'https://example.localhost', 'https://wallet.example.localhost'],
    threshold,
    session,
    publishableKeyAuth: createRouterApiPublishableKeyAuthAdapter(apiKeys),
    orgProjectEnv,
    bootstrapGrantBroker: createRouterApiBootstrapGrantBroker({
      apiKeys,
      tokenStore: bootstrapTokenStore,
      orgProjectEnv,
      rateLimitsByBucket: {
        default_web_v1: { windowMs: 60_000, maxIssued: 100 },
      },
      quotasByBucket: {
        free_registrations_v1: { maxIssued: 100 },
      },
    }),
    bootstrapTokenStore,
    routerAbNormalSigningAdmission,
    signingSessionSeal: createSigningSessionSealRoutesOptions({
      sessionPolicy: createSigningSessionSealPolicyFromWalletSessionStores({
        ed25519Stores: [thresholdWalletSessionStores.walletSessionStore as any],
        ecdsaStores: [thresholdWalletSessionStores.ecdsaWalletSessionStore as any],
        walletBudgetStores: [thresholdWalletSessionStores.walletBudgetSessionStore as any],
      }),
      cipher: createSigningSessionSealShamir3PassCipherAdapter({
        currentKeyVersion: TEST_KEY_VERSION,
        keys: [
          {
            keyVersion: TEST_KEY_VERSION,
            shamirPrimeB64u: TEST_SHAMIR_PRIME_B64U,
            serverEncryptExponentB64u: TEST_SERVER_ENCRYPT_EXPONENT_B64U,
            serverDecryptExponentB64u: TEST_SERVER_DECRYPT_EXPONENT_B64U,
          },
        ],
      }),
      capabilities: {
        mode: 'sealed_refresh_v1',
        keyVersion: TEST_KEY_VERSION,
        shamirPrimeB64u: TEST_SHAMIR_PRIME_B64U,
      },
    }),
    routerAbPublicKeyset: TEST_ROUTER_AB_PUBLIC_KEYSET,
  });
  const server = await startExpressRouter(router);

  const attachPage = async (targetPage: Page): Promise<void> => {
    await targetPage.addInitScript((config) => {
      (window as any).__w3aManagedRegistration = config;
    }, managedRegistration);
    await setupThresholdE2ePage(targetPage, {
      injectWalletServiceImportMap: options.injectWalletServiceImportMap,
    });
    await targetPage.evaluate((config) => {
      (window as any).__w3aManagedRegistration = config;
    }, managedRegistration);
    await installRouterApiProxyShim(targetPage, {
      routerApiOrigin: relayerUrl,
      routerApiUpstream: server.baseUrl,
      logStyle: 'silent',
    });
    await installThresholdRegistrationFinalizeRelayKeyMaterialCapture(targetPage, {
      relayerBaseUrl: relayerUrl,
      relayUpstreamBaseUrl: server.baseUrl,
      threshold,
    });
    await targetPage.route(`${relayerUrl}/wallet-session/seal/**`, async (route) => {
      const url = route.request().url();
      if (url.endsWith('/apply-server-seal')) {
        signingSessionSealRouteCounts.applyServerSealCalls += 1;
      } else if (url.endsWith('/remove-server-seal')) {
        signingSessionSealRouteCounts.removeServerSealCalls += 1;
      }
      await route.fallback();
    });
    await installThresholdRegistrationBootstrapMock(targetPage, {
      relayerBaseUrl: relayerUrl,
      threshold,
      session,
      runtimePolicyScope,
      onNewPublicKey: (publicKey) => {
        keysOnChain.add(publicKey);
        nonceByPublicKey.set(publicKey, 0);
      },
      onNewAccountId: (accountId) => {
        accountsOnChain.add(accountId);
      },
    });
    await installFastNearRpcMock(targetPage, {
      keysOnChain,
      nonceByPublicKey,
      accountsOnChain,
    });
  };

  await attachPage(page);

  return {
    baseUrl: server.baseUrl,
    relayerUrl,
    managedRegistration,
    signingSessionSealRouteCounts,
    attachPage,
    close: async () => {
      const results = await Promise.allSettled([server.close(), signingWorker.close()]);
      const failed = results.find(
        (result): result is PromiseRejectedResult => result.status === 'rejected',
      );
      if (failed) throw failed.reason;
    },
  };
}

export async function readWebAuthnGetCallCount(page: Page): Promise<number> {
  const countsByFrame = await Promise.all(
    page.frames().map(async (frame) => {
      return await frame
        .evaluate((storageKey) => {
          const parseCount = (value: unknown): number => {
            const n = Number(value);
            return Number.isFinite(n) && n >= 0 ? Math.floor(n) : 0;
          };

          const globalCount = parseCount((window as any).__w3aTestWebAuthnGetCalls);
          let storedCount = 0;
          try {
            storedCount = parseCount(window.localStorage?.getItem?.(storageKey));
          } catch {}

          return {
            origin: String(window.location?.origin || 'unknown'),
            count: Math.max(globalCount, storedCount),
          };
        }, TEST_WEBAUTHN_GET_COUNTER_KEY)
        .catch(() => ({ origin: 'unknown', count: 0 }));
    }),
  );

  const maxByOrigin = new Map<string, number>();
  for (const entry of countsByFrame) {
    const origin = String(entry?.origin || 'unknown');
    const count = Number.isFinite(Number(entry?.count))
      ? Math.max(0, Math.floor(Number(entry?.count)))
      : 0;
    const previous = maxByOrigin.get(origin) ?? 0;
    if (count > previous) {
      maxByOrigin.set(origin, count);
    }
  }

  let total = 0;
  for (const count of maxByOrigin.values()) {
    total += count;
  }
  return total;
}

export async function readWalletIframeThresholdPersistence(page: Page): Promise<
  Array<{
    origin: string;
    localEd25519Index: string | null;
    localSealIndex: string | null;
    sessionEd25519Index: string | null;
    sessionSealIndex: string | null;
    sealedRecords: Array<{
      storeKey: string;
      walletId: string;
      authMethod: string;
      curve: string;
      thresholdSessionIds: Record<string, unknown>;
      chainTargetKey: string;
      hasEcdsaThresholdKeyId: boolean;
      remainingUses: number | null;
    }>;
  }>
> {
  return await Promise.all(
    page.frames().map(async (frame) => {
      return await frame
        .evaluate(async () => {
          const readSealedRecords = async (): Promise<
            Array<{
              storeKey: string;
              walletId: string;
              authMethod: string;
              curve: string;
              thresholdSessionIds: Record<string, unknown>;
              chainTargetKey: string;
              hasEcdsaThresholdKeyId: boolean;
              remainingUses: number | null;
            }>
          > => {
            try {
              const request = indexedDB.open('seams_wallet');
              const db = await new Promise<IDBDatabase>((resolve, reject) => {
                request.onerror = () => reject(request.error);
                request.onsuccess = () => resolve(request.result);
              });
              try {
                if (!db.objectStoreNames.contains('signing_session_seals')) return [];
                const tx = db.transaction('signing_session_seals', 'readonly');
                const store = tx.objectStore('signing_session_seals');
                const getAll = store.getAll();
                const rows = await new Promise<unknown[]>((resolve, reject) => {
                  getAll.onerror = () => reject(getAll.error);
                  getAll.onsuccess = () =>
                    resolve(Array.isArray(getAll.result) ? getAll.result : []);
                });
                return rows
                  .filter((row): row is Record<string, unknown> => {
                    return !!row && typeof row === 'object' && !Array.isArray(row);
                  })
                  .map((row) => {
                    const ecdsaRestore =
                      row.ecdsaRestore && typeof row.ecdsaRestore === 'object'
                        ? (row.ecdsaRestore as Record<string, unknown>)
                        : null;
                    const chainTarget =
                      ecdsaRestore?.chainTarget && typeof ecdsaRestore.chainTarget === 'object'
                        ? (ecdsaRestore.chainTarget as Record<string, unknown>)
                        : null;
                    const kind = String(chainTarget?.kind || '').trim();
                    const chainId = Number(chainTarget?.chainId);
                    const chainTargetKey =
                      kind === 'tempo'
                        ? `tempo:${chainId}`
                        : kind === 'evm'
                          ? `evm:eip155:${chainId}`
                          : '';
                    const thresholdSessionIds =
                      row.thresholdSessionIds && typeof row.thresholdSessionIds === 'object'
                        ? (row.thresholdSessionIds as Record<string, unknown>)
                        : {};
                    const remainingUses = Number(row.remainingUses);
                    return {
                      storeKey: String(row.storeKey || ''),
                      walletId: String(row.walletId || ''),
                      authMethod: String(row.authMethod || ''),
                      curve: String(row.curve || ''),
                      thresholdSessionIds,
                      chainTargetKey,
                      hasEcdsaThresholdKeyId: Boolean(ecdsaRestore?.ecdsaThresholdKeyId),
                      remainingUses: Number.isFinite(remainingUses)
                        ? Math.floor(remainingUses)
                        : null,
                    };
                  });
              } finally {
                db.close();
              }
            } catch {
              return [];
            }
          };

          return {
            origin: String(window.location?.origin || 'unknown'),
            localEd25519Index:
              window.localStorage?.getItem?.('seams:threshold-ed25519-session:v1:index') || null,
            localSealIndex:
              window.localStorage?.getItem?.('seams:signing-session-sealed:v1:index') || null,
            sessionEd25519Index:
              window.sessionStorage?.getItem?.('seams:threshold-ed25519-session:v1:index') || null,
            sessionSealIndex:
              window.sessionStorage?.getItem?.('seams:signing-session-sealed:v1:index') || null,
            sealedRecords: await readSealedRecords(),
          };
        })
        .catch(() => ({
          origin: 'unknown',
          localEd25519Index: null,
          localSealIndex: null,
          sessionEd25519Index: null,
          sessionSealIndex: null,
          sealedRecords: [],
        }));
    }),
  );
}

export type PasskeyLifecycleCurve = 'ed25519' | 'ecdsa';
export type PasskeyLifecyclePhase = 'register_unlock_sign' | 'sign';

export async function runPasskeySigningSessionLifecyclePhase(
  page: Page,
  harness: SealedRefreshHarness,
  input: {
    accountId: string;
    curve: PasskeyLifecycleCurve;
    phase: PasskeyLifecyclePhase;
    tag: string;
    remainingUses: number;
  },
): Promise<{
  ok: boolean;
  accountId?: string;
  curve?: PasskeyLifecycleCurve;
  stage?: string;
  sessionStatus?: string;
  signKind?: string;
  chain?: string;
  error?: string;
}> {
  const phasePromise = page.evaluate(
    async ({
      relayerUrl,
      keyVersion,
      shamirPrimeB64u,
      accountId,
      curve,
      phase,
      tag,
      remainingUses,
    }) => {
      let stage = 'init';
      try {
        const sdkMod = await import('/sdk/esm/SeamsWeb/index.js');
        const actionsMod = await import('/sdk/esm/core/types/actions.js');
        const { SeamsWeb } = sdkMod as any;
        const { ActionType } = actionsMod as any;

        const confirmationConfig = {
          uiMode: 'none' as const,
          behavior: 'skipClick' as const,
          autoProceedDelay: 0,
        };
        const seams = new SeamsWeb({
          nearNetwork: 'testnet',
          nearRpcUrl: 'https://test.rpc.fastnear.com',
          relayerAccount: 'web3-authn-v4.testnet',
          relayer: {
            url: relayerUrl,
          },
          registration: {
            mode: 'managed',
            environmentId: String(
              (globalThis as any).__w3aManagedRegistration?.environmentId || '',
            ),
            publishableKey: String(
              (globalThis as any).__w3aManagedRegistration?.publishableKey || '',
            ),
          },
          signingSessionDefaults: {
            ttlMs: 120_000,
            remainingUses,
          },
          signingSessionPersistenceMode: 'sealed_refresh_v1',
          signingSessionSeal: {
            keyVersion,
            shamirPrimeB64u,
          },
          iframeWallet: {
            walletOrigin: 'https://wallet.example.localhost',
            servicePath: '/wallet-service',
            sdkBasePath: '/sdk',
            rpIdOverride: 'example.localhost',
          },
        });

        seams.preferences.setConfirmationConfig(confirmationConfig as any);

        if (phase === 'register_unlock_sign') {
          stage = 'registration';
          const registration = await seams.registration.registerPasskey({
            confirmationConfig: confirmationConfig as any,
          });
          if (!registration?.success) {
            return {
              ok: false,
              accountId,
              curve,
              stage,
              error: String(registration?.error || 'registration failed'),
            };
          }

          stage = 'unlock';
          const login = await seams.auth.unlock(accountId, {
            session: {
              kind: 'jwt',
              relayUrl: relayerUrl,
              exchange: { type: 'passkey_assertion' },
            },
            signingSession: { ttlMs: 120_000, remainingUses },
          });
          if (!login?.success) {
            return {
              ok: false,
              accountId,
              curve,
              stage,
              error: String(login?.error || 'unlock failed'),
            };
          }

          if (curve === 'ecdsa') {
            stage = 'bootstrap_ecdsa';
            const bootstrap = await seams.tempo.bootstrapEcdsaSession({
              kind: 'reuse_warm_ecdsa_bootstrap',
              walletSession: {
                walletId: accountId,
                walletSessionUserId: accountId,
              },
              chainTarget: {
                kind: 'tempo',
                chainId: 42431,
                networkSlug: 'tempo-moderato',
              },
              relayerUrl,
              ttlMs: 120_000,
              remainingUses,
            });
            if (!bootstrap?.thresholdEcdsaKeyRef?.ecdsaThresholdKeyId) {
              return {
                ok: false,
                accountId,
                curve,
                stage,
                error: 'threshold ECDSA bootstrap did not return ecdsaThresholdKeyId',
              };
            }
          }
        }

        stage = `sign_${curve}`;
        const sign = async (): Promise<
          { ok: true; signKind: string; chain: string } | { ok: false; error: string }
        > => {
          const tagHex = Array.from(new TextEncoder().encode(String(tag || 'x')))
            .map((byte) => byte.toString(16).padStart(2, '0'))
            .join('');
          if (curve === 'ed25519') {
            const signed = await seams.near.executeAction({
              nearAccount: { accountId },
              receiverId: 'w3a-v1.testnet',
              actionArgs: {
                type: ActionType.FunctionCall,
                methodName: 'set_greeting',
                args: { greeting: `hello-lifecycle-${tag}-${Date.now()}` },
                gas: '30000000000000',
                deposit: '0',
              },
              options: {
                waitUntil: 'EXECUTED_OPTIMISTIC' as any,
                confirmationConfig,
              },
            });
            if (!signed?.success) {
              return { ok: false, error: String(signed?.error || 'near sign failed') };
            }
            return { ok: true, signKind: 'nearAction', chain: 'near' };
          }

          const signed = await seams.tempo.signTempo({
            walletSession: {
              walletId: accountId,
              walletSessionUserId: accountId,
            },
            chainTarget: {
              kind: 'tempo',
              chainId: 42431,
              networkSlug: 'tempo-moderato',
            },
            request: {
              chain: 'tempo' as const,
              kind: 'tempoTransaction' as const,
              senderSignatureAlgorithm: 'secp256k1' as const,
              tx: {
                chainId: 42431,
                maxPriorityFeePerGas: 1n,
                maxFeePerGas: 2n,
                gasLimit: 21_000n,
                calls: [{ to: '0x' + '11'.repeat(20), value: 0n, input: `0x${tagHex}` }],
                accessList: [],
                nonceKey: 0n,
                validBefore: null,
                validAfter: null,
                feePayerSignature: { kind: 'none' as const },
                aaAuthorizationList: [],
              },
            },
            options: { confirmationConfig },
          });
          if (!signed || signed.kind !== 'tempoTransaction') {
            return { ok: false, error: 'tempo sign failed' };
          }
          return {
            ok: true,
            signKind: String(signed.kind || ''),
            chain: String(signed.chain || ''),
          };
        };

        const signResult = await sign();
        if (!signResult.ok) {
          return {
            ok: false,
            accountId,
            curve,
            stage,
            error: signResult.error,
          };
        }

        stage = 'get_session';
        const session = await seams.auth.getWalletSession(accountId);
        return {
          ok: true,
          accountId,
          curve,
          stage,
          signKind: signResult.signKind,
          chain: signResult.chain,
          sessionStatus: String(session?.signingSession?.status || ''),
        };
      } catch (error: unknown) {
        let sessionStatus = '';
        try {
          const sdkMod = await import('/sdk/esm/SeamsWeb/index.js');
          const { SeamsWeb } = sdkMod as any;
          const seams = new SeamsWeb({
            nearNetwork: 'testnet',
            nearRpcUrl: 'https://test.rpc.fastnear.com',
            relayerAccount: 'web3-authn-v4.testnet',
            relayer: {
              url: relayerUrl,
            },
            signingSessionPersistenceMode: 'sealed_refresh_v1',
            signingSessionSeal: {
              keyVersion,
              shamirPrimeB64u,
            },
            iframeWallet: {
              walletOrigin: 'https://wallet.example.localhost',
              servicePath: '/wallet-service',
              sdkBasePath: '/sdk',
              rpIdOverride: 'example.localhost',
            },
          });
          const session = await seams.auth.getWalletSession(accountId);
          sessionStatus = String(session?.signingSession?.status || '');
        } catch {}
        return {
          ok: false,
          accountId,
          curve,
          stage,
          ...(sessionStatus ? { sessionStatus } : {}),
          error: String(
            error && typeof error === 'object' && 'message' in error
              ? (error as { message?: unknown }).message
              : error || 'passkey lifecycle phase failed',
          ),
          ...(error instanceof Error && error.stack ? { stack: error.stack } : {}),
        };
      }
    },
    {
      relayerUrl: harness.relayerUrl,
      keyVersion: TEST_KEY_VERSION,
      shamirPrimeB64u: TEST_SHAMIR_PRIME_B64U,
      accountId: input.accountId,
      curve: input.curve,
      phase: input.phase,
      tag: input.tag,
      remainingUses: input.remainingUses,
    },
  );

  return await autoConfirmWalletIframeUntil(page, phasePromise, {
    timeoutMs: 150_000,
    intervalMs: 250,
  });
}
