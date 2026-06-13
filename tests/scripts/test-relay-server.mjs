#!/usr/bin/env node
import { createServer } from 'node:http';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { promises as fs } from 'node:fs';

// Import from built SDK to avoid TS transpilation for tests
import {
  AuthService,
  createHostedSigningRootShareResolver,
  createThresholdSigningService,
} from '../../packages/sdk-web/dist/esm/server/index.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const ROOT = path.resolve(path.join(__dirname, '../..'));
const RELAY_DIR = path.join(ROOT, 'examples', 'relay-server');
const DEFAULT_CACHE = path.join(RELAY_DIR, '.provision-cache.json');
const CACHE_PATH = process.env.RELAY_PROVISION_CACHE_PATH || DEFAULT_CACHE;
const SIGNING_ROOT_SHARE_WIRES = [
  {
    shareId: 1,
    wireHex: '0001d73847ea1a0888265782eb6998f3d905b8275fa4e5fda6556ddacc3b28741702',
  },
  {
    shareId: 2,
    wireHex: '0002b3ee4da8422ffeebb66bd0b55afb5d072f55aa324698a89c0a8b234042fd6c0f',
  },
  {
    shareId: 3,
    wireHex: '0003a2d05e0950f3615940b8bd5e3e0903f4a582f5c0a632aae3a73b7a445c86c20c',
  },
];

async function readCache() {
  const txt = await fs.readFile(CACHE_PATH, 'utf8');
  return JSON.parse(txt);
}

function createFixtureSigningRootShareResolver() {
  const shares = new Map(
    SIGNING_ROOT_SHARE_WIRES.map((share) => [
      share.shareId,
      new Uint8Array(Buffer.from(share.wireHex, 'hex')),
    ]),
  );
  return {
    listSealedSigningRootShares: async (input) =>
      Array.from(shares.keys())
        .sort((a, b) => a - b)
        .map((shareId) => ({
          signingRootId: input.signingRootId,
          ...(input.signingRootVersion ? { signingRootVersion: input.signingRootVersion } : {}),
          shareId,
          sealedShare: new Uint8Array([shareId]),
          storageId: `fixture-signing-root-${shareId}`,
          kekId: 'fixture-kek',
        })),
    decryptSigningRootSecretShare: async (record) => {
      const wire = shares.get(record.shareId);
      if (!wire) throw new Error(`missing fixture signing-root share ${record.shareId}`);
      return new Uint8Array(wire);
    },
  };
}

async function main() {
  const cache = await readCache();

  const config = {
    relayerAccount: cache.accountId,
    relayerPrivateKey: cache.nearPrivateKey,
    nearRpcUrl: process.env.NEAR_RPC_URL || 'https://test.rpc.fastnear.com',
    networkId: 'testnet',
    accountInitialBalance: '30000000000000000000000',
    createAccountAndRegisterGas: '85000000000000',
  };

  const authService = new AuthService(config);

  // Test harness: skip WebAuthn signature verification for relayer routes.
  // The Playwright suite validates client-side behavior; keeping the relay permissive avoids
  // failures caused by browser WebAuthn mock signature differences.
  try {
    authService.verifyWebAuthnAuthenticationLite = async () => ({ success: true, verified: true });
  } catch {}

  // Threshold signing services (in-memory stores are sufficient for test runs).
  const fixtureSigningRootShareResolver = createFixtureSigningRootShareResolver();
  const threshold = createThresholdSigningService({
    authService,
    thresholdStore: {
      kind: 'in-memory',
      THRESHOLD_NODE_ROLE: 'coordinator',
      signingRootShareResolver: createHostedSigningRootShareResolver({
        policy: {
          protocol: 'threshold-prf',
          threshold: 2,
          shareCount: 3,
        },
        storageAdapter: {
          listSealedSigningRootShares: (request) =>
            fixtureSigningRootShareResolver.listSealedSigningRootShares(request),
        },
        decryptAdapter: {
          decryptSigningRootShare: (record) =>
            fixtureSigningRootShareResolver.decryptSigningRootSecretShare(record),
        },
      }),
    },
    logger: null,
  });

  // Default to 3001 to avoid conflicts with the example relay-server (which defaults to 3000).
  const port = Number(process.env.RELAY_PORT || '3001');
  const allowedOrigins = [
    process.env.EXPECTED_ORIGIN || 'https://example.localhost',
    process.env.EXPECTED_WALLET_ORIGIN || 'https://wallet.example.localhost',
  ].filter(Boolean);

  const setCors = (req, res) => {
    // Test harness: be permissive in dev (ports can vary, e.g. 3600 vs 5175).
    // If an Origin is present, echo it so browsers accept the response.
    const requestOrigin = String(req.headers?.origin || '').trim();
    const allowOrigin = requestOrigin || allowedOrigins[0] || '*';

    res.setHeader('Access-Control-Allow-Origin', allowOrigin);
    res.setHeader('Vary', 'Origin');
    if (allowOrigin !== '*') {
      res.setHeader('Access-Control-Allow-Credentials', 'true');
    }
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');
    res.setHeader('Access-Control-Allow-Methods', 'GET,POST,OPTIONS');
  };

  const readJson = async (req) =>
    new Promise((resolve, reject) => {
      let data = '';
      req.on('data', (chunk) => {
        data += chunk;
      });
      req.on('end', () => {
        try {
          resolve(data ? JSON.parse(data) : {});
        } catch (e) {
          reject(e);
        }
      });
      req.on('error', reject);
    });

  const sendJson = (res, status, body) => {
    res.statusCode = status;
    res.setHeader('Content-Type', 'application/json');
    res.end(JSON.stringify(body));
  };

  const server = createServer(async (req, res) => {
    setCors(req, res);
    if (req.method === 'OPTIONS') {
      res.statusCode = 200;
      return res.end();
    }
    const url = new URL(req.url, `http://localhost:${port}`);
    try {
      if (req.method === 'GET' && url.pathname === '/healthz') {
        return sendJson(res, 200, { ok: true, relayerAccount: cache.accountId });
      }
      if (req.method === 'GET' && url.pathname === '/threshold-ed25519/healthz') {
        return sendJson(res, 200, { ok: true, configured: true });
      }
      if (req.method === 'POST' && url.pathname === '/auth/passkey/options') {
        const body = await readJson(req);
        const out = await authService.createWebAuthnLoginOptions(body);
        if (!out?.ok) {
          return sendJson(res, out?.code === 'internal' ? 500 : 400, out);
        }
        return sendJson(res, 200, out);
      }
      if (req.method === 'POST' && url.pathname === '/auth/passkey/verify') {
        const body = await readJson(req);
        const challengeId = String(body?.challengeId ?? body?.challenge_id ?? '').trim();
        if (!challengeId) {
          return sendJson(res, 400, {
            ok: false,
            code: 'invalid_body',
            message: 'challengeId is required',
          });
        }
        const authn = body?.webauthn_authentication;
        if (!authn || typeof authn !== 'object') {
          return sendJson(res, 400, {
            ok: false,
            code: 'invalid_body',
            message: 'webauthn_authentication is required',
          });
        }

        const origin = String(req.headers?.origin || req.headers?.Origin || '').trim() || undefined;
        const out = await authService.verifyWebAuthnLogin({
          challengeId,
          webauthn_authentication: authn,
          expected_origin: origin,
        });

        if (!out?.ok || !out?.verified) {
          return sendJson(res, out?.code === 'internal' ? 500 : 400, out);
        }

        return sendJson(res, 200, { ok: true, verified: true });
      }
      if (req.method === 'POST' && url.pathname === '/registration/bootstrap') {
        const body = await readJson(req);
        const {
          new_account_id,
          threshold_ed25519,
          device_number,
          rp_id,
          webauthn_registration,
          authenticator_options,
        } = body || {};

        if (
          !new_account_id ||
          !rp_id ||
          !webauthn_registration ||
          !threshold_ed25519 ||
          !String(threshold_ed25519?.public_key || '').trim()
        ) {
          return sendJson(res, 400, { success: false, error: 'missing required fields' });
        }
        const expected_origin = String(req.headers?.origin || '').trim();
        const result = await authService.createAccountAndRegisterUser({
          new_account_id,
          device_number,
          threshold_ed25519,
          rp_id,
          webauthn_registration,
          ...(expected_origin ? { expected_origin } : {}),
          authenticator_options,
        });
        return sendJson(res, result.success ? 200 : 400, result);
      }
      sendJson(res, 404, { error: 'not_found' });
    } catch (e) {
      sendJson(res, 500, { error: 'internal', details: e?.message });
    }
  });

  server.listen(port, () => {
    console.log(`[test-relay] listening on http://localhost:${port}`);
  });
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
