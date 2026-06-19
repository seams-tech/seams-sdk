#!/usr/bin/env node
import fs from 'node:fs';
import http from 'node:http';
import https from 'node:https';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const repoRoot = fileURLToPath(new URL('../../..', import.meta.url));
const caddyfilePath = path.join(repoRoot, 'apps/web-client/Caddyfile');
const publicOrigin = process.env.ROUTER_AB_PUBLIC_ROUTER_ORIGIN || 'https://localhost:9444';
const expectedUpstream = process.env.ROUTER_AB_LOCAL_ROUTER_UPSTREAM || '127.0.0.1:9090';

const routeProbes = [
  {
    label: 'Ed25519 normal signing prepare',
    path: '/v2/router-ab/ed25519/sign/prepare',
    headers: { authorization: 'Bearer local-router-route-smoke.invalid' },
  },
  {
    label: 'Ed25519 Wallet Session issuance',
    path: '/v2/router-ab/wallet-session/ed25519',
    headers: {},
  },
];
const expectedBoundaryFailureStatuses = new Set([400, 401, 403, 422]);

main().catch((error) => {
  console.error(error instanceof Error ? error.message : String(error));
  process.exit(1);
});

async function main() {
  const caddy = assertCaddySingleRouterUpstream();
  const probes = [];
  for (const probe of routeProbes) {
    probes.push(await postRouteProbe(probe));
  }

  console.log(
    JSON.stringify(
      {
        ok: true,
        publicOrigin,
        upstream: caddy.upstream,
        probes,
      },
      null,
      2,
    ),
  );
}

function assertCaddySingleRouterUpstream() {
  const source = fs.readFileSync(caddyfilePath, 'utf8');
  const block = extractCaddySiteBlock(source, 'localhost:9444');
  const forbiddenMarkers = [
    '@router_ab_public_signing',
    '/v2/router-ab/ed25519/sign',
    '/v1/hss/ecdsa/sign',
    'handle @router_ab',
    'handle_path /v2/router-ab',
    'handle_path /v1/hss/ecdsa',
  ];
  const offenders = forbiddenMarkers.filter((marker) => block.includes(marker));
  if (offenders.length > 0) {
    throw new Error(
      `localhost:9444 Caddy block still contains path-split routing: ${offenders.join(', ')}`,
    );
  }

  const upstreams = [...block.matchAll(/^\s*reverse_proxy\s+([^\s{]+)/gm)].map(
    (match) => match[1],
  );
  if (upstreams.length !== 1) {
    throw new Error(`localhost:9444 must have exactly one reverse_proxy; found ${upstreams.length}`);
  }
  if (upstreams[0] !== expectedUpstream) {
    throw new Error(
      `localhost:9444 reverse_proxy must point to ${expectedUpstream}; found ${upstreams[0]}`,
    );
  }
  return { upstream: upstreams[0] };
}

function extractCaddySiteBlock(source, siteLabel) {
  const lines = source.split(/\r?\n/);
  const start = lines.findIndex((line) => line.trim() === `${siteLabel} {`);
  if (start < 0) {
    throw new Error(`apps/web-client/Caddyfile is missing ${siteLabel} site block`);
  }

  let depth = 0;
  const block = [];
  for (let index = start; index < lines.length; index += 1) {
    const line = lines[index];
    block.push(line);
    depth += countChar(line, '{') - countChar(line, '}');
    if (index > start && depth === 0) {
      return block.join('\n');
    }
  }
  throw new Error(`${siteLabel} Caddy block is not closed`);
}

function countChar(value, char) {
  return [...value].filter((entry) => entry === char).length;
}

async function postRouteProbe(probe) {
  const url = new URL(probe.path, publicOrigin);
  let result;
  try {
    result = await postJson(url, probe.headers);
  } catch (error) {
    throw new Error(
      `${probe.label} probe could not reach ${url.href}. Start pnpm site and pnpm router before running this smoke. ${errorMessage(error)}`,
    );
  }

  if (result.status === 404 || /\bCannot POST\b/.test(result.body)) {
    throw new Error(
      `${probe.label} reached ${url.href} but the Router route was missing: HTTP ${result.status} ${result.body.slice(0, 160)}`,
    );
  }
  if (!expectedBoundaryFailureStatuses.has(result.status)) {
    throw new Error(
      `${probe.label} reached ${url.href} but returned unexpected HTTP ${result.status}: ${result.body.slice(0, 160)}`,
    );
  }

  return {
    label: probe.label,
    path: probe.path,
    status: result.status,
  };
}

function postJson(url, headers) {
  const client = url.protocol === 'https:' ? https : url.protocol === 'http:' ? http : null;
  if (!client) {
    throw new Error(`unsupported URL protocol ${url.protocol}`);
  }

  const body = '{}';
  const requestOptions = {
    protocol: url.protocol,
    hostname: url.hostname,
    port: url.port,
    path: `${url.pathname}${url.search}`,
    method: 'POST',
    headers: {
      origin: 'https://localhost',
      'content-type': 'application/json',
      'content-length': Buffer.byteLength(body),
      ...headers,
    },
  };
  if (url.protocol === 'https:') {
    requestOptions.rejectUnauthorized = false;
  }

  return new Promise((resolve, reject) => {
    const request = client.request(requestOptions, (response) => {
      const chunks = [];
      response.on('data', (chunk) => chunks.push(Buffer.from(chunk)));
      response.on('end', () => {
        resolve({
          status: response.statusCode || 0,
          body: Buffer.concat(chunks).toString('utf8'),
        });
      });
    });
    request.on('error', reject);
    request.write(body);
    request.end();
  });
}

function errorMessage(error) {
  return error && typeof error === 'object' && 'message' in error
    ? String(error.message)
    : String(error);
}
