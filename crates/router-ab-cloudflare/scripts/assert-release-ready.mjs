import { readFileSync } from 'node:fs';
import { spawnSync } from 'node:child_process';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const scriptDir = dirname(fileURLToPath(import.meta.url));
const repoRoot = join(scriptDir, '..', '..', '..');

const blockers = [];

const strictWorkerSource = readRepoFile('crates/router-ab-cloudflare/src/strict_worker.rs');
const cloudflareSource = readRepoFile('crates/router-ab-cloudflare/src/lib.rs');
const ecdsaProtocolSource = readRepoFile('crates/router-ab-core/src/protocol/ecdsa_hss.rs');
const routerWrangler = readRepoFile('crates/router-ab-cloudflare/wrangler.router.toml');
const signerAWrangler = readRepoFile('crates/router-ab-cloudflare/wrangler.signer-a.toml');
const signerBWrangler = readRepoFile('crates/router-ab-cloudflare/wrangler.signer-b.toml');
const signingWorkerWrangler = readRepoFile(
  'crates/router-ab-cloudflare/wrangler.signing-worker.toml',
);
if (strictWorkerSource.includes('strict SigningWorker normal-signing handler is not configured')) {
  blockers.push('P1: strict SigningWorker normal-signing handler is still fail-closed');
}
if (
  strictWorkerSource.includes(
    'strict SigningWorker normal signing requires persisted server round-1 nonce material',
  )
) {
  blockers.push(
    'P1: strict SigningWorker normal-signing finalizer still lacks server round-1 nonce persistence',
  );
}
for (const [label, source] of [
  ['Signer A', signerAWrangler],
  ['Signer B', signerBWrangler],
  ['SigningWorker', signingWorkerWrangler],
]) {
  if (source.includes('workers_dev = true')) {
    blockers.push(`P1: strict ${label} Wrangler config exposes workers_dev`);
  }
}
for (const [label, source] of [
  ['Router', routerWrangler],
  ['Signer A', signerAWrangler],
  ['Signer B', signerBWrangler],
  ['SigningWorker', signingWorkerWrangler],
]) {
  if (!source.includes('ROUTER_AB_INTERNAL_SERVICE_AUTH_SECRET_BINDING')) {
    blockers.push(`P1: strict ${label} Wrangler config is missing internal service auth binding`);
  }
}
for (const [label, startNeedle, endNeedle] of [
  [
    'Signer A',
    'async fn handle_strict_deriver_a_fetch_v1',
    'async fn handle_strict_signing_worker_fetch_v1',
  ],
  [
    'SigningWorker',
    'async fn handle_strict_signing_worker_fetch_v1',
    'async fn handle_strict_deriver_b_fetch_v1',
  ],
  [
    'Signer B',
    'async fn handle_strict_deriver_b_fetch_v1',
    'fn cloudflare_protocol_error_response_v1',
  ],
]) {
  requireSourceRangeIncludes(
    `P1: strict ${label} private dispatcher does not require internal service auth`,
    strictWorkerSource,
    startNeedle,
    endNeedle,
    'require_cloudflare_internal_service_auth_request_v1',
  );
}
for (const functionName of [
  'execute_cloudflare_signer_recipient_proof_bundle_service_call_v1',
  'execute_cloudflare_ecdsa_hss_deriver_registration_service_call_v1',
  'execute_cloudflare_ecdsa_hss_deriver_export_service_call_v1',
  'execute_cloudflare_ecdsa_hss_deriver_recovery_service_call_v1',
  'execute_cloudflare_ecdsa_hss_deriver_activation_refresh_service_call_v1',
  'execute_cloudflare_signing_worker_recipient_proof_bundle_activation_service_call_v1',
  'execute_cloudflare_ecdsa_hss_signing_worker_activation_service_call_v1',
  'execute_cloudflare_ecdsa_hss_signing_worker_activation_refresh_service_call_v1',
  'execute_cloudflare_signing_worker_normal_signing_finalize_service_call_v2',
  'execute_cloudflare_signing_worker_normal_signing_presign_pool_hit_finalize_service_call_v2',
  'execute_cloudflare_signing_worker_normal_signing_prepare_service_call_v2',
  'execute_cloudflare_signing_worker_normal_signing_presign_pool_prepare_service_call_v2',
  'execute_cloudflare_signing_worker_ecdsa_hss_evm_digest_prepare_service_call_v1',
  'execute_cloudflare_signing_worker_ecdsa_hss_evm_digest_finalize_service_call_v1',
]) {
  requireSourceRangeIncludes(
    `P1: ${functionName} does not attach internal service auth`,
    cloudflareSource,
    functionName,
    'let mut init = worker::RequestInit::new();',
    'set_cloudflare_internal_service_auth_header_v1',
  );
}
for (const [label, source, needle] of [
  [
    'P0: ECDSA-HSS protocol id is missing',
    ecdsaProtocolSource,
    'router_ab_ecdsa_hss_secp256k1_v1',
  ],
  [
    'P0: ECDSA-HSS registration public route is missing',
    strictWorkerSource,
    'CLOUDFLARE_ROUTER_ECDSA_HSS_REGISTRATION_PUBLIC_REQUEST_PATH_V1',
  ],
  [
    'P0: ECDSA-HSS export public route is missing',
    strictWorkerSource,
    'CLOUDFLARE_ROUTER_ECDSA_HSS_EXPORT_PUBLIC_REQUEST_PATH_V1',
  ],
  [
    'P0: ECDSA-HSS SigningWorker activation route is missing',
    strictWorkerSource,
    'CLOUDFLARE_SIGNING_WORKER_ECDSA_HSS_ACTIVATION_PATH_V1',
  ],
  [
    'P0: ECDSA-HSS activation does not derive identity through the ECDSA-HSS crate',
    cloudflareSource,
    'derive_relayer_share_for_client_public',
  ],
  [
    'P0: ECDSA-HSS client-only export Deriver response is missing',
    cloudflareSource,
    'CloudflareSignerClientRecipientProofBundleResponseV1',
  ],
  [
    'P0: ECDSA-HSS export does not use the client-only Deriver service path',
    cloudflareSource,
    'execute_cloudflare_ecdsa_hss_deriver_export_service_call_v1',
  ],
  [
    'P0: ECDSA-HSS Signer A export private Deriver route is missing',
    strictWorkerSource,
    'CLOUDFLARE_SIGNER_A_ECDSA_HSS_EXPORT_PRIVATE_REQUEST_PATH_V1',
  ],
  [
    'P0: ECDSA-HSS Signer B export private Deriver route is missing',
    strictWorkerSource,
    'CLOUDFLARE_SIGNER_B_ECDSA_HSS_EXPORT_PRIVATE_REQUEST_PATH_V1',
  ],
  [
    'P0: Signer A wrangler config is missing SIGNING_WORKER service binding',
    signerAWrangler,
    'binding = "SIGNING_WORKER"',
  ],
  [
    'P0: Signer B wrangler config is missing SIGNING_WORKER service binding',
    signerBWrangler,
    'binding = "SIGNING_WORKER"',
  ],
  [
    'P0: Signer A wrangler config is missing SIGNING_WORKER peer var',
    signerAWrangler,
    'SIGNING_WORKER_PEER_BINDING = "SIGNING_WORKER"',
  ],
  [
    'P0: Signer B wrangler config is missing SIGNING_WORKER peer var',
    signerBWrangler,
    'SIGNING_WORKER_PEER_BINDING = "SIGNING_WORKER"',
  ],
]) {
  if (!source.includes(needle)) {
    blockers.push(label);
  }
}
requireSourceRangeIncludes(
  'P0: Signer A runtime does not carry a SigningWorker peer binding',
  cloudflareSource,
  'pub struct CloudflareSignerABindingsV1',
  '/// SigningWorker startup bindings.',
  'pub signing_worker: CloudflarePeerBindingV1',
);
requireSourceRangeIncludes(
  'P0: Signer B runtime does not carry a SigningWorker peer binding',
  cloudflareSource,
  'pub struct CloudflareSignerBBindingsV1',
  'impl CloudflareSignerBBindingsV1',
  'pub signing_worker: CloudflarePeerBindingV1',
);
for (const [label, needle] of [
  [
    'P0: ECDSA-HSS normal-signing prepare strict-route wiring is not implemented',
    'handle_cloudflare_router_ecdsa_hss_evm_digest_signing_prepare_authenticated_public_request_v1',
  ],
  [
    'P0: ECDSA-HSS normal-signing finalize strict-route wiring is not implemented',
    'handle_cloudflare_router_ecdsa_hss_evm_digest_signing_finalize_authenticated_public_request_v1',
  ],
  [
    'P0: ECDSA-HSS normal-signing production signature computation is not implemented',
    'CloudflareRoleSeparatedEcdsaHssEvmDigestFinalizeHandlerV1',
  ],
  [
    'P0: ECDSA-HSS recovery flow is not implemented',
    'handle_cloudflare_router_ecdsa_hss_recovery_authenticated_public_request_v1',
  ],
  [
    'P0: ECDSA-HSS activation refresh flow is not implemented',
    'handle_cloudflare_router_ecdsa_hss_activation_refresh_authenticated_public_request_v1',
  ],
]) {
  if (!cloudflareSource.includes(needle)) {
    blockers.push(label);
  }
}

const p2Tests = [
  'durable_object_handler_stores_full_derivation_ceremony_lifecycle',
  'durable_object_handler_rejects_skipped_derivation_ceremony_activation',
  'durable_object_handler_rejects_derivation_ceremony_scope_change',
  'durable_object_handler_rejects_terminal_derivation_ceremony_rewrite',
];
const p2Result = runCargoTest(p2Tests);
if (p2Result.status !== 0) {
  blockers.push('P2: Cloudflare derivation ceremony lifecycle tests failed');
}

if (blockers.length > 0) {
  console.error('Router A/B release blockers remain:');
  for (const blocker of blockers) {
    console.error(`- ${blocker}`);
  }
  if (p2Result.status !== 0) {
    console.error('\nP2 ceremony lifecycle test output:');
    process.stderr.write(p2Result.output);
  }
  process.exit(1);
}

console.log('Router A/B release blockers clear.');

function readRepoFile(path) {
  return readFileSync(join(repoRoot, path), 'utf8');
}

function requireSourceRangeIncludes(label, source, startNeedle, endNeedle, requiredNeedle) {
  const start = source.indexOf(startNeedle);
  const end = source.indexOf(endNeedle, start + startNeedle.length);
  if (start < 0 || end < 0 || !source.slice(start, end).includes(requiredNeedle)) {
    blockers.push(label);
  }
}

function runCargoTest(testNames) {
  let output = '';
  for (const testName of testNames) {
    const args = [
      'test',
      '--manifest-path',
      'crates/router-ab-cloudflare/Cargo.toml',
      '--test',
      'bindings',
      testName,
      '--',
      '--exact',
    ];
    const result = spawnSync('cargo', args, {
      cwd: repoRoot,
      encoding: 'utf8',
    });
    output += `$ cargo ${args.join(' ')}\n`;
    output += `${result.stdout || ''}${result.stderr || ''}`;
    if ((result.status ?? 1) !== 0) {
      return {
        status: result.status ?? 1,
        output,
      };
    }
    if (!testOutputHasExactlyOnePassingTest(`${result.stdout || ''}${result.stderr || ''}`)) {
      output += `Expected exactly one passing test for ${testName}.\n`;
      return {
        status: 1,
        output,
      };
    }
  }
  return { status: 0, output };
}

function testOutputHasExactlyOnePassingTest(output) {
  return /\ntest result: ok\. 1 passed; 0 failed; 0 ignored; 0 measured; \d+ filtered out;/.test(
    output,
  );
}
