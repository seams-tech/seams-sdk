import { readFileSync } from 'node:fs';
import { spawnSync } from 'node:child_process';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const scriptDir = dirname(fileURLToPath(import.meta.url));
const repoRoot = join(scriptDir, '..', '..', '..');

const blockers = [];

const strictWorkerModuleSource = readRepoFile(
  'crates/router-ab-cloudflare/src/strict_worker/mod.rs',
);
const strictRouterSource = readRepoFile('crates/router-ab-cloudflare/src/strict_worker/router.rs');
const strictDeriverSource = readRepoFile(
  'crates/router-ab-cloudflare/src/strict_worker/deriver.rs',
);
const strictSigningWorkerSource = readRepoFile(
  'crates/router-ab-cloudflare/src/strict_worker/signing_worker.rs',
);
const ecdsaNormalSigningTransportSource = readRepoFile(
  'crates/router-ab-cloudflare/src/ecdsa_normal_signing_transport.rs',
);
const strictWorkerSource = [
  strictWorkerModuleSource,
  strictRouterSource,
  strictDeriverSource,
  strictSigningWorkerSource,
].join('\n');
const cloudflareSource = [
  readRepoFile('crates/router-ab-cloudflare/src/lib.rs'),
  readRepoFile('crates/router-ab-cloudflare/src/router/mod.rs'),
  readRepoFile('crates/router-ab-cloudflare/src/signing_worker/mod.rs'),
].join('\n');
const ecdsaProtocolSource = readRepoFile(
  'crates/router-ab-core/src/protocol/router_ab_ecdsa_derivation.rs',
);
const routerWrangler = readRepoFile('crates/router-ab-cloudflare/wrangler.router.toml');
const deriverAWrangler = readRepoFile('crates/router-ab-cloudflare/wrangler.deriver-a.toml');
const deriverBWrangler = readRepoFile('crates/router-ab-cloudflare/wrangler.deriver-b.toml');
const signingWorkerWrangler = readRepoFile(
  'crates/router-ab-cloudflare/wrangler.signing-worker.toml',
);
const deployRouterAbWorkflow = readRepoFile('.github/workflows/deploy-router-ab.yml');
const deployStagingWorkflow = readRepoFile('.github/workflows/deploy-staging.yml');
const deployProductionWorkflow = readRepoFile('.github/workflows/deploy-production.yml');
const deploymentSources = [
  routerWrangler,
  deriverAWrangler,
  deriverBWrangler,
  signingWorkerWrangler,
  deployRouterAbWorkflow,
].join('\n');
for (const forbidden of [
  'strict-worker-signer-a-entrypoint',
  'strict-worker-signer-b-entrypoint',
  'wrangler.signer-a.toml',
  'wrangler.signer-b.toml',
  'router-ab-signer-a',
  'router-ab-signer-b',
  'SIGNER_A_',
  'SIGNER_B_',
]) {
  if (deploymentSources.includes(forbidden)) {
    blockers.push(`P1: legacy derivation Worker deployment symbol remains: ${forbidden}`);
  }
}
for (const [label, source] of [
  ['Router', routerWrangler],
  ['Deriver A', deriverAWrangler],
  ['Deriver B', deriverBWrangler],
  ['SigningWorker', signingWorkerWrangler],
]) {
  if (source.includes('[env.production]')) {
    blockers.push(`P1: ${label} still exposes an unselected production Wrangler branch`);
  }
}
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
if (cloudflareSource.includes('STRICT_CLOUDFLARE_WALLET_SESSION_BUDGET_ENFORCEMENT_REQUIRED_V1')) {
  blockers.push(
    'P1: strict Cloudflare Router A/B Wallet Session budget enforcement is fail-closed pending reserve/commit store wiring',
  );
}
requireSourceRangeIncludes(
  'P1: strict Cloudflare Wallet Session model is missing signing_grant_id',
  cloudflareSource,
  'pub struct CloudflareRouterVerifiedWalletSessionV1',
  'impl CloudflareRouterVerifiedWalletSessionV1',
  'pub signing_grant_id: String',
);
requireSourceRangeIncludes(
  'P1: strict Cloudflare Wallet Session JWT payload is missing signingGrantId',
  cloudflareSource,
  'struct CloudflareRouterJwtClaimsPayloadV1',
  'struct CloudflareRouterJwtNormalSigningWalletSessionClaimsV1',
  'signingGrantId',
);
requireSourceRangeIncludes(
  'P1: strict Cloudflare Wallet Session validation does not require signingGrantId',
  cloudflareSource,
  'fn validate_for_wallet_session',
  'fn validate_common_for_request_expiry',
  'Router Wallet Session requires signingGrantId',
);
requireSourceRangeIncludes(
  'P1: strict Cloudflare Router private grant route is missing internal service auth',
  strictRouterSource,
  'CLOUDFLARE_ROUTER_WALLET_BUDGET_PUT_GRANT_PRIVATE_REQUEST_PATH',
  'if request.method() == Method::Options',
  'require_cloudflare_internal_service_auth_request_v1',
);
requireSourceRangeIncludes(
  'P1: strict Cloudflare grant issuer does not call Wallet Budget PutGrant',
  cloudflareSource,
  'handle_cloudflare_router_wallet_budget_put_grant_private_fetch_v1',
  'handle_cloudflare_router_normal_signing_prepare_authenticated_public_request_v2',
  'put_cloudflare_router_wallet_budget_grant_v1',
);
requireSourceRangeIncludes(
  'P1: strict Cloudflare grant issuer does not execute the Wallet Budget DO PutGrant operation',
  cloudflareSource,
  'put_cloudflare_router_wallet_budget_grant_v1',
  'validate_cloudflare_router_wallet_budget_v1',
  'wallet_budget_put_grant_call',
);
requireSourceRangeIncludes(
  'P1: strict Cloudflare Wallet Budget status route is missing from strict Router dispatch',
  strictRouterSource,
  'CLOUDFLARE_ROUTER_WALLET_BUDGET_STATUS_PUBLIC_REQUEST_PATH',
  'if path == CLOUDFLARE_ROUTER_NORMAL_SIGNING_ROUND1_PREPARE_PUBLIC_REQUEST_PATH',
  'handle_cloudflare_router_wallet_budget_status_authenticated_public_request_v1',
);
requireSourceRangeIncludes(
  'P1: strict Cloudflare Wallet Budget status route does not read the Wallet Budget DO',
  cloudflareSource,
  'handle_cloudflare_router_wallet_budget_status_authenticated_public_request_v1',
  'handle_cloudflare_router_normal_signing_prepare_authenticated_public_request_v2',
  'status_cloudflare_router_wallet_budget_v1',
);
for (const [label, startNeedle, endNeedle, requiredNeedle] of [
  [
    'P1: strict Ed25519 prepare route does not reserve Wallet Session budget before SigningWorker forwarding',
    'handle_cloudflare_router_normal_signing_prepare_authenticated_public_request_v2',
    'execute_cloudflare_signing_worker_normal_signing_prepare_service_call_v2',
    'reserve_cloudflare_router_wallet_budget_v1',
  ],
  [
    'P1: strict Router A/B ECDSA derivation prepare route does not reserve Wallet Session budget before SigningWorker forwarding',
    'handle_cloudflare_router_ab_ecdsa_derivation_evm_digest_signing_prepare_authenticated_public_request_v1',
    'execute_cloudflare_signing_worker_router_ab_ecdsa_derivation_evm_digest_prepare_service_call_v1',
    'reserve_cloudflare_router_wallet_budget_v1',
  ],
  [
    'P1: strict Router A/B ECDSA derivation finalize route does not validate Wallet Session budget before SigningWorker forwarding',
    'handle_cloudflare_router_ab_ecdsa_derivation_evm_digest_signing_finalize_authenticated_public_request_v1',
    'execute_cloudflare_signing_worker_router_ab_ecdsa_derivation_evm_digest_finalize_service_call_v1',
    'validate_cloudflare_router_wallet_budget_v1',
  ],
  [
    'P1: strict Ed25519 finalize route does not validate Wallet Session budget before SigningWorker forwarding',
    'handle_cloudflare_router_normal_signing_finalize_authenticated_public_request_v2',
    'execute_cloudflare_signing_worker_normal_signing_finalize_service_call_v2',
    'validate_cloudflare_router_wallet_budget_v1',
  ],
]) {
  requireSourceRangeIncludes(label, cloudflareSource, startNeedle, endNeedle, requiredNeedle);
}
for (const [label, startNeedle, endNeedle] of [
  [
    'P1: strict Router A/B ECDSA derivation finalize route does not commit Wallet Session budget after SigningWorker success',
    'execute_cloudflare_signing_worker_router_ab_ecdsa_derivation_evm_digest_finalize_service_call_v1',
    'CloudflareRouterWalletBudgetedFinalizeResponseV1::new(response, budget_status)',
  ],
  [
    'P1: strict Ed25519 finalize route does not commit Wallet Session budget after SigningWorker success',
    'execute_cloudflare_signing_worker_normal_signing_finalize_service_call_v2',
    'CloudflareRouterWalletBudgetedFinalizeResponseV1::new(response, budget_status)',
  ],
]) {
  requireSourceRangeIncludes(
    label,
    cloudflareSource,
    startNeedle,
    endNeedle,
    'commit_cloudflare_router_wallet_budget_v1',
  );
}
for (const [label, startNeedle, endNeedle] of [
  [
    'P1: strict Router A/B ECDSA derivation finalize route does not release Wallet Session budget on SigningWorker failure',
    'execute_cloudflare_signing_worker_router_ab_ecdsa_derivation_evm_digest_finalize_service_call_v1',
    'commit_cloudflare_router_wallet_budget_v1',
  ],
  [
    'P1: strict Ed25519 finalize route does not release Wallet Session budget on SigningWorker failure',
    'execute_cloudflare_signing_worker_normal_signing_finalize_service_call_v2',
    'commit_cloudflare_router_wallet_budget_v1',
  ],
]) {
  requireSourceRangeIncludes(
    label,
    cloudflareSource,
    startNeedle,
    endNeedle,
    'release_cloudflare_router_wallet_budget_best_effort_v1',
  );
}
for (const [label, needle] of [
  [
    'P1: Router Wrangler config is missing Wallet Budget Durable Object class',
    'RouterAbRouterWalletBudgetDurableObject',
  ],
  [
    'P1: Router Wrangler config is missing Wallet Budget Durable Object binding env',
    'ROUTER_WALLET_BUDGET_DO_BINDING',
  ],
  [
    'P1: Router Wrangler config is missing Wallet Budget Durable Object key prefix env',
    'ROUTER_WALLET_BUDGET_DO_KEY_PREFIX',
  ],
]) {
  if (!routerWrangler.includes(needle)) {
    blockers.push(label);
  }
}
for (const [label, source] of [
  ['Deriver A', deriverAWrangler],
  ['Deriver B', deriverBWrangler],
  ['SigningWorker', signingWorkerWrangler],
]) {
  if (source.includes('workers_dev = true')) {
    blockers.push(`P1: strict ${label} Wrangler config exposes workers_dev`);
  }
}
for (const [label, source] of [
  ['Router', routerWrangler],
  ['Deriver A', deriverAWrangler],
  ['Deriver B', deriverBWrangler],
  ['SigningWorker', signingWorkerWrangler],
]) {
  if (!source.includes('ROUTER_AB_INTERNAL_SERVICE_AUTH_SECRET_BINDING')) {
    blockers.push(`P1: strict ${label} Wrangler config is missing internal service auth binding`);
  }
}
for (const [label, source, startNeedle] of [
  ['Deriver A', strictDeriverSource, 'async fn handle_strict_deriver_a_fetch_v1'],
  ['SigningWorker', strictSigningWorkerSource, 'async fn handle_strict_signing_worker_fetch_v1'],
  ['Deriver B', strictDeriverSource, 'async fn handle_strict_deriver_b_fetch_v1'],
]) {
  requireSourceRangeIncludes(
    `P1: strict ${label} private dispatcher does not require internal service auth`,
    source,
    startNeedle,
    'let runtime =',
    'require_cloudflare_internal_service_auth_request_v1',
  );
}
requireDeployWorkflowSplitEnvironmentBoundary(deployRouterAbWorkflow);
requireDeployWorkflowBranchPromotionBoundary(
  deployRouterAbWorkflow,
  deployStagingWorkflow,
  deployProductionWorkflow,
);
requireFunctionIncludes(
  'P1: shared Cloudflare service dispatcher does not attach internal service auth',
  cloudflareSource,
  'post_service_json',
  'set_cloudflare_internal_service_auth_header_v1',
);
for (const functionName of [
  'execute_cloudflare_router_ab_ecdsa_derivation_deriver_registration_service_call_v1',
  'execute_cloudflare_router_ab_ecdsa_derivation_deriver_export_service_call_v1',
  'execute_cloudflare_router_ab_ecdsa_derivation_deriver_recovery_service_call_v1',
  'execute_cloudflare_router_ab_ecdsa_derivation_deriver_activation_refresh_service_call_v1',
  'execute_cloudflare_router_ab_ecdsa_derivation_signing_worker_activation_service_call_v1',
  'execute_cloudflare_router_ab_ecdsa_derivation_signing_worker_activation_refresh_service_call_v1',
  'execute_cloudflare_router_ab_ecdsa_derivation_signing_worker_export_share_service_call_v1',
  'execute_cloudflare_signing_worker_normal_signing_finalize_service_call_v2',
  'execute_cloudflare_signing_worker_normal_signing_prepare_service_call_v2',
  'execute_cloudflare_deriver_peer_service_call_v1',
]) {
  requireFunctionIncludes(
    `P1: ${functionName} bypasses the authenticated service dispatcher`,
    cloudflareSource,
    functionName,
    'post_service_json',
  );
}
requireSourceRangeOccurrenceCount(
  'P1: ECDSA normal-signing transport bypasses the authenticated service dispatcher',
  ecdsaNormalSigningTransportSource,
  'impl CloudflareRouterAbEcdsaNormalSigningServiceTransportV1',
  'pub(crate) async fn execute_cloudflare_router_ab_ecdsa_normal_signing_prepare_with_transport_v1',
  'post_service_json',
  2,
);
for (const [functionName, transportFunctionName] of [
  [
    'execute_cloudflare_signing_worker_router_ab_ecdsa_derivation_evm_digest_prepare_service_call_v1',
    'execute_cloudflare_router_ab_ecdsa_normal_signing_prepare_with_transport_v1',
  ],
  [
    'execute_cloudflare_signing_worker_router_ab_ecdsa_derivation_evm_digest_finalize_service_call_v1',
    'execute_cloudflare_router_ab_ecdsa_normal_signing_finalize_with_transport_v1',
  ],
]) {
  requireFunctionIncludes(
    `P1: ${functionName} bypasses the authenticated ECDSA service transport`,
    cloudflareSource,
    functionName,
    transportFunctionName,
  );
}
for (const [label, source, needle] of [
  [
    'P0: Router A/B ECDSA derivation protocol id is missing',
    ecdsaProtocolSource,
    'router_ab_ecdsa_derivation_v1',
  ],
  [
    'P0: Router A/B ECDSA derivation registration public route is missing',
    strictWorkerSource,
    'CLOUDFLARE_ROUTER_AB_ECDSA_DERIVATION_REGISTRATION_PUBLIC_REQUEST_PATH',
  ],
  [
    'P0: Router A/B ECDSA derivation export public route is missing',
    strictWorkerSource,
    'CLOUDFLARE_ROUTER_AB_ECDSA_DERIVATION_EXPORT_PUBLIC_REQUEST_PATH',
  ],
  [
    'P0: Router A/B ECDSA derivation SigningWorker activation route is missing',
    strictWorkerSource,
    'CLOUDFLARE_SIGNING_WORKER_ROUTER_AB_ECDSA_DERIVATION_ACTIVATION_PATH',
  ],
  [
    'P0: Router A/B ECDSA derivation activation does not derive identity through the Router A/B ECDSA derivation crate',
    cloudflareSource,
    'derive_relayer_share_for_client_public',
  ],
  [
    'P0: Router A/B ECDSA derivation client-only export Deriver response is missing',
    cloudflareSource,
    'CloudflareSignerClientRecipientProofBundleResponseV1',
  ],
  [
    'P0: Router A/B ECDSA derivation export does not use the client-only Deriver service path',
    cloudflareSource,
    'execute_cloudflare_router_ab_ecdsa_derivation_deriver_export_service_call_v1',
  ],
  [
    'P0: Router A/B ECDSA derivation Deriver A export private Deriver route is missing',
    strictWorkerSource,
    'CLOUDFLARE_DERIVER_A_ROUTER_AB_ECDSA_DERIVATION_EXPORT_PRIVATE_REQUEST_PATH',
  ],
  [
    'P0: Router A/B ECDSA derivation Deriver B export private Deriver route is missing',
    strictWorkerSource,
    'CLOUDFLARE_DERIVER_B_ROUTER_AB_ECDSA_DERIVATION_EXPORT_PRIVATE_REQUEST_PATH',
  ],
]) {
  if (!source.includes(needle)) {
    blockers.push(label);
  }
}
for (const [label, source, forbidden] of [
  [
    'P0: Deriver A must not retain a direct SigningWorker service binding',
    deriverAWrangler,
    'binding = "SIGNING_WORKER"',
  ],
  [
    'P0: Deriver B must not retain a direct SigningWorker service binding',
    deriverBWrangler,
    'binding = "SIGNING_WORKER"',
  ],
  [
    'P0: Deriver A must not retain a direct SigningWorker peer variable',
    deriverAWrangler,
    'SIGNING_WORKER_PEER_BINDING',
  ],
  [
    'P0: Deriver B must not retain a direct SigningWorker peer variable',
    deriverBWrangler,
    'SIGNING_WORKER_PEER_BINDING',
  ],
]) {
  if (source.includes(forbidden)) {
    blockers.push(label);
  }
}
if (strictDeriverSource.includes('send_strict_deriver_direct_activation_delivery_v1')) {
  blockers.push('P0: Derivers still push activation bundles directly to SigningWorker');
}
for (const [label, needle] of [
  [
    'P0: Router A/B ECDSA derivation normal-signing prepare strict-route wiring is not implemented',
    'handle_cloudflare_router_ab_ecdsa_derivation_evm_digest_signing_prepare_authenticated_public_request_v1',
  ],
  [
    'P0: Router A/B ECDSA derivation normal-signing finalize strict-route wiring is not implemented',
    'handle_cloudflare_router_ab_ecdsa_derivation_evm_digest_signing_finalize_authenticated_public_request_v1',
  ],
  [
    'P0: Router A/B ECDSA derivation normal-signing production signature computation is not implemented',
    'CloudflareRoleSeparatedRouterAbEcdsaDerivationEvmDigestFinalizeHandlerV1',
  ],
  [
    'P0: Router A/B ECDSA derivation recovery flow is not implemented',
    'handle_cloudflare_router_ab_ecdsa_derivation_recovery_authenticated_public_request_v1',
  ],
  [
    'P0: Router A/B ECDSA derivation activation refresh flow is not implemented',
    'handle_cloudflare_router_ab_ecdsa_derivation_activation_refresh_authenticated_public_request_v1',
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

function requireDeployWorkflowSplitEnvironmentBoundary(workflowSource) {
  if (/^\s+name:\s*\$\{\{\s*inputs\.target\s*\}\}\s*$/m.test(workflowSource)) {
    blockers.push('P1: deploy-router-ab workflow still uses the shared target environment');
  }

  for (const [jobId, requiredEnvironmentExpression] of [
    ['validate_router_ab', "format('{0}-mpc-router', inputs.target)"],
    ['upload_or_deploy_mpc_router', "format('{0}-mpc-router', inputs.target)"],
    ['upload_or_deploy_deriver_a', "format('{0}-deriver-a', inputs.target)"],
    ['upload_or_deploy_deriver_b', "format('{0}-deriver-b', inputs.target)"],
    ['upload_or_deploy_signing_worker', "format('{0}-signing-worker', inputs.target)"],
  ]) {
    const jobSource = workflowJobSource(workflowSource, jobId);
    if (!jobSource) {
      blockers.push(`P1: deploy-router-ab workflow is missing ${jobId}`);
      continue;
    }
    if (!jobSource.includes(requiredEnvironmentExpression)) {
      blockers.push(
        `P1: deploy-router-ab ${jobId} does not derive its protected environment from the fixed release target`,
      );
    }
  }

  for (const [jobId, forbiddenNeedles] of [
    [
      'upload_or_deploy_mpc_router',
      [
        'DERIVER_A_ROOT_SHARE_WIRE_SECRET',
        'DERIVER_A_ENVELOPE_HPKE_PRIVATE_KEY',
        'DERIVER_A_PEER_SIGNING_KEY',
        'DERIVER_B_ROOT_SHARE_WIRE_SECRET',
        'DERIVER_B_ENVELOPE_HPKE_PRIVATE_KEY',
        'DERIVER_B_PEER_SIGNING_KEY',
        'SIGNING_WORKER_SERVER_OUTPUT_HPKE_PRIVATE_KEY',
      ],
    ],
    [
      'upload_or_deploy_signing_worker',
      [
        'DERIVER_A_ROOT_SHARE_WIRE_SECRET',
        'DERIVER_A_ENVELOPE_HPKE_PRIVATE_KEY',
        'DERIVER_A_PEER_SIGNING_KEY',
        'DERIVER_B_ROOT_SHARE_WIRE_SECRET',
        'DERIVER_B_ENVELOPE_HPKE_PRIVATE_KEY',
        'DERIVER_B_PEER_SIGNING_KEY',
      ],
    ],
    [
      'upload_or_deploy_deriver_a',
      [
        'DERIVER_B_ROOT_SHARE_WIRE_SECRET',
        'DERIVER_B_ENVELOPE_HPKE_PRIVATE_KEY',
        'DERIVER_B_PEER_SIGNING_KEY',
        'SIGNING_WORKER_SERVER_OUTPUT_HPKE_PRIVATE_KEY',
      ],
    ],
    [
      'upload_or_deploy_deriver_b',
      [
        'DERIVER_A_ROOT_SHARE_WIRE_SECRET',
        'DERIVER_A_ENVELOPE_HPKE_PRIVATE_KEY',
        'DERIVER_A_PEER_SIGNING_KEY',
        'SIGNING_WORKER_SERVER_OUTPUT_HPKE_PRIVATE_KEY',
      ],
    ],
  ]) {
    const jobSource = workflowJobSource(workflowSource, jobId);
    if (!jobSource) {
      continue;
    }
    for (const forbiddenNeedle of forbiddenNeedles) {
      if (jobSource.includes(forbiddenNeedle)) {
        blockers.push(
          `P1: deploy-router-ab ${jobId} references forbidden secret ${forbiddenNeedle}`,
        );
      }
    }
  }
}

function requireDeployWorkflowBranchPromotionBoundary(
  workflowSource,
  stagingWorkflowSource,
  productionWorkflowSource,
) {
  for (const [label, entrypointSource, requiredNeedles] of [
    [
      'staging',
      stagingWorkflowSource,
      [
        'name: deploy-staging',
        "workflows: ['ci']",
        'branches: [dev]',
        "github.event.workflow_run.conclusion == 'success'",
        "github.event.workflow_run.event == 'push'",
        "github.event.workflow_run.head_branch == 'dev'",
        'target: staging',
        'source_branch: dev',
      ],
    ],
    [
      'production',
      productionWorkflowSource,
      [
        'name: deploy-production',
        "workflows: ['ci']",
        'branches: [main]',
        "github.event.workflow_run.conclusion == 'success'",
        "github.event.workflow_run.event == 'push'",
        "github.event.workflow_run.head_branch == 'main'",
        'target: production',
        'source_branch: main',
      ],
    ],
  ]) {
    for (const requiredNeedle of requiredNeedles) {
      if (!entrypointSource.includes(requiredNeedle)) {
        blockers.push(`P1: ${label} branch promotion is missing ${requiredNeedle}`);
      }
    }
  }

  for (const requiredNeedle of [
    'workflow_call:',
    "DEPLOY_OPERATION: ${{ github.event_name == 'workflow_call' && 'deploy' || inputs.operation }}",
    "DEPLOY_ROLE: ${{ github.event_name == 'workflow_call' && 'all' || inputs.role }}",
    'ref: ${{ env.DEPLOY_SHA }}',
  ]) {
    if (!workflowSource.includes(requiredNeedle)) {
      blockers.push(`P1: shared deploy-router-ab workflow is missing ${requiredNeedle}`);
    }
  }

  if (!/^\s*- production\s*$/m.test(workflowSource)) {
    blockers.push('P1: deploy-router-ab manual dispatch is missing the production target');
  }

  for (const jobId of [
    'upload_or_deploy_mpc_router',
    'upload_or_deploy_deriver_a',
    'upload_or_deploy_deriver_b',
    'upload_or_deploy_signing_worker',
  ]) {
    const jobSource = workflowJobSource(workflowSource, jobId);
    for (const requiredNeedle of [
      "WORKER_ENV: ${{ inputs.target == 'staging' && 'staging' || '' }}",
      'wrangler_env_args=()',
      'wrangler_env_args=(--env "$WORKER_ENV")',
      '"${wrangler_env_args[@]}"',
    ]) {
      if (!jobSource.includes(requiredNeedle)) {
        blockers.push(
          `P1: deploy-router-ab ${jobId} does not safely map staging to Wrangler --env and production to the top-level Worker`,
        );
        break;
      }
    }
  }

  const mpcRouterJobSource = workflowJobSource(workflowSource, 'upload_or_deploy_mpc_router');
  for (const requiredNeedle of [
    'ROUTER_AB_PROJECT_POLICY_BOOTSTRAP_JSON: ${{ vars.ROUTER_AB_PROJECT_POLICY_BOOTSTRAP_JSON }}',
    'ROUTER_AB_PROJECT_POLICY_BOOTSTRAP_JSON is required for production',
    'ROUTER_PROJECT_POLICY_BOOTSTRAP_JSON:${ROUTER_AB_PROJECT_POLICY_BOOTSTRAP_JSON}',
  ]) {
    if (!mpcRouterJobSource.includes(requiredNeedle)) {
      blockers.push(
        'P1: deploy-router-ab production MPCRouter does not require and override the project policy bootstrap',
      );
      break;
    }
  }
}

function workflowJobSource(workflowSource, jobId) {
  const startMarker = `  ${jobId}:\n`;
  const start = workflowSource.indexOf(startMarker);
  if (start < 0) {
    return '';
  }
  const nextJob = workflowSource.slice(start + startMarker.length).search(/\n  [a-zA-Z0-9_]+:\n/);
  if (nextJob < 0) {
    return workflowSource.slice(start);
  }
  return workflowSource.slice(start, start + startMarker.length + nextJob);
}

function requireSourceRangeIncludes(label, source, startNeedle, endNeedle, requiredNeedle) {
  const start = source.indexOf(startNeedle);
  const end = source.indexOf(endNeedle, start + startNeedle.length);
  if (start < 0 || end < 0 || !source.slice(start, end).includes(requiredNeedle)) {
    blockers.push(label);
  }
}

function requireFunctionIncludes(label, source, functionName, requiredNeedle) {
  const startNeedle = `fn ${functionName}`;
  const start = source.indexOf(startNeedle);
  const end = source.indexOf('\n}\n', start + startNeedle.length);
  if (start < 0 || end < 0 || !source.slice(start, end).includes(requiredNeedle)) {
    blockers.push(label);
  }
}

function requireSourceRangeOccurrenceCount(
  label,
  source,
  startNeedle,
  endNeedle,
  requiredNeedle,
  expectedCount,
) {
  const start = source.indexOf(startNeedle);
  const end = source.indexOf(endNeedle, start + startNeedle.length);
  if (start < 0 || end < 0) {
    blockers.push(label);
    return;
  }
  const occurrences = source.slice(start, end).split(requiredNeedle).length - 1;
  if (occurrences !== expectedCount) {
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
