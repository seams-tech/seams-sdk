import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { parse as parseYaml } from 'yaml';

const scriptDir = dirname(fileURLToPath(import.meta.url));
const repoRoot = join(scriptDir, '..', '..', '..');

const blockers = [];

function runReleaseReadinessChecks() {
  const strictWorkerModuleSource = readRepoFile(
    'crates/router-ab-cloudflare/src/strict_worker/mod.rs',
  );
  const strictRouterSource = readRepoFile(
    'crates/router-ab-cloudflare/src/strict_worker/router.rs',
  );
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
  const deployStackWorkflow = readRepoFile(
    '.github/workflows/internal-deploy-cloudflare-stack.yml',
  );
  const deployStackDocument = readRepoWorkflow(
    '.github/workflows/internal-deploy-cloudflare-stack.yml',
  );
  const deployStagingDocument = readRepoWorkflow(
    '.github/workflows/deploy-staging-cloudflare-stack.yml',
  );
  const deployProductionDocument = readRepoWorkflow(
    '.github/workflows/deploy-production-cloudflare-stack.yml',
  );
  const deploymentSources = [
    routerWrangler,
    deriverAWrangler,
    deriverBWrangler,
    signingWorkerWrangler,
    deployStackWorkflow,
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
  if (
    strictWorkerSource.includes('strict SigningWorker normal-signing handler is not configured')
  ) {
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
  if (
    cloudflareSource.includes('STRICT_CLOUDFLARE_WALLET_SESSION_BUDGET_ENFORCEMENT_REQUIRED_V1')
  ) {
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
  requireDeployWorkflowSplitEnvironmentBoundary(deployStackWorkflow, deployStackDocument);
  requireDeployWorkflowBranchPromotionBoundary(
    deployStackDocument,
    deployStagingDocument,
    deployProductionDocument,
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

  if (blockers.length > 0) {
    console.error('Router A/B release blockers remain:');
    for (const blocker of blockers) {
      console.error(`- ${blocker}`);
    }
    process.exit(1);
  }

  console.log('Router A/B release blockers clear.');
}

function readRepoFile(path) {
  return readFileSync(join(repoRoot, path), 'utf8');
}

function requireDeployWorkflowSplitEnvironmentBoundary(workflowSource, workflow) {
  const preflightJob = requireWorkflowJob(
    workflow,
    'preflight_release',
    'P1: internal Cloudflare stack deployment is missing preflight_release',
  );
  requireExactValue(
    'P1: internal Cloudflare stack preflight_release does not derive its protected environment from the fixed release target',
    preflightJob?.environment?.name,
    "${{ format('{0}-mpc-router', inputs.target) }}",
  );

  for (const [jobId, requiredEnvironmentExpression] of [
    ['deploy_mpc_router', "${{ format('{0}-mpc-router', inputs.target) }}"],
    ['deploy_deriver_a', "${{ format('{0}-deriver-a', inputs.target) }}"],
    ['deploy_deriver_b', "${{ format('{0}-deriver-b', inputs.target) }}"],
    ['deploy_signing_worker', "${{ format('{0}-signing-worker', inputs.target) }}"],
  ]) {
    const job = requireWorkflowJob(
      workflow,
      jobId,
      `P1: internal Cloudflare stack deployment is missing ${jobId}`,
    );
    if (!job) continue;
    const environment = isRecord(job.environment) ? job.environment.name : undefined;
    requireExactValue(
      `P1: internal Cloudflare stack ${jobId} does not derive its protected environment from the fixed release target`,
      environment,
      requiredEnvironmentExpression,
    );
  }

  for (const [jobId, forbiddenNeedles] of [
    [
      'deploy_mpc_router',
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
      'deploy_signing_worker',
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
      'deploy_deriver_a',
      [
        'DERIVER_B_ROOT_SHARE_WIRE_SECRET',
        'DERIVER_B_ENVELOPE_HPKE_PRIVATE_KEY',
        'DERIVER_B_PEER_SIGNING_KEY',
        'SIGNING_WORKER_SERVER_OUTPUT_HPKE_PRIVATE_KEY',
      ],
    ],
    [
      'deploy_deriver_b',
      [
        'DERIVER_A_ROOT_SHARE_WIRE_SECRET',
        'DERIVER_A_ENVELOPE_HPKE_PRIVATE_KEY',
        'DERIVER_A_PEER_SIGNING_KEY',
        'SIGNING_WORKER_SERVER_OUTPUT_HPKE_PRIVATE_KEY',
      ],
    ],
  ]) {
    const jobSource = workflowJobSource(workflowSource, jobId);
    if (!jobSource) continue;
    for (const forbiddenNeedle of forbiddenNeedles) {
      if (jobSource.includes(forbiddenNeedle)) {
        blockers.push(
          `P1: internal Cloudflare stack ${jobId} references forbidden secret ${forbiddenNeedle}`,
        );
      }
    }
  }
}

function requireDeployWorkflowBranchPromotionBoundary(
  workflow,
  stagingWorkflow,
  productionWorkflow,
) {
  for (const [environment, branch, entrypoint] of [
    ['staging', 'dev', stagingWorkflow],
    ['production', 'main', productionWorkflow],
  ]) {
    requireExactValue(
      `P1: ${environment} deployment entrypoint has the wrong workflow name`,
      entrypoint?.name,
      `Deploy / ${environment} / cloudflare-stack`,
    );
    requireTriggerPresent(
      `P1: ${environment} deployment entrypoint is missing workflow_dispatch`,
      entrypoint,
      'workflow_dispatch',
    );
    requireTriggerPresent(
      `P1: ${environment} deployment entrypoint is missing workflow_run`,
      entrypoint,
      'workflow_run',
    );
    requireArrayIncludes(
      `P1: ${environment} deployment entrypoint does not wait for repository validation`,
      entrypoint?.on?.workflow_run?.workflows,
      'Validate / repository',
    );
    requireArrayIncludes(
      `P1: ${environment} deployment entrypoint has the wrong validation branch`,
      entrypoint?.on?.workflow_run?.branches,
      branch,
    );

    const automaticJob = requireWorkflowJob(
      entrypoint,
      'automatic_release',
      `P1: ${environment} deployment entrypoint is missing automatic_release`,
    );
    requireExactValue(
      `P1: ${environment} automatic release must call the internal release workflow`,
      automaticJob?.uses,
      './.github/workflows/internal-release-cloudflare-stack.yml',
    );
    requireExactValue(
      `P1: ${environment} automatic release has the wrong target`,
      automaticJob?.with?.target,
      environment,
    );
    requireExactValue(
      `P1: ${environment} automatic release does not pass the workflow-run SHA`,
      automaticJob?.with?.source_sha,
      '${{ github.event.workflow_run.head_sha }}',
    );
    requireExactValue(
      `P1: ${environment} automatic release does not pass the validation run ID`,
      automaticJob?.with?.validation_run_id,
      '${{ github.event.workflow_run.id }}',
    );

    const manualJob = requireWorkflowJob(
      entrypoint,
      'manual_promotion',
      `P1: ${environment} deployment entrypoint is missing manual_promotion`,
    );
    requireExactValue(
      `P1: ${environment} manual promotion must call the internal deploy workflow`,
      manualJob?.uses,
      './.github/workflows/internal-deploy-cloudflare-stack.yml',
    );
    requireExactValue(
      `P1: ${environment} manual promotion has the wrong target`,
      manualJob?.with?.target,
      environment,
    );
    requireExactValue(
      `P1: ${environment} manual promotion does not pass the exact source SHA`,
      manualJob?.with?.deploy_sha,
      '${{ inputs.source_sha }}',
    );
    requireExactValue(
      `P1: ${environment} manual promotion does not pass the artifact run ID`,
      manualJob?.with?.artifact_run_id,
      '${{ inputs.artifact_run_id }}',
    );
    requireExactValue(
      `P1: ${environment} manual promotion does not pass the release-set ID`,
      manualJob?.with?.release_set_id,
      '${{ inputs.release_set_id }}',
    );
    requireExactValue(
      `P1: ${environment} manual promotion has the wrong source branch`,
      manualJob?.with?.source_branch,
      branch,
    );
    requireExactValue(
      `P1: ${environment} manual promotion must disable automatic branch-tip enforcement`,
      manualJob?.with?.enforce_current_branch,
      false,
    );
  }

  requireTriggerPresent(
    'P1: internal Cloudflare stack deployment is missing workflow_call',
    workflow,
    'workflow_call',
  );
  if (isRecord(workflow?.on) && Object.hasOwn(workflow.on, 'workflow_dispatch')) {
    blockers.push('P1: internal Cloudflare stack deployment exposes workflow_dispatch');
  }
  if (isRecord(workflow?.on) && Object.hasOwn(workflow.on, 'workflow_run')) {
    blockers.push('P1: internal Cloudflare stack deployment exposes workflow_run');
  }
  for (const inputName of [
    'target',
    'deploy_sha',
    'artifact_run_id',
    'release_set_id',
    'source_branch',
  ]) {
    requireWorkflowInput(
      `P1: internal Cloudflare stack workflow_call input ${inputName} is not required string data`,
      workflow,
      inputName,
      'string',
    );
  }
  requireExactValue(
    'P1: internal Cloudflare stack does not resolve the selected exact SHA',
    workflow?.env?.DEPLOY_SHA,
    '${{ inputs.deploy_sha }}',
  );
  requireExactValue(
    'P1: internal Cloudflare stack does not pass the accepted artifact run ID',
    workflow?.env?.ARTIFACT_RUN_ID,
    '${{ inputs.artifact_run_id }}',
  );
  requireExactValue(
    'P1: internal Cloudflare stack does not pass the accepted release-set ID',
    workflow?.env?.RELEASE_SET_ID,
    '${{ inputs.release_set_id }}',
  );
  requireExactValue(
    'P1: internal Cloudflare stack does not pass the source branch',
    workflow?.env?.DEPLOY_SOURCE_BRANCH,
    '${{ inputs.source_branch }}',
  );
  for (const jobId of ROUTER_AB_DEPLOY_JOB_IDS) {
    const job = requireWorkflowJob(
      workflow,
      jobId,
      `P1: internal Cloudflare stack deployment is missing ${jobId}`,
    );
    if (!job) continue;
    requireExactValue(
      `P1: internal Cloudflare stack ${jobId} does not map staging to Wrangler --env and production to the top-level Worker`,
      job.env?.WORKER_ENV,
      "${{ inputs.target == 'staging' && 'staging' || '' }}",
    );
    for (const fragment of [
      'wrangler_env_args=()',
      'wrangler_env_args=(--env "$WORKER_ENV")',
      '"${wrangler_env_args[@]}"',
    ]) {
      requireJobRunFragment(
        `P1: internal Cloudflare stack ${jobId} does not safely map staging to Wrangler --env and production to the top-level Worker`,
        job,
        fragment,
      );
    }
  }

  const mpcRouterJob = requireWorkflowJob(
    workflow,
    'deploy_mpc_router',
    'P1: internal Cloudflare stack deployment is missing deploy_mpc_router',
  );
  requireExactValue(
    'P1: internal Cloudflare stack production MPCRouter does not expose the project policy bootstrap variable',
    mpcRouterJob?.env?.ROUTER_AB_PROJECT_POLICY_BOOTSTRAP_JSON,
    '${{ vars.ROUTER_AB_PROJECT_POLICY_BOOTSTRAP_JSON }}',
  );
  requireJobRunFragment(
    'P1: internal Cloudflare stack production MPCRouter does not require the project policy bootstrap',
    mpcRouterJob,
    'ROUTER_AB_PROJECT_POLICY_BOOTSTRAP_JSON is required for production',
  );
  requireJobRunFragment(
    'P1: internal Cloudflare stack production MPCRouter does not override the project policy bootstrap',
    mpcRouterJob,
    'ROUTER_PROJECT_POLICY_BOOTSTRAP_JSON:${ROUTER_AB_PROJECT_POLICY_BOOTSTRAP_JSON}',
  );

  requireRouterArtifactBoundaries(workflow);
  requireRouterDependencyOrdering(workflow);
}

const ROUTER_AB_DEPLOY_JOB_IDS = [
  'deploy_mpc_router',
  'deploy_deriver_a',
  'deploy_deriver_b',
  'deploy_signing_worker',
];

const ROUTER_AB_ARTIFACT_ROLES = [
  ['signing-worker', 'deploy_signing_worker'],
  ['deriver-a', 'deploy_deriver_a'],
  ['deriver-b', 'deploy_deriver_b'],
  ['router', 'deploy_mpc_router'],
];

function requireRouterArtifactBoundaries(workflow) {
  const preflightJob = requireWorkflowJob(
    workflow,
    'preflight_release',
    'P1: Router A/B deployment is missing the accepted release preflight',
  );
  requireExactValue(
    'P1: Router A/B release preflight does not pass the accepted artifact run ID',
    workflow?.env?.ARTIFACT_RUN_ID,
    '${{ inputs.artifact_run_id }}',
  );
  requireExactValue(
    'P1: Router A/B release preflight does not pass the release-set ID',
    workflow?.env?.RELEASE_SET_ID,
    '${{ inputs.release_set_id }}',
  );
  requireCheckoutRef(
    'P1: Router A/B release preflight does not check out the selected exact SHA',
    preflightJob,
  );
  const releaseSetDownloadStep = requireWorkflowStep(
    'P1: Router A/B release preflight is missing the release-set artifact download',
    preflightJob,
    isDownloadArtifactStep,
  );
  requireExactStepValue(
    'P1: Router A/B release preflight downloads the wrong release-set artifact',
    releaseSetDownloadStep,
    'name',
    'release-set-${{ env.RELEASE_SET_ID }}',
  );
  requireExactStepValue(
    'P1: Router A/B release preflight downloads the release set into the wrong path',
    releaseSetDownloadStep,
    'path',
    '.release-artifacts/release-set',
  );
  requireExactStepValue(
    'P1: Router A/B release preflight does not use the GitHub token for cross-run artifacts',
    releaseSetDownloadStep,
    'github-token',
    '${{ secrets.GITHUB_TOKEN }}',
  );
  requireExactStepValue(
    'P1: Router A/B release preflight does not constrain the artifact repository',
    releaseSetDownloadStep,
    'repository',
    '${{ github.repository }}',
  );
  requireExactStepValue(
    'P1: Router A/B release preflight does not select the accepted artifact run',
    releaseSetDownloadStep,
    'run-id',
    '${{ env.ARTIFACT_RUN_ID }}',
  );
  const releaseSetVerificationStep = requireWorkflowStep(
    'P1: Router A/B release preflight is missing release-set verification',
    preflightJob,
    isReleaseSetVerificationStep,
  );
  for (const fragment of [
    'node scripts/deployment-release.mjs verify',
    '--manifest "$RELEASE_MANIFEST"',
    '--target "$DEPLOY_TARGET"',
    '--source-sha "$DEPLOY_SHA"',
    '--artifact-run-id "$ARTIFACT_RUN_ID"',
    '--release-set-id "$RELEASE_SET_ID"',
  ]) {
    requireStepRunFragment(
      'P1: Router A/B release preflight verification is incomplete',
      releaseSetVerificationStep,
      fragment,
    );
  }

  for (const [role, jobId] of ROUTER_AB_ARTIFACT_ROLES) {
    const job = requireWorkflowJob(
      workflow,
      jobId,
      `P1: internal Cloudflare stack deployment is missing ${jobId}`,
    );
    if (!job) continue;
    requireExactValue(
      `P1: ${role} deployment does not pass the selected target to artifact verification`,
      job.env?.ROUTER_AB_DEPLOY_TARGET,
      '${{ inputs.target }}',
    );
    requireExactValue(
      `P1: ${role} deployment does not pass the selected exact SHA to artifact verification`,
      job.env?.ROUTER_AB_DEPLOY_SHA,
      '${{ inputs.deploy_sha }}',
    );
    requireExactValue(
      `P1: ${role} deployment has the wrong artifact identity`,
      job.env?.ROUTER_AB_ARTIFACT_IDENTITY_JSON,
      JSON.stringify({ profile: 'release', role }),
    );
    requireCheckoutRef(`P1: ${role} deployment does not check out the selected exact SHA`, job);

    const downloadStep = requireWorkflowStep(
      `P1: ${role} deployment is missing its artifact download`,
      job,
      isDownloadArtifactStep,
    );
    requireExactStepValue(
      `P1: ${role} deployment downloads an artifact with the wrong target or SHA`,
      downloadStep,
      'name',
      `release-\${{ env.DEPLOY_TARGET }}-\${{ env.DEPLOY_SHA }}-${role}`,
    );
    requireExactStepValue(
      `P1: ${role} deployment downloads its artifact into the wrong path`,
      downloadStep,
      'path',
      'crates/router-ab-cloudflare',
    );
    requireExactStepValue(
      `P1: ${role} deployment does not use the GitHub token for cross-run artifacts`,
      downloadStep,
      'github-token',
      '${{ secrets.GITHUB_TOKEN }}',
    );
    requireExactStepValue(
      `P1: ${role} deployment does not constrain the artifact repository`,
      downloadStep,
      'repository',
      '${{ github.repository }}',
    );
    requireExactStepValue(
      `P1: ${role} deployment does not select the accepted artifact run`,
      downloadStep,
      'run-id',
      '${{ env.ARTIFACT_RUN_ID }}',
    );
    const verificationStep = requireWorkflowStep(
      `P1: ${role} deployment is missing artifact verification`,
      job,
      isArtifactVerificationStep,
    );
    for (const fragment of [
      `--kind ${role}`,
      '--target "$DEPLOY_TARGET"',
      '--sha "$DEPLOY_SHA"',
      `--root crates/router-ab-cloudflare/build/${role}`,
      `--manifest crates/router-ab-cloudflare/.release-artifacts/${role}.json`,
      '--identity-json "$ROUTER_AB_ARTIFACT_IDENTITY_JSON"',
    ]) {
      requireStepRunFragment(
        `P1: ${role} deployment artifact verification is incomplete`,
        verificationStep,
        fragment,
      );
    }
  }
}

function requireRouterDependencyOrdering(workflow) {
  const expectedRoleNeeds = ['preflight_release'];
  for (const jobId of ['deploy_signing_worker', 'deploy_deriver_a', 'deploy_deriver_b']) {
    const job = requireWorkflowJob(
      workflow,
      jobId,
      `P1: Router A/B workflow is missing ${jobId} for independent role deployment`,
    );
    requireJobNeeds(
      `P1: ${jobId} must run independently after release preflight`,
      job,
      expectedRoleNeeds,
    );
  }
  const routerJob = requireWorkflowJob(
    workflow,
    'deploy_mpc_router',
    'P1: Router A/B workflow is missing deploy_mpc_router for activation ordering',
  );
  requireJobNeeds(
    'P1: MPCRouter activation must wait for every selected Router A/B role',
    routerJob,
    ['preflight_release', 'deploy_signing_worker', 'deploy_deriver_a', 'deploy_deriver_b'],
  );
  requireExpressionFragments(
    'P1: MPCRouter activation does not require every selected Router A/B role to succeed',
    routerJob?.if,
    [
      'always()',
      "needs.preflight_release.result == 'success'",
      "contains(fromJSON(needs.preflight_release.outputs.selected_components), 'router')",
      "needs.deploy_signing_worker.result == 'success'",
      "needs.deploy_deriver_a.result == 'success'",
      "needs.deploy_deriver_b.result == 'success'",
    ],
  );

  const gatewayJob = requireWorkflowJob(
    workflow,
    'deploy_gateway',
    'P1: Router A/B workflow is missing deploy_gateway after release preflight',
  );
  requireJobNeeds('P1: deploy_gateway must run after release preflight', gatewayJob, [
    'preflight_release',
  ]);
  const pagesJob = requireWorkflowJob(
    workflow,
    'deploy_pages',
    'P1: Router A/B workflow is missing deploy_pages after release preflight',
  );
  requireJobNeeds('P1: deploy_pages must wait for release preflight and Gateway', pagesJob, [
    'preflight_release',
    'deploy_gateway',
  ]);
  const finalSmokeJob = requireWorkflowJob(
    workflow,
    'final_smoke',
    'P1: Router A/B workflow is missing final_smoke release validation',
  );
  requireJobNeeds(
    'P1: final smoke must wait for Router A/B, gateway, and Pages deployment',
    finalSmokeJob,
    ['preflight_release', 'deploy_mpc_router', 'deploy_gateway', 'deploy_pages'],
  );
  requireExpressionFragments(
    'P1: final smoke does not wait for every selected deployment without failure',
    finalSmokeJob?.if,
    [
      'always()',
      "needs.preflight_release.result == 'success'",
      "needs.deploy_mpc_router.result == 'success'",
      "needs.deploy_gateway.result == 'success'",
      "needs.deploy_pages.result == 'success'",
    ],
  );
}

export function parseWorkflowYaml(source, label = 'workflow') {
  if (typeof source !== 'string') {
    throw new TypeError(`${label} must be YAML source text`);
  }
  let parsed;
  try {
    parsed = parseYaml(source, { version: '1.2' });
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    throw new Error(`${label} is not valid YAML: ${message}`);
  }
  if (!isRecord(parsed)) {
    throw new Error(`${label} must decode to a YAML mapping`);
  }
  return parsed;
}

function readRepoWorkflow(path) {
  try {
    return parseWorkflowYaml(readRepoFile(path), path);
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    blockers.push(`P1: ${message}`);
    return null;
  }
}

function isRecord(value) {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}

function requireExactValue(label, actual, expected) {
  if (actual !== expected) {
    blockers.push(`${label}: expected ${JSON.stringify(expected)}`);
  }
}

function requireArrayIncludes(label, actual, expected) {
  if (!Array.isArray(actual) || !actual.includes(expected)) {
    blockers.push(`${label}: expected ${JSON.stringify(expected)}`);
  }
}

function requireExpressionFragments(label, actual, fragments) {
  if (typeof actual !== 'string' || !includesAllFragments(actual, fragments)) {
    blockers.push(label);
  }
}

function requireTriggerPresent(label, workflow, triggerName) {
  if (!isRecord(workflow?.on) || !Object.hasOwn(workflow.on, triggerName)) {
    blockers.push(label);
  }
}

function requireWorkflowInput(label, workflow, inputName, expectedType) {
  const input = workflow?.on?.workflow_call?.inputs?.[inputName];
  if (!isRecord(input) || input.required !== true || input.type !== expectedType) {
    blockers.push(label);
  }
}

function requireWorkflowDispatchInput(label, workflow, inputName, expectedType) {
  const input = workflow?.on?.workflow_dispatch?.inputs?.[inputName];
  if (!isRecord(input) || input.required !== true || input.type !== expectedType) {
    blockers.push(label);
  }
}

function requireWorkflowJob(workflow, jobId, missingMessage) {
  const job = workflow?.jobs?.[jobId];
  if (!isRecord(job)) {
    blockers.push(missingMessage);
    return null;
  }
  return job;
}

function requireJobNeeds(label, job, expectedNeeds) {
  if (!job) return;
  const actualNeeds = normalizeNeeds(job.needs);
  if (
    actualNeeds === null ||
    actualNeeds.length !== expectedNeeds.length ||
    new Set(actualNeeds).size !== actualNeeds.length ||
    !containsOnlyExpectedNeeds(actualNeeds, expectedNeeds)
  ) {
    blockers.push(`${label}: expected ${expectedNeeds.join(', ')}`);
  }
}

function normalizeNeeds(value) {
  if (typeof value === 'string') return [value];
  if (Array.isArray(value) && allStrings(value)) return value;
  return null;
}

function containsOnlyExpectedNeeds(actualNeeds, expectedNeeds) {
  for (const need of actualNeeds) {
    if (!expectedNeeds.includes(need)) return false;
  }
  return true;
}

function allStrings(values) {
  for (const value of values) {
    if (typeof value !== 'string') return false;
  }
  return true;
}

function requireCheckoutRef(label, job) {
  const checkoutStep = requireWorkflowStep(label, job, isCheckoutStep);
  requireExactStepValue(
    `${label}: checkout ref is not the selected exact SHA`,
    checkoutStep,
    'ref',
    '${{ env.DEPLOY_SHA }}',
  );
}

function requireWorkflowStep(label, job, predicate) {
  const steps = job?.steps;
  const step = Array.isArray(steps) ? steps.find(predicate) : undefined;
  if (!isRecord(step)) {
    blockers.push(label);
    return null;
  }
  return step;
}

function requireExactStepValue(label, step, key, expected) {
  requireExactValue(label, step?.with?.[key], expected);
}

function requireJobRunFragment(label, job, fragment) {
  if (!jobContainsRunFragment(job, fragment)) {
    blockers.push(label);
  }
}

function requireStepRunFragment(label, step, fragment) {
  if (typeof step?.run !== 'string' || !step.run.includes(fragment)) {
    blockers.push(label);
  }
}

function stepHasRunFragment(step, fragment) {
  return isRecord(step) && typeof step.run === 'string' && step.run.includes(fragment);
}

function jobContainsRunFragment(job, fragment) {
  const steps = job?.steps;
  if (!Array.isArray(steps)) return false;
  for (const step of steps) {
    if (stepHasRunFragment(step, fragment)) return true;
  }
  return false;
}

function includesAllFragments(source, fragments) {
  for (const fragment of fragments) {
    if (!source.includes(fragment)) return false;
  }
  return true;
}

function isCheckoutStep(step) {
  return isRecord(step) && step.uses === 'actions/checkout@v6';
}

function isDownloadArtifactStep(step) {
  return isRecord(step) && step.uses === 'actions/download-artifact@v8';
}

function isArtifactVerificationStep(step) {
  return (
    isRecord(step) &&
    typeof step.run === 'string' &&
    step.run.includes('node scripts/deployment-artifact.mjs verify')
  );
}

function isReleaseSetVerificationStep(step) {
  return (
    isRecord(step) &&
    typeof step.run === 'string' &&
    step.run.includes('node scripts/deployment-release.mjs verify')
  );
}

function workflowJobSource(workflowSource, jobId) {
  const startMarker = `  ${jobId}:\n`;
  const start = workflowSource.indexOf(startMarker);
  if (start < 0) {
    return '';
  }
  const nextJob = workflowSource.slice(start + startMarker.length).search(/\n {2}[a-zA-Z0-9_]+:\n/);
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

if (process.argv[1] !== undefined && import.meta.url === pathToFileURL(process.argv[1]).href) {
  runReleaseReadinessChecks();
}
