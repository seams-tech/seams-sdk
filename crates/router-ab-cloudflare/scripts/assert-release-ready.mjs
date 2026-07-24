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
  const deployStagingSource = readRepoFile('.github/workflows/deploy-staging-cloudflare-stack.yml');
  const deployProductionSource = readRepoFile(
    '.github/workflows/deploy-production-cloudflare-stack.yml',
  );
  const deployStagingFrontendSource = readRepoFile('.github/workflows/deploy-staging-frontend.yml');
  const deployProductionFrontendSource = readRepoFile(
    '.github/workflows/deploy-production-frontend.yml',
  );
  const deployStagingDocument = readRepoWorkflow(
    '.github/workflows/deploy-staging-cloudflare-stack.yml',
  );
  const deployProductionDocument = readRepoWorkflow(
    '.github/workflows/deploy-production-cloudflare-stack.yml',
  );
  const deployStagingFrontendDocument = readRepoWorkflow(
    '.github/workflows/deploy-staging-frontend.yml',
  );
  const deployProductionFrontendDocument = readRepoWorkflow(
    '.github/workflows/deploy-production-frontend.yml',
  );
  const deploymentSources = [
    routerWrangler,
    deriverAWrangler,
    deriverBWrangler,
    signingWorkerWrangler,
    deployStagingSource,
    deployProductionSource,
    deployStagingFrontendSource,
    deployProductionFrontendSource,
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
  requireDeploymentWorkflowBoundaries([
    {
      environment: 'staging',
      backend: deployStagingDocument,
      backendSource: deployStagingSource,
      frontend: deployStagingFrontendDocument,
      frontendSource: deployStagingFrontendSource,
    },
    {
      environment: 'production',
      backend: deployProductionDocument,
      backendSource: deployProductionSource,
      frontend: deployProductionFrontendDocument,
      frontendSource: deployProductionFrontendSource,
    },
  ]);
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

function requireDeploymentWorkflowBoundaries(targets) {
  for (const target of targets) {
    const branch = target.environment === 'production' ? 'main' : 'dev';
    const backend = target.backend;
    const frontend = target.frontend;
    const backendSource = target.backendSource;
    const frontendSource = target.frontendSource;

    requireExactValue(
      `P1: ${target.environment} backend deployment entrypoint has the wrong workflow name`,
      backend?.name,
      `Deploy / ${target.environment} / cloudflare-stack`,
    );
    requireExactValue(
      `P1: ${target.environment} frontend deployment entrypoint has the wrong workflow name`,
      frontend?.name,
      `Deploy / ${target.environment} / frontend`,
    );
    requireTriggerPresent(
      `P1: ${target.environment} backend deployment entrypoint is missing workflow_dispatch`,
      backend,
      'workflow_dispatch',
    );
    requireTriggerPresent(
      `P1: ${target.environment} backend deployment entrypoint is missing workflow_run`,
      backend,
      'workflow_run',
    );
    requireTriggerPresent(
      `P1: ${target.environment} frontend deployment entrypoint is missing workflow_dispatch`,
      frontend,
      'workflow_dispatch',
    );
    requireTriggerPresent(
      `P1: ${target.environment} frontend deployment entrypoint is missing workflow_run`,
      frontend,
      'workflow_run',
    );
    requireArrayIncludes(
      `P1: ${target.environment} backend deployment does not wait for repository validation`,
      backend?.on?.workflow_run?.workflows,
      'Validate / repository',
    );
    requireArrayIncludes(
      `P1: ${target.environment} frontend deployment does not wait for its backend workflow`,
      frontend?.on?.workflow_run?.workflows,
      `Deploy / ${target.environment} / cloudflare-stack`,
    );
    requireArrayIncludes(
      `P1: ${target.environment} backend deployment has the wrong validation branch`,
      backend?.on?.workflow_run?.branches,
      branch,
    );
    requireArrayIncludes(
      `P1: ${target.environment} frontend deployment has the wrong backend branch`,
      frontend?.on?.workflow_run?.branches,
      branch,
    );

    for (const [label, source, event] of [
      ['backend', backendSource, "github.event.workflow_run.event == 'push'"],
      ['frontend', frontendSource, "github.event.workflow_run.event == 'workflow_run'"],
    ]) {
      if (!source.includes(event)) {
        blockers.push(
          `P1: ${target.environment} ${label} automatic deployment has the wrong upstream event`,
        );
      }
      if (!source.includes("github.event.workflow_run.conclusion == 'success'")) {
        blockers.push(
          `P1: ${target.environment} ${label} automatic deployment does not require upstream success`,
        );
      }
      if (source.includes('workflow_call')) {
        blockers.push(`P1: ${target.environment} ${label} deployment declares workflow_call`);
      }
    }

    const backendJobs = backend?.jobs ?? {};
    const frontendJobs = frontend?.jobs ?? {};
    for (const [jobId, job] of Object.entries(backendJobs)) {
      if (!isRecord(job?.environment)) continue;
      const environmentName = job.environment.name;
      if (
        typeof environmentName !== 'string' ||
        !environmentName.startsWith(`${target.environment}-`)
      ) {
        blockers.push(
          `P1: ${target.environment} backend job ${jobId} is not bound to a target-specific GitHub Environment`,
        );
      }
    }
    for (const [jobId, job] of Object.entries(frontendJobs)) {
      if (!isRecord(job?.environment)) continue;
      const environmentName = job.environment.name;
      if (
        typeof environmentName !== 'string' ||
        environmentName !== `${target.environment}-frontend`
      ) {
        blockers.push(
          `P1: ${target.environment} frontend job ${jobId} is not bound to ${target.environment}-frontend`,
        );
      }
    }

    for (const prefix of ['auto_', 'manual_']) {
      const preflight = requireWorkflowJob(
        backend,
        `${prefix}preflight_release`,
        `P1: ${target.environment} backend deployment is missing ${prefix}preflight_release`,
      );
      const signingWorker = requireWorkflowJob(
        backend,
        `${prefix}deploy_signing_worker`,
        `P1: ${target.environment} backend deployment is missing ${prefix}deploy_signing_worker`,
      );
      const deriverA = requireWorkflowJob(
        backend,
        `${prefix}deploy_deriver_a`,
        `P1: ${target.environment} backend deployment is missing ${prefix}deploy_deriver_a`,
      );
      const deriverB = requireWorkflowJob(
        backend,
        `${prefix}deploy_deriver_b`,
        `P1: ${target.environment} backend deployment is missing ${prefix}deploy_deriver_b`,
      );
      const router = requireWorkflowJob(
        backend,
        `${prefix}deploy_mpc_router`,
        `P1: ${target.environment} backend deployment is missing ${prefix}deploy_mpc_router`,
      );
      const gateway = requireWorkflowJob(
        backend,
        `${prefix}deploy_gateway`,
        `P1: ${target.environment} backend deployment is missing ${prefix}deploy_gateway`,
      );
      if (prefix === 'auto_') {
        requireJobNeeds(
          `P1: ${target.environment} automatic Router role deployment is not gated by release preflight`,
          signingWorker,
          ['auto_preflight_release', 'auto_create_release_set'],
        );
        requireJobNeeds(
          `P1: ${target.environment} automatic Router activation does not wait for every role`,
          router,
          [
            'auto_preflight_release',
            'auto_deploy_signing_worker',
            'auto_deploy_deriver_a',
            'auto_deploy_deriver_b',
            'auto_create_release_set',
          ],
        );
      } else {
        requireJobNeeds(
          `P1: ${target.environment} manual Router role deployment is not gated by release preflight`,
          signingWorker,
          ['manual_preflight_release'],
        );
        requireJobNeeds(
          `P1: ${target.environment} manual Router activation does not wait for every role`,
          router,
          [
            'manual_preflight_release',
            'manual_deploy_signing_worker',
            'manual_deploy_deriver_a',
            'manual_deploy_deriver_b',
          ],
        );
      }
      requireJobNeeds(
        `P1: ${target.environment} ${prefix} Gateway deployment is missing release preflight`,
        gateway,
        prefix === 'auto_'
          ? ['auto_preflight_release', 'auto_create_release_set']
          : ['manual_preflight_release'],
      );
      if (!preflight?.env || preflight.env.DEPLOY_TARGET !== target.environment) {
        blockers.push(
          `P1: ${target.environment} ${prefix}preflight_release has an unfixed deployment target`,
        );
      }
    }

    for (const [jobId, job] of Object.entries(backendJobs)) {
      const jobName = typeof job?.name === 'string' ? job.name : '';
      if (jobName.includes('cloudflare-pages')) {
        blockers.push(
          `P1: ${target.environment} backend workflow contains frontend deployment authority in ${jobId}`,
        );
      }
    }
    for (const [jobId, job] of Object.entries(frontendJobs)) {
      const jobName = typeof job?.name === 'string' ? job.name : '';
      if (
        jobName.includes('cloudflare-api-gateway') ||
        jobName.includes('cloudflare-mpc-router-ab')
      ) {
        blockers.push(
          `P1: ${target.environment} frontend workflow contains backend deployment authority in ${jobId}`,
        );
      }
    }
    for (const forbidden of [
      'RELAY_SESSION_HMAC_SECRET',
      'ACCOUNT_ID_DERIVATION_SECRET',
      'ROUTER_AB_INTERNAL_SERVICE_AUTH_SECRET',
      'DERIVER_A_ROOT_SHARE_WIRE_SECRET',
      'DERIVER_B_ROOT_SHARE_WIRE_SECRET',
      'SIGNING_WORKER_SERVER_OUTPUT_HPKE_PRIVATE_KEY',
      'wrangler deploy',
    ]) {
      if (frontendSource.includes(forbidden)) {
        blockers.push(
          `P1: ${target.environment} frontend workflow references backend deployment material ${forbidden}`,
        );
      }
    }
    for (const forbidden of [
      'CF_PAGES_PROJECT_VITE',
      'CF_PAGES_PROJECT_WALLET',
      'wrangler pages deploy',
    ]) {
      if (backendSource.includes(forbidden)) {
        blockers.push(
          `P1: ${target.environment} backend workflow references frontend deployment material ${forbidden}`,
        );
      }
    }

    const frontendInputNames = Object.keys(frontend?.on?.workflow_dispatch?.inputs ?? {});
    for (const inputName of [
      'source_sha',
      'artifact_run_id',
      'release_set_id',
      'backend_receipt_run_id',
    ]) {
      if (!frontendInputNames.includes(inputName)) {
        blockers.push(`P1: ${target.environment} frontend promotion is missing ${inputName}`);
      }
    }
  }
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

function requireTriggerPresent(label, workflow, triggerName) {
  if (!isRecord(workflow?.on) || !Object.hasOwn(workflow.on, triggerName)) {
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
