import { execFileSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { readdirSync, readFileSync, writeFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const SCRIPT_DIR = dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = resolve(SCRIPT_DIR, '../../..');
const EVIDENCE_PATH = resolve(
  REPO_ROOT,
  'docs/evidence/r120-boundary-inventory-v1.json',
);

const SEARCH_TERMS = [
  'TenantRoot',
  'tenant_root',
  'tenantRoot',
  'RootShareEpoch',
  'root_share_epoch',
  'rootShareEpoch',
  'activation_epoch',
  'TenantRootShareEpoch',
  'tenant_root_share_epoch',
  'tenantRootShareEpoch',
  'signingRootId',
  'signing_root_id',
  'signingRootVersion',
  'signing_root_version',
  'DERIVER_A_ROOT_SHARE_WIRE_SECRET',
  'DERIVER_B_ROOT_SHARE_WIRE_SECRET',
  'root_share_wire',
  'root share',
  'derivation-root/v1',
  'PrfPurpose',
  'PrfOutput32',
  'EcdsaPrfPurposeV1',
  'server contribution root',
  'ed25519_yao',
  'pair_digest',
  'root_metadata_digest',
  'circuit_digest',
];

const IGNORED_DEPLOYMENT_BOUNDARIES = [
  {
    path: '.env.router-ab.deriver-a.local',
    category: 'deployment',
    rationale: 'ignored local Deriver A secret binding; inventory records the boundary, never its contents',
  },
  {
    path: '.env.router-ab.deriver-b.local',
    category: 'deployment',
    rationale: 'ignored local Deriver B secret binding; inventory records the boundary, never its contents',
  },
];

const GENERATED_ARTIFACTS = new Map([
  [
    'crates/ed25519-yao/artifacts/passive-benchmark-v1/phase5-stream-wire-kats-v1.json',
    {
      regenerate:
        'python3 tools/ed25519-yao-verifier/generate_phase5_stream_kats.py',
      verify:
        'python3 tools/ed25519-yao-verifier/generate_phase5_stream_kats.py --check',
    },
  ],
  [
    'crates/router-ab-core/fixtures/protocol/ed25519-yao/pair-digest-vectors-v1.json',
    {
      regenerate:
        'UPDATE_ROUTER_AB_ED25519_YAO_PAIR_DIGEST_VECTORS=1 cargo test --manifest-path crates/router-ab-core/Cargo.toml --test ed25519_yao_pair_digest_vectors',
      verify:
        'cargo test --manifest-path crates/router-ab-core/Cargo.toml --test ed25519_yao_pair_digest_vectors',
    },
  ],
  [
    'crates/router-ab-core/fixtures/protocol/payload/payload-vectors-v1.json',
    {
      regenerate:
        'cargo run --manifest-path crates/router-ab-core/Cargo.toml --bin emit_payload_vectors > crates/router-ab-core/fixtures/protocol/payload/payload-vectors-v1.json',
      verify:
        'cargo test --manifest-path crates/router-ab-core/Cargo.toml --test payload_vectors',
    },
  ],
  [
    'crates/router-ab-core/fixtures/protocol/r102/ed25519-wire-vectors-v1.json',
    {
      regenerate:
        'UPDATE_R102_ED25519_WIRE_FIXTURES=1 cargo test --manifest-path crates/router-ab-core/Cargo.toml --test r102_ed25519_wire_vectors',
      verify:
        'cargo test --manifest-path crates/router-ab-core/Cargo.toml --test r102_ed25519_wire_vectors',
    },
  ],
  [
    'packages/shared-ts/src/utils/generated/routerAbEd25519YaoCore.ts',
    {
      regenerate: 'pnpm generate:router-ab-ed25519-yao-types',
      verify:
        'cargo test --manifest-path crates/router-ab-core/Cargo.toml --features typescript-bindings --test export_typescript_bindings',
    },
  ],
  [
    'tools/ed25519-yao-verifier/fixtures/differential-one-case-v1.json',
    {
      regenerate:
        'cargo run --manifest-path tools/ed25519-yao-generator/Cargo.toml --bin ed25519-yao-vectors -- emit-differential --seed-hex 5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a --cases 1 --output tools/ed25519-yao-verifier/fixtures/differential-one-case-v1.json',
      verify: 'cargo yao-fv cross-language-check',
    },
  ],
]);

const YAO_VECTOR_ACTION_BY_FILE = new Map([
  ['ed25519-yao-v1.json', 'emit'],
  ['ed25519-yao-kdf-v1.json', 'emit-kdf'],
  ['ed25519-yao-ceremony-context-v1.json', 'emit-ceremony-context'],
  ['ed25519-yao-lifecycle-continuity-v1.json', 'emit-lifecycle-continuity'],
  ['ed25519-yao-provenance-v1.json', 'emit-provenance'],
  ['ed25519-yao-output-sharing-v1.json', 'emit-output-sharing'],
  ['ed25519-yao-output-party-views-v1.json', 'emit-output-party-views'],
  ['ed25519-yao-export-delivery-v1.json', 'emit-export-delivery'],
  [
    'ed25519-yao-export-evaluator-authorization-v1.json',
    'emit-export-evaluator-authorization',
  ],
  [
    'ed25519-yao-registration-evaluator-admission-v1.json',
    'emit-registration-evaluator-admission',
  ],
  [
    'ed25519-yao-recovery-evaluator-admission-v1.json',
    'emit-recovery-evaluator-admission',
  ],
  [
    'ed25519-yao-refresh-evaluator-admission-v1.json',
    'emit-refresh-evaluator-admission',
  ],
  ['ed25519-yao-semantic-frame-party-views-v1.json', 'emit-semantic-frame-party-views'],
  ['ed25519-yao-phase2b-core-reconciliation-v1.json', 'emit-phase2b-core-reconciliation'],
  ['ed25519-yao-activation-delivery-v1.json', 'emit-activation-delivery'],
  [
    'ed25519-yao-activation-recipient-party-views-v1.json',
    'emit-activation-recipient-party-views',
  ],
  [
    'ed25519-yao-evaluation-input-party-views-v1.json',
    'emit-evaluation-input-party-views',
  ],
  ['ed25519-yao-semantic-lifecycle-v1.json', 'emit-semantic-lifecycle'],
  ['ed25519-yao-uniform-abort-envelope-v1.json', 'emit-uniform-abort'],
  [
    'ed25519-yao-evaluator-abort-state-party-views-v1.json',
    'emit-evaluator-abort-views',
  ],
  [
    'ed25519-yao-recovery-credential-transition-v1.json',
    'emit-recovery-credential-transition',
  ],
]);

for (const [filename, action] of YAO_VECTOR_ACTION_BY_FILE) {
  const path = `tools/ed25519-yao-generator/vectors/${filename}`;
  GENERATED_ARTIFACTS.set(path, {
    regenerate: `cargo run --manifest-path tools/ed25519-yao-generator/Cargo.toml --bin ed25519-yao-vectors -- ${action} --output ${path}`,
    verify:
      filename === 'ed25519-yao-phase2b-core-reconciliation-v1.json'
        ? 'cargo yao-fv phase2b-reconciliation-check'
        : 'cargo yao-fv cross-language-check',
  });
}

const SCHEDULE_ARTIFACT_DIR = 'crates/ed25519-yao/artifacts/passive-benchmark-v1';
for (const filename of ['activation.schedule.bin', 'export.schedule.bin']) {
  GENERATED_ARTIFACTS.set(`${SCHEDULE_ARTIFACT_DIR}/${filename}`, {
    regenerate:
      "sh -c 'r120_artifact_parent=$(mktemp -d); r120_artifact_parent=$(cd \"$r120_artifact_parent\" && pwd -P); r120_artifact_dir=\"$r120_artifact_parent/bundle\"; cargo run --manifest-path tools/ed25519-yao-generator/Cargo.toml --bin ed25519-yao-circuit-artifacts -- emit --output-dir \"$r120_artifact_dir\" && cp \"$r120_artifact_dir/activation.schedule.bin\" \"$r120_artifact_dir/export.schedule.bin\" crates/ed25519-yao/artifacts/passive-benchmark-v1/'",
    verify:
      'cargo test --manifest-path tools/ed25519-yao-generator/Cargo.toml --test phase3_schedule_fixtures',
  });
}
for (const filename of [
  'activation-private-output.schedule.bin',
  'export-private-output.schedule.bin',
]) {
  GENERATED_ARTIFACTS.set(`${SCHEDULE_ARTIFACT_DIR}/${filename}`, {
    regenerate:
      'cargo run --manifest-path tools/ed25519-yao-generator/Cargo.toml --bin ed25519-yao-phase4-schedules -- emit --output-dir crates/ed25519-yao/artifacts/passive-benchmark-v1',
    verify:
      'cargo test --manifest-path tools/ed25519-yao-generator/Cargo.toml --test phase4_schedule_fixtures',
  });
}
GENERATED_ARTIFACTS.set(`${SCHEDULE_ARTIFACT_DIR}/lane-materialization.schedule.bin`, {
  regenerate:
    'cargo run --manifest-path tools/ed25519-yao-generator/Cargo.toml --bin ed25519-yao-lane-materialization-schedules -- emit --output-dir crates/ed25519-yao/artifacts/passive-benchmark-v1',
  verify:
    'cargo test --manifest-path tools/ed25519-yao-generator/Cargo.toml --test lane_materialization_vectors',
});
GENERATED_ARTIFACTS.set(`${SCHEDULE_ARTIFACT_DIR}/phase5-stream-wire-kats-v1.bin`, {
  regenerate: 'python3 tools/ed25519-yao-verifier/generate_phase5_stream_kats.py',
  verify: 'python3 tools/ed25519-yao-verifier/generate_phase5_stream_kats.py --check',
});
GENERATED_ARTIFACTS.set(
  'tools/ed25519-yao-generator/vectors/ed25519-yao-lane-materialization-v1.json',
  {
    regenerate:
      'UPDATE_ED25519_YAO_LANE_MATERIALIZATION_VECTOR=1 cargo test --manifest-path tools/ed25519-yao-generator/Cargo.toml --test lane_materialization_vectors',
    verify:
      'cargo test --manifest-path tools/ed25519-yao-generator/Cargo.toml --test lane_materialization_vectors',
  },
);

function classifyPath(path) {
  if (GENERATED_ARTIFACTS.has(path)) return 'generated artifact';
  if (path === 'AGENTS.md' || path.endsWith('.md') || path.startsWith('docs/')) {
    return 'documentation';
  }
  if (
    path.startsWith('tests/') ||
    path.includes('/tests/') ||
    path.includes('/test/') ||
    path.includes('/fixtures/') ||
    path.includes('/benches/') ||
    path.includes('/examples/') ||
    path.startsWith('tools/') ||
    path.startsWith('examples/') ||
    path.includes('cloudflare-bench')
  ) {
    return 'test fixture';
  }
  if (
    path.includes('/migrations/') ||
    /(?:^|\/)(?:d1|indexedDB|persistence|store)(?:\/|[A-Z_.-])/.test(path) ||
    /(?:D1|d1|Persistence|persistence|Store|(?:^|[._-])store)/.test(
      path.split('/').at(-1),
    )
  ) {
    return 'persistence';
  }
  if (
    path.startsWith('.github/') ||
    path.includes('wrangler') ||
    path.includes('/deployment-env/') ||
    path.includes('/deployment/') ||
    path.includes('/env/') ||
    path.includes('/.env') ||
    path.endsWith('/env.rs') ||
    path.includes('/scripts/generate-deployment-') ||
    path.includes('/scripts/generate-github-env-') ||
    path.includes('/scripts/generate-root-share-') ||
    path.startsWith('scripts/deploy') ||
    path === 'scripts/deployment-targets.mjs' ||
    path.startsWith('crates/router-ab-dev/') ||
    path.startsWith('packages/wallet-console-server-ts/')
  ) {
    return 'deployment';
  }
  if (/(?:tenant_root|tenantRoot)/.test(path)) return 'custody binding';
  if (
    path.startsWith('crates/threshold-prf/') ||
    path.startsWith('crates/router-ab-core/src/derivation/') ||
    /ecdsa_threshold_prf|ecdsaThresholdPrf|stable_context|stableContext/.test(path)
  ) {
    return 'stable derivation';
  }
  if (
    path.startsWith('wasm/') ||
    path.startsWith('packages/shared-ts/') ||
    path.startsWith('crates/router-ab-ed25519-yao-protocol/') ||
    path.includes('/protocol/') ||
    path.includes('bindings') ||
    path.includes('encoding')
  ) {
    return 'wire';
  }
  if (
    path.startsWith('packages/wallet/') ||
    path.startsWith('packages/wallet-server/') ||
    path.startsWith('crates/signer-') ||
    path.startsWith('crates/router-ab-ed25519-yao/') ||
    path.startsWith('crates/router-ab-ed25519-yao-client/') ||
    path.startsWith('crates/router-ab-ecdsa-') ||
    path.startsWith('crates/ed25519-yao/') ||
    path.startsWith('crates/router-ab-cloudflare/src/') ||
    path.includes('signing_worker') ||
    path.includes('signingWorker')
  ) {
    return 'active signing';
  }
  if (
    path.startsWith('apps/') ||
    path.startsWith('packages/console-') ||
    path.startsWith('packages/wallet-console-') ||
    path.startsWith('scripts/')
  ) {
    return 'unrelated';
  }
  return undefined;
}

function runGrep() {
  const pattern = SEARCH_TERMS.join('|');
  const output = execFileSync(
    'git',
    [
      'grep',
      '-n',
      '-I',
      '--untracked',
      '--exclude-standard',
      '-E',
      pattern,
      '--',
      ':!docs/evidence/r120-boundary-inventory-v1.json',
      ':!crates/router-ab-dev/scripts/check-r120-boundary-inventory.mjs',
      ':(exclude,glob)**/target/**',
    ],
    { cwd: REPO_ROOT, encoding: 'utf8', maxBuffer: 64 * 1024 * 1024 },
  );
  return output
    .trimEnd()
    .split('\n')
    .map((record) => {
      const firstColon = record.indexOf(':');
      const secondColon = record.indexOf(':', firstColon + 1);
      if (firstColon <= 0 || secondColon <= firstColon + 1) {
        throw new Error(`Malformed git grep record: ${record}`);
      }
      const path = record.slice(0, firstColon);
      const line = Number.parseInt(record.slice(firstColon + 1, secondColon), 10);
      const text = record.slice(secondColon + 1);
      const category = classifyPath(path);
      const terms = SEARCH_TERMS.filter((term) => text.includes(term));
      return { path, line, category, terms, text };
    });
}

function buildEvidence(matches) {
  const unclassified = matches.filter((match) => match.category === undefined);
  if (unclassified.length > 0) {
    const paths = [...new Set(unclassified.map((match) => match.path))];
    throw new Error(
      `R120 boundary inventory has ${unclassified.length} unclassified hits:\n${paths.join('\n')}`,
    );
  }

  const byFile = new Map();
  for (const match of matches) {
    const record = byFile.get(match.path) ?? {
      path: match.path,
      category: match.category,
      hitCount: 0,
      firstLine: match.line,
      lastLine: match.line,
      terms: new Set(),
      canonicalMatches: [],
    };
    record.hitCount += 1;
    record.firstLine = Math.min(record.firstLine, match.line);
    record.lastLine = Math.max(record.lastLine, match.line);
    for (const term of match.terms) record.terms.add(term);
    record.canonicalMatches.push(`${match.line}:${match.terms.join(',')}:${match.text}`);
    byFile.set(match.path, record);
  }

  const files = [...byFile.values()]
    .sort((left, right) => left.path.localeCompare(right.path))
    .map((record) => ({
      path: record.path,
      category: record.category,
      hitCount: record.hitCount,
      firstLine: record.firstLine,
      lastLine: record.lastLine,
      terms: [...record.terms].sort(),
      matchesDigestSha256: createHash('sha256')
        .update(record.canonicalMatches.join('\n'))
        .digest('hex'),
      generatedArtifact: GENERATED_ARTIFACTS.get(record.path),
    }));

  const categorySummary = {};
  for (const file of files) {
    const summary = categorySummary[file.category] ?? { fileCount: 0, hitCount: 0 };
    summary.fileCount += 1;
    summary.hitCount += file.hitCount;
    categorySummary[file.category] = summary;
  }

  const canonicalInventory = files
    .flatMap((file) =>
      file.terms.map(
        (term) =>
          `${file.path}\0${file.category}\0${file.hitCount}\0${term}\0${file.matchesDigestSha256}`,
      ),
    )
    .join('\n');

  const generatedArtifacts = [...GENERATED_ARTIFACTS.entries()]
    .sort(([left], [right]) => left.localeCompare(right))
    .map(([path, commands]) => {
      const bytes = readFileSync(resolve(REPO_ROOT, path));
      return {
        path,
        byteLength: bytes.length,
        sha256: createHash('sha256').update(bytes).digest('hex'),
        boundaryHitCount: byFile.get(path)?.hitCount ?? 0,
        ...commands,
      };
    });
  const generatedArtifactDigestSha256 = createHash('sha256')
    .update(
      generatedArtifacts
        .map(
          (artifact) =>
            `${artifact.path}\0${artifact.sha256}\0${artifact.regenerate}\0${artifact.verify}`,
        )
        .join('\n'),
    )
    .digest('hex');
  const signerD1MigrationTree = buildSignerD1MigrationTreeEvidence();

  return {
    schema: 'r120_boundary_inventory_v1',
    searchTerms: SEARCH_TERMS,
    totalFiles: files.length,
    totalHits: matches.length,
    classificationDigestSha256: createHash('sha256')
      .update(canonicalInventory)
      .digest('hex'),
    generatedArtifactDigestSha256,
    categorySummary,
    ignoredDeploymentBoundaries: IGNORED_DEPLOYMENT_BOUNDARIES,
    signerD1MigrationTree,
    generatedArtifacts,
    files,
  };
}

function buildSignerD1MigrationTreeEvidence() {
  const directory = 'packages/wallet-server/migrations/d1-signer';
  const filenames = readdirSync(resolve(REPO_ROOT, directory), {
    withFileTypes: true,
  })
    .filter((entry) => entry.isFile() && entry.name.endsWith('.sql'))
    .map((entry) => entry.name)
    .sort();
  const files = filenames.map((filename) => {
    const path = `${directory}/${filename}`;
    return {
      path,
      sha256: createHash('sha256')
        .update(readFileSync(resolve(REPO_ROOT, path)))
        .digest('hex'),
    };
  });
  const aggregateDigestSha256 = createHash('sha256')
    .update(Buffer.concat(files.map((file) => Buffer.from(file.sha256, 'hex'))))
    .digest('hex');
  return {
    algorithm:
      'sha256(concat(sha256(file_bytes) in lexicographic filename order))',
    fileCount: files.length,
    aggregateDigestSha256,
    files,
  };
}

function canonicalJson(value) {
  return `${JSON.stringify(value, null, 2)}\n`;
}

const evidence = buildEvidence(runGrep());
if (process.argv.includes('--write')) {
  writeFileSync(EVIDENCE_PATH, canonicalJson(evidence));
  process.stdout.write(`Wrote ${EVIDENCE_PATH}\n`);
} else {
  const committed = JSON.parse(readFileSync(EVIDENCE_PATH, 'utf8'));
  if (canonicalJson(committed) !== canonicalJson(evidence)) {
    throw new Error(
      'R120 boundary inventory is stale; rerun with --write and review every classification change',
    );
  }
  process.stdout.write(
    `R120 boundary inventory is current: ${evidence.totalHits} hits in ${evidence.totalFiles} files (${evidence.classificationDigestSha256})\n`,
  );
}
