import { expect, test } from '@playwright/test';
import {
  DEPLOYMENT_WORKFLOWS,
  REQUIRED_CODEOWNER_PATTERNS,
  WORKFLOW_NAMES,
  validateCodeowners,
  validateDeploymentWorkflowPolicy,
} from '../../scripts/check-deployment-workflows.mjs';

type Workflow = {
  readonly name: string;
  readonly on: {
    readonly workflow_run: {
      readonly workflows: readonly string[];
      readonly branches: readonly string[];
    };
    readonly workflow_dispatch: {
      readonly inputs: Readonly<Record<string, { readonly required: boolean }>>;
    };
  };
  readonly env?: {
    readonly DEPLOY_TARGET: string;
    readonly DEPLOY_SOURCE_BRANCH: string;
  };
  readonly concurrency?: { readonly group: string };
  readonly jobs: Readonly<
    Record<
      string,
      {
        readonly name: string;
        readonly environment?: string;
        readonly [key: string]: unknown;
      }
    >
  >;
};

function createWorkflowSet(): {
  readonly workflows: Map<string, Workflow>;
  readonly sources: Map<string, string>;
} {
  const workflows = new Map<string, Workflow>();
  const sources = new Map<string, string>();

  for (const [filename, name] of Object.entries(WORKFLOW_NAMES)) {
    const descriptor = DEPLOYMENT_WORKFLOWS.find((value) => value.filename === filename);
    if (!descriptor) {
      workflows.set(filename, {
        name,
        on: {
          workflow_run: { workflows: [], branches: [] },
          workflow_dispatch: { inputs: {} },
        },
        jobs: {},
      });
      sources.set(filename, '');
      continue;
    }

    const isBackend = descriptor.lane === 'backend';
    const mutationJob = isBackend
      ? {
          name: `Deploy / ${descriptor.environment} / cloudflare-api-gateway`,
          environment: `${descriptor.environment}-gateway`,
        }
      : {
          name: `Deploy / ${descriptor.environment} / cloudflare-pages / app`,
          environment: `${descriptor.environment}-frontend`,
        };
    const inputs = Object.fromEntries(
      descriptor.requiredInputs.map((inputName) => [inputName, { required: true }]),
    );
    const workflow: Workflow = {
      name,
      on: {
        workflow_run: {
          workflows: [descriptor.upstreamWorkflow],
          branches: [descriptor.branch],
        },
        workflow_dispatch: { inputs },
      },
      env: {
        DEPLOY_TARGET: descriptor.environment,
        DEPLOY_SOURCE_BRANCH: descriptor.branch,
      },
      concurrency: { group: `deployment-${descriptor.environment}-${descriptor.lane}` },
      jobs: { mutation: mutationJob },
    };
    workflows.set(filename, workflow);
    sources.set(
      filename,
      [
        descriptor.environment === 'production' ? '"$EVENT_BRANCH" != \'main\'' : '',
        isBackend
          ? "github.event.workflow_run.event == 'push'\ngithub.event.workflow_run.conclusion == 'success'"
          : "github.event.workflow_run.event == 'workflow_run'\ngithub.event.workflow_run.conclusion == 'success'",
      ].join('\n'),
    );
  }

  return { workflows, sources };
}

function policyFailures(
  workflows: Map<string, Workflow>,
  sources: Map<string, string>,
): readonly string[] {
  return validateDeploymentWorkflowPolicy(workflows, sources);
}

test('accepts the six-workflow surface with lane-specific mutation ownership', () => {
  const { workflows, sources } = createWorkflowSet();

  expect(policyFailures(workflows, sources)).toEqual([]);
});

test('requires ownership for deployment-sensitive repository paths', () => {
  const source = REQUIRED_CODEOWNER_PATTERNS.map((pattern) => `${pattern} @peitalin`).join('\n');
  expect(validateCodeowners(source)).toEqual([]);
  expect(validateCodeowners('/.github/workflows/** @peitalin')).toContain(
    'CODEOWNERS is missing an owner rule for /docs/deployment/**',
  );
});

test('requires exactly the target six workflow files', () => {
  const { workflows, sources } = createWorkflowSet();
  workflows.delete('deploy-production-frontend.yml');
  sources.delete('deploy-production-frontend.yml');

  expect(policyFailures(workflows, sources)).toContain(
    'missing workflow: deploy-production-frontend.yml',
  );
});

test('rejects frontend mutation jobs and source references in backend workflows', () => {
  const { workflows, sources } = createWorkflowSet();
  const workflow = workflows.get('deploy-staging-cloudflare-stack.yml');
  if (!workflow) throw new Error('backend fixture was not created');
  workflows.set('deploy-staging-cloudflare-stack.yml', {
    ...workflow,
    jobs: {
      ...workflow.jobs,
      pages: {
        name: 'Deploy / staging / cloudflare-pages / app',
        environment: 'staging-frontend',
      },
    },
  });
  sources.set('deploy-staging-cloudflare-stack.yml', 'deploy-cloudflare-pages.yml');

  const failures = policyFailures(workflows, sources);
  expect(failures).toContain(
    'deploy-staging-cloudflare-stack.yml:pages: frontend mutation belongs in the frontend lane',
  );
  expect(failures).toContain(
    'deploy-staging-cloudflare-stack.yml: frontend mutation source is forbidden in the backend lane',
  );
});

test('rejects backend mutation jobs and source references in frontend workflows', () => {
  const { workflows, sources } = createWorkflowSet();
  const workflow = workflows.get('deploy-staging-frontend.yml');
  if (!workflow) throw new Error('frontend fixture was not created');
  workflows.set('deploy-staging-frontend.yml', {
    ...workflow,
    jobs: {
      ...workflow.jobs,
      gateway: {
        name: 'Deploy / staging / cloudflare-api-gateway',
        environment: 'staging-gateway',
      },
    },
  });
  sources.set('deploy-staging-frontend.yml', 'deploy-cloudflare-gateway.yml');

  const failures = policyFailures(workflows, sources);
  expect(failures).toContain(
    'deploy-staging-frontend.yml:gateway: backend mutation belongs in the backend lane',
  );
  expect(failures).toContain(
    'deploy-staging-frontend.yml: backend mutation source is forbidden in the frontend lane',
  );
});

test('requires the backend coordination receipt for manual frontend promotion', () => {
  const { workflows, sources } = createWorkflowSet();
  const workflow = workflows.get('deploy-production-frontend.yml');
  if (!workflow) throw new Error('frontend fixture was not created');
  const inputs = { ...workflow.on.workflow_dispatch.inputs };
  delete inputs.backend_receipt_run_id;
  workflows.set('deploy-production-frontend.yml', {
    ...workflow,
    on: {
      ...workflow.on,
      workflow_dispatch: { inputs },
    },
  });

  expect(policyFailures(workflows, sources)).toContain(
    'deploy-production-frontend.yml: manual promotion is missing backend_receipt_run_id input',
  );
});

test('rejects mutation jobs in validation workflows', () => {
  const { workflows, sources } = createWorkflowSet();
  const workflow = workflows.get('validate-repository.yml');
  if (!workflow) throw new Error('validation fixture was not created');
  workflows.set('validate-repository.yml', {
    ...workflow,
    jobs: {
      pages: {
        name: 'Deploy / staging / cloudflare-pages / app',
        environment: 'staging-frontend',
      },
    },
  });

  expect(policyFailures(workflows, sources)).toContain(
    'validate-repository.yml:pages: mutation job is outside a deployment workflow',
  );
});

test('rejects frontend and Gateway credential boundary violations', () => {
  const { workflows, sources } = createWorkflowSet();
  const frontendWorkflow = workflows.get('deploy-staging-frontend.yml');
  if (!frontendWorkflow) throw new Error('frontend fixture was not created');
  workflows.set('deploy-staging-frontend.yml', {
    ...frontendWorkflow,
    jobs: {
      ...frontendWorkflow.jobs,
      leaked_secret: {
        name: 'Verify / staging / frontend',
        environment: 'staging-frontend',
        env: { LEAKED: '${{ secrets.RELAY_SESSION_HMAC_SECRET }}' },
      },
    },
  });

  const backendWorkflow = workflows.get('deploy-staging-cloudflare-stack.yml');
  if (!backendWorkflow) throw new Error('backend fixture was not created');
  workflows.set('deploy-staging-cloudflare-stack.yml', {
    ...backendWorkflow,
    jobs: {
      ...backendWorkflow.jobs,
      gateway: {
        name: 'Deploy / staging / cloudflare-api-gateway',
        environment: 'staging-gateway',
        env: { LEAKED: '${{ secrets.DERIVER_A_ROOT_SHARE_WIRE_SECRET }}' },
      },
    },
  });

  const failures = policyFailures(workflows, sources);
  expect(failures).toContain(
    'deploy-staging-frontend.yml:leaked_secret: frontend job reads backend or unapproved secret RELAY_SESSION_HMAC_SECRET',
  );
  expect(failures).toContain(
    'deploy-staging-cloudflare-stack.yml:gateway: Gateway job reads Pages-only or Router-only secret DERIVER_A_ROOT_SHARE_WIRE_SECRET',
  );
});

test('rejects unscoped deployment variables and secrets', () => {
  const { workflows, sources } = createWorkflowSet();
  const workflow = workflows.get('deploy-staging-frontend.yml');
  if (!workflow) throw new Error('frontend fixture was not created');
  workflows.set('deploy-staging-frontend.yml', {
    ...workflow,
    jobs: {
      ...workflow.jobs,
      unscoped: {
        name: 'Verify / staging / frontend',
        env: {
          CONTRACT: '${{ vars.GATEWAY_API_CONTRACT_VERSION }}',
          TOKEN: '${{ secrets.CLOUDFLARE_API_TOKEN }}',
        },
      },
    },
  });

  const failures = policyFailures(workflows, sources);
  expect(failures).toContain(
    'deploy-staging-frontend.yml:unscoped: jobs that read environment variables must declare a GitHub environment',
  );
  expect(failures).toContain(
    'deploy-staging-frontend.yml:unscoped: jobs that read deployment secrets must declare a GitHub environment (CLOUDFLARE_API_TOKEN)',
  );
});

test('rejects deployment jobs bound to the other target environment', () => {
  const { workflows, sources } = createWorkflowSet();
  const workflow = workflows.get('deploy-staging-cloudflare-stack.yml');
  if (!workflow) throw new Error('staging backend fixture was not created');
  workflows.set('deploy-staging-cloudflare-stack.yml', {
    ...workflow,
    jobs: {
      ...workflow.jobs,
      mutation: {
        name: 'Deploy / staging / cloudflare-api-gateway',
        environment: 'production-gateway',
      },
    },
  });

  expect(policyFailures(workflows, sources)).toContain(
    'deploy-staging-cloudflare-stack.yml:mutation: deployment job references the production environment',
  );
});
