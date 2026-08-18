import { WALLET_API_CREDENTIAL_SCOPE_VALIDATION } from '@seams-internal/wallet-console-shared/apiKeyScopes';
import { expect, test } from '@playwright/test';
import { createInMemoryConsoleApiKeyService } from '../../packages/console-server-ts/src/apiKeys/service';
import { createInMemoryConsoleOnboardingService } from '../../packages/console-server-ts/src/onboarding/service';
import { createInMemoryConsoleOrgProjectEnvService } from '../../packages/console-server-ts/src/orgProjectEnv/service';
import { createInMemoryConsoleOrganizationAccessService } from '../../packages/console-server-ts/src/teamRbac/service';
import type {
  ConsoleOnboardingWelcomeEmail,
  ConsoleOnboardingWelcomeEmailPort,
} from '../../packages/console-server-ts/src/onboarding/welcomeEmail';

class RecordingWelcomeEmail implements ConsoleOnboardingWelcomeEmailPort {
  readonly messages: ConsoleOnboardingWelcomeEmail[] = [];

  async enqueue(email: ConsoleOnboardingWelcomeEmail): Promise<void> {
    this.messages.push(email);
  }
}

test('organization onboarding persists the organization before bootstrapping its first owner', async () => {
  const orgProjectEnv = createInMemoryConsoleOrgProjectEnvService();
  const organizationAccess = createInMemoryConsoleOrganizationAccessService();
  const onboarding = createInMemoryConsoleOnboardingService({
    orgProjectEnv,
    organizationAccess,
    apiKeys: createInMemoryConsoleApiKeyService({ scopeValidation: WALLET_API_CREDENTIAL_SCOPE_VALIDATION }),
  });
  const ctx = {
    orgId: 'org_onboarding_owner',
    actorUserId: 'user_onboarding_owner',
    actorEmail: 'owner@example.com',
    actorDisplayName: 'Owner',
    projectId: null,
    environmentId: null,
  };

  const first = await onboarding.createOnboardingOrganization(ctx, {
    org: { name: 'Onboarding Organization', slug: 'onboarding-organization' },
  });
  expect(first.created).toEqual({ organization: true, owner: true });
  expect(
    await organizationAccess.lookupAuthorization({
      orgId: ctx.orgId,
      userId: ctx.actorUserId,
    }),
  ).toMatchObject({
    kind: 'authorized',
    role: 'OWNER',
  });

  const repeated = await onboarding.createOnboardingOrganization(ctx, {
    org: { name: 'Onboarding Organization' },
  });
  expect(repeated.created).toEqual({ organization: false, owner: false });
});

test('project onboarding requests a welcome email after the organization and project exist', async () => {
  const welcomeEmail = new RecordingWelcomeEmail();
  const onboarding = createInMemoryConsoleOnboardingService({
    orgProjectEnv: createInMemoryConsoleOrgProjectEnvService(),
    organizationAccess: createInMemoryConsoleOrganizationAccessService(),
    apiKeys: createInMemoryConsoleApiKeyService({ scopeValidation: WALLET_API_CREDENTIAL_SCOPE_VALIDATION }),
    welcomeEmail,
  });
  const ctx = {
    orgId: 'org_welcome',
    actorUserId: 'user_welcome',
    actorEmail: 'ada@example.com',
    actorDisplayName: 'Ada',
    projectId: null,
    environmentId: null,
  };

  await onboarding.createOnboardingOrganization(ctx, {
    org: { name: 'Acme', slug: 'acme' },
  });
  expect(welcomeEmail.messages).toHaveLength(0);

  const result = await onboarding.createOnboardingProject(ctx, {
    project: { name: 'Checkout' },
  });
  expect(result.state.onboardingComplete).toBe(true);
  expect(welcomeEmail.messages).toEqual([
    {
      orgId: 'org_welcome',
      userId: 'user_welcome',
      recipientEmail: 'ada@example.com',
      recipientDisplayName: 'Ada',
      organizationName: 'Acme',
      projectName: 'Checkout',
    },
  ]);
});
