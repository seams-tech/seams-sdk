import { expect, test } from '@playwright/test';

const IMPORT_PATHS = {
  react: '/node_modules/.vite/deps/react.js',
  reactDomClient: '/node_modules/.vite/deps/react-dom_client.js',
  reactDom: '/node_modules/.vite/deps/react-dom.js',
  useSessionDraft: '/src/pages/dashboard/drafts/useSessionDraft.ts',
  sessionDraftStore: '/src/pages/dashboard/drafts/sessionDraftStore.ts',
} as const;

test.describe('useSessionDraft lifecycle behavior', () => {
  test('restores on open, resets on close, and re-reads on reopen', async ({ page }) => {
    await page.goto('/dashboard/login');

    const result = await page.evaluate(async ({ paths }) => {
      const reactDomClientMod: any = await import(paths.reactDomClient);
      const reactEntry = performance
        .getEntriesByType('resource')
        .map((entry) => entry.name)
        .find((name) => name.includes('/node_modules/.vite/deps/react.js?v='));
      const reactQuery = reactEntry ? new URL(reactEntry).search : '';
      const reactMod: any = await import(`${paths.react}${reactQuery}`);
      const reactDomMod: any = await import(`${paths.reactDom}${reactQuery}`);
      const React = reactMod.default || reactMod;
      const ReactDOMClient = reactDomClientMod.default || reactDomClientMod;
      const ReactDOM = reactDomMod.default || reactDomMod;
      const hookMod: any = await import(paths.useSessionDraft);
      const storeMod: any = await import(paths.sessionDraftStore);

      const useSessionDraft = hookMod.useSessionDraft;
      const writeSessionDashboardDraft = storeMod.writeSessionDashboardDraft;
      const readSessionDashboardDraft = storeMod.readSessionDashboardDraft;
      const clearSessionDashboardDraft = storeMod.clearSessionDashboardDraft;

      if (typeof useSessionDraft !== 'function') {
        throw new Error('useSessionDraft export missing');
      }

      type DraftForm = {
        policyName: string;
        enabled: boolean;
      };

      const parseForm = (raw: unknown): DraftForm | null => {
        if (!raw || typeof raw !== 'object' || Array.isArray(raw)) return null;
        const row = raw as Record<string, unknown>;
        return {
          policyName: String(row.policyName || '').trim(),
          enabled: row.enabled === true,
        };
      };

      const identity = {
        route: '/dashboard/gas-sponsorship',
        builderId: 'gas-sponsorship-policy-modal',
        mode: 'create' as const,
        orgId: 'org_lifecycle',
        projectId: 'proj_lifecycle',
        environmentId: 'env_lifecycle',
        resourceId: '',
      };

      clearSessionDashboardDraft(identity);
      writeSessionDashboardDraft(identity, {
        policyName: 'stored-before-open',
        enabled: true,
      });

      const mountId = 'dashboard-use-session-draft-lifecycle-open-close';
      let mount = document.getElementById(mountId);
      if (!mount) {
        mount = document.createElement('div');
        mount.id = mountId;
        document.body.appendChild(mount);
      }

      function Harness() {
        const [isOpen, setIsOpen] = React.useState(false);
        const [initialForm] = React.useState({
          policyName: 'default-form',
          enabled: false,
        });
        const hook = useSessionDraft({
          identity,
          initialForm,
          isOpen,
          parseForm,
        });

        React.useEffect(() => {
          (window as any).__useSessionDraftLifecycle = {
            snapshot: () => ({
              form: hook.form,
              restoreState: hook.restoreState,
              isOpen,
            }),
            setIsOpen,
            setForm: (nextForm: DraftForm) => hook.setForm(nextForm),
          };
        }, [hook, isOpen]);

        return null;
      }

      const root = ReactDOMClient.createRoot(mount);
      ReactDOM.flushSync(() => {
        root.render(React.createElement(Harness));
      });

      const controller = () => (window as any).__useSessionDraftLifecycle;
      const snapshot = () => controller().snapshot();
      const waitFor = async (
        predicate: () => boolean,
        timeoutMs = 3000,
        intervalMs = 10,
      ): Promise<void> => {
        const started = Date.now();
        while (Date.now() - started < timeoutMs) {
          if (predicate()) return;
          await new Promise((resolve) => setTimeout(resolve, intervalMs));
        }
        throw new Error('Timed out waiting for lifecycle condition');
      };

      await waitFor(() => Boolean(controller()));
      const closedBeforeOpen = snapshot();

      controller().setIsOpen(true);
      await waitFor(
        () =>
          snapshot().restoreState === 'restored' &&
          snapshot().form.policyName === 'stored-before-open',
      );
      const afterOpen = snapshot();

      controller().setForm({
        policyName: 'edited-while-open',
        enabled: false,
      });
      await waitFor(() => {
        const persisted = readSessionDashboardDraft({
          identity,
          parseForm,
        });
        return persisted?.form.policyName === 'edited-while-open';
      });
      const persistedAfterEdit = readSessionDashboardDraft({
        identity,
        parseForm,
      });

      controller().setIsOpen(false);
      await waitFor(() => snapshot().restoreState === 'default' && snapshot().isOpen === false);
      const afterClose = snapshot();

      writeSessionDashboardDraft(identity, {
        policyName: 'stored-before-reopen',
        enabled: true,
      });

      controller().setIsOpen(true);
      await waitFor(
        () =>
          snapshot().restoreState === 'restored' &&
          snapshot().form.policyName === 'stored-before-reopen',
      );
      const afterReopen = snapshot();

      root.unmount();
      mount.remove();
      clearSessionDashboardDraft(identity);

      return {
        closedBeforeOpen,
        afterOpen,
        persistedAfterEditPolicyName: String(persistedAfterEdit?.form.policyName || ''),
        afterClose,
        afterReopen,
      };
    }, { paths: IMPORT_PATHS });

    expect(result.closedBeforeOpen.restoreState).toBe('default');
    expect(result.closedBeforeOpen.form.policyName).toBe('default-form');
    expect(result.afterOpen.restoreState).toBe('restored');
    expect(result.afterOpen.form.policyName).toBe('stored-before-open');
    expect(result.persistedAfterEditPolicyName).toBe('edited-while-open');
    expect(result.afterClose.restoreState).toBe('default');
    expect(result.afterReopen.restoreState).toBe('restored');
    expect(result.afterReopen.form.policyName).toBe('stored-before-reopen');
  });

  test('switches drafts when identity changes while modal stays open', async ({ page }) => {
    await page.goto('/dashboard/login');

    const result = await page.evaluate(async ({ paths }) => {
      const reactDomClientMod: any = await import(paths.reactDomClient);
      const reactEntry = performance
        .getEntriesByType('resource')
        .map((entry) => entry.name)
        .find((name) => name.includes('/node_modules/.vite/deps/react.js?v='));
      const reactQuery = reactEntry ? new URL(reactEntry).search : '';
      const reactMod: any = await import(`${paths.react}${reactQuery}`);
      const reactDomMod: any = await import(`${paths.reactDom}${reactQuery}`);
      const React = reactMod.default || reactMod;
      const ReactDOMClient = reactDomClientMod.default || reactDomClientMod;
      const ReactDOM = reactDomMod.default || reactDomMod;
      const hookMod: any = await import(paths.useSessionDraft);
      const storeMod: any = await import(paths.sessionDraftStore);

      const useSessionDraft = hookMod.useSessionDraft;
      const writeSessionDashboardDraft = storeMod.writeSessionDashboardDraft;
      const readSessionDashboardDraft = storeMod.readSessionDashboardDraft;
      const clearSessionDashboardDraft = storeMod.clearSessionDashboardDraft;

      if (typeof useSessionDraft !== 'function') {
        throw new Error('useSessionDraft export missing');
      }

      type DraftForm = {
        policyName: string;
        enabled: boolean;
      };

      const parseForm = (raw: unknown): DraftForm | null => {
        if (!raw || typeof raw !== 'object' || Array.isArray(raw)) return null;
        const row = raw as Record<string, unknown>;
        return {
          policyName: String(row.policyName || '').trim(),
          enabled: row.enabled === true,
        };
      };

      const identityA = {
        route: '/dashboard/policy-engine',
        builderId: 'policy-engine-policy-modal',
        mode: 'edit' as const,
        orgId: 'org_lifecycle',
        projectId: 'proj_lifecycle',
        environmentId: 'env_lifecycle',
        resourceId: 'policy_a',
      };
      const identityB = {
        ...identityA,
        resourceId: 'policy_b',
      };

      clearSessionDashboardDraft(identityA);
      clearSessionDashboardDraft(identityB);
      writeSessionDashboardDraft(identityA, {
        policyName: 'draft-a',
        enabled: true,
      });
      writeSessionDashboardDraft(identityB, {
        policyName: 'draft-b',
        enabled: false,
      });

      const mountId = 'dashboard-use-session-draft-lifecycle-identity-switch';
      let mount = document.getElementById(mountId);
      if (!mount) {
        mount = document.createElement('div');
        mount.id = mountId;
        document.body.appendChild(mount);
      }

      function Harness() {
        const [identity, setIdentity] = React.useState(identityA as typeof identityA | null);
        const [initialForm] = React.useState({
          policyName: 'default-policy',
          enabled: false,
        });
        const hook = useSessionDraft({
          identity,
          initialForm,
          isOpen: true,
          parseForm,
        });

        React.useEffect(() => {
          (window as any).__useSessionDraftIdentitySwitch = {
            snapshot: () => ({
              identityResourceId: String(identity?.resourceId || ''),
              form: hook.form,
              restoreState: hook.restoreState,
            }),
            setIdentity,
            setForm: (nextForm: DraftForm) => hook.setForm(nextForm),
          };
        }, [hook, identity]);

        return null;
      }

      const root = ReactDOMClient.createRoot(mount);
      ReactDOM.flushSync(() => {
        root.render(React.createElement(Harness));
      });

      const controller = () => (window as any).__useSessionDraftIdentitySwitch;
      const snapshot = () => controller().snapshot();
      const waitFor = async (
        predicate: () => boolean,
        timeoutMs = 3000,
        intervalMs = 10,
      ): Promise<void> => {
        const started = Date.now();
        while (Date.now() - started < timeoutMs) {
          if (predicate()) return;
          await new Promise((resolve) => setTimeout(resolve, intervalMs));
        }
        throw new Error('Timed out waiting for identity switch condition');
      };

      await waitFor(() => Boolean(controller()));
      await waitFor(
        () => snapshot().identityResourceId === 'policy_a' && snapshot().form.policyName === 'draft-a',
      );
      const initialA = snapshot();

      controller().setIdentity(identityB);
      await waitFor(
        () => snapshot().identityResourceId === 'policy_b' && snapshot().form.policyName === 'draft-b',
      );
      const switchedToB = snapshot();

      controller().setForm({
        policyName: 'draft-b-edited',
        enabled: true,
      });
      await waitFor(() => {
        const persistedB = readSessionDashboardDraft({
          identity: identityB,
          parseForm,
        });
        return persistedB?.form.policyName === 'draft-b-edited';
      });

      const persistedA = readSessionDashboardDraft({
        identity: identityA,
        parseForm,
      });
      const persistedB = readSessionDashboardDraft({
        identity: identityB,
        parseForm,
      });

      controller().setIdentity(identityA);
      await waitFor(
        () => snapshot().identityResourceId === 'policy_a' && snapshot().form.policyName === 'draft-a',
      );
      const switchedBackToA = snapshot();

      root.unmount();
      mount.remove();
      clearSessionDashboardDraft(identityA);
      clearSessionDashboardDraft(identityB);

      return {
        initialA,
        switchedToB,
        switchedBackToA,
        persistedAName: String(persistedA?.form.policyName || ''),
        persistedBName: String(persistedB?.form.policyName || ''),
      };
    }, { paths: IMPORT_PATHS });

    expect(result.initialA.restoreState).toBe('restored');
    expect(result.initialA.form.policyName).toBe('draft-a');
    expect(result.switchedToB.restoreState).toBe('restored');
    expect(result.switchedToB.form.policyName).toBe('draft-b');
    expect(result.persistedAName).toBe('draft-a');
    expect(result.persistedBName).toBe('draft-b-edited');
    expect(result.switchedBackToA.restoreState).toBe('restored');
    expect(result.switchedBackToA.form.policyName).toBe('draft-a');
  });
});
