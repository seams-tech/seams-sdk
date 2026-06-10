import { expect, test } from '@playwright/test';
import {
  buildDashboardDraftStorageKey,
  clearSessionDashboardDraft,
  readSessionDashboardDraft,
  writeSessionDashboardDraft,
  type DashboardDraftIdentity,
} from '../../apps/web-client/src/pages/dashboard/drafts/sessionDraftStore';

class MemoryStorage implements Storage {
  private readonly entries = new Map<string, string>();

  get length(): number {
    return this.entries.size;
  }

  clear(): void {
    this.entries.clear();
  }

  getItem(key: string): string | null {
    return this.entries.has(key) ? this.entries.get(key) || null : null;
  }

  key(index: number): string | null {
    return Array.from(this.entries.keys())[index] || null;
  }

  removeItem(key: string): void {
    this.entries.delete(key);
  }

  setItem(key: string, value: string): void {
    this.entries.set(key, value);
  }
}

type DraftForm = {
  policyName: string;
  enabled: boolean;
};

function draftIdentity(overrides: Partial<DashboardDraftIdentity> = {}): DashboardDraftIdentity {
  return {
    route: '/dashboard/gas-sponsorship',
    builderId: 'gas-sponsorship-policy-modal',
    mode: 'create',
    orgId: 'org_test',
    projectId: 'proj_test',
    environmentId: 'env_test',
    resourceId: '',
    ...overrides,
  };
}

function parseDraftForm(raw: unknown): DraftForm | null {
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) return null;
  const row = raw as Record<string, unknown>;
  return {
    policyName: String(row.policyName || '').trim(),
    enabled: row.enabled === true,
  };
}

test.describe('dashboard session draft store', () => {
  const originalWindow = globalThis.window;

  test.afterEach(() => {
    if (originalWindow === undefined) {
      delete (globalThis as Record<string, unknown>).window;
      return;
    }
    (globalThis as Record<string, unknown>).window = originalWindow;
  });

  test('builds deterministic keys and separates create/edit resources', async () => {
    const createKey = buildDashboardDraftStorageKey(
      draftIdentity({ mode: 'create', resourceId: '' }),
    );
    const editAKey = buildDashboardDraftStorageKey(
      draftIdentity({ mode: 'edit', resourceId: 'policy_a' }),
    );
    const editBKey = buildDashboardDraftStorageKey(
      draftIdentity({ mode: 'edit', resourceId: 'policy_b' }),
    );

    expect(createKey).not.toBe(editAKey);
    expect(editAKey).not.toBe(editBKey);
    expect(editBKey).toContain('policy_b');
  });

  test('writes and restores a valid draft payload', async () => {
    const storage = new MemoryStorage();
    (globalThis as Record<string, unknown>).window = { sessionStorage: storage };

    const identity = draftIdentity({ mode: 'edit', resourceId: 'policy_123' });
    writeSessionDashboardDraft(identity, {
      policyName: 'Draft policy',
      enabled: true,
    });

    const restored = readSessionDashboardDraft({
      identity,
      parseForm: parseDraftForm,
    });

    expect(restored?.route).toBe('/dashboard/gas-sponsorship');
    expect(restored?.mode).toBe('edit');
    expect(restored?.resourceId).toBe('policy_123');
    expect(restored?.form.policyName).toBe('Draft policy');
    expect(restored?.form.enabled).toBe(true);
  });

  test('removes corrupt JSON entries during read', async () => {
    const storage = new MemoryStorage();
    (globalThis as Record<string, unknown>).window = { sessionStorage: storage };

    const identity = draftIdentity();
    const key = buildDashboardDraftStorageKey(identity);
    storage.setItem(key, '{not json');

    const restored = readSessionDashboardDraft({
      identity,
      parseForm: parseDraftForm,
    });

    expect(restored).toBeNull();
    expect(storage.getItem(key)).toBeNull();
  });

  test('removes invalid payload shape entries during read', async () => {
    const storage = new MemoryStorage();
    (globalThis as Record<string, unknown>).window = { sessionStorage: storage };

    const identity = draftIdentity();
    const key = buildDashboardDraftStorageKey(identity);
    storage.setItem(
      key,
      JSON.stringify({
        version: 'v1',
        route: '/dashboard/gas-sponsorship',
        builderId: 'gas-sponsorship-policy-modal',
        mode: 'create',
        resourceId: null,
        orgId: 'org_test',
        projectId: 'proj_test',
        environmentId: 'env_test',
        savedAt: new Date().toISOString(),
        form: 'wrong-shape',
      }),
    );

    const restored = readSessionDashboardDraft({
      identity,
      parseForm: parseDraftForm,
    });

    expect(restored).toBeNull();
    expect(storage.getItem(key)).toBeNull();
  });

  test('removes version-mismatched entries during read', async () => {
    const storage = new MemoryStorage();
    (globalThis as Record<string, unknown>).window = { sessionStorage: storage };

    const identity = draftIdentity();
    const key = buildDashboardDraftStorageKey(identity);
    storage.setItem(
      key,
      JSON.stringify({
        version: 'v0',
        route: '/dashboard/gas-sponsorship',
        builderId: 'gas-sponsorship-policy-modal',
        mode: 'create',
        resourceId: null,
        orgId: 'org_test',
        projectId: 'proj_test',
        environmentId: 'env_test',
        savedAt: new Date().toISOString(),
        form: { policyName: 'old', enabled: true },
      }),
    );

    const restored = readSessionDashboardDraft({
      identity,
      parseForm: parseDraftForm,
    });

    expect(restored).toBeNull();
    expect(storage.getItem(key)).toBeNull();
  });

  test('removes scope-mismatched entries during read', async () => {
    const storage = new MemoryStorage();
    (globalThis as Record<string, unknown>).window = { sessionStorage: storage };

    const identity = draftIdentity();
    const key = buildDashboardDraftStorageKey(identity);
    storage.setItem(
      key,
      JSON.stringify({
        version: 'v1',
        route: '/dashboard/gas-sponsorship',
        builderId: 'gas-sponsorship-policy-modal',
        mode: 'create',
        resourceId: null,
        orgId: 'org_other',
        projectId: 'proj_test',
        environmentId: 'env_test',
        savedAt: new Date().toISOString(),
        form: { policyName: 'wrong-scope', enabled: true },
      }),
    );

    const restored = readSessionDashboardDraft({
      identity,
      parseForm: parseDraftForm,
    });

    expect(restored).toBeNull();
    expect(storage.getItem(key)).toBeNull();
  });

  test('removes edit resource-mismatched entries during read', async () => {
    const storage = new MemoryStorage();
    (globalThis as Record<string, unknown>).window = { sessionStorage: storage };

    const identity = draftIdentity({ mode: 'edit', resourceId: 'policy_expected' });
    const key = buildDashboardDraftStorageKey(identity);
    storage.setItem(
      key,
      JSON.stringify({
        version: 'v1',
        route: '/dashboard/gas-sponsorship',
        builderId: 'gas-sponsorship-policy-modal',
        mode: 'edit',
        resourceId: 'policy_other',
        orgId: 'org_test',
        projectId: 'proj_test',
        environmentId: 'env_test',
        savedAt: new Date().toISOString(),
        form: { policyName: 'wrong-resource', enabled: true },
      }),
    );

    const restored = readSessionDashboardDraft({
      identity,
      parseForm: parseDraftForm,
    });

    expect(restored).toBeNull();
    expect(storage.getItem(key)).toBeNull();
  });

  test('clear removes stored drafts by identity', async () => {
    const storage = new MemoryStorage();
    (globalThis as Record<string, unknown>).window = { sessionStorage: storage };

    const identity = draftIdentity({ mode: 'edit', resourceId: 'policy_clear' });
    writeSessionDashboardDraft(identity, {
      policyName: 'to-clear',
      enabled: false,
    });

    clearSessionDashboardDraft(identity);

    const key = buildDashboardDraftStorageKey(identity);
    expect(storage.getItem(key)).toBeNull();
  });
});
