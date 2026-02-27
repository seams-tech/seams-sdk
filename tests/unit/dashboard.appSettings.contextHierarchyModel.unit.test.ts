import { test, expect } from '@playwright/test';
import {
  ALL_PROJECTS_SCOPE,
  buildEnvironmentsListRequest,
  buildProjectsListRequest,
  canCreateEnvironmentInProject,
  filterActiveProjects,
  resolveCreateEnvironmentProjectId,
} from '../../examples/tatchi-site/src/pages/dashboard/routes/app-settings/contextHierarchyModel';

test.describe('dashboard app-settings context hierarchy model', () => {
  test('project request + active project filtering honor archived toggle', () => {
    expect(buildProjectsListRequest(false)).toEqual({ status: 'ACTIVE' });
    expect(buildProjectsListRequest(true)).toEqual({});

    const filtered = filterActiveProjects([
      { id: 'proj_a', status: 'ACTIVE' },
      { id: 'proj_b', status: 'archived' },
      { id: 'proj_c' },
    ]);
    expect(filtered.map((entry) => entry.id)).toEqual(['proj_a', 'proj_c']);
  });

  test('environment request resolves scope and status filters', () => {
    const projects = [{ id: 'proj_a' }, { id: 'proj_b' }];

    const withInvalidRequestedScope = buildEnvironmentsListRequest({
      requestedScopeProjectId: 'proj_unknown',
      selectedProjectId: 'proj_b',
      projects,
      showArchivedEnvironments: false,
    });
    expect(withInvalidRequestedScope.resolvedScopeProjectId).toBe('proj_b');
    expect(withInvalidRequestedScope.request).toEqual({
      projectId: 'proj_b',
      status: 'ACTIVE',
    });

    const allProjectsScope = buildEnvironmentsListRequest({
      requestedScopeProjectId: ALL_PROJECTS_SCOPE,
      selectedProjectId: 'proj_a',
      projects,
      showArchivedEnvironments: true,
    });
    expect(allProjectsScope.resolvedScopeProjectId).toBe(ALL_PROJECTS_SCOPE);
    expect(allProjectsScope.request).toEqual({});

    const fallbackToFirstProject = buildEnvironmentsListRequest({
      requestedScopeProjectId: '',
      selectedProjectId: '',
      projects,
      showArchivedEnvironments: false,
    });
    expect(fallbackToFirstProject.resolvedScopeProjectId).toBe('proj_a');
    expect(fallbackToFirstProject.request).toEqual({
      projectId: 'proj_a',
      status: 'ACTIVE',
    });
  });

  test('create-environment project selection and guard use active projects only', () => {
    const activeProjects = [{ id: 'proj_a' }, { id: 'proj_b' }];

    expect(
      resolveCreateEnvironmentProjectId({
        currentProjectId: 'proj_b',
        selectedProjectId: 'proj_a',
        activeProjects,
      }),
    ).toBe('proj_b');
    expect(
      resolveCreateEnvironmentProjectId({
        currentProjectId: 'proj_archived',
        selectedProjectId: 'proj_a',
        activeProjects,
      }),
    ).toBe('proj_a');
    expect(
      resolveCreateEnvironmentProjectId({
        currentProjectId: 'proj_archived',
        selectedProjectId: '',
        activeProjects,
      }),
    ).toBe('proj_a');
    expect(
      resolveCreateEnvironmentProjectId({
        currentProjectId: '',
        selectedProjectId: '',
        activeProjects: [],
      }),
    ).toBe('');

    expect(canCreateEnvironmentInProject('proj_a', activeProjects)).toBe(true);
    expect(canCreateEnvironmentInProject('proj_archived', activeProjects)).toBe(false);
    expect(canCreateEnvironmentInProject('', activeProjects)).toBe(false);
  });
});
