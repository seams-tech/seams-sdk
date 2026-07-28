// Deliberately broken: `absentExport` does not exist, so this file throws a
// link-time SyntaxError during Playwright's collection phase. Used by
// unit/collectionGuard.unit.test.ts to prove load failures stay fatal.
// @ts-expect-error -- the missing export is the point of this fixture.
import { absentExport } from './moduleUnderTest';
import { expect, test } from '@playwright/test';

test('never runs because the module above fails to link', () => {
  expect(absentExport).toBeDefined();
});
