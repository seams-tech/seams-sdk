// Fixture module for the collection-guard regression test. `absentExport` is
// deliberately absent so `broken.spec.ts` fails to link at module-load time.
export const presentExport = 'present';
