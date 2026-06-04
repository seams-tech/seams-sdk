import type { KeyExportCapability } from '../interfaces';

export function createKeyExportCapability(handlers: KeyExportCapability): KeyExportCapability {
  return {
    exportKeypairWithUI: async (input) => await handlers.exportKeypairWithUI(input),
    exportThresholdEd25519SeedFromHssReport: async (args) =>
      await handlers.exportThresholdEd25519SeedFromHssReport(args),
  };
}
