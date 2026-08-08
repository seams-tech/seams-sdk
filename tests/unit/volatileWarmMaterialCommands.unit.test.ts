import { expect, test } from '@playwright/test';
import {
  createClearVolatileWarmSessionMaterialCommand,
  parseClearVolatileWarmMaterialCommand,
} from '@/core/signingEngine/session/warmCapabilities/volatileWarmMaterialCommands';
import { parseThresholdEd25519SessionId } from '@shared/utils/domainIds';

test('volatile warm-material commands address threshold sessions explicitly', () => {
  const parsed = parseThresholdEd25519SessionId('threshold-session-command-test');
  if (!parsed.ok) throw new Error('expected threshold session fixture');

  const command = createClearVolatileWarmSessionMaterialCommand(parsed.value);
  expect(command.scope).toEqual({
    kind: 'session',
    thresholdSessionId: 'threshold-session-command-test',
  });
  expect(parseClearVolatileWarmMaterialCommand(command)).toEqual(command);

  expect(
    parseClearVolatileWarmMaterialCommand({
      kind: 'clear_volatile_warm_material',
      scope: { kind: 'session', sessionId: 'threshold-session-command-test' },
    }),
  ).toBeNull();
});
