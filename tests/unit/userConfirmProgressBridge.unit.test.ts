import fs from 'node:fs';
import path from 'node:path';
import { expect, test } from '@playwright/test';

test('UserConfirm worker forwards prompt progress envelopes back to the host listener', () => {
  const workerSource = fs.readFileSync(
    path.resolve(
      process.cwd(),
      '../packages/sdk-web/src/core/signingEngine/workerManager/workers/passkey-confirm.worker.ts',
    ),
    'utf8',
  );

  expect(workerSource).toContain(
    'eventType === UserConfirmMessageType.USER_PASSKEY_CONFIRM_PROGRESS',
  );
  expect(workerSource).toContain('forwardUserConfirmProgressToHost(event.data)');
  expect(workerSource).toContain('self.postMessage(envelope)');
});
