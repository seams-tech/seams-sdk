import { expect, test } from '@playwright/test';
import fs from 'fs';
import path from 'path';

/**
 * The account-menu dialogs render while their inventory loads and keep
 * themselves out of sight with the `hidden` attribute. Their stylesheet also
 * gives them `display: flex`, and an author `display` beats the user agent's
 * `[hidden] { display: none }` whatever its specificity — so the gate is only
 * real while the stylesheet restores it. Without that rule the empty shell
 * paints and the dialog visibly grows the moment its data lands.
 */
const MODAL_CSS = path.join(
  process.env.W3A_REPO_ROOT ?? path.resolve(process.cwd(), '..'),
  'packages/wallet/src/react/components/AccountMenuButton/LinkedDevicesModal.css',
);

test('a loading account-menu dialog is really hidden', async ({ page }) => {
  const css = fs.readFileSync(MODAL_CSS, 'utf8');
  await page.setContent('<!doctype html><html><head></head><body></body></html>');
  const display = await page.evaluate((styles) => {
    const style = document.createElement('style');
    style.textContent = styles;
    document.head.appendChild(style);
    const dialog = document.createElement('div');
    dialog.className = 'w3a-linked-devices-modal-content';
    dialog.hidden = true;
    document.body.appendChild(dialog);
    return {
      whileLoading: getComputedStyle(dialog).display,
      onceReady: ((): string => {
        dialog.hidden = false;
        return getComputedStyle(dialog).display;
      })(),
    };
  }, css);

  expect(display.whileLoading).toBe('none');
  expect(display.onceReady).toBe('flex');
});
