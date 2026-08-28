import { expect, test } from '@playwright/test';
import { setupBasicPasskeyTest, sdkEsmPath } from '../setup';
import { ensureComponentModule, mountComponent } from './harness';

/**
 * The waiting view's message must be centred on the CARD, not merely on its own
 * box. The card carries a height floor, so a shorter waiting box sits
 * top-anchored inside it and pushes the message above the card's true centre.
 * The visible symptom is motion: while the card animates its height, a message
 * that is not on the centre line rides the moving top edge instead of holding
 * still.
 *
 * Asserting the offset between the message's centre and the card's centre
 * catches that directly — a fixed pixel height would not, since the bug is a
 * relationship between two boxes rather than any one value.
 */

const AUTH_MENU_MODULE = sdkEsmPath(
  'SeamsWeb/walletIframe/host/lit-ui/auth-menu/seams-auth-menu-surface.js',
);
const AUTH_MENU_TAG = 'seams-auth-menu-surface';

test.describe('auth menu waiting view centering', () => {
  test.beforeEach(async ({ page }) => {
    await setupBasicPasskeyTest(page);
    await ensureComponentModule(page, {
      modulePath: AUTH_MENU_MODULE,
      tagName: AUTH_MENU_TAG,
    });
  });

  test('waiting message sits on the card centre line', async ({ page }) => {
    await mountComponent(page, {
      tagName: AUTH_MENU_TAG,
      props: {
        viewModel: {
          appearance: {
            theme: { id: 'default', mode: 'light', colors: {} },
            palette: 'default',
          },
          hostname: 'wallet.example.test',
          closeLabel: 'Close authentication menu',
          heading: 'Sign in',
          subtitle: 'Use your passkey to continue.',
          ctaLabel: 'Continue with passkey',
          showProgress: true,
          kind: 'passkey',
          mode: 'login',
          accountOptions: [],
          selectedAccount: null,
          status: { kind: 'busy', headline: 'Signing in…' },
        },
      },
    });
    await page.waitForSelector(`${AUTH_MENU_TAG} .w3a-waiting`, { state: 'attached' });

    const geometry = await page.evaluate(async (tagName) => {
      const surface = document.querySelector(tagName) as HTMLElement;
      // Measure the SETTLED layout. Enter animations translate content by a few
      // px, and sampling mid-flight reports that transient offset as if it were
      // the resting position.
      const settleDeadline = Date.now() + 4000;
      while (Date.now() < settleDeadline) {
        const running = surface
          .getAnimations({ subtree: true })
          .filter((a) => a.playState === 'running');
        if (running.length === 0) break;
        await Promise.race([
          Promise.allSettled(running.map((a) => a.finished)),
          new Promise((resolve) => setTimeout(resolve, 300)),
        ]);
      }
      await new Promise((resolve) => requestAnimationFrame(() => requestAnimationFrame(resolve)));
      const deadline = Date.now() + 5000;
      while (Date.now() < deadline) {
        const waiting = surface.querySelector('.w3a-waiting') as HTMLElement | null;
        const card = surface.querySelector('.w3a-signup-menu-root') as HTMLElement | null;
        const text = surface.querySelector('.w3a-waiting-text') as HTMLElement | null;
        if (waiting && card && text && card.offsetHeight > 0 && text.offsetHeight > 0) {
          const cardRect = card.getBoundingClientRect();
          const waitingRect = waiting.getBoundingClientRect();
          const textRect = text.getBoundingClientRect();
          const spinner = surface.querySelector('.w3a-waiting .w3a-spinner') as HTMLElement | null;
          const spinnerRect = spinner?.getBoundingClientRect() ?? null;
          // Centre of the whole message block (headline through spinner), which
          // is what the eye tracks during a resize.
          const blockTop = textRect.top;
          const blockBottom = spinnerRect ? spinnerRect.bottom : textRect.bottom;
          return {
            ready: true,
            cardHeight: Math.round(cardRect.height),
            waitingHeight: Math.round(waitingRect.height),
            // How far the waiting box falls short of the card's inner height.
            blockOffsetFromCardCentre: Math.round(
              (blockTop + blockBottom) / 2 - (cardRect.top + cardRect.bottom) / 2,
            ),
          };
        }
        await new Promise((resolve) => setTimeout(resolve, 50));
      }
      return { ready: false } as const;
    }, AUTH_MENU_TAG);

    expect(geometry.ready, JSON.stringify(geometry)).toBe(true);
    if (!geometry.ready) return;

    // The message block sits on the card's centre line. Tolerance covers
    // sub-pixel rounding and the card's 1px borders, and is far tighter than
    // the ~26px top-anchored offset this guards against.
    expect(
      Math.abs(geometry.blockOffsetFromCardCentre),
      JSON.stringify(geometry),
    ).toBeLessThanOrEqual(5);
  });
});
