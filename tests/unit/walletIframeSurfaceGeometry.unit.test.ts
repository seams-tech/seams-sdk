import { expect, test } from '@playwright/test';
import { setupBasicPasskeyTest } from '../setup';

const GEOMETRY_PATH = '/_test-sdk/esm/SeamsWeb/walletIframe/client/surface/geometry.js';
const DOMAIN_PATH = '/_test-sdk/esm/SeamsWeb/walletIframe/client/surface/domain.js';
const MESSAGES_PATH = '/_test-sdk/esm/SeamsWeb/walletIframe/shared/messages.js';

test.describe('wallet iframe surface geometry', () => {
  test.beforeEach(async ({ page }) => {
    await setupBasicPasskeyTest(page);
  });

  test('clamps, places, and falls back compact surfaces at the visual viewport boundary', async ({
    page,
  }) => {
    const result = await page.evaluate(
      async ({ geometryPath, domainPath, messagesPath }) => {
        const geometry = await import(geometryPath);
        const domain = await import(domainPath);
        const messages = await import(messagesPath);
        const viewport = {
          widthCssPx: 1024,
          heightCssPx: 768,
          offsetLeftCssPx: 10,
          offsetTopCssPx: 20,
        };
        const modal = domain.modalWalletIframeSurfacePresentation('Confirm');
        const drawer = domain.drawerWalletIframeSurfacePresentation('Confirm');
        const provisionalModal = geometry.provisionalWalletIframeSurfaceGeometry(modal, viewport);
        const provisionalDrawer = geometry.provisionalWalletIframeSurfaceGeometry(drawer, viewport);
        const measuredModal = geometry.measuredWalletIframeSurfaceGeometry(modal, viewport, {
          widthCssPx: 700,
          heightCssPx: 900,
        });
        const measuredGrowingModal = geometry.measuredWalletIframeSurfaceGeometry(modal, viewport, {
          widthCssPx: 416,
          heightCssPx: 400,
        });
        const anchoredAuthMenu = geometry.anchorWalletIframeModalGeometry(
          {
            kind: 'centered_modal',
            widthCssPx: 377,
            heightCssPx: 390,
            topCssPx: 189,
            leftCssPx: 37,
          },
          {
            topCssPx: 600,
            leftCssPx: 37,
            widthCssPx: 377,
            heightCssPx: 450,
          },
        );
        const scrolledAnchoredAuthMenu = geometry.anchorWalletIframeModalGeometry(
          anchoredAuthMenu,
          {
            topCssPx: -120,
            leftCssPx: 37,
            widthCssPx: 377,
            heightCssPx: 450,
          },
        );
        // Browser zoom shrinks the viewport's CSS px while the in-flow anchor
        // keeps its CSS size; the anchored menu must mirror the anchor rather
        // than clamp to the (now smaller) viewport.
        const zoomedAnchoredAuthMenu = geometry.anchorWalletIframeModalGeometry(
          {
            kind: 'centered_modal',
            widthCssPx: 420,
            heightCssPx: 390,
            topCssPx: 189,
            leftCssPx: 37,
          },
          {
            topCssPx: 600,
            leftCssPx: 20,
            widthCssPx: 420,
            heightCssPx: 450,
          },
        );
        const measuredDrawer = geometry.measuredWalletIframeSurfaceGeometry(drawer, viewport, {
          widthCssPx: 700,
          heightCssPx: 900,
        });
        const compactMeasuredDrawer = geometry.measuredWalletIframeSurfaceGeometry(
          drawer,
          viewport,
          {
            widthCssPx: 320,
            heightCssPx: 240,
          },
        );
        const smallViewport = geometry.resolveWalletIframeSurfaceGeometry({
          presentation: modal,
          viewport: { ...viewport, widthCssPx: 300, heightCssPx: 500 },
          measurement: { kind: 'pending' },
        });
        const smallDrawerViewport = geometry.resolveWalletIframeSurfaceGeometry({
          presentation: drawer,
          viewport: { ...viewport, widthCssPx: 300, heightCssPx: 500 },
          measurement: { kind: 'pending' },
        });
        const smallMeasuredDrawer = geometry.resolveWalletIframeSurfaceGeometry({
          presentation: drawer,
          viewport: { ...viewport, widthCssPx: 300, heightCssPx: 500 },
          measurement: { kind: 'measured', widthCssPx: 120, heightCssPx: 120 },
        });
        const unavailable = geometry.resolveWalletIframeSurfaceGeometry({
          presentation: modal,
          viewport,
          measurement: { kind: 'unavailable' },
        });
        const unavailableDrawer = geometry.resolveWalletIframeSurfaceGeometry({
          presentation: drawer,
          viewport,
          measurement: { kind: 'unavailable' },
        });
        const parsed = geometry.parseWalletIframeSurfaceGeometry(measuredModal);
        const rejected = geometry.parseWalletIframeSurfaceGeometry({
          ...measuredModal,
          widthCssPx: Number.POSITIVE_INFINITY,
        });
        const extraKeyRejected = geometry.parseWalletIframeSurfaceGeometry({
          ...measuredModal,
          extra: true,
        });
        const rightEdgeRejected = geometry.parseWalletIframeSurfaceGeometry({
          kind: 'bottom_drawer',
          edge: 'right',
          widthCssPx: 320,
          heightCssPx: 320,
          topCssPx: 432,
          leftCssPx: 352,
        });
        const measurement = {
          kind: 'measured_v1',
          requestId: 'request-a',
          sequence: 1,
          widthCssPx: 320,
          heightCssPx: 240,
        };
        const parsedMeasurement = messages.parseWalletIframeSurfaceMeasurement(measurement);
        const measurementExtraKeyRejected = messages.parseWalletIframeSurfaceMeasurement({
          ...measurement,
          extra: true,
        });
        const measurementWrongBranchKeyRejected = messages.parseWalletIframeSurfaceMeasurement({
          ...measurement,
          authMenuSessionId: 'auth-session',
        });
        return {
          provisionalModal,
          provisionalDrawer,
          measuredModal,
          measuredGrowingModal,
          anchoredAuthMenu,
          scrolledAnchoredAuthMenu,
          zoomedAnchoredAuthMenu,
          measuredDrawer,
          compactMeasuredDrawer,
          smallViewport,
          smallDrawerViewport,
          smallMeasuredDrawer,
          unavailable,
          unavailableDrawer,
          parsed,
          rejected,
          extraKeyRejected,
          rightEdgeRejected,
          parsedMeasurement,
          measurementExtraKeyRejected,
          measurementWrongBranchKeyRejected,
        };
      },
      { geometryPath: GEOMETRY_PATH, domainPath: DOMAIN_PATH, messagesPath: MESSAGES_PATH },
    );

    expect(result.provisionalModal).toEqual({
      kind: 'provisional_centered_modal',
      widthCssPx: 560,
      heightCssPx: 320,
      topCssPx: 244,
      leftCssPx: 242,
    });
    expect(result.provisionalDrawer).toEqual({
      kind: 'provisional_bottom_drawer',
      edge: 'bottom',
      widthCssPx: 1024,
      heightCssPx: 768,
      topCssPx: 20,
      leftCssPx: 10,
    });
    expect(result.measuredModal).toEqual({
      kind: 'centered_modal',
      widthCssPx: 560,
      heightCssPx: 736,
      topCssPx: 36,
      leftCssPx: 242,
    });
    expect(result.measuredGrowingModal).toEqual({
      kind: 'centered_modal',
      widthCssPx: 416,
      heightCssPx: 400,
      topCssPx: 204,
      leftCssPx: 314,
    });
    expect(result.measuredGrowingModal.widthCssPx).toBeGreaterThan(360);
    expect(result.anchoredAuthMenu).toEqual({
      kind: 'centered_modal',
      widthCssPx: 377,
      heightCssPx: 390,
      topCssPx: 600,
      leftCssPx: 37,
    });
    expect(result.scrolledAnchoredAuthMenu.topCssPx).toBe(-120);
    expect(result.zoomedAnchoredAuthMenu).toEqual({
      kind: 'centered_modal',
      widthCssPx: 420,
      heightCssPx: 390,
      topCssPx: 600,
      leftCssPx: 20,
    });
    expect(result.measuredDrawer).toEqual({
      kind: 'bottom_drawer',
      edge: 'bottom',
      widthCssPx: 1024,
      heightCssPx: 768,
      topCssPx: 20,
      leftCssPx: 10,
    });
    expect(result.compactMeasuredDrawer).toEqual({
      kind: 'bottom_drawer',
      edge: 'bottom',
      widthCssPx: 1024,
      heightCssPx: 768,
      topCssPx: 20,
      leftCssPx: 10,
    });
    expect(result.smallViewport).toEqual({
      kind: 'viewport_fallback',
      reason: 'small_visual_viewport',
      widthCssPx: 268,
      heightCssPx: 468,
      topCssPx: 36,
      leftCssPx: 26,
    });
    expect(result.smallDrawerViewport).toEqual({
      kind: 'provisional_bottom_drawer',
      edge: 'bottom',
      widthCssPx: 300,
      heightCssPx: 500,
      topCssPx: 20,
      leftCssPx: 10,
    });
    expect(result.smallMeasuredDrawer).toEqual({
      kind: 'bottom_drawer',
      edge: 'bottom',
      widthCssPx: 300,
      heightCssPx: 500,
      topCssPx: 20,
      leftCssPx: 10,
    });
    expect(result.unavailable).toEqual({
      kind: 'viewport_fallback',
      reason: 'measurement_unavailable',
      widthCssPx: 992,
      heightCssPx: 736,
      topCssPx: 36,
      leftCssPx: 26,
    });
    expect(result.unavailableDrawer).toEqual({
      kind: 'bottom_drawer',
      edge: 'bottom',
      widthCssPx: 1024,
      heightCssPx: 768,
      topCssPx: 20,
      leftCssPx: 10,
    });
    expect(result.parsed).toEqual(result.measuredModal);
    expect(result.rejected).toBeNull();
    expect(result.extraKeyRejected).toBeNull();
    expect(result.rightEdgeRejected).toBeNull();
    expect(result.parsedMeasurement).toMatchObject({
      kind: 'measured_v1',
      requestId: 'request-a',
      sequence: 1,
      widthCssPx: 320,
      heightCssPx: 240,
    });
    expect(result.measurementExtraKeyRejected).toBeNull();
    expect(result.measurementWrongBranchKeyRejected).toBeNull();
  });
});
