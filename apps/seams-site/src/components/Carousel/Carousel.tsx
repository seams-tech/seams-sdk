import React from 'react';
import './CarouselStyles.css';

export type CarouselPage = {
  /** Stable identity (kept for readability; the component keys DOM by index). */
  key: string;
  title?: string;
  disabled?: boolean;
  element: React.ReactNode | (() => React.ReactNode);
};

/* Timing. The outgoing page stays mounted for HOLD_MS so its fade can finish;
   the height eases over HEIGHT_MS. Both are shorter than HOLD_MS so the stage
   settles before the outgoing page unmounts. */
const HOLD_MS = 300;
const HEIGHT_MS = 260;

/**
 * A minimal controlled carousel: shows `pages[index]`, cross-fades on change,
 * and eases the container height between differently-sized pages.
 *
 * Geometry is deliberately fixed: pages stack in a single grid cell and the
 * container width comes from `style` (the consumer's fixed width), never from
 * content — so switching pages can't resize or re-center the card. The only
 * animated dimension is height, driven imperatively in a layout effect.
 *
 * Enter/exit motion is pure CSS: the incoming page (keyed by index) mounts
 * fresh and runs its keyframe; the outgoing page keeps the exact DOM that was
 * on screen and fades out. No transition state machine.
 */
export function Carousel({
  pages,
  index,
  className,
  style,
}: {
  pages: CarouselPage[];
  index: number;
  className?: string;
  style?: React.CSSProperties;
}) {
  const [leavingIndex, setLeavingIndex] = React.useState<number | null>(null);
  const prevIndexRef = React.useRef(index);
  const stageRef = React.useRef<HTMLDivElement | null>(null);
  const enterRef = React.useRef<HTMLDivElement | null>(null);
  const exitRef = React.useRef<HTMLDivElement | null>(null);

  // Begin a transition the instant the controlled index changes — before paint,
  // so the outgoing copy is already mounted on the first painted frame (no
  // hard-cut flash).
  React.useLayoutEffect(() => {
    if (index === prevIndexRef.current) return;
    const prev = prevIndexRef.current;
    prevIndexRef.current = index;
    setLeavingIndex(prev);
    const timeout = setTimeout(() => setLeavingIndex(null), HOLD_MS);
    return () => clearTimeout(timeout);
  }, [index]);

  // Ease the stage height from the outgoing page's height to the incoming
  // one's, in the same pre-paint pass. Runs on [leavingIndex] so both nodes are
  // guaranteed mounted and measurable. Freeze → animate → release.
  React.useLayoutEffect(() => {
    if (leavingIndex == null) return;
    const stage = stageRef.current;
    const enter = enterRef.current;
    const exit = exitRef.current;
    if (!stage || !enter || !exit) return;
    const from = exit.offsetHeight;
    const to = enter.offsetHeight;
    if (!from || !to || Math.abs(from - to) < 1) return;

    stage.style.height = `${from}px`;
    void stage.offsetHeight; // reflow to lock the start height
    stage.style.transition = `height ${HEIGHT_MS}ms var(--site-ease)`;
    stage.style.height = `${to}px`;

    // Release to auto only after the outgoing page unmounts (HOLD_MS) — clearing
    // earlier would resolve auto against the taller page for a frame.
    const clear = () => {
      stage.style.transition = '';
      stage.style.height = '';
    };
    const timer = setTimeout(clear, HOLD_MS + 20);
    return () => {
      clearTimeout(timer);
      clear();
    };
  }, [leavingIndex]);

  const render = (page: CarouselPage | undefined): React.ReactNode =>
    page ? (typeof page.element === 'function' ? page.element() : page.element) : null;

  const activePage = pages[index];
  const leavingPage = leavingIndex != null ? pages[leavingIndex] : null;

  return (
    <div
      className={['carousel-root', className].filter(Boolean).join(' ')}
      style={style}
      aria-live="polite"
    >
      <div className="carousel-stage" ref={stageRef}>
        {leavingPage && (
          <div
            key={`exit-${leavingIndex}`}
            ref={exitRef}
            className="carousel-page page--exit"
            aria-hidden
          >
            {render(leavingPage)}
          </div>
        )}
        {activePage && (
          <div
            key={`enter-${index}`}
            ref={enterRef}
            className={`carousel-page page--enter${leavingPage ? ' page--animating' : ''}`}
          >
            {render(activePage)}
          </div>
        )}
      </div>
    </div>
  );
}

export default Carousel;
