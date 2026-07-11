import React from 'react';

/* Keeps its own height matched to the children's height.
 *
 * Two modes, decided per ResizeObserver tick:
 * - Continuous reflow (an animation inside is driving the content, e.g. an
 *   expander's ::details-content transition): glue to the content with no
 *   transition of our own. A follower transition retargeted every frame
 *   lags a moving edge by ~its whole duration and keeps easing after the
 *   source animation ends, which reads as a two-stage resize. Writing the
 *   height directly inside the RO callback happens before paint, so the
 *   wrapper tracks the animation pixel-perfect.
 * - Isolated jump (async content appears, view swap): let the short CSS
 *   transition on .animated-height ease it.
 *
 * Heights are written straight to the DOM (no React state) so tracking
 * doesn't pay a re-render per frame.
 */
export function AnimatedHeight(props: {
  children: React.ReactNode;
  className?: string;
}): React.JSX.Element {
  const outerRef = React.useRef<HTMLDivElement | null>(null);
  const innerRef = React.useRef<HTMLDivElement | null>(null);

  React.useLayoutEffect(() => {
    const outer = outerRef.current;
    const inner = innerRef.current;
    if (!outer || !inner) return;

    let lastHeight = inner.offsetHeight;
    let lastChangeAt = -Infinity;
    outer.style.height = `${lastHeight}px`;

    const update = () => {
      const next = inner.offsetHeight;
      if (next === lastHeight) return;
      const now = performance.now();
      /* changes on back-to-back frames = mid-animation → track, don't ease */
      const continuous = now - lastChangeAt < 120;
      outer.style.transition = continuous ? 'none' : '';
      outer.style.height = `${next}px`;
      lastHeight = next;
      lastChangeAt = now;
    };

    const observer = new ResizeObserver(update);
    observer.observe(inner);
    return () => observer.disconnect();
  }, []);

  return (
    <div
      ref={outerRef}
      className={['animated-height', props.className].filter(Boolean).join(' ')}
    >
      <div ref={innerRef}>{props.children}</div>
    </div>
  );
}

export default AnimatedHeight;
