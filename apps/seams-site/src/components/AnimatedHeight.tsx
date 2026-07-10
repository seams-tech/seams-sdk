import React from 'react';

/* Animates its own height whenever the children reflow (tab switches,
   expanders, async content). Uses a CSS transition rather than keyframes so
   mid-flight changes retarget smoothly instead of restarting. */
export function AnimatedHeight(props: {
  children: React.ReactNode;
  className?: string;
}): React.JSX.Element {
  const innerRef = React.useRef<HTMLDivElement | null>(null);
  const [height, setHeight] = React.useState<number | null>(null);

  React.useLayoutEffect(() => {
    const el = innerRef.current;
    if (!el) return;
    const update = () => setHeight(el.offsetHeight);
    update();
    const observer = new ResizeObserver(update);
    observer.observe(el);
    return () => observer.disconnect();
  }, []);

  return (
    <div
      className={['animated-height', props.className].filter(Boolean).join(' ')}
      style={height === null ? undefined : { height }}
    >
      <div ref={innerRef}>{props.children}</div>
    </div>
  );
}

export default AnimatedHeight;
