import React from 'react';

/* Structural placeholder for the demo transaction card: mirrors the loaded
   layout (title, subtitle, chain seg, greeting box, input, status slot, two
   buttons) at the real geometry, so both the lazy-chunk fallback and the
   data-settle skeleton swap into content without a layout jump. Inline-styled
   on purpose: it must render before any lazy chunk (and its CSS) arrives. */

const bone: React.CSSProperties = {
  background: 'color-mix(in srgb, currentColor 7%, transparent)',
  borderRadius: 12,
};

export function DemoTxCardSkeleton(): React.JSX.Element {
  return (
    <div aria-hidden style={{ display: 'grid', gap: 12, padding: '8px 0' }}>
      <div style={{ ...bone, height: 34, width: '38%' }} />
      <div style={{ ...bone, height: 20, width: '72%' }} />
      <div style={{ ...bone, height: 44, borderRadius: 22 }} />
      <div style={{ ...bone, height: 56 }} />
      <div style={{ ...bone, height: 48 }} />
      <div style={{ ...bone, height: 20, width: '46%' }} />
      <div style={{ ...bone, height: 48, borderRadius: 14 }} />
      <div style={{ ...bone, height: 48, borderRadius: 14 }} />
    </div>
  );
}

export default DemoTxCardSkeleton;
