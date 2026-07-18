import React from 'react';
import { ECOSYSTEM_LOGO_MARKS, type EcosystemLogoMark } from './ecosystemLogoTiles';

/* Isometric integrations plane (ElevenLabs-style): an oversized square grid
   tilted back in 3D, with the tool marks lying flat on it in grid cells. The
   band clips and fades the plane; each mark counter-rotates the plane's Z
   spin so it faces the viewer while staying foreshortened with the surface.
   Collapses to a flat wrapped logo row on small screens. */

const CELL = 100;

function markStyle(mark: EcosystemLogoMark): React.CSSProperties {
  return { left: mark.col * CELL, top: mark.row * CELL };
}

export function EcosystemLattice(): React.JSX.Element {
  const label = `Tools Seams connects: ${ECOSYSTEM_LOGO_MARKS.map((m) => m.label).join(', ')}`;
  return (
    <div className="h2-lattice" role="img" aria-label={label}>
      <div className="h2-lattice__plane">
        {ECOSYSTEM_LOGO_MARKS.map((mark) => (
          <span
            key={mark.id}
            className="h2-latticemark"
            style={markStyle(mark)}
            title={mark.label}
          >
            <svg
              viewBox="0 0 24 24"
              aria-hidden
              focusable="false"
              style={mark.glyphSize ? { width: mark.glyphSize, height: mark.glyphSize } : undefined}
            >
              {mark.glyphs.map((glyph, i) => (
                <path key={i} d={glyph.d} fill={glyph.fill} />
              ))}
            </svg>
          </span>
        ))}
      </div>
    </div>
  );
}

export default EcosystemLattice;
