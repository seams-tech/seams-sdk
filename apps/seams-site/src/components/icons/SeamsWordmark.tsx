import React from 'react';
import { useSiteTheme } from '@/shared/hooks/useSiteTheme';

export type SeamsWordmarkProps = {
  /** Rendered height in px; type and mark scale proportionally. */
  height?: number;
  className?: string;
  style?: React.CSSProperties;
  /** Pin to a specific theme instead of following the site theme. */
  theme?: 'light' | 'dark';
};

/* Monochrome lockup: the mark matches the text ink. */
const WORDMARK_COLORS: Record<'light' | 'dark', { text: string; mark: string }> = {
  light: { text: '#0a0a0a', mark: '#0a0a0a' },
  dark: { text: '#f4f4f5', mark: '#f4f4f5' },
};

/**
 * Live-type wordmark: "Seams" set in the site's own face (Hanken Grotesk 700,
 * bold enough to sit level with the solid stitch mark)
 * with the stitch mark as inline SVG. Replaces the traced-path SVG assets so
 * the logo always matches site typography and stays crisp at any size. The
 * static SVGs under public/seams-v9 remain for standalone contexts
 * (favicons, og-images).
 */
const SeamsWordmark: React.FC<SeamsWordmarkProps> = ({
  height = 28,
  className,
  style,
  theme: themeOverride,
}) => {
  const { theme: siteTheme } = useSiteTheme();
  const theme = themeOverride ?? siteTheme;
  const colors = WORDMARK_COLORS[theme] ?? WORDMARK_COLORS.light;

  // font-size equals the lockup height: 28px in the navbar (height=28)
  const fontSize = height;
  const markSize = height * 0.68;

  return (
    <span
      className={['seams-wordmark', className].filter(Boolean).join(' ')}
      style={{
        display: 'inline-flex',
        alignItems: 'center',
        height,
        fontFamily:
          "'Hanken Grotesk', ui-sans-serif, system-ui, -apple-system, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif",
        fontWeight: 700,
        fontSize,
        lineHeight: 1,
        letterSpacing: '-0.02em',
        color: colors.text,
        whiteSpace: 'nowrap',
        userSelect: 'none',
        ...style,
      }}
    >
      seams
      <svg
        width={markSize}
        height={markSize}
        viewBox="19.969586 19.967394 24.047676 24.047676"
        aria-hidden
        style={{
          flex: '0 0 auto',
          // 2px gap and 2px down-nudge at the reference 28px height, scaled
          marginLeft: (height * 2) / 28,
          transform: `translateY(${(height * 2) / 28}px)`,
        }}
      >
        <g transform="translate(32 32) rotate(45) scale(1.55) translate(-9.549 -9.5495)">
          <path
            fill={colors.mark}
            stroke={colors.mark}
            strokeWidth={0.25}
            strokeLinejoin="round"
            fillRule="nonzero"
            d="M11.731 3.43c1.295 2.776 4.11 4.706 7.367 4.706v2.827h-.028c-4.479 0-8.124 3.65-8.124 8.136H8.122v-.002c0-4.096 2.255-7.675 5.588-9.556a11 11 0 0 1-3.387-2.992c.616-.97 1.09-2.02 1.408-3.12M10.946 0c0 2.929-1.138 5.68-3.207 7.752a11 11 0 0 1-2.346 1.793c1.32.751 2.469 1.77 3.375 2.98a12.2 12.2 0 0 0-1.415 3.101c-1.25-2.655-3.894-4.529-6.98-4.669q-.187.006-.373.006V8.12q.188 0 .373.006a8.07 8.07 0 0 0 5.372-2.374A8.08 8.08 0 0 0 8.122 0z"
          />
        </g>
      </svg>
    </span>
  );
};

export default SeamsWordmark;
