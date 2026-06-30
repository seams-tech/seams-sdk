import React from 'react';
import { resolveSeamsWordmarkAsset } from '@/context/seamsBranding';
import { useSiteTheme } from '@/shared/hooks/useSiteTheme';

export type SeamsWordmarkProps = Omit<React.ImgHTMLAttributes<HTMLImageElement>, 'src'> & {
  height?: number | string;
};

const SeamsWordmark: React.FC<SeamsWordmarkProps> = ({
  height = 28,
  className,
  alt = '',
  draggable = false,
  style,
  ...rest
}) => {
  const numericHeight = typeof height === 'number' ? height : undefined;
  const { theme } = useSiteTheme();

  return (
    <img
      {...rest}
      src={resolveSeamsWordmarkAsset(theme)}
      alt={alt}
      height={numericHeight}
      draggable={draggable}
      className={['seams-wordmark', className].filter(Boolean).join(' ')}
      style={{ height, width: 'auto', ...style }}
      aria-hidden={alt ? rest['aria-hidden'] : true}
    />
  );
};

export default SeamsWordmark;
