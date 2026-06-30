import React from 'react';
import { resolveSeamsLogoAsset, type SeamsLogoVariant } from '@/context/seamsBranding';
import { useSiteTheme } from '@/shared/hooks/useSiteTheme';

export type SeamsLogoProps = Omit<React.ImgHTMLAttributes<HTMLImageElement>, 'src'> & {
  size?: number | string;
  variant?: SeamsLogoVariant;
};

const SeamsLogo: React.FC<SeamsLogoProps> = ({
  size = 36,
  variant = 'app-icon',
  className,
  alt = '',
  draggable = false,
  style,
  ...rest
}) => {
  const numericSize = typeof size === 'number' ? size : undefined;
  const { theme } = useSiteTheme();

  return (
    <img
      {...rest}
      src={resolveSeamsLogoAsset(variant, theme)}
      alt={alt}
      width={numericSize}
      height={numericSize}
      draggable={draggable}
      className={['seams-logo-icon', `seams-logo-icon--${variant}`, className]
        .filter(Boolean)
        .join(' ')}
      style={{ width: size, height: size, ...style }}
      aria-hidden={alt ? rest['aria-hidden'] : true}
    />
  );
};

export default SeamsLogo;
