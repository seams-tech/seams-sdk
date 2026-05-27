import React from 'react';
import { SEAMS_LOGO_ASSETS, type SeamsLogoVariant } from '@/context/seamsBranding';

export type SeamsLogoProps = Omit<React.ImgHTMLAttributes<HTMLImageElement>, 'src'> & {
  size?: number | string;
  variant?: SeamsLogoVariant;
};

const SeamsLogo: React.FC<SeamsLogoProps> = ({
  size = 24,
  variant = 'app-icon',
  className,
  alt = '',
  draggable = false,
  style,
  ...rest
}) => {
  const numericSize = typeof size === 'number' ? size : undefined;

  return (
    <img
      {...rest}
      src={SEAMS_LOGO_ASSETS[variant]}
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
