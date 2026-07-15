import React from 'react';
import './GlassBorder.css';

interface GlassBorderProps {
  children: React.ReactNode;
  className?: string;
  style?: React.CSSProperties;
}

export const GlassBorder: React.FC<GlassBorderProps> = ({
  children,
  className = '',
  style = {},
}) => {
  return (
    <div className={`glass-border-inner ${className}`.trim()} style={style}>
      {children}
    </div>
  );
};
