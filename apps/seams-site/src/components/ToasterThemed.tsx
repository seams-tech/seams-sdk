import React from 'react';
import { Toaster } from 'sonner';
import { useTheme } from '@seams/sdk/react';
import './Toaster.css';

export const ToasterThemed: React.FC = () => {
  const { isDark } = useTheme();
  return (
    <Toaster
      position="bottom-right"
      theme={isDark ? 'dark' : 'light'}
      closeButton
      toastOptions={{
        duration: 3500,
        style: {
          background: 'var(--site-toast-background, var(--w3a-colors-surface))',
          color: 'var(--site-toast-text-primary, var(--w3a-colors-textPrimary))',
          border: '1px solid var(--site-toast-border, var(--w3a-colors-borderPrimary))',
          borderRadius: '1rem',
          boxShadow: 'var(--site-toast-shadow, var(--w3a-shadows-lg))',
        },
        // Keep error toasts (e.g., registration failures) visible
        // until the user explicitly closes them.
        // @ts-ignore
        error: {
          duration: Infinity,
        },
      }}
    />
  );
};

export default ToasterThemed;
