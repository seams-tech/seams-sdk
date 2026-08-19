import React from 'react';
import { createRoot } from 'react-dom/client';
import '@fontsource/hanken-grotesk/300.css';
import '@fontsource/hanken-grotesk/400.css';
import '@fontsource/hanken-grotesk/500.css';
import '@fontsource/hanken-grotesk/600.css';
import '@fontsource/hanken-grotesk/700.css';
import '@core/dashboard/styles.css';
import { App } from './App';

const container = document.getElementById('root');
if (!container) throw new Error('Missing #root container');
createRoot(container).render(
  <React.StrictMode>
    <App />
  </React.StrictMode>,
);
