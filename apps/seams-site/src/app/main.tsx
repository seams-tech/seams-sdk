import { createRoot } from 'react-dom/client';
import { App } from './App';
import '../app.css';
import '@fontsource/hanken-grotesk/300.css';
import '@fontsource/hanken-grotesk/400.css';
import '@fontsource/hanken-grotesk/400-italic.css';
import '@fontsource/hanken-grotesk/500.css';
import '@fontsource/hanken-grotesk/500-italic.css';
import '@fontsource/hanken-grotesk/600.css';
import '@fontsource/hanken-grotesk/600-italic.css';
import '@fontsource/hanken-grotesk/700.css';
import '@fontsource/hanken-grotesk/700-italic.css';
// Standalone dev page needs SDK styles globally
import '@seams/sdk/react/styles';

const rootEl = document.getElementById('app-root');

if (!rootEl) {
  throw new Error('[seams-site] Missing #app-root mount element');
}

const root = createRoot(rootEl);
root.render(<App />);
