export const TEST_BROWSER_IMPORTS = {
  react: 'https://esm.sh/react@19.1.1',
  'react/jsx-runtime': 'https://esm.sh/react@19.1.1/jsx-runtime',
  'react/jsx-dev-runtime': 'https://esm.sh/react@19.1.1/jsx-dev-runtime',
  'react-dom': 'https://esm.sh/react-dom@19.1.1',
  'react-dom/client': 'https://esm.sh/react-dom@19.1.1/client',
  bs58: 'https://esm.sh/bs58@6.0.0',
  idb: 'https://esm.sh/idb@8.0.0',
  '@noble/ed25519': 'https://esm.sh/@noble/ed25519@3.0.0',
  '@noble/curves/': 'https://esm.sh/@noble/curves@2.0.1/',
  '@noble/hashes/': 'https://esm.sh/@noble/hashes@2.0.1/',
  qrcode: 'https://esm.sh/qrcode@1.5.4',
  jsqr: 'https://esm.sh/jsqr@1.4.0',
  '@near-js/types': 'https://esm.sh/@near-js/types@2.0.1',
  tslib: 'https://esm.sh/tslib@2.8.1',
  buffer: 'https://esm.sh/buffer@6.0.3',
  lit: 'https://esm.sh/lit@3.1.0',
  'lit/decorators.js': 'https://esm.sh/lit@3.1.0/decorators.js',
  'lit/directive.js': 'https://esm.sh/lit@3.1.0/directive.js',
  'lit/directive-helpers.js': 'https://esm.sh/lit@3.1.0/directive-helpers.js',
  'lit/async-directive.js': 'https://esm.sh/lit@3.1.0/async-directive.js',
  'lit/directives/when.js': 'https://esm.sh/lit@3.1.0/directives/when.js',
  'lit/directives/if-defined.js': 'https://esm.sh/lit@3.1.0/directives/if-defined.js',
  'lit/directives/class-map.js': 'https://esm.sh/lit@3.1.0/directives/class-map.js',
  'lit/directives/style-map.js': 'https://esm.sh/lit@3.1.0/directives/style-map.js',
  'lit/directives/repeat.js': 'https://esm.sh/lit@3.1.0/directives/repeat.js',
  'lit/directives/guard.js': 'https://esm.sh/lit@3.1.0/directives/guard.js',
  'lit/directives/cache.js': 'https://esm.sh/lit@3.1.0/directives/cache.js',
  'lit/directives/until.js': 'https://esm.sh/lit@3.1.0/directives/until.js',
  'lit/directives/ref.js': 'https://esm.sh/lit@3.1.0/directives/ref.js',
  'lit/directives/live.js': 'https://esm.sh/lit@3.1.0/directives/live.js',
  'lit/directives/unsafe-html.js': 'https://esm.sh/lit@3.1.0/directives/unsafe-html.js',
  'lit/directives/unsafe-svg.js': 'https://esm.sh/lit@3.1.0/directives/unsafe-svg.js',
  'lit/static-html.js': 'https://esm.sh/lit@3.1.0/static-html.js',
  'lit/html.js': 'https://esm.sh/lit@3.1.0/html.js',
  'lit/css.js': 'https://esm.sh/lit@3.1.0/css.js',
  'lit/lit-element.js': 'https://esm.sh/lit@3.1.0/lit-element.js',
  'lit/reactive-element.js': 'https://esm.sh/lit@3.1.0/reactive-element.js',
} as const;

export const TEST_BROWSER_IMPORT_MAP_ATTR = 'data-w3a-importmap';
export const TEST_BROWSER_IMPORT_MAP_MARKER = `${TEST_BROWSER_IMPORT_MAP_ATTR}="1"`;

export function buildTestBrowserImportMapHtml(): string {
  return `<script type="importmap" ${TEST_BROWSER_IMPORT_MAP_MARKER}>${JSON.stringify({
    imports: TEST_BROWSER_IMPORTS,
  })}</script>`;
}
