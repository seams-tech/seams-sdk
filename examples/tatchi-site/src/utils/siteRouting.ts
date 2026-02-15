const DOCS_PREFIX = '/docs'
const DEFAULT_DOCS_ORIGIN = 'https://docs.example.localhost'

function stripTrailingSlash(path: string): string {
  if (path.length <= 1) return path
  return path.endsWith('/') ? path.slice(0, -1) : path
}

export function getSiteBase(): string {
  const base = ((import.meta as any)?.env?.BASE_URL || '/') as string
  return stripTrailingSlash(base) || '/'
}

export function getDocsOrigin(): string {
  const configured = String((import.meta as any)?.env?.VITE_DOCS_ORIGIN || '').trim()
  return stripTrailingSlash(configured) || DEFAULT_DOCS_ORIGIN
}

export function isHttpUrl(value: string): boolean {
  return /^https?:\/\//.test(value)
}

function toSiteAbsolutePath(pathOrHash: string): string {
  if (!pathOrHash) return '/'
  if (pathOrHash.startsWith('#')) return `${window.location.pathname}${pathOrHash}`
  const normalized = pathOrHash.startsWith('/') ? pathOrHash : `/${pathOrHash}`
  const base = getSiteBase()
  if (base === '/') return normalized
  return `${base}${normalized}`
}

export function maybeDocsHref(target: string): string | null {
  if (!target.startsWith(DOCS_PREFIX)) return null
  const docsOrigin = getDocsOrigin()
  const suffix = target === DOCS_PREFIX ? '/' : target.slice(DOCS_PREFIX.length)
  return `${docsOrigin}${suffix.startsWith('/') ? suffix : `/${suffix}`}`
}

export function resolveHref(target: string): string {
  if (isHttpUrl(target)) return target

  const docsHref = maybeDocsHref(target)
  if (docsHref) return docsHref

  return toSiteAbsolutePath(target)
}

export function normalizePathname(pathname: string): string {
  if (!pathname) return '/'
  const clean = pathname.split('?')[0].split('#')[0]
  const normalized = clean.startsWith('/') ? clean : `/${clean}`
  return stripTrailingSlash(normalized) || '/'
}

