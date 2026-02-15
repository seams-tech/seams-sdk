import * as React from 'react'
import { isHttpUrl, resolveHref } from '../utils/siteRouting'

type GoFn = (to: string) => void

function isModifiedClick(e: React.MouseEvent<any>): boolean {
  return !!(e.metaKey || e.ctrlKey || e.shiftKey || e.altKey || e.button !== 0)
}

function navigateInternal(href: string): void {
  if (window.location.pathname + window.location.search + window.location.hash === href) return
  window.history.pushState({}, '', href)
  window.dispatchEvent(new Event('site:navigate'))
}

export function useSiteRouter(): {
  go: GoFn
  linkProps: (to: string) => { href: string; onClick: (e: React.MouseEvent<HTMLAnchorElement>) => void }
} {
  const go = React.useCallback<GoFn>((to: string) => {
    const href = resolveHref(to)
    if (isHttpUrl(href)) {
      window.location.href = href
      return
    }
    navigateInternal(href)
  }, [])

  const linkProps = React.useCallback((to: string) => {
    const href = resolveHref(to)
    return {
      href,
      onClick: (e: React.MouseEvent<HTMLAnchorElement>) => {
        if (isModifiedClick(e)) return
        const target = (e.currentTarget.getAttribute('target') || '').toLowerCase()
        if (target && target !== '_self') return
        e.preventDefault()
        if (isHttpUrl(href)) {
          window.location.href = href
          return
        }
        navigateInternal(href)
      },
    }
  }, [])

  return { go, linkProps }
}

export default useSiteRouter

