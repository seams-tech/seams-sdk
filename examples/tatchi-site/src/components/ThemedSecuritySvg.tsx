import { useEffect, useState } from 'react'

type ThemedSecuritySvgProps = {
  src: string
  alt: string
  className?: string
  style?: React.CSSProperties
}

const themedMarkupCache = new Map<string, string>()
const loadPromiseCache = new Map<string, Promise<string>>()
const SVG_OPEN_TAG_PATTERN = /<svg\b[^>]*>/i
const SVG_RECT_TAG_PATTERN = /<rect\b[^>]*\/?>/gi
const SVG_PATH_TAG_PATTERN = /<path\b[^>]*\/?>/gi

function parseSvgDimension(svgTag: string, attribute: 'width' | 'height'): number | null {
  const match = svgTag.match(new RegExp(`\\b${attribute}=["']\\s*([-+]?\\d*\\.?\\d+)`))
  if (!match) return null

  const value = Number.parseFloat(match[1])
  return Number.isFinite(value) ? value : null
}

function parseSvgViewBox(svgTag: string): { width: number; height: number } | null {
  const match = svgTag.match(/\bviewBox=["']\s*[-+]?\d*\.?\d+\s+[-+]?\d*\.?\d+\s+([-+]?\d*\.?\d+)\s+([-+]?\d*\.?\d+)\s*["']/i)
  if (!match) return null

  const width = Number.parseFloat(match[1])
  const height = Number.parseFloat(match[2])
  if (!Number.isFinite(width) || !Number.isFinite(height)) return null

  return { width, height }
}

function withSvgAttribute(svgTag: string, name: string, value: string): string {
  const attributePattern = new RegExp(`\\s${name}=(\"[^\"]*\"|'[^']*')`, 'i')
  if (attributePattern.test(svgTag)) {
    return svgTag.replace(attributePattern, ` ${name}="${value}"`)
  }
  return svgTag.replace('<svg', `<svg ${name}="${value}"`)
}

function formatDimension(value: number): string {
  return Number.isInteger(value) ? String(value) : String(Number.parseFloat(value.toFixed(4)))
}

function parseTagAttribute(tagMarkup: string, attributeName: string): string | null {
  const match = tagMarkup.match(new RegExp(`\\b${attributeName}\\s*=\\s*(?:"([^"]*)"|'([^']*)')`, 'i'))
  if (!match) return null
  return match[1] ?? match[2] ?? null
}

function parseSvgNumericValue(value: string | null): number | null {
  if (!value) return null
  const match = value.match(/[-+]?\d*\.?\d+/)
  if (!match) return null

  const numericValue = Number.parseFloat(match[0])
  return Number.isFinite(numericValue) ? numericValue : null
}

function isApproximatelyEqual(left: number, right: number, tolerance = 0.01): boolean {
  return Math.abs(left - right) <= tolerance
}

function isSecurityCanvasFill(fillValue: string | null): boolean {
  if (!fillValue) return false
  const normalized = fillValue.replace(/\s+/g, '').toLowerCase()
  return normalized === '#2a3144' || normalized === 'var(--security-diagram-canvas,#2a3144)'
}

function getSvgCanvasSize(svgTag: string): { width: number; height: number } | null {
  const viewBoxSize = parseSvgViewBox(svgTag)
  if (viewBoxSize) return viewBoxSize

  const width = parseSvgDimension(svgTag, 'width')
  const height = parseSvgDimension(svgTag, 'height')
  if (!width || !height) return null

  return { width, height }
}

function isFullCanvasRectTag(
  rectTagMarkup: string,
  canvasSize: { width: number; height: number },
): boolean {
  if (!isSecurityCanvasFill(parseTagAttribute(rectTagMarkup, 'fill'))) return false

  const x = parseSvgNumericValue(parseTagAttribute(rectTagMarkup, 'x')) ?? 0
  const y = parseSvgNumericValue(parseTagAttribute(rectTagMarkup, 'y')) ?? 0
  const width = parseSvgNumericValue(parseTagAttribute(rectTagMarkup, 'width'))
  const height = parseSvgNumericValue(parseTagAttribute(rectTagMarkup, 'height'))
  if (width == null || height == null) return false

  return (
    isApproximatelyEqual(x, 0)
    && isApproximatelyEqual(y, 0)
    && isApproximatelyEqual(width, canvasSize.width)
    && isApproximatelyEqual(height, canvasSize.height)
  )
}

function tokenizePathData(pathData: string): string[] {
  return pathData
    .replace(/,/g, ' ')
    .replace(/([a-zA-Z])/g, ' $1 ')
    .trim()
    .replace(/\s+/g, ' ')
    .split(' ')
}

function isFullCanvasPathTag(
  pathTagMarkup: string,
  canvasSize: { width: number; height: number },
): boolean {
  if (!isSecurityCanvasFill(parseTagAttribute(pathTagMarkup, 'fill'))) return false

  const pathData = parseTagAttribute(pathTagMarkup, 'd')
  if (!pathData) return false

  const tokens = tokenizePathData(pathData)
  if (tokens.length !== 10) return false

  const commands = [tokens[0], tokens[3], tokens[5], tokens[7], tokens[9]].map((value) => value.toLowerCase())
  if (commands.join(' ') !== 'm h v h z') return false

  const originX = Number.parseFloat(tokens[1])
  const originY = Number.parseFloat(tokens[2])
  const width = Number.parseFloat(tokens[4])
  const height = Number.parseFloat(tokens[6])
  const endX = Number.parseFloat(tokens[8])
  if (
    !Number.isFinite(originX)
    || !Number.isFinite(originY)
    || !Number.isFinite(width)
    || !Number.isFinite(height)
    || !Number.isFinite(endX)
  ) {
    return false
  }

  return (
    isApproximatelyEqual(originX, 0)
    && isApproximatelyEqual(originY, 0)
    && isApproximatelyEqual(width, canvasSize.width)
    && isApproximatelyEqual(height, canvasSize.height)
    && isApproximatelyEqual(endX, 0)
  )
}

function stripMatchingTags(
  svgMarkup: string,
  tagPattern: RegExp,
  isTagMatch: (tagMarkup: string) => boolean,
): string {
  return svgMarkup.replace(tagPattern, (tagMarkup) => (isTagMatch(tagMarkup) ? '' : tagMarkup))
}

function stripFullCanvasFill(svgMarkup: string): string {
  const svgTagMatch = svgMarkup.match(SVG_OPEN_TAG_PATTERN)
  if (!svgTagMatch) return svgMarkup

  const canvasSize = getSvgCanvasSize(svgTagMatch[0])
  if (!canvasSize) return svgMarkup

  let strippedMarkup = stripMatchingTags(
    svgMarkup,
    SVG_RECT_TAG_PATTERN,
    (tagMarkup) => isFullCanvasRectTag(tagMarkup, canvasSize),
  )

  strippedMarkup = stripMatchingTags(
    strippedMarkup,
    SVG_PATH_TAG_PATTERN,
    (tagMarkup) => isFullCanvasPathTag(tagMarkup, canvasSize),
  )

  // Some source diagrams contain multiple canvas-color fill paths used as baked backgrounds.
  // Remove all remaining canvas fills so card-level theme gradients are visible.
  strippedMarkup = stripMatchingTags(
    strippedMarkup,
    SVG_RECT_TAG_PATTERN,
    (tagMarkup) => isSecurityCanvasFill(parseTagAttribute(tagMarkup, 'fill')),
  )

  strippedMarkup = stripMatchingTags(
    strippedMarkup,
    SVG_PATH_TAG_PATTERN,
    (tagMarkup) => isSecurityCanvasFill(parseTagAttribute(tagMarkup, 'fill')),
  )

  return strippedMarkup
}

function normalizeSvgMarkup(svgMarkup: string): string {
  const svgTagMatch = svgMarkup.match(SVG_OPEN_TAG_PATTERN)
  if (!svgTagMatch) return svgMarkup

  const originalSvgTag = svgTagMatch[0]
  let normalizedSvgTag = originalSvgTag
  const viewBoxSize = parseSvgViewBox(normalizedSvgTag)
  const width = parseSvgDimension(normalizedSvgTag, 'width')
  const height = parseSvgDimension(normalizedSvgTag, 'height')

  if (!viewBoxSize && width && height) {
    normalizedSvgTag = withSvgAttribute(normalizedSvgTag, 'viewBox', `0 0 ${formatDimension(width)} ${formatDimension(height)}`)
  }

  normalizedSvgTag = withSvgAttribute(normalizedSvgTag, 'preserveAspectRatio', 'xMidYMid slice')
  normalizedSvgTag = withSvgAttribute(normalizedSvgTag, 'overflow', 'hidden')

  return svgMarkup.replace(originalSvgTag, normalizedSvgTag)
}

function toThemedMarkup(svgMarkup: string): string {
  let themedSvg = svgMarkup.replace(/^\s*<\?xml[^>]*>\s*/i, '')
  themedSvg = normalizeSvgMarkup(themedSvg)
  themedSvg = stripFullCanvasFill(themedSvg)
  return themedSvg
}

async function loadThemedSvg(src: string): Promise<string> {
  const cachedMarkup = themedMarkupCache.get(src)
  if (cachedMarkup) return cachedMarkup

  const existingLoadPromise = loadPromiseCache.get(src)
  if (existingLoadPromise) return existingLoadPromise

  const loadPromise = fetch(src)
    .then(async (response) => {
      if (!response.ok) {
        throw new Error(`Failed to load diagram: ${src} (${response.status})`)
      }
      return response.text()
    })
    .then((rawMarkup) => {
      const themedMarkup = toThemedMarkup(rawMarkup)
      themedMarkupCache.set(src, themedMarkup)
      loadPromiseCache.delete(src)
      return themedMarkup
    })
    .catch((error) => {
      loadPromiseCache.delete(src)
      throw error
    })

  loadPromiseCache.set(src, loadPromise)
  return loadPromise
}

export function ThemedSecuritySvg({ src, alt, className, style }: ThemedSecuritySvgProps): React.JSX.Element {
  const [markup, setMarkup] = useState<string | null>(() => themedMarkupCache.get(src) ?? null)
  const [useFallbackImage, setUseFallbackImage] = useState(false)

  useEffect(() => {
    let isCancelled = false
    setUseFallbackImage(false)
    setMarkup(themedMarkupCache.get(src) ?? null)

    void loadThemedSvg(src)
      .then((nextMarkup) => {
        if (!isCancelled) {
          setMarkup(nextMarkup)
        }
      })
      .catch(() => {
        if (!isCancelled) {
          setUseFallbackImage(true)
        }
      })

    return () => {
      isCancelled = true
    }
  }, [src])

  if (!markup || useFallbackImage) {
    return <img className={className} src={src} alt={alt} loading="lazy" style={style} />
  }

  return <div className={className} style={style} role="img" aria-label={alt} dangerouslySetInnerHTML={{ __html: markup }} />
}
