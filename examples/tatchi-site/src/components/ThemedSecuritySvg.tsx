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
const SVG_RGBA_COLOR_PATTERN = /rgba\(\s*(\d{1,3})\s*,\s*(\d{1,3})\s*,\s*(\d{1,3})\s*,\s*([+-]?\d*\.?\d+)\s*\)/gi

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
  return (
    normalized === '#2a3144'
    || normalized === '#202633'
    || normalized === 'var(--security-diagram-canvas,#2a3144)'
    || normalized === 'var(--security-diagram-canvas,#202633)'
    || normalized === 'url(#bggrad)'
  )
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

function clamp(value: number, min: number, max: number): number {
  return Math.min(Math.max(value, min), max)
}

function formatAlphaPercent(alpha: number): string {
  const normalized = clamp(alpha, 0, 1)
  const rounded = Math.round(normalized * 1000) / 10
  return `${Number.isInteger(rounded) ? rounded.toFixed(0) : rounded}%`
}

function toAlphaColorMix(variableName: string, fallbackColor: string, alpha: number): string {
  const percent = formatAlphaPercent(alpha)
  return `color-mix(in srgb, var(${variableName}, ${fallbackColor}) ${percent}, transparent)`
}

function themedRgbaColor(
  red: number,
  green: number,
  blue: number,
  alpha: number,
): string | null {
  const colorKey = `${red},${green},${blue}`

  switch (colorKey) {
    case '200,225,255':
      return toAlphaColorMix('--security-diagram-line-strong', '#c8e1ff', alpha)
    case '180,210,255':
      return toAlphaColorMix('--security-diagram-line-strong', '#b4d2ff', alpha)
    case '150,190,255':
      return toAlphaColorMix('--security-diagram-line', '#96beff', alpha)
    case '100,150,255':
      return toAlphaColorMix('--security-diagram-line', '#6496ff', alpha)
    case '100,180,255':
      return toAlphaColorMix('--diagram-glow', '#64b4ff', alpha)
    case '100,200,255':
      return toAlphaColorMix('--diagram-node', '#64c8ff', alpha)
    case '100,255,150':
      return toAlphaColorMix('--security-diagram-line-strong', '#64ff96', alpha)
    case '80,150,255':
      return toAlphaColorMix('--diagram-glow', '#5096ff', alpha)
    case '40,90,180':
      return toAlphaColorMix('--security-diagram-line', '#285ab4', alpha)
    case '32,38,51':
      return toAlphaColorMix('--security-diagram-canvas', '#202633', alpha)
    case '40,50,70':
      return toAlphaColorMix('--security-diagram-canvas', '#283246', alpha)
    default:
      return null
  }
}

function mapLegacyDiagramColors(svgMarkup: string): string {
  let themedMarkup = svgMarkup
    .replace(/#2a3243/gi, 'var(--security-diagram-canvas-top, #2a3243)')
    .replace(/#181e29/gi, 'var(--security-diagram-canvas-bottom, #181e29)')
    .replace(
      /#1a1f2b/gi,
      'color-mix(in srgb, var(--site-surface, #f5f1ea) 72%, var(--security-diagram-canvas, #1a1f2b) 28%)',
    )

  themedMarkup = themedMarkup.replace(
    SVG_RGBA_COLOR_PATTERN,
    (originalColor, red, green, blue, alpha) => {
      const mappedColor = themedRgbaColor(
        Number.parseInt(red, 10),
        Number.parseInt(green, 10),
        Number.parseInt(blue, 10),
        Number.parseFloat(alpha),
      )
      return mappedColor ?? originalColor
    },
  )

  return themedMarkup
}

function toThemedMarkup(svgMarkup: string): string {
  let themedSvg = svgMarkup.replace(/^\s*<\?xml[^>]*>\s*/i, '')
  themedSvg = normalizeSvgMarkup(themedSvg)
  themedSvg = stripFullCanvasFill(themedSvg)
  themedSvg = mapLegacyDiagramColors(themedSvg)
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
