import { config } from '@/lib/config'
import { useDarkMode } from '@/lib/theme'

/**
 * The templates shipped both logo variants as <img> tags and let a
 * prefers-color-scheme rule hide one. That downloads two images to show one —
 * cheap on a desk, not on a phone that has not been let onto the network yet.
 * Picking the src from the resolved scheme fetches exactly one; the <link
 * rel="preload"> pair in the HTML carries the same media queries, so the right
 * variant is already in flight before this component mounts.
 *
 * BRAND_LOGO_URL overrides both when a deployment supplies its own asset.
 */
export function BrandLogo() {
  const dark = useDarkMode()
  const src =
    config.brand.logoUrl ||
    (dark ? '/static/logo+title-circle-darkmode.png' : '/static/logo+title-circle.png')
  return <img className="card-logo" src={src} alt={config.brand.name} />
}
