import { setLang, t, type Lang } from '@/lib/i18n'
import './LangSwitch.css'
import { SUPPORTED_LANGS } from '@/lib/config'

const LABEL_KEY: Record<Lang, string> = {
  'zh-cn': 'lang.zhCn',
  'zh-tw': 'lang.zhTw',
  en: 'lang.en',
}

/**
 * Language switch.
 *
 * The templates rendered these as <a href="?lang=xx"> plus a script that copied
 * the current query string onto each link — necessary because iKuai puts the
 * device's user_ip/mac in that query and losing them breaks the auth flow. That
 * whole hazard disappears here: setLang swaps the strings in place and rewrites
 * only the lang parameter via replaceState, so every other parameter survives
 * untouched and no document request is made on a link that is still walled off.
 */
export function LangSwitch({ current, onChange }: { current: Lang; onChange: (l: Lang) => void }) {
  return (
    <div className="lang-switch">
      {SUPPORTED_LANGS.map((l) => (
        <button
          key={l}
          type="button"
          lang={l}
          className={l === current ? 'active' : undefined}
          disabled={l === current}
          onClick={() => {
            setLang(l)
            onChange(l)
          }}
        >
          {t(LABEL_KEY[l])}
        </button>
      ))}
    </div>
  )
}
