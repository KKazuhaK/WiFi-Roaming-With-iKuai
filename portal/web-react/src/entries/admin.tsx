// Entry for the guest-code administration panel.
//
// Separate from portal.tsx on purpose — see the note there. Everything heavy
// (Table, DatePicker, Upload, the CSV paths, antd's message/modal machinery and
// the locale tables) is reachable only from here.

import { StrictMode, useState } from 'react'
import { createRoot } from 'react-dom/client'
import { App as AntApp } from 'antd'
import type { Locale } from 'antd/es/locale'
import zhCN from 'antd/locale/zh_CN'
import zhTW from 'antd/locale/zh_TW'
import enUS from 'antd/locale/en_US'
import { ThemeProvider } from '@/lib/theme'
import { config } from '@/lib/config'
import { type Lang } from '@/lib/i18n'
import { AdminPage } from '@/pages/AdminPage'
import '@/styles/admin.css'

// antd's own component strings — pagination labels, the Table filter menu, the
// DatePicker calendar, the Empty placeholder. Distinct from portal/i18n/*.json,
// which covers this application's copy.
const LOCALES: Record<Lang, Locale> = {
  'zh-cn': zhCN,
  'zh-tw': zhTW,
  en: enUS,
}

function Root() {
  const [lang, setLang] = useState<Lang>(config.lang)
  return (
    <ThemeProvider locale={LOCALES[lang]}>
      {/* Supplies the message/modal instances reached through useApp(). Without
          it those APIs fall back to a static call path that renders outside the
          ConfigProvider above — wrong theme, wrong locale, and in dark mode a
          white toast on a dark page. */}
      <AntApp>
        <AdminPage lang={lang} onLang={setLang} />
      </AntApp>
    </ThemeProvider>
  )
}

const host = document.getElementById('root')
if (host) {
  createRoot(host).render(
    <StrictMode>
      <Root />
    </StrictMode>,
  )
}
