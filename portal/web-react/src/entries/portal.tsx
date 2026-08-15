// Entry for the three lightweight card pages: captive-portal sign-in, the admin
// SSO hand-off, and the error page.
//
// The admin panel deliberately lives in its own entry (admin.tsx). Keeping them
// apart is what lets Rollup analyse the two import graphs independently, so the
// Table, DatePicker and Upload components that only the panel uses never reach
// the page a phone loads before it has internet access.

import { StrictMode, useState } from 'react'
import { createRoot } from 'react-dom/client'
import { ThemeProvider } from '@/lib/theme'
import { config } from '@/lib/config'
import { type Lang } from '@/lib/i18n'
import { LoginPage } from '@/pages/LoginPage'
import { ErrorPage } from '@/pages/ErrorPage'
import { AdminLoginPage } from '@/pages/AdminLoginPage'
import { LocalAdminLoginPage } from '@/pages/LocalAdminLoginPage'
import '@/styles/card.css'

function Root() {
  // t() resolves against a module-level language, so it is not reactive on its
  // own. Holding the language here and threading it down as a prop makes every
  // string re-render on a switch — cheap for a three-page tree, and it avoids
  // dragging in a context or a store for one value.
  const [lang, setLang] = useState<Lang>(config.lang)
  return (
    <ThemeProvider>
      {config.page === 'error' ? (
        <ErrorPage lang={lang} onLang={setLang} />
      ) : config.page === 'adminLogin' ? (
        <AdminLoginPage lang={lang} onLang={setLang} />
      ) : config.page === 'localLogin' ? (
        <LocalAdminLoginPage lang={lang} onLang={setLang} />
      ) : (
        <LoginPage lang={lang} onLang={setLang} />
      )}
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
