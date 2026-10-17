import { useEffect, useRef } from 'react'

const SCRIPT = 'https://challenges.cloudflare.com/turnstile/v0/api.js?render=explicit'

function loadScript() {
  if (window.turnstile) return Promise.resolve()
  if (window.__shizuhaTurnstileLoading) return window.__shizuhaTurnstileLoading
  window.__shizuhaTurnstileLoading = new Promise((resolve, reject) => {
    const existing = document.querySelector('script[data-shizuha-turnstile]')
    if (existing) {
      existing.addEventListener('load', () => resolve())
      existing.addEventListener('error', reject)
      return
    }
    const script = document.createElement('script')
    script.src = SCRIPT
    script.async = true
    script.defer = true
    script.dataset.shizuhaTurnstile = '1'
    script.onload = () => resolve()
    script.onerror = reject
    document.head.appendChild(script)
  })
  return window.__shizuhaTurnstileLoading
}

export default function Turnstile({ sitekey, onToken, theme = 'auto' }) {
  const host = useRef(null)
  const widgetId = useRef(null)
  const onTokenRef = useRef(onToken)
  onTokenRef.current = onToken

  useEffect(() => {
    if (!sitekey) return undefined
    let cancelled = false
    const emit = (token) => onTokenRef.current?.(token || '')
    loadScript().then(() => {
      if (cancelled || !host.current || !window.turnstile) return
      if (widgetId.current != null) {
        window.turnstile.remove(widgetId.current)
        widgetId.current = null
      }
      widgetId.current = window.turnstile.render(host.current, {
        sitekey,
        theme,
        appearance: 'always',
        callback: emit,
        'expired-callback': () => emit(''),
        'error-callback': () => emit(''),
      })
    }).catch(() => emit(''))
    return () => {
      cancelled = true
      if (widgetId.current != null && window.turnstile) {
        try { window.turnstile.remove(widgetId.current) } catch { /* ignore */ }
        widgetId.current = null
      }
    }
  }, [sitekey, theme])

  if (!sitekey) return null
  return <div ref={host} className="cf-turnstile" />
}
