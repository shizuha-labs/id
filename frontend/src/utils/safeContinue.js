// PLAT-273: validate a `?continue=` target is a SAME-ORIGIN PATH before we ever
// redirect the browser to it. Without this, `window.location.href = continueUrl`
// is an open redirect — `?continue=https://evil.com` (or the protocol-relative
// `//evil.com`) would send a freshly-authenticated user straight off-site.
//
// Only a same-site absolute path is allowed (must start with a single '/'); any
// scheme, protocol-relative URL, or cross-origin target falls back to `fallback`.
export function safeContinueUrl(raw, fallback = '/') {
  if (!raw || typeof raw !== 'string') return fallback
  // Must be an absolute path on THIS origin. Reject protocol-relative ('//host')
  // and backslash tricks ('/\\host') that some browsers normalise to a new host.
  if (!raw.startsWith('/') || raw.startsWith('//') || raw.startsWith('/\\')) {
    return fallback
  }
  // Belt-and-suspenders: resolve against the current origin and confirm it stays
  // same-origin (catches encoded/edge tricks). Return only the path portion.
  try {
    const u = new URL(raw, window.location.origin)
    if (u.origin !== window.location.origin) return fallback
    return u.pathname + u.search + u.hash
  } catch {
    return fallback
  }
}

export function continuePathOnly(url) {
  if (!url || typeof url !== 'string') return ''
  return url.split(/[?#]/)[0].replace(/\/+$/, '') || '/'
}

/** Default post-login landing (`/account`) is not a user-chosen destination. */
export function isDefaultContinueTarget(url, fallback = '/account') {
  const path = continuePathOnly(url)
  const fb = continuePathOnly(fallback) || '/account'
  if (!path || path === fb) return true
  return path === '/account' || path === '/id/account' || path === '/'
}
