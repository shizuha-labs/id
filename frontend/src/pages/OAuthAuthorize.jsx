import { useCallback, useEffect, useRef, useState } from 'react'
import { useLocation, Navigate } from 'react-router-dom'
import { useAuth } from '../contexts/AuthContext'
import api from '../services/api'
import { requestedSocialProvider, shouldSkipFirstPartyConsent } from '../utils/socialLogin'

function buildErrorRedirect(redirectUri, state, error, description) {
  if (!redirectUri) return null
  const sep = redirectUri.includes('?') ? '&' : '?'
  const params = new URLSearchParams({ error })
  if (description) params.set('error_description', description)
  if (state) params.set('state', state)
  return `${redirectUri}${sep}${params.toString()}`
}

export default function OAuthAuthorize() {
  const { isAuthenticated, isLoading, user } = useAuth()
  const location = useLocation()
  const [info, setInfo] = useState(null)
  const [error, setError] = useState(null)
  const [submitting, setSubmitting] = useState(false)
  const autoApproved = useRef(false)

  const query = new URLSearchParams(location.search)
  const clientId = query.get('client_id')
  const redirectUri = query.get('redirect_uri')
  const state = query.get('state') || ''
  const scope = query.get('scope') || '*'
  const requestedProvider = requestedSocialProvider(query.get('provider') || query.get('idp'))
  const codeChallenge = query.get('code_challenge') || ''
  const codeChallengeMethod = query.get('code_challenge_method') || 'S256'
  const nonce = query.get('nonce') || ''

  useEffect(() => {
    if (isLoading || !isAuthenticated) return
    const qs = location.search.startsWith('?') ? location.search.slice(1) : location.search
    api.get(`/oauth/authorize/info?${qs}`)
      .then((res) => setInfo(res.data))
      .catch((err) => {
        const body = err.response?.data || {}
        setError({
          code: body.error || 'server_error',
          description: body.error_description || err.message || 'Unknown error',
        })
      })
  }, [isAuthenticated, isLoading, location.search])

  const approve = useCallback(async () => {
    setSubmitting(true)
    try {
      const body = {
        client_id: clientId,
        redirect_uri: redirectUri,
        response_type: 'code',
        scope,
        state,
        code_challenge: codeChallenge,
        code_challenge_method: codeChallengeMethod,
        nonce,
      }
      const res = await api.post('/oauth/authorize/approve', body)
      window.location.href = res.data.redirect_url
    } catch (err) {
      const body = err.response?.data || {}
      setError({
        code: body.error || 'server_error',
        description: body.error_description || err.message,
      })
      setSubmitting(false)
    }
  }, [clientId, redirectUri, scope, state, codeChallenge, codeChallengeMethod, nonce])

  useEffect(() => {
    if (!isAuthenticated || !info || error || autoApproved.current) return
    if (!shouldSkipFirstPartyConsent(info.client, info.redirect_uri || redirectUri)) return
    autoApproved.current = true
    approve()
  }, [isAuthenticated, info, error, approve, redirectUri])

  if (isLoading) {
    return (
      <div className="min-h-screen flex items-center justify-center bg-gray-50 dark:bg-gray-950">
        <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-brand-600" />
      </div>
    )
  }

  if (!isAuthenticated) {
    // Use the BROWSER path (includes the app basename, e.g. /id) — the login
    // page performs an absolute window.location redirect with this value, so a
    // router-relative path would land on the wrong app at the edge (PLAT-353).
    const continueUrl = window.location.pathname + window.location.search
    const loginQs = new URLSearchParams({ continue: continueUrl })
    if (requestedProvider) loginQs.set('provider', requestedProvider)
    return <Navigate to={`/login?${loginQs.toString()}`} replace />
  }

  const deny = () => {
    const url = buildErrorRedirect(
      redirectUri, state, 'access_denied', 'user denied authorization',
    )
    if (url) {
      window.location.href = url
    } else {
      setError({ code: 'access_denied', description: 'Authorization cancelled.' })
    }
  }

  if (error) {
    return (
      <div className="min-h-screen flex items-center justify-center bg-gray-50 dark:bg-gray-950 p-6">
        <div className="max-w-md w-full bg-white dark:bg-gray-900 rounded-2xl shadow-xl p-6 space-y-4">
          <h1 className="text-xl font-semibold text-red-600 dark:text-red-400">Authorization error</h1>
          <p className="text-sm text-gray-700 dark:text-gray-300">
            <code className="font-mono text-xs">{error.code}</code>
          </p>
          <p className="text-sm text-gray-600 dark:text-gray-400">{error.description}</p>
        </div>
      </div>
    )
  }

  if (!info || shouldSkipFirstPartyConsent(info.client, info.redirect_uri || redirectUri)) {
    return (
      <div className="min-h-screen flex items-center justify-center bg-gray-50 dark:bg-gray-950">
        <div className="text-center space-y-3">
          <div className="mx-auto animate-spin rounded-full h-8 w-8 border-b-2 border-brand-600" />
          {info && (
            <p className="text-sm text-gray-500 dark:text-gray-400">
              Continuing to {info.client?.client_name || 'the app'}…
            </p>
          )}
        </div>
      </div>
    )
  }

  return (
    <div className="min-h-screen flex items-center justify-center bg-gray-50 dark:bg-gray-950 p-6">
      <div className="max-w-md w-full bg-white dark:bg-gray-900 rounded-2xl shadow-xl p-6 space-y-5">
        <div className="text-center">
          <h1 className="text-xl font-semibold text-gray-900 dark:text-white">
            Authorize access
          </h1>
          <p className="text-sm text-gray-500 dark:text-gray-400 mt-1">
            Shizuha ID
          </p>
        </div>

        <div className="rounded-lg bg-gray-50 dark:bg-gray-800 p-4 space-y-2">
          <div className="flex items-start justify-between gap-3">
            <div className="text-sm text-gray-600 dark:text-gray-400">Application</div>
            <div className="text-sm font-medium text-gray-900 dark:text-white text-right break-all">
              {info.client?.client_name}
            </div>
          </div>
          <div className="flex items-start justify-between gap-3">
            <div className="text-sm text-gray-600 dark:text-gray-400">Redirect</div>
            <div className="text-xs font-mono text-gray-700 dark:text-gray-300 text-right break-all">
              {info.redirect_uri}
            </div>
          </div>
          <div className="flex items-start justify-between gap-3">
            <div className="text-sm text-gray-600 dark:text-gray-400">Scope</div>
            <div className="text-sm font-medium text-gray-900 dark:text-white text-right break-all">
              {info.scope}
            </div>
          </div>
        </div>

        <p className="text-sm text-gray-600 dark:text-gray-400">
          <strong>{info.client?.client_name}</strong> wants to access your Shizuha
          account as <strong>{user?.email || info.user?.email}</strong>. It will
          be able to read and write data across services enabled for your account.
        </p>

        <div className="flex gap-3">
          <button
            type="button"
            onClick={deny}
            disabled={submitting}
            className="flex-1 px-4 py-2 rounded-lg border border-gray-300 dark:border-gray-700 text-gray-700 dark:text-gray-200 hover:bg-gray-100 dark:hover:bg-gray-800 transition disabled:opacity-50"
          >
            Deny
          </button>
          <button
            type="button"
            onClick={approve}
            disabled={submitting}
            className="flex-1 px-4 py-2 rounded-lg bg-brand-600 text-white hover:bg-brand-700 transition disabled:opacity-50"
          >
            {submitting ? 'Authorizing…' : 'Authorize'}
          </button>
        </div>
      </div>
    </div>
  )
}
