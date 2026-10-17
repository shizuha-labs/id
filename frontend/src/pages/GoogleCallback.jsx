import { useEffect, useRef, useState } from 'react'
import { useSearchParams, Link } from 'react-router-dom'
import { useAuth } from '../contexts/AuthContext'
import { safeContinueUrl } from '../utils/safeContinue'
import { humanizeAuthMessage, userFacingApiError } from '../utils/userFacingApiError'

// /id/auth/google — Google redirects to the ID backend callback, which mints
// tokens, stashes them server-side, and bounces the browser here with a
// one-time `handoff` code (tokens never touch the URL). We claim it, persist
// the session, and continue to wherever the user started.
export default function GoogleCallback() {
  const [params] = useSearchParams()
  const { completeSocialLogin } = useAuth()
  const [error, setError] = useState('')
  const [pending, setPending] = useState(false)
  const ran = useRef(false) // StrictMode double-mount guard: handoff is single-use

  useEffect(() => {
    if (ran.current) return
    ran.current = true

    const err = params.get('error')
    if (err) { setError(humanizeAuthMessage(err, 'Google sign-in could not be completed')); return }
    if (params.get('pending')) { setPending(true); return }

    const handoff = params.get('handoff')
    if (!handoff) { setError('missing sign-in handoff'); return }
    const continueUrl = safeContinueUrl(
      params.get('continue') || sessionStorage.getItem('oauth_continue') || '',
      '/account',
    )
    sessionStorage.removeItem('oauth_continue')

    completeSocialLogin(handoff)
      .then(() => { window.location.href = continueUrl })
      .catch((e) => setError(userFacingApiError(e, 'Google sign-in could not be completed')))
  }, [params, completeSocialLogin])

  return (
    <div className="min-h-screen flex items-center justify-center bg-gray-50 dark:bg-gray-950 px-4">
      <div className="w-full max-w-md text-center">
        <h1 className="text-2xl font-bold text-gray-900 dark:text-white mb-4">Shizuha ID</h1>
        {pending ? (
          <div className="rounded-lg border border-amber-300 dark:border-amber-700 bg-amber-50 dark:bg-amber-900/20 p-4 text-sm text-amber-800 dark:text-amber-300">
            Your account was created and is pending approval. You'll be able to sign in once it's approved.
            <div className="mt-3"><Link to="/login" className="text-brand-600 hover:underline">Back to sign-in</Link></div>
          </div>
        ) : error ? (
          <div className="rounded-lg border border-red-300 dark:border-red-700 bg-red-50 dark:bg-red-900/20 p-4 text-sm text-red-700 dark:text-red-300">
            {error}
            <div className="mt-3"><Link to="/login" className="text-brand-600 hover:underline">Back to sign-in</Link></div>
          </div>
        ) : (
          <p className="text-gray-500 dark:text-gray-400">Completing Google sign-in…</p>
        )}
      </div>
    </div>
  )
}
