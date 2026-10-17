import { useEffect, useState } from 'react'
import { Link, useSearchParams } from 'react-router-dom'
import { AlertCircle, Check, Loader2, ShieldCheck } from 'lucide-react'
import api from '../services/api'
import { RecoveryCodesPanel } from '../components/TwoFactorSecurity'

function messageFromError(err) {
  const data = err.response?.data
  return data?.detail || data?.error || data?.message || err.message || 'Could not confirm this 2FA enrollment link.'
}

function needsTotpCode(err) {
  const error = err.response?.data?.error || ''
  return error === 'totp code is required' || error === 'totp_code_required'
}

export default function StepUpEnrollConfirm() {
  const [searchParams] = useSearchParams()
  const [state, setState] = useState({
    loading: true,
    error: '',
    confirmed: false,
    recoveryCodes: [],
    needsTotpCode: false,
  })
  const [totpCode, setTotpCode] = useState('')
  const token = searchParams.get('token') || ''

  const confirmEnrollment = async ({ code, autoProbe = false } = {}) => {
    if (!token) {
      setState({ loading: false, error: 'Confirmation token is missing.', confirmed: false, recoveryCodes: [], needsTotpCode: false })
      return
    }

    setState((current) => ({ ...current, loading: true, error: '' }))
    try {
      const payload = { token }
      if (code) payload.code = code
      const response = await api.post('/auth/step-up/enroll/confirm/', payload)
      localStorage.setItem('shizuha_2fa_enrolled', '1')
      localStorage.removeItem('shizuha_2fa_nudge_pending')
      setState({
        loading: false,
        error: '',
        confirmed: Boolean(response.data?.confirmed ?? true),
        recoveryCodes: response.data?.recovery_codes || [],
        needsTotpCode: false,
      })
    } catch (err) {
      if (autoProbe && needsTotpCode(err)) {
        setState({ loading: false, error: '', confirmed: false, recoveryCodes: [], needsTotpCode: true })
        return
      }
      setState({ loading: false, error: messageFromError(err), confirmed: false, recoveryCodes: [], needsTotpCode: needsTotpCode(err) })
    }
  }

  useEffect(() => {
    let cancelled = false
    const run = async () => {
      if (cancelled) return
      await confirmEnrollment({ autoProbe: true })
    }
    run()
    return () => {
      cancelled = true
    }
    // Intentionally run once for this token; manual retries submit through the form.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [token])

  const handleTotpSubmit = (e) => {
    e.preventDefault()
    confirmEnrollment({ code: totpCode.trim() })
  }

  return (
    <div className="min-h-screen flex items-center justify-center bg-gray-50 dark:bg-gray-950 px-4">
      <div className="w-full max-w-xl">
        <div className="card p-8">
          <h1 className="text-2xl font-bold text-gray-900 dark:text-white">Confirm two-factor enrollment</h1>

          {state.loading && (
            <div className="mt-6 flex items-center gap-3 text-gray-600 dark:text-gray-300">
              <Loader2 className="h-5 w-5 animate-spin" />
              Confirming your enrollment link…
            </div>
          )}

          {!state.loading && state.needsTotpCode && !state.confirmed && (
            <form onSubmit={handleTotpSubmit} className="mt-6 rounded-lg border border-indigo-200 dark:border-indigo-800 bg-indigo-50 dark:bg-indigo-950/30 p-4">
              <div className="flex items-center gap-2 text-indigo-800 dark:text-indigo-200">
                <ShieldCheck className="h-5 w-5" />
                <span className="font-medium">Enter your authenticator code</span>
              </div>
              <p className="mt-2 text-sm text-indigo-800 dark:text-indigo-200">
                To activate this authenticator, enter the current 6-digit code from the app that scanned the QR code. This prevents enabling a factor whose secret was not stored correctly.
              </p>
              <label className="mt-4 block text-sm font-medium text-indigo-900 dark:text-indigo-100" htmlFor="totp-code">
                Authenticator code
              </label>
              <input
                id="totp-code"
                type="text"
                inputMode="numeric"
                autoComplete="one-time-code"
                value={totpCode}
                onChange={(e) => setTotpCode(e.target.value)}
                className="mt-1 w-full rounded-lg border border-indigo-300 dark:border-indigo-700 bg-white dark:bg-gray-900 px-3 py-2 text-gray-900 dark:text-white focus:border-indigo-500 focus:ring-2 focus:ring-indigo-500"
                placeholder="123456"
              />
              <button
                type="submit"
                disabled={!totpCode.trim() || state.loading}
                className="mt-4 rounded-lg bg-indigo-600 px-4 py-2 text-sm font-medium text-white hover:bg-indigo-700 disabled:opacity-50"
              >
                Verify code and activate
              </button>
            </form>
          )}

          {!state.loading && state.error && (
            <div className="mt-6 rounded-lg border border-red-200 dark:border-red-800 bg-red-50 dark:bg-red-950/30 p-4">
              <div className="flex items-center gap-2 text-red-700 dark:text-red-300">
                <AlertCircle className="h-5 w-5" />
                <span className="font-medium">Confirmation failed</span>
              </div>
              <p className="mt-2 text-sm text-red-700 dark:text-red-300">{state.error}</p>
            </div>
          )}

          {!state.loading && state.confirmed && (
            <div className="mt-6 rounded-lg border border-green-200 dark:border-green-800 bg-green-50 dark:bg-green-950/30 p-4">
              <div className="flex items-center gap-2 text-green-700 dark:text-green-300">
                <Check className="h-5 w-5" />
                <span className="font-medium">Two-factor authentication is active</span>
              </div>
              <p className="mt-2 text-sm text-green-700 dark:text-green-300">
                Your new factor can now be used during login and for sensitive step-up prompts.
              </p>
            </div>
          )}

          <div className="mt-6">
            <RecoveryCodesPanel codes={state.recoveryCodes} />
          </div>

          <div className="mt-8 flex flex-wrap gap-3">
            <Link to="/account" className="rounded-lg bg-indigo-600 px-4 py-2 text-sm font-medium text-white hover:bg-indigo-700">
              Back to account security
            </Link>
            <Link to="/login" className="rounded-lg border border-gray-300 dark:border-gray-700 px-4 py-2 text-sm font-medium text-gray-700 dark:text-gray-300 hover:bg-gray-50 dark:hover:bg-gray-800">
              Sign in
            </Link>
          </div>
        </div>
      </div>
    </div>
  )
}
