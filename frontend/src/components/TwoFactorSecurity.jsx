import { useEffect, useMemo, useState } from 'react'
import QRCode from 'qrcode'
import {
  AlertCircle,
  Check,
  Copy,
  Download,
  Fingerprint,
  Key,
  Loader2,
  QrCode,
  RefreshCw,
  Shield,
} from 'lucide-react'
import api from '../services/api'
import { cn } from '../utils/cn'
import { browserSupportsWebAuthn, createPasskeyCredential, getPasskeyAssertion } from '../utils/webauthn'

const NUDGE_DISMISSED_UNTIL_KEY = 'shizuha_2fa_nudge_dismissed_until'
const NUDGE_PENDING_KEY = 'shizuha_2fa_nudge_pending'
const RECOVERY_LOW_KEY = 'shizuha_2fa_recovery_low'
const ENROLLED_KEY = 'shizuha_2fa_enrolled'

function getErrorMessage(err, fallback) {
  const data = err.response?.data
  return data?.detail || data?.error || data?.message || err.message || fallback
}

function downloadText(filename, text) {
  const blob = new Blob([text], { type: 'text/plain;charset=utf-8' })
  const url = URL.createObjectURL(blob)
  const link = document.createElement('a')
  link.href = url
  link.download = filename
  document.body.appendChild(link)
  link.click()
  link.remove()
  URL.revokeObjectURL(url)
}

function copyText(text) {
  return navigator.clipboard?.writeText(text)
}

function useQrDataUrl(value) {
  const [dataUrl, setDataUrl] = useState('')

  useEffect(() => {
    let cancelled = false
    if (!value) {
      setDataUrl('')
      return undefined
    }
    QRCode.toDataURL(value, { margin: 1, width: 192 })
      .then((url) => {
        if (!cancelled) setDataUrl(url)
      })
      .catch(() => {
        if (!cancelled) setDataUrl('')
      })
    return () => {
      cancelled = true
    }
  }, [value])

  return dataUrl
}

function RecoveryCodesPanel({ codes, onClear }) {
  if (!codes?.length) return null
  const text = [
    'Shizuha ID recovery codes',
    'Store these somewhere safe. Each code can be used once and is shown only now.',
    '',
    ...codes,
    '',
  ].join('\n')

  return (
    <div className="rounded-lg border border-amber-200 dark:border-amber-800 bg-amber-50 dark:bg-amber-950/30 p-4">
      <div className="flex items-start justify-between gap-3">
        <div>
          <h4 className="font-semibold text-amber-900 dark:text-amber-100">Save your recovery codes now</h4>
          <p className="mt-1 text-sm text-amber-800 dark:text-amber-200">
            They are shown once. Each code can complete login if you lose your authenticator or passkey.
          </p>
        </div>
        {onClear && (
          <button type="button" onClick={onClear} className="text-xs text-amber-700 dark:text-amber-300 hover:underline">
            Dismiss
          </button>
        )}
      </div>
      <div className="mt-3 grid grid-cols-1 sm:grid-cols-2 gap-2 font-mono text-sm">
        {codes.map((code) => (
          <div key={code} className="rounded bg-white/70 dark:bg-gray-900/70 px-3 py-2 text-gray-900 dark:text-gray-100">
            {code}
          </div>
        ))}
      </div>
      <div className="mt-4 flex flex-wrap gap-2">
        <button
          type="button"
          onClick={() => downloadText('shizuha-id-recovery-codes.txt', text)}
          className="inline-flex items-center gap-2 rounded-lg bg-amber-600 px-3 py-2 text-sm font-medium text-white hover:bg-amber-700"
        >
          <Download className="h-4 w-4" /> Download
        </button>
        <button
          type="button"
          onClick={() => copyText(codes.join('\n'))}
          className="inline-flex items-center gap-2 rounded-lg border border-amber-300 dark:border-amber-700 px-3 py-2 text-sm font-medium text-amber-800 dark:text-amber-200 hover:bg-amber-100 dark:hover:bg-amber-900/40"
        >
          <Copy className="h-4 w-4" /> Copy
        </button>
      </div>
    </div>
  )
}

function TwoFactorNudge({ user }) {
  const [visible, setVisible] = useState(false)
  const profile = user?.profile || {}
  const isEnrolled = Boolean(
    profile.twofa_enrolled_at || profile.twofa_enrolled || profile.two_factor_enabled || profile.mfa_enabled || localStorage.getItem(ENROLLED_KEY) === '1'
  )

  useEffect(() => {
    if (isEnrolled) {
      setVisible(false)
      return
    }
    const dismissedUntil = Number(localStorage.getItem(NUDGE_DISMISSED_UNTIL_KEY) || 0)
    const loginNudgePending = localStorage.getItem(NUDGE_PENDING_KEY) === '1'
    setVisible(loginNudgePending || Date.now() > dismissedUntil)
  }, [isEnrolled])

  if (!visible) return null

  return (
    <div className="mb-6 rounded-xl border border-indigo-200 dark:border-indigo-800 bg-indigo-50 dark:bg-indigo-950/40 p-4">
      <div className="flex items-start gap-3">
        <Shield className="h-5 w-5 text-indigo-600 dark:text-indigo-300 mt-0.5" />
        <div className="flex-1">
          <h3 className="font-semibold text-indigo-900 dark:text-indigo-100">Protect your account with two-factor authentication</h3>
          <p className="mt-1 text-sm text-indigo-800 dark:text-indigo-200">
            Add an authenticator app or passkey. Shizuha ID will keep reminding unenrolled users until a factor is enabled.
          </p>
          <div className="mt-3 flex flex-wrap gap-2">
            <button
              type="button"
              onClick={() => {
                localStorage.removeItem(NUDGE_PENDING_KEY)
                document.getElementById('two-factor-enrollment')?.scrollIntoView({ behavior: 'smooth', block: 'start' })
              }}
              className="rounded-lg bg-indigo-600 px-3 py-2 text-sm font-medium text-white hover:bg-indigo-700"
            >
              Set up 2FA
            </button>
            <button
              type="button"
              onClick={() => {
                localStorage.removeItem(NUDGE_PENDING_KEY)
                localStorage.setItem(NUDGE_DISMISSED_UNTIL_KEY, String(Date.now() + 24 * 60 * 60 * 1000))
                setVisible(false)
              }}
              className="rounded-lg px-3 py-2 text-sm font-medium text-indigo-700 dark:text-indigo-300 hover:bg-indigo-100 dark:hover:bg-indigo-900/40"
            >
              Remind me tomorrow
            </button>
          </div>
        </div>
      </div>
    </div>
  )
}

export function TwoFactorSecurity({ user }) {
  const [password, setPassword] = useState('')
  const [totpEnrollment, setTotpEnrollment] = useState(null)
  const [recoveryCodes, setRecoveryCodes] = useState([])
  const [statusMessage, setStatusMessage] = useState('')
  const [error, setError] = useState('')
  const [busy, setBusy] = useState('')
  const [recoveryLow, setRecoveryLow] = useState(false)
  const [currentTotpCode, setCurrentTotpCode] = useState('')
  const qrDataUrl = useQrDataUrl(totpEnrollment?.otpauth_uri)

  useEffect(() => {
    setRecoveryLow(localStorage.getItem(RECOVERY_LOW_KEY) === '1')
  }, [])

  const canUsePasskeys = useMemo(() => browserSupportsWebAuthn(), [])

  const startTotpEnrollment = async () => {
    setBusy('totp')
    setError('')
    setStatusMessage('')
    try {
      const response = await api.post('/auth/step-up/enroll/begin/', {
        password,
        name: 'Authenticator app',
        current_code: currentTotpCode.trim() || undefined,
      })
      setTotpEnrollment(response.data)
      setStatusMessage('Scan the QR code, open the confirmation link sent to your email, then enter the current authenticator code to activate this factor.')
    } catch (err) {
      setError(getErrorMessage(err, 'Could not start authenticator enrollment.'))
    } finally {
      setBusy('')
    }
  }

  const registerPasskey = async () => {
    if (!canUsePasskeys) {
      setError('This browser does not support passkey registration.')
      return
    }
    setBusy('passkey')
    setError('')
    setStatusMessage('')
    try {
      const begin = await api.post('/auth/step-up/webauthn/register/begin/', {
        password,
        name: 'Passkey',
        current_code: currentTotpCode.trim() || undefined,
      })
      const credential = await createPasskeyCredential(begin.data.public_key)
      const complete = await api.post('/auth/step-up/webauthn/register/complete/', {
        device_id: begin.data.device_id,
        response: credential,
      })
      setRecoveryCodes(complete.data?.recovery_codes || [])
      setStatusMessage(
        complete.data?.confirmation_required
          ? 'Passkey registration was accepted. Open the confirmation link sent to your email to activate it.'
          : 'Passkey registered.'
      )
    } catch (err) {
      setError(getErrorMessage(err, 'Could not register passkey.'))
    } finally {
      setBusy('')
    }
  }

  const getCurrentFactorProof = async () => {
    const currentCode = currentTotpCode.trim()
    if (currentCode) {
      return { current_code: currentCode }
    }

    if (!canUsePasskeys) {
      throw new Error('Enter a current authenticator code before regenerating recovery codes.')
    }

    const begin = await api.post('/auth/step-up/begin/', {
      action: 'factor-reenroll',
      resource_id: 'step-up-enrollment',
      factor: 'webauthn',
    })
    const assertion = await getPasskeyAssertion(begin.data?.public_key)
    const answer = await api.post('/auth/step-up/answer/', {
      challenge_id: begin.data?.challenge_id,
      assertion,
    })
    return { step_up_token: answer.data?.step_up_token }
  }

  const regenerateRecoveryCodes = async () => {
    setBusy('recovery')
    setError('')
    setStatusMessage('')
    try {
      const proof = await getCurrentFactorProof()
      const response = await api.post('/auth/step-up/recovery-codes/regenerate/', {
        password,
        ...proof,
      })
      setRecoveryCodes(response.data?.recovery_codes || [])
      localStorage.removeItem(RECOVERY_LOW_KEY)
      setRecoveryLow(false)
      setCurrentTotpCode('')
      setStatusMessage('Recovery codes regenerated. Save the new set now; old unused codes are invalidated.')
    } catch (err) {
      setError(getErrorMessage(err, 'Could not regenerate recovery codes.'))
    } finally {
      setBusy('')
    }
  }

  return (
    <div className="space-y-6" id="two-factor-enrollment">
      <TwoFactorNudge user={user} />

      <div className="bg-white dark:bg-gray-900 rounded-xl border border-gray-200 dark:border-gray-800 p-6">
        <div className="flex items-start gap-3">
          <Shield className="h-5 w-5 text-indigo-600 dark:text-indigo-400 mt-1" />
          <div>
            <h3 className="text-lg font-semibold text-gray-900 dark:text-white">Two-factor authentication</h3>
            <p className="mt-1 text-sm text-gray-500 dark:text-gray-400">
              Add an authenticator app or passkey before login enforcement rolls out. Re-enter your password before enrollment.
            </p>
          </div>
        </div>

        <div className="mt-5">
          <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
            Current password
          </label>
          <input
            type="password"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-800 text-gray-900 dark:text-white focus:ring-2 focus:ring-indigo-500 focus:border-transparent"
            autoComplete="current-password"
          />
        </div>

        {error && (
          <div className="mt-4 flex items-center gap-2 text-red-600 dark:text-red-400 text-sm">
            <AlertCircle className="h-4 w-4" />
            {error}
          </div>
        )}
        {statusMessage && (
          <div className="mt-4 flex items-center gap-2 text-green-700 dark:text-green-300 text-sm">
            <Check className="h-4 w-4" />
            {statusMessage}
          </div>
        )}
        {recoveryLow && (
          <div className="mt-4 rounded-lg border border-amber-200 dark:border-amber-800 bg-amber-50 dark:bg-amber-950/30 p-3 text-sm text-amber-800 dark:text-amber-200">
            You are low on recovery codes. Regenerate and save a new set.
          </div>
        )}

        <div className="mt-6 grid gap-4 md:grid-cols-3">
          <button
            type="button"
            onClick={startTotpEnrollment}
            disabled={!password || Boolean(busy)}
            className={cn(
              'rounded-xl border border-gray-200 dark:border-gray-700 p-4 text-left hover:border-indigo-300 dark:hover:border-indigo-600 transition-colors disabled:opacity-50',
              busy === 'totp' && 'border-indigo-400'
            )}
          >
            <QrCode className="h-5 w-5 text-indigo-600 dark:text-indigo-400" />
            <div className="mt-3 font-medium text-gray-900 dark:text-white">Authenticator app</div>
            <div className="mt-1 text-sm text-gray-500 dark:text-gray-400">Show a QR code for TOTP apps.</div>
            {busy === 'totp' && <Loader2 className="mt-3 h-4 w-4 animate-spin" />}
          </button>

          <button
            type="button"
            onClick={registerPasskey}
            disabled={!password || Boolean(busy) || !canUsePasskeys}
            className={cn(
              'rounded-xl border border-gray-200 dark:border-gray-700 p-4 text-left hover:border-indigo-300 dark:hover:border-indigo-600 transition-colors disabled:opacity-50',
              busy === 'passkey' && 'border-indigo-400'
            )}
          >
            <Fingerprint className="h-5 w-5 text-indigo-600 dark:text-indigo-400" />
            <div className="mt-3 font-medium text-gray-900 dark:text-white">Passkey</div>
            <div className="mt-1 text-sm text-gray-500 dark:text-gray-400">Use your device biometrics or security key.</div>
            {busy === 'passkey' && <Loader2 className="mt-3 h-4 w-4 animate-spin" />}
          </button>

          <button
            type="button"
            onClick={regenerateRecoveryCodes}
            disabled={!password || (!currentTotpCode.trim() && !canUsePasskeys) || Boolean(busy)}
            className={cn(
              'rounded-xl border border-gray-200 dark:border-gray-700 p-4 text-left hover:border-indigo-300 dark:hover:border-indigo-600 transition-colors disabled:opacity-50',
              busy === 'recovery' && 'border-indigo-400'
            )}
          >
            <RefreshCw className="h-5 w-5 text-indigo-600 dark:text-indigo-400" />
            <div className="mt-3 font-medium text-gray-900 dark:text-white">Recovery codes</div>
            <div className="mt-1 text-sm text-gray-500 dark:text-gray-400">Generate a fresh single-use backup set.</div>
            {busy === 'recovery' && <Loader2 className="mt-3 h-4 w-4 animate-spin" />}
          </button>
        </div>

        <div className="mt-5 rounded-lg border border-gray-200 dark:border-gray-800 p-4">
          <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1" htmlFor="current-totp-code">
            Current authenticator code for re-enrollment or recovery-code regeneration
          </label>
          <input
            id="current-totp-code"
            type="text"
            inputMode="numeric"
            autoComplete="one-time-code"
            value={currentTotpCode}
            onChange={(e) => setCurrentTotpCode(e.target.value)}
            className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-800 text-gray-900 dark:text-white focus:ring-2 focus:ring-indigo-500 focus:border-transparent"
            placeholder="123456"
          />
          <p className="mt-2 text-xs text-gray-500 dark:text-gray-400">
            Re-enrolling a factor or regenerating recovery codes requires your password plus a current confirmed factor. Enter a TOTP code, or leave this blank to use a passkey prompt when regenerating recovery codes.
          </p>
        </div>

        {totpEnrollment?.otpauth_uri && (
          <div className="mt-6 rounded-lg border border-gray-200 dark:border-gray-800 p-4">
            <div className="flex items-start gap-4">
              {qrDataUrl ? (
                <img src={qrDataUrl} alt="Authenticator app QR code" className="rounded-lg border border-gray-200 bg-white p-2" />
              ) : (
                <div className="flex h-48 w-48 items-center justify-center rounded-lg border border-gray-200 bg-white text-gray-500">
                  QR unavailable
                </div>
              )}
              <div className="min-w-0 flex-1">
                <h4 className="font-semibold text-gray-900 dark:text-white">Scan with your authenticator app</h4>
                <p className="mt-1 text-sm text-gray-500 dark:text-gray-400">
                  After scanning, open the email confirmation link and enter the current authenticator code from this app to activate the factor. The secret URI is shown only for setup.
                </p>
                <div className="mt-3 break-all rounded bg-gray-50 dark:bg-gray-800 p-3 font-mono text-xs text-gray-700 dark:text-gray-300">
                  {totpEnrollment.otpauth_uri}
                </div>
                <button
                  type="button"
                  onClick={() => copyText(totpEnrollment.otpauth_uri)}
                  className="mt-3 inline-flex items-center gap-2 text-sm font-medium text-indigo-600 dark:text-indigo-400 hover:underline"
                >
                  <Copy className="h-4 w-4" /> Copy setup URI
                </button>
              </div>
            </div>
          </div>
        )}
      </div>

      <RecoveryCodesPanel codes={recoveryCodes} onClear={() => setRecoveryCodes([])} />

      <div className="rounded-xl border border-gray-200 dark:border-gray-800 bg-gray-50 dark:bg-gray-900/50 p-4 text-sm text-gray-600 dark:text-gray-400">
        <div className="flex items-center gap-2 font-medium text-gray-900 dark:text-white">
          <Key className="h-4 w-4" /> Enrollment notes
        </div>
        <ul className="mt-2 list-disc space-y-1 pl-5">
          <li>Email or SMS are not supported second factors.</li>
          <li>TOTP enrollment remains pending until the confirmation email link is opened and a live code from the scanned app is verified.</li>
          <li>Passkey enrollment remains pending until the confirmation email link is opened.</li>
          <li>Recovery codes are single-use and shown only once; store them outside this browser.</li>
        </ul>
      </div>
    </div>
  )
}

export { RecoveryCodesPanel }
