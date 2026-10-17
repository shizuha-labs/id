import { useState, useEffect, useRef } from 'react'
import { Link, useNavigate, useSearchParams } from 'react-router-dom'
import { useAuth } from '../contexts/AuthContext'
import { Mail, Lock, Eye, EyeOff, AlertCircle, Loader2 } from 'lucide-react'
import { cn } from '../utils/cn'
import { isDefaultContinueTarget, safeContinueUrl } from '../utils/safeContinue'
import { userFacingApiError } from '../utils/userFacingApiError'
import { requestedSocialProvider } from '../utils/socialLogin'

// OAuth icons
// Official multi-color Google "G" (brand guidelines) — a gray currentColor G
// reads as a dead/disabled control and undersells the OAuth path (ID-64).
function GoogleIcon({ className }) {
  return (
    <svg className={className} viewBox="0 0 24 24" aria-hidden="true">
      <path
        fill="#4285F4"
        d="M22.56 12.25c0-.78-.07-1.53-.2-2.25H12v4.26h5.92c-.26 1.37-1.04 2.53-2.21 3.31v2.77h3.57c2.08-1.92 3.28-4.74 3.28-8.09z"
      />
      <path
        fill="#34A853"
        d="M12 23c2.97 0 5.46-.98 7.28-2.66l-3.57-2.77c-.98.66-2.23 1.06-3.71 1.06-2.86 0-5.29-1.93-6.16-4.53H2.18v2.84C3.99 20.53 7.7 23 12 23z"
      />
      <path
        fill="#FBBC05"
        d="M5.84 14.09c-.22-.66-.35-1.36-.35-2.09s.13-1.43.35-2.09V7.07H2.18C1.43 8.55 1 10.22 1 12s.43 3.45 1.18 4.93l2.85-2.22.81-.62z"
      />
      <path
        fill="#EA4335"
        d="M12 5.38c1.62 0 3.06.56 4.21 1.64l3.15-3.15C17.45 2.09 14.97 1 12 1 7.7 1 3.99 3.47 2.18 7.07l3.66 2.84c.87-2.6 3.3-4.53 6.16-4.53z"
      />
    </svg>
  )
}

function GitHubIcon({ className }) {
  return (
    <svg className={className} viewBox="0 0 24 24" fill="currentColor">
      <path d="M12 0c-6.626 0-12 5.373-12 12 0 5.302 3.438 9.8 8.207 11.387.599.111.793-.261.793-.577v-2.234c-3.338.726-4.033-1.416-4.033-1.416-.546-1.387-1.333-1.756-1.333-1.756-1.089-.745.083-.729.083-.729 1.205.084 1.839 1.237 1.839 1.237 1.07 1.834 2.807 1.304 3.492.997.107-.775.418-1.305.762-1.604-2.665-.305-5.467-1.334-5.467-5.931 0-1.311.469-2.381 1.236-3.221-.124-.303-.535-1.524.117-3.176 0 0 1.008-.322 3.301 1.23.957-.266 1.983-.399 3.003-.404 1.02.005 2.047.138 3.006.404 2.291-1.552 3.297-1.23 3.297-1.23.653 1.653.242 2.874.118 3.176.77.84 1.235 1.911 1.235 3.221 0 4.609-2.807 5.624-5.479 5.921.43.372.823 1.102.823 2.222v3.293c0 .319.192.694.801.576 4.765-1.589 8.199-6.086 8.199-11.386 0-6.627-5.373-12-12-12z" />
    </svg>
  )
}

export default function Login() {
  const navigate = useNavigate()
  const [searchParams] = useSearchParams()
  const { login, completeLogin2FA, isAuthenticated, getOAuthStatus, getOAuthUrl } = useAuth()

  const [username, setUsername] = useState('')
  const [password, setPassword] = useState('')
  const [showPassword, setShowPassword] = useState(false)
  const [error, setError] = useState('')
  const [isLoading, setIsLoading] = useState(false)
  const [oauthProviders, setOauthProviders] = useState({ google: false, github: false })
  const [oauthLoading, setOauthLoading] = useState('')
  const [twoFactorChallenge, setTwoFactorChallenge] = useState(null)
  const [secondFactor, setSecondFactor] = useState('totp')
  const [secondFactorCode, setSecondFactorCode] = useState('')
  const [recoveryWarning, setRecoveryWarning] = useState(false)

  // Get the continue URL from query params — validated to a same-origin path so
  // the redirects below can't be turned into an open redirect (PLAT-273).
  // Accept `next` as a Django/allauth-compatible alias for browser handoffs.
  const continueUrl = safeContinueUrl(searchParams.get('continue') || searchParams.get('next'), '/account')
  const requestedProvider = requestedSocialProvider(searchParams.get('provider') || searchParams.get('idp'))
  const autoStarted = useRef(false)

  // Redirect if already authenticated
  useEffect(() => {
    if (isAuthenticated) {
      // Redirect to the continue URL (external redirect)
      window.location.href = continueUrl
    }
  }, [isAuthenticated, continueUrl])

  // Check available OAuth providers
  useEffect(() => {
    const checkOAuth = async () => {
      try {
        const status = await getOAuthStatus()
        setOauthProviders(status.providers || {})
      } catch {
        // OAuth status check failed, providers not available
      }
    }
    checkOAuth()
  }, [getOAuthStatus])

  const handleSubmit = async (e) => {
    e.preventDefault()
    setError('')
    setIsLoading(true)

    try {
      const result = await login(username, password)
      if (result?.requires2FA) {
        const preferredFactor = result.webauthnAvailable
          ? 'webauthn'
          : (result.factors?.includes('totp') ? 'totp' : 'recovery')
        setTwoFactorChallenge(result)
        setSecondFactor(preferredFactor)
        setSecondFactorCode('')
        setError('')
        return
      }
      if (result?.twofaNudge?.enroll) {
        localStorage.setItem('shizuha_2fa_nudge_pending', '1')
      }
      // After successful login, redirect to continue URL
      window.location.href = continueUrl
    } catch (err) {
      const code = err.response?.data?.code
      if (code === 'pending_approval') {
        navigate('/pending-approval')
        return
      }
      setError(userFacingApiError(err, 'Login failed. Please try again.'))
    } finally {
      setIsLoading(false)
    }
  }


  const handleSecondFactorSubmit = async (e) => {
    e.preventDefault()
    if (!twoFactorChallenge) return
    setError('')
    setIsLoading(true)

    try {
      const result = await completeLogin2FA({
        pendingToken: twoFactorChallenge.pendingToken,
        factor: secondFactor,
        answer: secondFactor === 'webauthn' ? undefined : secondFactorCode,
      })
      if (result?.recoveryCodesLow) {
        localStorage.setItem('shizuha_2fa_recovery_low', '1')
        setRecoveryWarning(true)
      }
      window.location.href = continueUrl
    } catch (err) {
      setError(userFacingApiError(err, 'Second-factor verification failed. Please try again.'))
    } finally {
      setIsLoading(false)
    }
  }

  const handleOAuthLogin = async (provider) => {
    setError('')
    setOauthLoading(provider)
    try {
      // Pass the continue target so ID carries it through OAuth `state`
      // (server-side, not trusted back from the URL); keep a session copy too.
      const url = await getOAuthUrl(provider, continueUrl)
      sessionStorage.setItem('oauth_continue', continueUrl)
      window.location.href = url
    } catch (err) {
      setOauthLoading('')
      setError(`${provider === 'google' ? 'Google' : 'GitHub'} sign-in is not available right now`)
    }
  }

  // Cortex/Studio (and other first-party apps) send ?provider=google so new
  // users skip the extra "Shizuha ID" form and go straight to Google.
  useEffect(() => {
    if (autoStarted.current || twoFactorChallenge || isAuthenticated) return
    if (!requestedProvider || !oauthProviders[requestedProvider]) return
    autoStarted.current = true
    handleOAuthLogin(requestedProvider)
  }, [requestedProvider, oauthProviders, isAuthenticated, twoFactorChallenge])

  const enabledOAuthProviders = ['google', 'github'].filter((p) => oauthProviders[p])

  return (
    <div className="min-h-screen flex items-center justify-center bg-gray-50 dark:bg-gray-950 px-4">
      <div className="w-full max-w-md">
        {/* Logo/Header */}
        <div className="text-center mb-8">
          <h1 className="text-3xl font-bold tracking-tight text-gray-900 dark:text-white">
            Shizuha ID
          </h1>
          <p className="mt-2 text-sm text-gray-500 dark:text-gray-400">
            One account for everything Shizuha
          </p>
        </div>

        {/* Login Card */}
        <div className="card p-6 sm:p-8 shadow-lg shadow-gray-200/60 dark:shadow-gray-950/60">
          {requestedProvider && !twoFactorChallenge && !error && (
            <p className="mb-5 text-sm text-gray-500 dark:text-gray-400 text-center">
              {oauthLoading === requestedProvider || autoStarted.current
                ? `Continuing with ${requestedProvider === 'google' ? 'Google' : 'GitHub'}…`
                : `Sign in with ${requestedProvider === 'google' ? 'Google' : 'GitHub'} to continue`}
            </p>
          )}
          {/* Error Message */}
          {error && (
            <div className="mb-6 p-3 rounded-lg bg-critical-50 dark:bg-critical-900/30 border border-critical-200 dark:border-critical-800">
              <div className="flex items-center gap-2 text-critical-700 dark:text-critical-300">
                <AlertCircle size={18} />
                <span className="text-sm">{error}</span>
              </div>
            </div>
          )}

          {twoFactorChallenge ? (
            <form onSubmit={handleSecondFactorSubmit} className="space-y-5">
              <div className="rounded-lg border border-indigo-200 dark:border-indigo-800 bg-indigo-50 dark:bg-indigo-950/40 p-4">
                <h2 className="text-sm font-semibold text-indigo-900 dark:text-indigo-100">
                  Two-factor verification required
                </h2>
                <p className="mt-1 text-sm text-indigo-700 dark:text-indigo-300">
                  Your password was accepted. Complete a second factor to finish signing in.
                </p>
                {twoFactorChallenge.expiresAt && (
                  <p className="mt-2 text-xs text-indigo-600 dark:text-indigo-400">
                    Challenge expires {new Date(twoFactorChallenge.expiresAt).toLocaleTimeString()}.
                  </p>
                )}
              </div>

              <div>
                <label htmlFor="second-factor" className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1.5">
                  Verification method
                </label>
                <select
                  id="second-factor"
                  value={secondFactor}
                  onChange={(e) => {
                    setSecondFactor(e.target.value)
                    setSecondFactorCode('')
                  }}
                  className="input"
                >
                  {twoFactorChallenge.factors?.includes('totp') && <option value="totp">Authenticator app code</option>}
                  {twoFactorChallenge.webauthnAvailable && <option value="webauthn">Passkey</option>}
                  {twoFactorChallenge.factors?.includes('recovery') && <option value="recovery">Recovery code</option>}
                  {!twoFactorChallenge.factors?.length && <option value="totp">Authenticator app code</option>}
                </select>
              </div>

              {secondFactor !== 'webauthn' ? (
                <div>
                  <label htmlFor="second-factor-code" className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1.5">
                    {secondFactor === 'recovery' ? 'Recovery code' : 'Authenticator code'}
                  </label>
                  <div className="relative">
                    <Lock className="absolute left-3 top-1/2 -translate-y-1/2 text-gray-400" size={18} />
                    <input
                      id="second-factor-code"
                      type="text"
                      value={secondFactorCode}
                      onChange={(e) => setSecondFactorCode(e.target.value)}
                      placeholder={secondFactor === 'recovery' ? 'XXXX-XXXX-XXXX-XXXX-XXXX' : '123456'}
                      className="input pl-10"
                      required
                      autoComplete="one-time-code"
                      autoFocus
                    />
                  </div>
                </div>
              ) : (
                <p className="text-sm text-gray-600 dark:text-gray-400">
                  Choose Continue and approve the browser passkey prompt.
                </p>
              )}

              {recoveryWarning && (
                <div className="rounded-lg border border-amber-200 dark:border-amber-800 bg-amber-50 dark:bg-amber-950/30 p-3 text-sm text-amber-800 dark:text-amber-200">
                  You are low on recovery codes. Regenerate them from Account → Security after signing in.
                </div>
              )}

              <button
                type="submit"
                disabled={isLoading || (secondFactor !== 'webauthn' && !secondFactorCode)}
                className={cn(
                  'w-full btn-primary py-2.5',
                  isLoading && 'opacity-70 cursor-not-allowed'
                )}
              >
                {isLoading ? (
                  <span className="flex items-center justify-center gap-2">
                    <Loader2 className="animate-spin" size={18} />
                    Verifying...
                  </span>
                ) : (
                  'Continue'
                )}
              </button>

              <button
                type="button"
                onClick={() => {
                  setTwoFactorChallenge(null)
                  setPassword('')
                  setSecondFactorCode('')
                  setError('')
                }}
                className="w-full text-sm text-gray-600 dark:text-gray-400 hover:text-gray-900 dark:hover:text-gray-200"
              >
                Use a different account
              </button>
            </form>
          ) : (
            <form onSubmit={handleSubmit} className="space-y-5">
            {/* Username/Email */}
            <div>
              <label htmlFor="username" className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1.5">
                Username or Email
              </label>
              <div className="relative">
                <Mail className="absolute left-3 top-1/2 -translate-y-1/2 text-gray-400" size={18} />
                <input
                  id="username"
                  type="text"
                  value={username}
                  onChange={(e) => setUsername(e.target.value)}
                  placeholder="Enter your username or email"
                  className="input pl-10"
                  required
                  autoComplete="username"
                  autoFocus
                />
              </div>
            </div>

            {/* Password */}
            <div>
              <label htmlFor="password" className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1.5">
                Password
              </label>
              <div className="relative">
                <Lock className="absolute left-3 top-1/2 -translate-y-1/2 text-gray-400" size={18} />
                <input
                  id="password"
                  type={showPassword ? 'text' : 'password'}
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  placeholder="Enter your password"
                  className="input pl-10 pr-10"
                  required
                  autoComplete="current-password"
                />
                <button
                  type="button"
                  onClick={() => setShowPassword(!showPassword)}
                  aria-label={showPassword ? 'Hide password' : 'Show password'}
                  className="absolute right-3 top-1/2 -translate-y-1/2 rounded text-gray-400 hover:text-gray-600 dark:hover:text-gray-300 focus:outline-none focus-visible:ring-2 focus-visible:ring-brand-500"
                >
                  {showPassword ? <EyeOff size={18} aria-hidden="true" /> : <Eye size={18} aria-hidden="true" />}
                </button>
              </div>
            </div>

            {/* Forgot Password Link */}
            <div className="flex justify-end">
              <Link
                to="/forgot-password"
                className="text-sm text-indigo-600 hover:text-indigo-500 dark:text-indigo-400"
              >
                Forgot password?
              </Link>
            </div>

            {/* Submit Button */}
            <button
              type="submit"
              disabled={isLoading}
              className={cn(
                'w-full btn-primary py-2.5',
                isLoading && 'opacity-70 cursor-not-allowed'
              )}
            >
              {isLoading ? (
                <span className="flex items-center justify-center gap-2">
                  <Loader2 className="animate-spin" size={18} />
                  Signing in...
                </span>
              ) : (
                'Sign in'
              )}
            </button>
          </form>
          )}

          {/* Divider */}
          {!twoFactorChallenge && enabledOAuthProviders.length > 0 && (
            <div className="relative my-6" role="separator" aria-label="Or continue with">
              <div className="absolute inset-0 flex items-center">
                <div className="w-full border-t border-gray-200 dark:border-gray-700" />
              </div>
              <div className="relative flex justify-center">
                <span className="px-3 bg-white dark:bg-gray-900 text-xs font-medium uppercase tracking-wider text-gray-400 dark:text-gray-500">
                  Or continue with
                </span>
              </div>
            </div>
          )}

          {/* OAuth Buttons — one enabled provider gets the full row (a lone
              half-width button in a 2-col grid was the ID-64 imbalance);
              two providers share the row. Heights match the primary button. */}
          {!twoFactorChallenge && enabledOAuthProviders.length > 0 && (
            <div className={cn('grid gap-3', enabledOAuthProviders.length > 1 ? 'grid-cols-2' : 'grid-cols-1')}>
              {oauthProviders.google && (
                <button
                  type="button"
                  onClick={() => handleOAuthLogin('google')}
                  disabled={!!oauthLoading}
                  aria-label="Continue with Google"
                  className={cn(
                    'flex items-center justify-center gap-2.5 px-4 py-2.5 rounded-lg',
                    'border border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-900',
                    'text-sm font-medium text-gray-700 dark:text-gray-200',
                    'shadow-sm hover:bg-gray-50 dark:hover:bg-gray-800 active:bg-gray-100 dark:active:bg-gray-700',
                    'transition-colors focus:outline-none focus-visible:ring-2 focus-visible:ring-brand-500 focus-visible:ring-offset-2 dark:focus-visible:ring-offset-gray-900',
                    oauthLoading && 'opacity-70 cursor-not-allowed'
                  )}
                >
                  {oauthLoading === 'google' ? (
                    <Loader2 className="w-5 h-5 animate-spin text-gray-400" aria-hidden="true" />
                  ) : (
                    <GoogleIcon className="w-5 h-5" />
                  )}
                  <span>{enabledOAuthProviders.length > 1 ? 'Google' : 'Continue with Google'}</span>
                </button>
              )}
              {oauthProviders.github && (
                <button
                  type="button"
                  onClick={() => handleOAuthLogin('github')}
                  disabled={!!oauthLoading}
                  aria-label="Continue with GitHub"
                  className={cn(
                    'flex items-center justify-center gap-2.5 px-4 py-2.5 rounded-lg',
                    'border border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-900',
                    'text-sm font-medium text-gray-700 dark:text-gray-200',
                    'shadow-sm hover:bg-gray-50 dark:hover:bg-gray-800 active:bg-gray-100 dark:active:bg-gray-700',
                    'transition-colors focus:outline-none focus-visible:ring-2 focus-visible:ring-brand-500 focus-visible:ring-offset-2 dark:focus-visible:ring-offset-gray-900',
                    oauthLoading && 'opacity-70 cursor-not-allowed'
                  )}
                >
                  {oauthLoading === 'github' ? (
                    <Loader2 className="w-5 h-5 animate-spin text-gray-400" aria-hidden="true" />
                  ) : (
                    <GitHubIcon className="w-5 h-5 text-gray-900 dark:text-white" />
                  )}
                  <span>{enabledOAuthProviders.length > 1 ? 'GitHub' : 'Continue with GitHub'}</span>
                </button>
              )}
            </div>
          )}

          {/* Register Link - preserve continue URL */}
          {!twoFactorChallenge && (
          <p className="mt-6 text-center text-sm text-gray-600 dark:text-gray-400">
            Don't have an account?{' '}
            <Link
              to={`/register${continueUrl !== '/' ? `?continue=${encodeURIComponent(continueUrl)}` : ''}`}
              className="link font-medium"
            >
              Create one
            </Link>
          </p>
          )}
        </div>

        {/* Continue to info */}
        {!isDefaultContinueTarget(continueUrl, '/account') && !requestedProvider && !continueUrl.includes('/oauth/authorize') && (
          <p className="mt-4 text-center text-xs text-gray-500 dark:text-gray-500">
            You'll return to the page you came from after signing in
          </p>
        )}
      </div>
    </div>
  )
}
