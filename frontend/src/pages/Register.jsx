import { useState, useEffect } from 'react'
import { Link, useNavigate, useSearchParams } from 'react-router-dom'
import { useAuth } from '../contexts/AuthContext'
import { User, Mail, Lock, Eye, EyeOff, AlertCircle, Loader2, CheckCircle } from 'lucide-react'
import { cn } from '../utils/cn'
import { isDefaultContinueTarget, safeContinueUrl } from '../utils/safeContinue'
import { userFacingApiError } from '../utils/userFacingApiError'
import api from '../services/api'
import Turnstile from '../components/Turnstile'

export default function Register() {
  const navigate = useNavigate()
  const [searchParams] = useSearchParams()
  const { register, isAuthenticated } = useAuth()

  const [formData, setFormData] = useState({
    username: '',
    email: '',
    password: '',
    password2: '',
    first_name: '',
    last_name: '',
  })
  const [showPassword, setShowPassword] = useState(false)
  const [showPassword2, setShowPassword2] = useState(false)
  const [error, setError] = useState('')
  const [errors, setErrors] = useState([])
  const [isLoading, setIsLoading] = useState(false)
  const [captchaToken, setCaptchaToken] = useState('')
  const [captcha, setCaptcha] = useState({ sitekey: '', required: false })

  // Get the continue URL from query params — validated to a same-origin path
  // (PLAT-273) so the post-register redirect can't be an open redirect.
  const continueUrl = safeContinueUrl(searchParams.get('continue'))

  // Redirect if already authenticated
  useEffect(() => {
    if (isAuthenticated) {
      // Redirect to the continue URL (external redirect)
      window.location.href = continueUrl
    }
  }, [isAuthenticated, continueUrl])

  useEffect(() => {
    let cancelled = false
    api.get('/auth/signup-config/')
      .then((res) => {
        if (cancelled) return
        const cfg = res.data?.captcha || {}
        setCaptcha({
          sitekey: cfg.sitekey || '',
          required: Boolean(cfg.required),
        })
      })
      .catch(() => {})
    return () => { cancelled = true }
  }, [])

  const handleChange = (e) => {
    const { name, value } = e.target
    setFormData((prev) => ({ ...prev, [name]: value }))
  }

  // Password strength indicators
  const passwordChecks = {
    length: formData.password.length >= 8,
    hasLetter: /[a-zA-Z]/.test(formData.password),
    hasNumber: /\d/.test(formData.password),
    match: formData.password && formData.password === formData.password2,
  }

  const handleSubmit = async (e) => {
    e.preventDefault()
    setError('')
    setErrors([])

    // Validate passwords match
    if (formData.password !== formData.password2) {
      setError('Passwords do not match')
      return
    }

    if (captcha.required && !captchaToken) {
      setError('Complete the verification check before creating an account.')
      return
    }

    setIsLoading(true)

    try {
      const bait = e.currentTarget?.elements?.website?.value || ''
      const result = await register({
        ...formData,
        captcha_token: captchaToken,
        website: bait,
      })
      if (result?.pending_approval) {
        navigate('/pending-approval')
        return
      }
      // After successful registration, redirect to continue URL
      window.location.href = continueUrl
    } catch (err) {
      const errorData = err.response?.data?.error
      if (Array.isArray(errorData)) {
        setErrors(errorData)
      } else {
        setError(userFacingApiError(err, 'Registration failed. Please try again.'))
      }
    } finally {
      setIsLoading(false)
    }
  }

  return (
    <div className="min-h-screen flex items-center justify-center bg-gray-50 dark:bg-gray-950 px-4 py-8">
      <div className="w-full max-w-md">
        {/* Logo/Header */}
        <div className="text-center mb-8">
          <h1 className="text-3xl font-bold text-gray-900 dark:text-white">
            Shizuha ID
          </h1>
          <p className="mt-2 text-gray-600 dark:text-gray-400">
            Create your account
          </p>
        </div>

        {/* Register Card */}
        <div className="card p-8">
          {/* Error Messages */}
          {(error || errors.length > 0) && (
            <div className="mb-6 p-3 rounded-lg bg-critical-50 dark:bg-critical-900/30 border border-critical-200 dark:border-critical-800">
              <div className="flex items-start gap-2 text-critical-700 dark:text-critical-300">
                <AlertCircle size={18} className="flex-shrink-0 mt-0.5" />
                <div className="text-sm">
                  {error && <p>{error}</p>}
                  {errors.length > 0 && (
                    <ul className="list-disc list-inside space-y-1">
                      {errors.map((err, i) => (
                        <li key={i}>{err}</li>
                      ))}
                    </ul>
                  )}
                </div>
              </div>
            </div>
          )}

          {/* Register Form */}
          <form onSubmit={handleSubmit} className="space-y-4">
            {/* Name Fields */}
            <div className="grid grid-cols-2 gap-3">
              <div>
                <label htmlFor="first_name" className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1.5">
                  First Name
                </label>
                <input
                  id="first_name"
                  name="first_name"
                  type="text"
                  value={formData.first_name}
                  onChange={handleChange}
                  placeholder="John"
                  className="input"
                  autoComplete="given-name"
                />
              </div>
              <div>
                <label htmlFor="last_name" className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1.5">
                  Last Name
                </label>
                <input
                  id="last_name"
                  name="last_name"
                  type="text"
                  value={formData.last_name}
                  onChange={handleChange}
                  placeholder="Doe"
                  className="input"
                  autoComplete="family-name"
                />
              </div>
            </div>

            {/* Username */}
            <div>
              <label htmlFor="username" className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1.5">
                Username <span className="text-critical-500">*</span>
              </label>
              <div className="relative">
                <User className="absolute left-3 top-1/2 -translate-y-1/2 text-gray-400" size={18} />
                <input
                  id="username"
                  name="username"
                  type="text"
                  value={formData.username}
                  onChange={handleChange}
                  placeholder="Choose a username"
                  className="input pl-10"
                  required
                  autoComplete="username"
                />
              </div>
            </div>

            {/* Email */}
            <div>
              <label htmlFor="email" className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1.5">
                Email <span className="text-critical-500">*</span>
              </label>
              <div className="relative">
                <Mail className="absolute left-3 top-1/2 -translate-y-1/2 text-gray-400" size={18} />
                <input
                  id="email"
                  name="email"
                  type="email"
                  value={formData.email}
                  onChange={handleChange}
                  placeholder="you@example.com"
                  className="input pl-10"
                  required
                  autoComplete="email"
                />
              </div>
            </div>

            {/* Password */}
            <div>
              <label htmlFor="password" className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1.5">
                Password <span className="text-critical-500">*</span>
              </label>
              <div className="relative">
                <Lock className="absolute left-3 top-1/2 -translate-y-1/2 text-gray-400" size={18} />
                <input
                  id="password"
                  name="password"
                  type={showPassword ? 'text' : 'password'}
                  value={formData.password}
                  onChange={handleChange}
                  placeholder="Create a password"
                  className="input pl-10 pr-10"
                  required
                  autoComplete="new-password"
                />
                <button
                  type="button"
                  onClick={() => setShowPassword(!showPassword)}
                  className="absolute right-3 top-1/2 -translate-y-1/2 text-gray-400 hover:text-gray-600 dark:hover:text-gray-300"
                >
                  {showPassword ? <EyeOff size={18} /> : <Eye size={18} />}
                </button>
              </div>

              {/* Password Requirements */}
              {formData.password && (
                <div className="mt-2 space-y-1">
                  <PasswordCheck passed={passwordChecks.length} text="At least 8 characters" />
                  <PasswordCheck passed={passwordChecks.hasLetter} text="Contains a letter" />
                  <PasswordCheck passed={passwordChecks.hasNumber} text="Contains a number" />
                </div>
              )}
            </div>

            {/* Confirm Password */}
            <div>
              <label htmlFor="password2" className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1.5">
                Confirm Password <span className="text-critical-500">*</span>
              </label>
              <div className="relative">
                <Lock className="absolute left-3 top-1/2 -translate-y-1/2 text-gray-400" size={18} />
                <input
                  id="password2"
                  name="password2"
                  type={showPassword2 ? 'text' : 'password'}
                  value={formData.password2}
                  onChange={handleChange}
                  placeholder="Confirm your password"
                  className="input pl-10 pr-10"
                  required
                  autoComplete="new-password"
                />
                <button
                  type="button"
                  onClick={() => setShowPassword2(!showPassword2)}
                  className="absolute right-3 top-1/2 -translate-y-1/2 text-gray-400 hover:text-gray-600 dark:hover:text-gray-300"
                >
                  {showPassword2 ? <EyeOff size={18} /> : <Eye size={18} />}
                </button>
              </div>

              {formData.password2 && (
                <div className="mt-2">
                  <PasswordCheck passed={passwordChecks.match} text="Passwords match" />
                </div>
              )}
            </div>

            <div className="absolute -left-[9999px] h-0 w-0 overflow-hidden" aria-hidden="true">
              <label htmlFor="website">Website</label>
              <input id="website" name="website" type="text" tabIndex={-1} autoComplete="off" />
            </div>

            {captcha.sitekey ? (
              <div className="pt-1">
                <Turnstile sitekey={captcha.sitekey} onToken={setCaptchaToken} theme="auto" />
              </div>
            ) : null}

            {/* Submit Button */}
            <button
              type="submit"
              disabled={isLoading || (captcha.required && !captchaToken)}
              className={cn(
                'w-full btn-primary py-2.5 mt-2',
                isLoading && 'opacity-70 cursor-not-allowed'
              )}
            >
              {isLoading ? (
                <span className="flex items-center justify-center gap-2">
                  <Loader2 className="animate-spin" size={18} />
                  Creating account...
                </span>
              ) : (
                'Create account'
              )}
            </button>
          </form>

          {/* Login Link - preserve continue URL */}
          <p className="mt-6 text-center text-sm text-gray-600 dark:text-gray-400">
            Already have an account?{' '}
            <Link
              to={`/login${continueUrl !== '/' ? `?continue=${encodeURIComponent(continueUrl)}` : ''}`}
              className="link font-medium"
            >
              Sign in
            </Link>
          </p>
        </div>

        {/* Continue to info */}
        {!isDefaultContinueTarget(continueUrl, '/') && (
          <p className="mt-4 text-center text-xs text-gray-500 dark:text-gray-500">
            You'll return to the page you came from after creating your account
          </p>
        )}
      </div>
    </div>
  )
}

function PasswordCheck({ passed, text }) {
  return (
    <div className="flex items-center gap-2 text-xs">
      {passed ? (
        <CheckCircle size={14} className="text-success-500" />
      ) : (
        <div className="w-3.5 h-3.5 rounded-full border border-gray-300 dark:border-gray-600" />
      )}
      <span className={cn(passed ? 'text-success-600 dark:text-success-400' : 'text-gray-500')}>
        {text}
      </span>
    </div>
  )
}
