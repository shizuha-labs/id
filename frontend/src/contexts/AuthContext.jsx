import { createContext, useContext, useState, useEffect, useCallback } from 'react'
import api from '../services/api'
import { getPasskeyAssertion } from '../utils/webauthn'

const AuthContext = createContext(null)

// Token storage keys - shared across all Shizuha apps
const ACCESS_TOKEN_KEY = 'shizuha_access_token'
const REFRESH_TOKEN_KEY = 'shizuha_refresh_token'
const USER_KEY = 'shizuha_user'

export function AuthProvider({ children }) {
  const [user, setUser] = useState(null)
  const [isLoading, setIsLoading] = useState(true)
  const [isAuthenticated, setIsAuthenticated] = useState(false)

  // Initialize auth state from localStorage
  useEffect(() => {
    const initAuth = async () => {
      const accessToken = localStorage.getItem(ACCESS_TOKEN_KEY)
      const storedUser = localStorage.getItem(USER_KEY)

      if (accessToken && storedUser) {
        try {
          // Set the token in axios headers
          api.defaults.headers.common['Authorization'] = `Bearer ${accessToken}`

          // Verify token is still valid by fetching user
          const response = await api.get('/auth/user/')
          setUser(response.data)
          setIsAuthenticated(true)
        } catch (error) {
          console.error('Token validation failed:', error)
          // Try to refresh the token
          const refreshToken = localStorage.getItem(REFRESH_TOKEN_KEY)
          if (refreshToken) {
            try {
              await refreshAccessToken(refreshToken)
            } catch {
              // Clear invalid auth state
              clearAuthState()
            }
          } else {
            clearAuthState()
          }
        }
      }
      setIsLoading(false)
    }

    initAuth()
  }, [])

  const refreshAccessToken = async (refreshToken) => {
    const response = await api.post('/auth/refresh/', { refresh: refreshToken })
    const newAccessToken = response.data.access
    localStorage.setItem(ACCESS_TOKEN_KEY, newAccessToken)
    api.defaults.headers.common['Authorization'] = `Bearer ${newAccessToken}`

    // If new refresh token provided, save it
    if (response.data.refresh) {
      localStorage.setItem(REFRESH_TOKEN_KEY, response.data.refresh)
    }

    // Fetch user data
    const userResponse = await api.get('/auth/user/')
    setUser(userResponse.data)
    setIsAuthenticated(true)
    localStorage.setItem(USER_KEY, JSON.stringify(userResponse.data))

    return newAccessToken
  }

  const clearAuthState = () => {
    localStorage.removeItem(ACCESS_TOKEN_KEY)
    localStorage.removeItem(REFRESH_TOKEN_KEY)
    localStorage.removeItem(USER_KEY)
    delete api.defaults.headers.common['Authorization']
    setUser(null)
    setIsAuthenticated(false)
  }

  const storeSession = useCallback((userData, tokens) => {
    localStorage.setItem(ACCESS_TOKEN_KEY, tokens.access)
    localStorage.setItem(REFRESH_TOKEN_KEY, tokens.refresh)
    localStorage.setItem(USER_KEY, JSON.stringify(userData))
    api.defaults.headers.common['Authorization'] = `Bearer ${tokens.access}`
    setUser(userData)
    setIsAuthenticated(true)
    return userData
  }, [])

  const login = useCallback(async (username, password) => {
    // Clear any existing auth header before login to avoid JWT validation errors
    delete api.defaults.headers.common['Authorization']
    const response = await api.post('/auth/login/', { username, password })

    if (response.data?.status === '2fa_required' || response.data?.pending_token) {
      return {
        requires2FA: true,
        pendingToken: response.data.pending_token,
        expiresAt: response.data.expires_at,
        factors: response.data.factors || [],
        webauthnAvailable: Boolean(response.data.webauthn_available),
      }
    }

    const { user: userData, tokens } = response.data
    const storedUser = storeSession(userData, tokens)
    return { user: storedUser, twofaNudge: response.data?.twofa_nudge }
  }, [storeSession])

  const completeLogin2FA = useCallback(async ({ pendingToken, factor, answer, deviceId }) => {
    let payload = { pending_token: pendingToken, factor, answer, device_id: deviceId }

    if (factor === 'webauthn' && !answer) {
      const challengeResponse = await api.post('/auth/login/2fa/', {
        pending_token: pendingToken,
        factor: 'webauthn',
        device_id: deviceId,
      })
      const publicKey = challengeResponse.data?.challenge?.publicKey || challengeResponse.data?.challenge?.public_key
      const resolvedDeviceId = challengeResponse.data?.device_id || deviceId
      const assertion = await getPasskeyAssertion(publicKey)
      payload = {
        pending_token: pendingToken,
        factor: 'webauthn',
        device_id: resolvedDeviceId,
        answer: assertion,
      }
    }

    const response = await api.post('/auth/login/2fa/', payload)
    const { user: userData, tokens } = response.data
    const storedUser = storeSession(userData, tokens)
    return {
      user: storedUser,
      recoveryCodesLow: Boolean(response.data?.recovery_codes_low),
      amr: response.data?.amr || [],
    }
  }, [storeSession])

  const register = useCallback(async (data) => {
    // Clear any existing auth header before register to avoid JWT validation errors
    delete api.defaults.headers.common['Authorization']
    const response = await api.post('/auth/register/', data)

    // If pending approval, don't store tokens (none were issued)
    if (response.data.pending_approval) {
      return { pending_approval: true }
    }

    const { user: userData } = response.data
    const tokens = response.data.tokens || {
      access: response.data.access,
      refresh: response.data.refresh,
    }
    if (!tokens?.access || !tokens?.refresh) {
      throw new Error('Registration response did not include auth tokens')
    }

    // Save tokens and user
    localStorage.setItem(ACCESS_TOKEN_KEY, tokens.access)
    localStorage.setItem(REFRESH_TOKEN_KEY, tokens.refresh)
    localStorage.setItem(USER_KEY, JSON.stringify(userData))

    // Set auth header
    api.defaults.headers.common['Authorization'] = `Bearer ${tokens.access}`

    setUser(userData)
    setIsAuthenticated(true)

    return userData
  }, [])

  const logout = useCallback(async () => {
    try {
      const refreshToken = localStorage.getItem(REFRESH_TOKEN_KEY)
      if (refreshToken) {
        await api.post('/auth/logout/', { refresh: refreshToken })
      }
    } catch (error) {
      console.error('Logout error:', error)
    } finally {
      clearAuthState()
    }
  }, [])

  const getOAuthStatus = useCallback(async () => {
    const response = await api.get('/auth/oauth/status/')
    return response.data
  }, [])

  const getOAuthUrl = useCallback(async (provider, continueUrl = '') => {
    const response = await api.get(`/auth/social/${provider}/`, {
      params: continueUrl ? { continue: continueUrl } : {},
    })
    return response.data.url
  }, [])

  // Finish a social sign-in: claim the one-time handoff for tokens, persist.
  const completeSocialLogin = useCallback(async (handoff) => {
    const response = await api.post('/auth/social/handoff/', { handoff })
    const { user: userData, tokens } = response.data
    return storeSession(userData, tokens)
  }, [storeSession])

  const value = {
    user,
    isLoading,
    isAuthenticated,
    login,
    completeLogin2FA,
    register,
    logout,
    getOAuthStatus,
    getOAuthUrl,
    completeSocialLogin,
  }

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>
}

export function useAuth() {
  const context = useContext(AuthContext)
  if (!context) {
    throw new Error('useAuth must be used within an AuthProvider')
  }
  return context
}

export default AuthContext
