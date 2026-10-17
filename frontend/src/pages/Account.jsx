import { useState, useEffect } from 'react'
import { useNavigate } from 'react-router-dom'
import { useAuth } from '../contexts/AuthContext'
import AppSwitcher from '../components/AppSwitcher'
import { TwoFactorSecurity } from '../components/TwoFactorSecurity'
import AvatarManager from '../components/AvatarManager'
import { useEnabledServices } from '@shizuha/ui'
import api from '../services/api'
import { userFacingApiError } from '../utils/userFacingApiError'
import {
  User,
  Mail,
  Calendar,
  Shield,
  Key,
  LogOut,
  Loader2,
  Check,
  AlertCircle,
  Moon,
  Sun,
  ChevronRight,
  Trash2,
  Building2,
  Plus,
  Users,
  ExternalLink,
  Crown,
} from 'lucide-react'
import { cn } from '../utils/cn'

function AuthorizedAppsSection() {
  const [apps, setApps] = useState(null)
  const [error, setError] = useState('')
  const [busy, setBusy] = useState(null)

  const load = async () => {
    try {
      const res = await api.get('/oauth/authorized-apps')
      setApps(res.data.apps || [])
      setError('')
    } catch (err) {
      setError(err.response?.data?.detail || err.message)
    }
  }

  useEffect(() => {
    load()
  }, [])

  const revoke = async (clientId, clientName) => {
    if (!window.confirm(`Revoke access for "${clientName}"? All active sessions for this app will stop working immediately.`)) return
    setBusy(clientId)
    try {
      await api.delete(`/oauth/authorized-apps/${encodeURIComponent(clientId)}`)
      await load()
    } catch (err) {
      setError(err.response?.data?.detail || err.message)
    } finally {
      setBusy(null)
    }
  }

  return (
    <div className="bg-white dark:bg-gray-900 rounded-xl border border-gray-200 dark:border-gray-800 p-6">
      <h3 className="text-lg font-semibold text-gray-900 dark:text-white mb-4">
        Connected Apps
      </h3>
      <p className="text-sm text-gray-500 dark:text-gray-400 mb-4">
        Third-party apps and CLIs you've authorized to access your Shizuha account via OAuth.
      </p>
      {error && (
        <div className="flex items-center gap-2 text-red-600 dark:text-red-400 text-sm mb-4">
          <AlertCircle className="h-4 w-4" />
          {error}
        </div>
      )}
      {apps === null ? (
        <div className="flex items-center gap-2 text-gray-500 dark:text-gray-400 text-sm">
          <Loader2 className="h-4 w-4 animate-spin" />
          Loading…
        </div>
      ) : apps.length === 0 ? (
        <p className="text-sm text-gray-500 dark:text-gray-400">
          No connected apps. When you authorize an external tool (e.g. Claude Code), it will appear here.
        </p>
      ) : (
        <ul className="divide-y divide-gray-200 dark:divide-gray-800">
          {apps.map((app) => (
            <li key={app.client_id} className="py-3 flex items-center justify-between gap-4">
              <div className="min-w-0 flex-1">
                <div className="flex items-center gap-2">
                  <Key className="h-4 w-4 text-gray-400 flex-shrink-0" />
                  <div className="font-medium text-gray-900 dark:text-white truncate">
                    {app.client_name}
                  </div>
                  {app.is_system && (
                    <span className="text-[10px] uppercase tracking-wide font-semibold px-1.5 py-0.5 rounded bg-indigo-100 dark:bg-indigo-900/40 text-indigo-700 dark:text-indigo-300">
                      System
                    </span>
                  )}
                </div>
                <div className="text-xs text-gray-500 dark:text-gray-400 mt-0.5">
                  {app.session_count} active session{app.session_count === 1 ? '' : 's'}
                  {app.last_used_at ? ` · last used ${new Date(app.last_used_at).toLocaleString()}` : ''}
                </div>
              </div>
              <button
                onClick={() => revoke(app.client_id, app.client_name)}
                disabled={busy === app.client_id}
                className="text-sm text-red-600 dark:text-red-400 hover:text-red-700 dark:hover:text-red-300 font-medium disabled:opacity-50"
              >
                {busy === app.client_id ? 'Revoking…' : 'Revoke'}
              </button>
            </li>
          ))}
        </ul>
      )}
    </div>
  )
}


export default function Account() {
  const navigate = useNavigate()
  const { user, logout, isLoading: authLoading } = useAuth()
  const enabledServices = useEnabledServices()
  const [activeTab, setActiveTab] = useState('profile')
  const [isDark, setIsDark] = useState(false)
  const [isUpdating, setIsUpdating] = useState(false)
  const [updateSuccess, setUpdateSuccess] = useState(false)
  const [updateError, setUpdateError] = useState('')

  // Profile form state
  const [username, setUsername] = useState('')
  const [firstName, setFirstName] = useState('')
  const [lastName, setLastName] = useState('')
  const [email, setEmail] = useState('')
  const [timezone, setTimezone] = useState('Asia/Kolkata')
  const [displayCurrency, setDisplayCurrency] = useState('USD')

  // Password form state
  const [currentPassword, setCurrentPassword] = useState('')
  const [newPassword, setNewPassword] = useState('')
  const [confirmPassword, setConfirmPassword] = useState('')
  const [passwordError, setPasswordError] = useState('')
  const [passwordSuccess, setPasswordSuccess] = useState(false)

  // Organizations state
  const [organizations, setOrganizations] = useState([])
  const [orgsLoading, setOrgsLoading] = useState(false)
  const [orgsError, setOrgsError] = useState('')
  const [showCreateOrg, setShowCreateOrg] = useState(false)
  const [newOrgName, setNewOrgName] = useState('')
  const [newOrgSlug, setNewOrgSlug] = useState('')
  const [creatingOrg, setCreatingOrg] = useState(false)

  // Initialize theme
  useEffect(() => {
    const savedTheme = localStorage.getItem('theme')
    const prefersDark = window.matchMedia('(prefers-color-scheme: dark)').matches
    const shouldBeDark = savedTheme === 'dark' || (!savedTheme && prefersDark)
    setIsDark(shouldBeDark)
    document.documentElement.classList.toggle('dark', shouldBeDark)
  }, [])

  // Initialize form data
  useEffect(() => {
    if (user) {
      setUsername(user.username || '')
      setFirstName(user.first_name || '')
      setLastName(user.last_name || '')
      setEmail(user.email || '')
      const fromUser = user.profile || {}
      if (fromUser.timezone) setTimezone(fromUser.timezone)
      if (fromUser.display_currency) setDisplayCurrency(fromUser.display_currency)
    }
    let cancelled = false
    api.get('/auth/profile/').then(({ data }) => {
      if (cancelled || !data) return
      if (data.timezone) setTimezone(data.timezone)
      if (data.display_currency) setDisplayCurrency(data.display_currency)
    }).catch(() => {})
    return () => { cancelled = true }
  }, [user])

  const toggleTheme = () => {
    const newTheme = !isDark
    setIsDark(newTheme)
    document.documentElement.classList.toggle('dark', newTheme)
    localStorage.setItem('theme', newTheme ? 'dark' : 'light')
  }

  const handleLogout = async () => {
    await logout()
    window.location.href = '/id/login'
  }

  const handleUpdateProfile = async (e) => {
    e.preventDefault()
    setIsUpdating(true)
    setUpdateError('')
    setUpdateSuccess(false)

    try {
      await api.patch('/auth/user/', {
        username,
        first_name: firstName,
        last_name: lastName,
      })
      await api.patch('/auth/profile/', {
        timezone,
        display_currency: displayCurrency,
      })
      setUpdateSuccess(true)
      setTimeout(() => setUpdateSuccess(false), 3000)
    } catch (error) {
      setUpdateError(userFacingApiError(error, 'Failed to update profile'))
    } finally {
      setIsUpdating(false)
    }
  }

  const handleChangePassword = async (e) => {
    e.preventDefault()
    setPasswordError('')
    setPasswordSuccess(false)

    if (newPassword !== confirmPassword) {
      setPasswordError('Passwords do not match')
      return
    }

    if (newPassword.length < 8) {
      setPasswordError('Password must be at least 8 characters')
      return
    }

    setIsUpdating(true)

    try {
      await api.post('/auth/password/change/', {
        old_password: currentPassword,
        new_password: newPassword,
        new_password2: confirmPassword,
      })
      setPasswordSuccess(true)
      setCurrentPassword('')
      setNewPassword('')
      setConfirmPassword('')
      setTimeout(() => setPasswordSuccess(false), 3000)
    } catch (error) {
      const errorData = error.response?.data
      const errorMsg = errorData?.error || errorData?.detail || 'Failed to change password'
      setPasswordError(Array.isArray(errorMsg) ? errorMsg.join(' ') : errorMsg)
    } finally {
      setIsUpdating(false)
    }
  }

  // Fetch organizations when tab is active
  const fetchOrganizations = async () => {
    setOrgsLoading(true)
    setOrgsError('')
    try {
      // Use admin API for organizations
      const token = localStorage.getItem('shizuha_access_token')
      const response = await fetch('/admin/api/organizations/', {
        headers: {
          'Authorization': `Bearer ${token}`,
          'Content-Type': 'application/json',
        },
      })
      if (!response.ok) {
        throw new Error('Failed to fetch organizations')
      }
      const data = await response.json()
      setOrganizations(data.results || data)
    } catch (error) {
      console.error('Error fetching organizations:', error)
      setOrgsError('Failed to load organizations')
    } finally {
      setOrgsLoading(false)
    }
  }

  useEffect(() => {
    if (activeTab === 'organizations') {
      fetchOrganizations()
    }
  }, [activeTab])

  const handleCreateOrg = async (e) => {
    e.preventDefault()
    if (!newOrgName.trim()) return

    setCreatingOrg(true)
    try {
      const token = localStorage.getItem('shizuha_access_token')
      const response = await fetch('/admin/api/organizations/', {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${token}`,
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          name: newOrgName.trim(),
          slug: newOrgSlug.trim() || newOrgName.trim().toLowerCase().replace(/\s+/g, '-'),
        }),
      })
      if (!response.ok) {
        const errorData = await response.json()
        throw new Error(errorData.detail || 'Failed to create organization')
      }
      setNewOrgName('')
      setNewOrgSlug('')
      setShowCreateOrg(false)
      fetchOrganizations()
    } catch (error) {
      setOrgsError(error.message)
    } finally {
      setCreatingOrg(false)
    }
  }

  const getRoleBadgeColor = (role) => {
    switch (role) {
      case 'owner':
        return 'bg-yellow-100 text-yellow-800 dark:bg-yellow-900/30 dark:text-yellow-400'
      case 'admin':
        return 'bg-purple-100 text-purple-800 dark:bg-purple-900/30 dark:text-purple-400'
      case 'member':
        return 'bg-blue-100 text-blue-800 dark:bg-blue-900/30 dark:text-blue-400'
      default:
        return 'bg-gray-100 text-gray-800 dark:bg-gray-900/30 dark:text-gray-400'
    }
  }

  if (authLoading) {
    return (
      <div className="min-h-screen flex items-center justify-center bg-gray-50 dark:bg-gray-950">
        <Loader2 className="h-8 w-8 animate-spin text-gray-500" />
      </div>
    )
  }

  if (!user) {
    navigate('/login')
    return null
  }

  const tabs = [
    { id: 'profile', label: 'Profile', icon: User },
    { id: 'organizations', label: 'Organizations', icon: Building2 },
    { id: 'security', label: 'Security', icon: Shield },
    { id: 'preferences', label: 'Preferences', icon: Sun },
  ]

  return (
    <div className="min-h-screen bg-gray-50 dark:bg-gray-950">
      {/* Header */}
      <header className="bg-white dark:bg-gray-900 border-b border-gray-200 dark:border-gray-800">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="flex items-center justify-between h-16">
            <div className="flex items-center gap-4">
              <AppSwitcher currentAppId="id" enabledServices={enabledServices} />
              <h1 className="text-xl font-semibold text-gray-900 dark:text-white">
                Account Settings
              </h1>
            </div>
            <button
              onClick={handleLogout}
              className="flex items-center gap-2 px-4 py-2 text-sm font-medium text-gray-700 dark:text-gray-300 hover:text-gray-900 dark:hover:text-white hover:bg-gray-100 dark:hover:bg-gray-800 rounded-lg transition-colors"
            >
              <LogOut className="h-4 w-4" />
              Sign Out
            </button>
          </div>
        </div>
      </header>

      <main className="max-w-4xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
        {/* User Info Card */}
        <div className="bg-white dark:bg-gray-900 rounded-xl border border-gray-200 dark:border-gray-800 p-6 mb-8">
          <div className="flex items-center gap-4">
            {user.profile?.profile_picture ? (
              <img
                src={user.profile.profile_picture}
                alt={user.username || 'avatar'}
                className="w-16 h-16 rounded-full object-cover ring-2 ring-indigo-500/30"
              />
            ) : (
              <div className="w-16 h-16 rounded-full bg-gradient-to-br from-indigo-500 to-purple-600 flex items-center justify-center text-white text-2xl font-semibold">
                {user.first_name?.[0] || user.username?.[0] || 'U'}
              </div>
            )}
            <div>
              <h2 className="text-xl font-semibold text-gray-900 dark:text-white">
                {user.first_name && user.last_name
                  ? `${user.first_name} ${user.last_name}`
                  : user.username}
              </h2>
              <p className="text-sm text-gray-500 dark:text-gray-400">{user.email}</p>
              <p className="text-xs text-gray-400 dark:text-gray-500 mt-1">
                Member since {new Date(user.date_joined).toLocaleDateString()}
              </p>
            </div>
          </div>
        </div>

        <div className="flex gap-8">
          {/* Sidebar Tabs */}
          <nav className="w-48 flex-shrink-0">
            <ul className="space-y-1">
              {tabs.map((tab) => (
                <li key={tab.id}>
                  <button
                    onClick={() => setActiveTab(tab.id)}
                    className={cn(
                      'w-full flex items-center gap-3 px-4 py-2.5 rounded-lg text-sm font-medium transition-colors',
                      activeTab === tab.id
                        ? 'bg-indigo-50 dark:bg-indigo-900/20 text-indigo-700 dark:text-indigo-400'
                        : 'text-gray-700 dark:text-gray-300 hover:bg-gray-100 dark:hover:bg-gray-800'
                    )}
                  >
                    <tab.icon className="h-4 w-4" />
                    {tab.label}
                  </button>
                </li>
              ))}
            </ul>
          </nav>

          {/* Content */}
          <div className="flex-1">
            {/* Profile Tab */}
            {activeTab === 'profile' && (
              <div className="bg-white dark:bg-gray-900 rounded-xl border border-gray-200 dark:border-gray-800 p-6">
                <h3 className="text-lg font-semibold text-gray-900 dark:text-white mb-6">
                  Profile Information
                </h3>

                <form onSubmit={handleUpdateProfile} className="space-y-4">
                  <div>
                    <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
                      Username
                    </label>
                    <input
                      type="text"
                      value={username}
                      onChange={(e) => setUsername(e.target.value.replace(/[^a-zA-Z0-9_]/g, ''))}
                      pattern="^[a-zA-Z0-9_]+$"
                      minLength={3}
                      maxLength={30}
                      className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-800 text-gray-900 dark:text-white focus:ring-2 focus:ring-indigo-500 focus:border-transparent"
                    />
                    <p className="text-xs text-gray-500 dark:text-gray-400 mt-1">
                      3-30 characters, letters, numbers, and underscores only
                    </p>
                  </div>

                  <div className="grid grid-cols-2 gap-4">
                    <div>
                      <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
                        First Name
                      </label>
                      <input
                        type="text"
                        value={firstName}
                        onChange={(e) => setFirstName(e.target.value)}
                        className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-800 text-gray-900 dark:text-white focus:ring-2 focus:ring-indigo-500 focus:border-transparent"
                      />
                    </div>
                    <div>
                      <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
                        Last Name
                      </label>
                      <input
                        type="text"
                        value={lastName}
                        onChange={(e) => setLastName(e.target.value)}
                        className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-800 text-gray-900 dark:text-white focus:ring-2 focus:ring-indigo-500 focus:border-transparent"
                      />
                    </div>
                  </div>

                  <div>
                    <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
                      Email
                    </label>
                    <input
                      type="email"
                      value={email}
                      disabled
                      className="w-full px-3 py-2 border border-gray-200 dark:border-gray-700 rounded-lg bg-gray-50 dark:bg-gray-800 text-gray-500 dark:text-gray-400 cursor-not-allowed"
                    />
                    <p className="text-xs text-gray-500 dark:text-gray-400 mt-1">
                      Email cannot be changed
                    </p>
                  </div>

                  <div className="grid grid-cols-2 gap-4">
                    <div>
                      <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
                        Timezone
                      </label>
                      <select
                        value={timezone}
                        onChange={(e) => setTimezone(e.target.value)}
                        className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-800 text-gray-900 dark:text-white focus:ring-2 focus:ring-indigo-500 focus:border-transparent"
                      >
                        {['Asia/Kolkata', 'UTC', 'America/New_York', 'America/Los_Angeles', 'Europe/London', 'Europe/Paris', 'Asia/Dubai', 'Asia/Singapore', 'Asia/Tokyo'].map((zone) => (
                          <option key={zone} value={zone}>{zone}</option>
                        ))}
                      </select>
                    </div>
                    <div>
                      <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
                        Display currency
                      </label>
                      <select
                        value={displayCurrency}
                        onChange={(e) => setDisplayCurrency(e.target.value)}
                        className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-800 text-gray-900 dark:text-white focus:ring-2 focus:ring-indigo-500 focus:border-transparent"
                      >
                        <option value="USD">USD — US dollar</option>
                        <option value="INR">INR — Indian rupee</option>
                        <option value="EUR">EUR — Euro</option>
                        <option value="GBP">GBP — Pound sterling</option>
                      </select>
                      <p className="text-xs text-gray-500 dark:text-gray-400 mt-1">
                        Used as an indicative suffix on Hane. Not redeemable.
                      </p>
                    </div>
                  </div>

                  {updateError && (
                    <div className="flex items-center gap-2 text-red-600 dark:text-red-400 text-sm">
                      <AlertCircle className="h-4 w-4" />
                      {updateError}
                    </div>
                  )}

                  {updateSuccess && (
                    <div className="flex items-center gap-2 text-green-600 dark:text-green-400 text-sm">
                      <Check className="h-4 w-4" />
                      Profile updated successfully
                    </div>
                  )}

                  <button
                    type="submit"
                    disabled={isUpdating}
                    className="px-4 py-2 bg-indigo-600 hover:bg-indigo-700 text-white font-medium rounded-lg transition-colors disabled:opacity-50"
                  >
                    {isUpdating ? (
                      <Loader2 className="h-4 w-4 animate-spin" />
                    ) : (
                      'Save Changes'
                    )}
                  </button>
                </form>
              </div>
            )}

            {/* Avatar — avatar == profile image (operator 2026-08) */}
            {activeTab === 'profile' && <AvatarManager />}

            {/* Organizations Tab */}
            {activeTab === 'organizations' && (
              <div className="space-y-6">
                <div className="bg-white dark:bg-gray-900 rounded-xl border border-gray-200 dark:border-gray-800 p-6">
                  <div className="flex items-center justify-between mb-6">
                    <div>
                      <h3 className="text-lg font-semibold text-gray-900 dark:text-white">
                        Your Organizations
                      </h3>
                      <p className="text-sm text-gray-500 dark:text-gray-400 mt-1">
                        Organizations you own or are a member of
                      </p>
                    </div>
                    <button
                      onClick={() => setShowCreateOrg(true)}
                      className="flex items-center gap-2 px-4 py-2 bg-indigo-600 hover:bg-indigo-700 text-white font-medium rounded-lg transition-colors"
                    >
                      <Plus className="h-4 w-4" />
                      New Organization
                    </button>
                  </div>

                  {orgsError && (
                    <div className="flex items-center gap-2 text-red-600 dark:text-red-400 text-sm mb-4 p-3 bg-red-50 dark:bg-red-900/20 rounded-lg">
                      <AlertCircle className="h-4 w-4" />
                      {orgsError}
                    </div>
                  )}

                  {orgsLoading ? (
                    <div className="flex items-center justify-center py-12">
                      <Loader2 className="h-8 w-8 animate-spin text-gray-400" />
                    </div>
                  ) : organizations.length === 0 ? (
                    <div className="text-center py-12">
                      <Building2 className="h-12 w-12 mx-auto text-gray-400 mb-4" />
                      <h4 className="text-lg font-medium text-gray-900 dark:text-white mb-2">
                        No organizations yet
                      </h4>
                      <p className="text-sm text-gray-500 dark:text-gray-400 mb-4">
                        Create an organization to collaborate with your team
                      </p>
                      <button
                        onClick={() => setShowCreateOrg(true)}
                        className="inline-flex items-center gap-2 px-4 py-2 bg-indigo-600 hover:bg-indigo-700 text-white font-medium rounded-lg transition-colors"
                      >
                        <Plus className="h-4 w-4" />
                        Create Organization
                      </button>
                    </div>
                  ) : (
                    <div className="space-y-3">
                      {organizations.map((org) => (
                        <div
                          key={org.id}
                          className="flex items-center justify-between p-4 bg-gray-50 dark:bg-gray-800/50 rounded-lg hover:bg-gray-100 dark:hover:bg-gray-800 transition-colors"
                        >
                          <div className="flex items-center gap-4">
                            <div className="w-10 h-10 rounded-lg bg-gradient-to-br from-indigo-500 to-purple-600 flex items-center justify-center text-white font-semibold">
                              {org.name?.[0]?.toUpperCase() || 'O'}
                            </div>
                            <div>
                              <h4 className="font-medium text-gray-900 dark:text-white">
                                {org.name}
                              </h4>
                              <p className="text-sm text-gray-500 dark:text-gray-400">
                                {org.slug}
                              </p>
                            </div>
                          </div>
                          <div className="flex items-center gap-3">
                            {org.membership?.role && (
                              <span className={cn(
                                'px-2.5 py-1 text-xs font-medium rounded-full flex items-center gap-1',
                                getRoleBadgeColor(org.membership.role)
                              )}>
                                {org.membership.role === 'owner' && <Crown className="h-3 w-3" />}
                                {org.membership.role.charAt(0).toUpperCase() + org.membership.role.slice(1)}
                              </span>
                            )}
                            <a
                              href={`/pulse/?org=${org.slug}`}
                              className="p-2 text-gray-400 hover:text-gray-600 dark:hover:text-gray-300 hover:bg-gray-200 dark:hover:bg-gray-700 rounded-lg transition-colors"
                              title="Open in Pulse"
                            >
                              <ExternalLink className="h-4 w-4" />
                            </a>
                          </div>
                        </div>
                      ))}
                    </div>
                  )}
                </div>

                {/* Create Organization Modal */}
                {showCreateOrg && (
                  <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50">
                    <div className="bg-white dark:bg-gray-900 rounded-xl border border-gray-200 dark:border-gray-700 p-6 w-full max-w-md mx-4 shadow-xl">
                      <h3 className="text-lg font-semibold text-gray-900 dark:text-white mb-4">
                        Create Organization
                      </h3>
                      <form onSubmit={handleCreateOrg} className="space-y-4">
                        <div>
                          <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
                            Organization Name
                          </label>
                          <input
                            type="text"
                            value={newOrgName}
                            onChange={(e) => {
                              setNewOrgName(e.target.value)
                              if (!newOrgSlug) {
                                setNewOrgSlug(e.target.value.toLowerCase().replace(/\s+/g, '-'))
                              }
                            }}
                            placeholder="My Team"
                            className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-800 text-gray-900 dark:text-white focus:ring-2 focus:ring-indigo-500 focus:border-transparent"
                            required
                          />
                        </div>
                        <div>
                          <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
                            URL Slug
                          </label>
                          <input
                            type="text"
                            value={newOrgSlug}
                            onChange={(e) => setNewOrgSlug(e.target.value.toLowerCase().replace(/\s+/g, '-'))}
                            placeholder="my-team"
                            className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-800 text-gray-900 dark:text-white focus:ring-2 focus:ring-indigo-500 focus:border-transparent"
                            required
                          />
                          <p className="text-xs text-gray-500 dark:text-gray-400 mt-1">
                            Used in URLs like /pulse/?org={newOrgSlug || 'my-team'}
                          </p>
                        </div>
                        <div className="flex gap-3 pt-2">
                          <button
                            type="button"
                            onClick={() => {
                              setShowCreateOrg(false)
                              setNewOrgName('')
                              setNewOrgSlug('')
                            }}
                            className="flex-1 px-4 py-2 border border-gray-300 dark:border-gray-600 text-gray-700 dark:text-gray-300 font-medium rounded-lg hover:bg-gray-50 dark:hover:bg-gray-800 transition-colors"
                          >
                            Cancel
                          </button>
                          <button
                            type="submit"
                            disabled={creatingOrg || !newOrgName.trim()}
                            className="flex-1 px-4 py-2 bg-indigo-600 hover:bg-indigo-700 text-white font-medium rounded-lg transition-colors disabled:opacity-50 flex items-center justify-center gap-2"
                          >
                            {creatingOrg ? (
                              <Loader2 className="h-4 w-4 animate-spin" />
                            ) : (
                              'Create'
                            )}
                          </button>
                        </div>
                      </form>
                    </div>
                  </div>
                )}
              </div>
            )}

            {/* Security Tab */}
            {activeTab === 'security' && (
              <div className="space-y-6">
                <TwoFactorSecurity user={user} />

                <div className="bg-white dark:bg-gray-900 rounded-xl border border-gray-200 dark:border-gray-800 p-6">
                  <h3 className="text-lg font-semibold text-gray-900 dark:text-white mb-6">
                    Change Password
                  </h3>

                  <form onSubmit={handleChangePassword} className="space-y-4">
                    <div>
                      <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
                        Current Password
                      </label>
                      <input
                        type="password"
                        value={currentPassword}
                        onChange={(e) => setCurrentPassword(e.target.value)}
                        className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-800 text-gray-900 dark:text-white focus:ring-2 focus:ring-indigo-500 focus:border-transparent"
                      />
                    </div>

                    <div>
                      <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
                        New Password
                      </label>
                      <input
                        type="password"
                        value={newPassword}
                        onChange={(e) => setNewPassword(e.target.value)}
                        className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-800 text-gray-900 dark:text-white focus:ring-2 focus:ring-indigo-500 focus:border-transparent"
                      />
                    </div>

                    <div>
                      <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
                        Confirm New Password
                      </label>
                      <input
                        type="password"
                        value={confirmPassword}
                        onChange={(e) => setConfirmPassword(e.target.value)}
                        className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-800 text-gray-900 dark:text-white focus:ring-2 focus:ring-indigo-500 focus:border-transparent"
                      />
                    </div>

                    {passwordError && (
                      <div className="flex items-center gap-2 text-red-600 dark:text-red-400 text-sm">
                        <AlertCircle className="h-4 w-4" />
                        {passwordError}
                      </div>
                    )}

                    {passwordSuccess && (
                      <div className="flex items-center gap-2 text-green-600 dark:text-green-400 text-sm">
                        <Check className="h-4 w-4" />
                        Password changed successfully
                      </div>
                    )}

                    <button
                      type="submit"
                      disabled={isUpdating}
                      className="px-4 py-2 bg-indigo-600 hover:bg-indigo-700 text-white font-medium rounded-lg transition-colors disabled:opacity-50"
                    >
                      {isUpdating ? (
                        <Loader2 className="h-4 w-4 animate-spin" />
                      ) : (
                        'Change Password'
                      )}
                    </button>
                  </form>
                </div>

                {/* Sessions */}
                <div className="bg-white dark:bg-gray-900 rounded-xl border border-gray-200 dark:border-gray-800 p-6">
                  <h3 className="text-lg font-semibold text-gray-900 dark:text-white mb-4">
                    Active Sessions
                  </h3>
                  <p className="text-sm text-gray-500 dark:text-gray-400 mb-4">
                    Manage your active sessions across devices
                  </p>
                  <button className="text-sm text-red-600 dark:text-red-400 hover:text-red-700 dark:hover:text-red-300 font-medium">
                    Sign out all other sessions
                  </button>
                </div>

                {/* Connected Apps (OAuth authorizations) */}
                <AuthorizedAppsSection />
              </div>
            )}

            {/* Preferences Tab */}
            {activeTab === 'preferences' && (
              <div className="bg-white dark:bg-gray-900 rounded-xl border border-gray-200 dark:border-gray-800 p-6">
                <h3 className="text-lg font-semibold text-gray-900 dark:text-white mb-6">
                  Preferences
                </h3>

                <div className="space-y-6">
                  {/* Theme Toggle */}
                  <div className="flex items-center justify-between">
                    <div>
                      <h4 className="text-sm font-medium text-gray-900 dark:text-white">
                        Dark Mode
                      </h4>
                      <p className="text-sm text-gray-500 dark:text-gray-400">
                        Toggle between light and dark theme
                      </p>
                    </div>
                    <button
                      onClick={toggleTheme}
                      className={cn(
                        'relative inline-flex h-6 w-11 items-center rounded-full transition-colors',
                        isDark ? 'bg-indigo-600' : 'bg-gray-200'
                      )}
                    >
                      <span
                        className={cn(
                          'inline-block h-4 w-4 transform rounded-full bg-white transition-transform',
                          isDark ? 'translate-x-6' : 'translate-x-1'
                        )}
                      />
                    </button>
                  </div>

                  {/* Delete Account */}
                  <div className="pt-6 border-t border-gray-200 dark:border-gray-700">
                    <h4 className="text-sm font-medium text-red-600 dark:text-red-400 mb-2">
                      Danger Zone
                    </h4>
                    <p className="text-sm text-gray-500 dark:text-gray-400 mb-4">
                      Once you delete your account, there is no going back. Please be certain.
                    </p>
                    <button className="flex items-center gap-2 px-4 py-2 border border-red-300 dark:border-red-700 text-red-600 dark:text-red-400 rounded-lg hover:bg-red-50 dark:hover:bg-red-900/20 transition-colors">
                      <Trash2 className="h-4 w-4" />
                      Delete Account
                    </button>
                  </div>
                </div>
              </div>
            )}
          </div>
        </div>
      </main>
    </div>
  )
}
