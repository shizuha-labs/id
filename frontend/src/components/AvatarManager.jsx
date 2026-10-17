import { useEffect, useState } from 'react'
import { Shuffle, Check, AlertCircle, Loader2, RefreshCw, ImagePlus } from 'lucide-react'
import api from '../services/api'
import { userFacingApiError } from '../utils/userFacingApiError'

// The stock avatar pool (matches home/scripts/generate_avatars.py count and the
// hive/id default-resolution algorithm). Served statically from shizuha.com.
const STOCK_COUNT = 160
const STOCK_BASE = 'https://shizuha.com/avatars/stock'

const stockUrl = (i) => `${STOCK_BASE}/${String(i).padStart(3, '0')}.png`
const randomStockUrl = () => stockUrl(Math.floor(Math.random() * STOCK_COUNT))

function initialsFor(name) {
  return (name || '?').slice(0, 2).toUpperCase()
}

/**
 * Avatar editor — avatar == profile image (operator 2026-08).
 * Shows the user's current avatar, a stock pool to pick from, a Shuffle
 * (random stock avatar), and a custom image-URL field. Persists via the
 * existing writable `profile_picture` on /auth/profile/.
 */
export default function AvatarManager() {
  const [profile, setProfile] = useState(null)
  const [busy, setBusy] = useState(false)
  const [customUrl, setCustomUrl] = useState('')
  const [error, setError] = useState('')
  const [saved, setSaved] = useState(false)

  const load = async () => {
    try {
      const { data } = await api.get('/auth/profile/')
      setProfile(data)
      setCustomUrl(data.profile_picture || '')
    } catch (err) {
      setError(userFacingApiError(err, 'Failed to load profile'))
    }
  }

  useEffect(() => {
    load()
  }, [])

  const save = async (url) => {
    setBusy(true)
    setError('')
    setSaved(false)
    try {
      await api.patch('/auth/profile/', { profile_picture: url || null })
      setProfile((p) => ({ ...p, profile_picture: url || null }))
      setCustomUrl(url || '')
      setSaved(true)
      setTimeout(() => setSaved(false), 2500)
    } catch (err) {
      setError(userFacingApiError(err, 'Failed to update avatar'))
    } finally {
      setBusy(false)
    }
  }

  const avatarUrl = profile?.profile_picture
  const avatarName = profile?.username || '?'

  return (
    <div className="bg-white dark:bg-gray-900 rounded-xl border border-gray-200 dark:border-gray-800 p-6 mt-6">
      <div className="flex items-center justify-between mb-1">
        <h3 className="text-lg font-semibold text-gray-900 dark:text-white">Avatar</h3>
        <span className="text-[10px] uppercase tracking-wide font-semibold px-2 py-0.5 rounded-full bg-indigo-50 dark:bg-indigo-900/40 text-indigo-600 dark:text-indigo-300">
          Profile image
        </span>
      </div>
      <p className="text-sm text-gray-500 dark:text-gray-400 mb-5">
        Every account gets a random avatar by default. Pick one from the stock, shuffle, or set your own image.
      </p>

      {error && (
        <div className="flex items-center gap-2 text-red-600 dark:text-red-400 text-sm mb-4">
          <AlertCircle className="h-4 w-4" /> {error}
        </div>
      )}
      {saved && (
        <div className="flex items-center gap-2 text-green-600 dark:text-green-400 text-sm mb-4">
          <Check className="h-4 w-4" /> Avatar updated
        </div>
      )}

      {!profile ? (
        <div className="flex items-center gap-2 text-gray-500 dark:text-gray-400 text-sm">
          <Loader2 className="h-4 w-4 animate-spin" /> Loading…
        </div>
      ) : (
        <>
          {/* Current avatar + shuffle */}
          <div className="flex items-center gap-4 mb-5">
            {avatarUrl ? (
              <img
                src={avatarUrl}
                alt={avatarName}
                className="h-16 w-16 rounded-full object-cover ring-2 ring-indigo-500/30"
              />
            ) : (
              <div className="h-16 w-16 rounded-full bg-gradient-to-br from-indigo-500 to-purple-600 flex items-center justify-center text-white text-2xl font-semibold">
                {initialsFor(avatarName)}
              </div>
            )}
            <div className="flex flex-col gap-2">
              <button
                type="button"
                onClick={() => save(randomStockUrl())}
                disabled={busy}
                className="inline-flex items-center gap-2 px-4 py-2 bg-indigo-600 hover:bg-indigo-700 text-white text-sm font-medium rounded-lg transition-colors disabled:opacity-50"
              >
                {busy ? <Loader2 className="h-4 w-4 animate-spin" /> : <Shuffle className="h-4 w-4" />}
                Shuffle
              </button>
              {avatarUrl && (
                <button
                  type="button"
                  onClick={() => save(null)}
                  disabled={busy}
                  className="inline-flex items-center gap-2 px-3 py-1.5 border border-gray-300 dark:border-gray-600 text-gray-600 dark:text-gray-300 text-xs rounded-lg hover:bg-gray-50 dark:hover:bg-gray-800 transition-colors disabled:opacity-50"
                >
                  <RefreshCw className="h-3.5 w-3.5" /> Reset to default
                </button>
              )}
            </div>
          </div>

          {/* Stock pool grid */}
          <div className="mb-5">
            <div className="text-xs font-medium text-gray-500 dark:text-gray-400 mb-2">
              Or pick from the stock pool
            </div>
            <div className="grid grid-cols-8 sm:grid-cols-10 md:grid-cols-12 gap-2 max-h-56 overflow-y-auto p-2 rounded-lg border border-gray-200 dark:border-gray-700 bg-gray-50 dark:bg-gray-800/40">
              {Array.from({ length: STOCK_COUNT }, (_, i) => (
                <button
                  key={i}
                  type="button"
                  title={`Avatar ${String(i).padStart(3, '0')}`}
                  onClick={() => save(stockUrl(i))}
                  disabled={busy}
                  className={`h-10 w-10 rounded-lg overflow-hidden ring-offset-2 transition focus:outline-none ${
                    avatarUrl === stockUrl(i)
                      ? 'ring-2 ring-indigo-500'
                      : 'ring-1 ring-black/5 hover:ring-indigo-400'
                  }`}
                >
                  <img src={stockUrl(i)} alt={`stock ${i}`} className="h-full w-full object-cover" loading="lazy" />
                </button>
              ))}
            </div>
          </div>

          {/* Custom URL */}
          <div>
            <label className="block text-xs font-medium text-gray-500 dark:text-gray-400 mb-1">
              Custom image URL
            </label>
            <div className="flex gap-2">
              <div className="flex-1 relative">
                <ImagePlus className="h-4 w-4 absolute left-3 top-1/2 -translate-y-1/2 text-gray-400" />
                <input
                  type="url"
                  value={customUrl}
                  onChange={(e) => setCustomUrl(e.target.value)}
                  placeholder="https://… (your own profile image)"
                  className="w-full pl-9 pr-3 py-2 border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-800 text-gray-900 dark:text-white text-sm focus:ring-2 focus:ring-indigo-500 focus:border-transparent"
                />
              </div>
              <button
                type="button"
                onClick={() => save(customUrl.trim())}
                disabled={busy || !customUrl.trim()}
                className="px-4 py-2 bg-indigo-600 hover:bg-indigo-700 text-white text-sm font-medium rounded-lg transition-colors disabled:opacity-50"
              >
                {busy ? <Loader2 className="h-4 w-4 animate-spin" /> : 'Set image'}
              </button>
            </div>
          </div>
        </>
      )}
    </div>
  )
}
