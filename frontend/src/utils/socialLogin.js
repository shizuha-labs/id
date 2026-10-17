// First-party IdP + consent helpers. Cortex/Studio start Google by sending
// users here with ?provider=google; system / first-party web clients skip
// the extra authorize click.

const FIRST_PARTY_HOSTS = new Set([
  'shizuha.com',
  'www.shizuha.com',
  'cortex.shizuha.com',
  'hive.shizuha.com',
  'pulse.shizuha.com',
  'id.shizuha.com',
])

export function requestedSocialProvider(raw) {
  const v = String(raw || '').trim().toLowerCase()
  return (v === 'google' || v === 'github') ? v : ''
}

export function shouldSkipFirstPartyConsent(client, redirectUri) {
  if (client?.is_system) return true
  try {
    const host = new URL(redirectUri).hostname
    return FIRST_PARTY_HOSTS.has(host)
  } catch {
    return false
  }
}
