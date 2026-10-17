function base64UrlToBuffer(value) {
  const normalized = value.replace(/-/g, '+').replace(/_/g, '/')
  const padded = normalized.padEnd(normalized.length + ((4 - (normalized.length % 4)) % 4), '=')
  const binary = window.atob(padded)
  const bytes = new Uint8Array(binary.length)
  for (let i = 0; i < binary.length; i += 1) {
    bytes[i] = binary.charCodeAt(i)
  }
  return bytes.buffer
}

function bufferToBase64Url(buffer) {
  const bytes = buffer instanceof Uint8Array ? buffer : new Uint8Array(buffer)
  let binary = ''
  bytes.forEach((byte) => {
    binary += String.fromCharCode(byte)
  })
  return window.btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '')
}

function normalizePublicKeyOptions(options = {}) {
  const publicKey = { ...options }
  if (typeof publicKey.challenge === 'string') {
    publicKey.challenge = base64UrlToBuffer(publicKey.challenge)
  }
  if (publicKey.user?.id && typeof publicKey.user.id === 'string') {
    publicKey.user = { ...publicKey.user, id: base64UrlToBuffer(publicKey.user.id) }
  }
  if (Array.isArray(publicKey.excludeCredentials)) {
    publicKey.excludeCredentials = publicKey.excludeCredentials.map((credential) => ({
      ...credential,
      id: typeof credential.id === 'string' ? base64UrlToBuffer(credential.id) : credential.id,
    }))
  }
  if (Array.isArray(publicKey.allowCredentials)) {
    publicKey.allowCredentials = publicKey.allowCredentials.map((credential) => ({
      ...credential,
      id: typeof credential.id === 'string' ? base64UrlToBuffer(credential.id) : credential.id,
    }))
  }
  return publicKey
}

export function browserSupportsWebAuthn() {
  return Boolean(window.PublicKeyCredential && navigator.credentials?.create)
}

export async function createPasskeyCredential(publicKeyOptions) {
  const credential = await navigator.credentials.create({
    publicKey: normalizePublicKeyOptions(publicKeyOptions),
  })
  return serializeCredential(credential)
}

export async function getPasskeyAssertion(publicKeyOptions) {
  const credential = await navigator.credentials.get({
    publicKey: normalizePublicKeyOptions(publicKeyOptions),
  })
  return serializeCredential(credential)
}

export function serializeCredential(credential) {
  if (!credential) return null
  const response = credential.response || {}
  const serialized = {
    id: credential.id,
    rawId: bufferToBase64Url(credential.rawId),
    type: credential.type,
    response: {},
  }

  for (const key of [
    'clientDataJSON',
    'attestationObject',
    'authenticatorData',
    'signature',
    'userHandle',
  ]) {
    if (response[key]) {
      serialized.response[key] = bufferToBase64Url(response[key])
    }
  }

  if (typeof response.getTransports === 'function') {
    serialized.response.transports = response.getTransports()
  }

  return serialized
}
