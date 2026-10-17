/** Machine codes (snake_case) must never paint on login/register. */

const MACHINE_CODE = /^[a-z][a-z0-9]*(?:_[a-z0-9]+)+$/
const HTML_MARKUP = /<!doctype\b|<!--|<\/?[a-z][^>]*>/i
const UNAVAILABLE_MESSAGE = 'Sign-in is temporarily unavailable. Please try again in a moment.'

const CODE_COPY = {
  membership_projection_unavailable:
    'Organization memberships are temporarily unavailable. Retry in a moment — no session was created.',
  access_denied: 'Sign-in was cancelled.',
  invalid_grant: 'Sign-in could not be completed. Try again.',
  server_error: 'Sign-in is temporarily unavailable. Retry in a moment.',
}

export function humanizeAuthMessage(value, fallback = 'Something went wrong. Please try again.') {
  if (typeof value !== 'string') return fallback
  const text = value.trim()
  if (!text || HTML_MARKUP.test(text)) return fallback
  if (CODE_COPY[text]) return CODE_COPY[text]
  if (MACHINE_CODE.test(text) && !/\s/.test(text)) return fallback
  return text
}

export function userFacingApiError(err, fallback = 'Something went wrong. Please try again.') {
  if (typeof err === 'string') return humanizeAuthMessage(err, fallback)
  const data = err?.response?.data
  const responseFallback = err?.response?.status >= 500 ? UNAVAILABLE_MESSAGE : fallback
  if (typeof data === 'string') return err?.response?.status >= 500 ? responseFallback : humanizeAuthMessage(data, responseFallback)
  if (data && typeof data === 'object') {
    if (typeof data.detail === 'string' && data.detail.trim()) {
      return humanizeAuthMessage(data.detail, responseFallback)
    }
    if (Array.isArray(data.detail) && typeof data.detail[0] === 'string') {
      return humanizeAuthMessage(data.detail[0], responseFallback)
    }
    if (typeof data.error === 'string' && data.error.trim()) {
      return humanizeAuthMessage(data.error, responseFallback)
    }
    if (typeof data.message === 'string' && data.message.trim()) {
      return humanizeAuthMessage(data.message, responseFallback)
    }
  }
  return responseFallback
}
