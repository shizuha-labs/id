import assert from 'node:assert/strict'
import { requestedSocialProvider, shouldSkipFirstPartyConsent } from '../src/utils/socialLogin.js'

assert.equal(requestedSocialProvider('google'), 'google')
assert.equal(requestedSocialProvider('GOOGLE'), 'google')
assert.equal(requestedSocialProvider('github'), 'github')
assert.equal(requestedSocialProvider('facebook'), '')
assert.equal(requestedSocialProvider(''), '')

assert.equal(shouldSkipFirstPartyConsent({ is_system: true }, 'http://localhost/callback'), true)
assert.equal(
  shouldSkipFirstPartyConsent({ is_system: false }, 'https://cortex.shizuha.com/cortex/auth/callback'),
  true,
)
assert.equal(
  shouldSkipFirstPartyConsent({ is_system: false }, 'https://shizuha.com/id/auth/google'),
  true,
)
assert.equal(
  shouldSkipFirstPartyConsent({ is_system: false }, 'https://evil.example/callback'),
  false,
)
assert.equal(shouldSkipFirstPartyConsent({}, ''), false)

console.log('social login helpers: PASS')
