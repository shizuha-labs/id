import assert from 'node:assert/strict'
import { humanizeAuthMessage, userFacingApiError } from './userFacingApiError.js'

assert.equal(
  userFacingApiError({
    response: {
      data: {
        error: 'membership_projection_unavailable',
        detail: 'Organization and project memberships are temporarily unavailable. No token was issued; retry shortly.',
      },
    },
  }),
  'Organization and project memberships are temporarily unavailable. No token was issued; retry shortly.',
)

assert.equal(
  userFacingApiError({ response: { data: { error: 'membership_projection_unavailable' } } }),
  'Organization memberships are temporarily unavailable. Retry in a moment — no session was created.',
)

assert.equal(
  userFacingApiError({ response: { data: { error: 'Username and password are required' } } }),
  'Username and password are required',
)

assert.equal(humanizeAuthMessage('membership_projection_unavailable'), 'Organization memberships are temporarily unavailable. Retry in a moment — no session was created.')
assert.equal(humanizeAuthMessage('access_denied'), 'Sign-in was cancelled.')
assert.notEqual(humanizeAuthMessage('token_split_failed'), 'token_split_failed')
assert.equal(userFacingApiError(null, 'Login failed. Please try again.'), 'Login failed. Please try again.')
const gatewayHtml = '<html>\r\n<head><title>504 Gateway Time-out</title></head>\r\n<body>\r\n<center><h1>504 Gateway Time-out</h1></center>\r\n<hr><center>nginx/1.27.5</center>\r\n</body>\r\n</html>\r\n'
const unavailable = 'Sign-in is temporarily unavailable. Please try again in a moment.'
const gatewayError = { name: 'AxiosError', code: 'ERR_BAD_RESPONSE', message: 'Request failed with status code 504', response: { status: 504, statusText: 'Gateway Time-out', headers: { 'content-type': 'text/html' }, data: gatewayHtml } }
assert.equal(userFacingApiError(gatewayError, 'Login failed. Please try again.'), unavailable)
assert.equal(userFacingApiError({ response: { status: 502, data: 'upstream connection refused' } }), unavailable)
assert.equal(userFacingApiError({ response: { status: 503 } }), unavailable)
assert.equal(userFacingApiError({ response: { status: 500, data: { detail: gatewayHtml } } }), unavailable)
assert.equal(userFacingApiError({ response: { status: 400, data: '<!DOCTYPE HTML><title>Bad Request</title>' } }, 'Try again.'), 'Try again.')
assert.equal(userFacingApiError(gatewayHtml, 'Try again.'), 'Try again.')
assert.equal(humanizeAuthMessage('<!-- proxy error -->hidden internals', 'Try again.'), 'Try again.')
assert.equal(userFacingApiError({ response: { status: 401, data: { error: 'Invalid credentials' } } }), 'Invalid credentials')
assert.equal(userFacingApiError({ response: { status: 400, data: { detail: ['Enter a valid email address.'] } } }), 'Enter a valid email address.')
assert.equal(userFacingApiError({ response: { status: 403, data: { message: 'Your account is pending admin approval.' } } }), 'Your account is pending admin approval.')
assert.equal(userFacingApiError({ response: { status: 503, data: { detail: 'Organization memberships are temporarily unavailable.' } } }), 'Organization memberships are temporarily unavailable.')
assert.equal(humanizeAuthMessage('Password length must be < 8 characters.'), 'Password length must be < 8 characters.')
console.log('userFacingApiError: ok')
