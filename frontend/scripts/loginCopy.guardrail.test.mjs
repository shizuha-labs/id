import assert from 'node:assert/strict'
import { readFile } from 'node:fs/promises'
import { isDefaultContinueTarget } from '../src/utils/safeContinue.js'

const login = await readFile(new URL('../src/pages/Login.jsx', import.meta.url), 'utf8')
const register = await readFile(new URL('../src/pages/Register.jsx', import.meta.url), 'utf8')

assert.match(login, /userFacingApiError/)
assert.doesNotMatch(login, /setError\(err\.response\?\.data\?\.error/)
assert.doesNotMatch(login, /You'll be redirected to/)
assert.match(login, /isDefaultContinueTarget\(continueUrl/)
assert.doesNotMatch(login, /font-mono\}\{continueUrl\}/)

assert.match(register, /userFacingApiError/)
assert.doesNotMatch(register, /You'll be redirected to/)

assert.equal(isDefaultContinueTarget('/account', '/account'), true)
assert.equal(isDefaultContinueTarget('/id/account', '/account'), true)
assert.equal(isDefaultContinueTarget('/', '/account'), true)
assert.equal(isDefaultContinueTarget('/hive/agents', '/account'), false)
console.log('login copy guardrail: ok')
