/** PLAT-5530 / PLAT-4440: brace-expansion stays 1.x CJS function for minimatch@3 */
import { createRequire } from 'node:module'
const require = createRequire(import.meta.url)
const braceExpand = require('brace-expansion')
const minimatch = require('minimatch')
const bePkg = require('brace-expansion/package.json')
if (typeof braceExpand !== 'function') throw new Error('brace-expansion not a function')
if (!minimatch('src/App.jsx', '**/*.{js,jsx}')) throw new Error('minimatch failed')
const [maj, min, pat] = bePkg.version.split('.').map(Number)
if (maj !== 1 || min < 1 || pat < 17) throw new Error(`brace-expansion ${bePkg.version} not patched 1.x`)
const rr = require('react-router-dom/package.json')
const [rMaj, rMin] = rr.version.split('.').map(Number)
if (rMaj < 7 || (rMaj === 7 && rMin < 18)) throw new Error(`react-router-dom ${rr.version} < 7.18`)
const pc = require('postcss/package.json')
const parts = pc.version.split('.').map(Number)
if (parts[0] < 8 || (parts[0] === 8 && parts[1] === 5 && parts[2] < 18)) {
  throw new Error(`postcss ${pc.version} < 8.5.18`)
}
console.log('plat5530 deps OK', { brace: bePkg.version, rr: rr.version, postcss: pc.version })
