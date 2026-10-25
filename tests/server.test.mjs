import test from 'node:test'
import assert from 'node:assert/strict'
import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'
import { once, EventEmitter } from 'node:events'
import { WebSocket } from 'ws'
import { AccountManager } from '../src/account/AccountManager.mjs'
import { AutoKeyServer } from '../src/server/Server.mjs'

const token = 'autokey-test-only-'.repeat(3)
async function fixture(t, options = {}) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'autokey-server-'))
  const manager = new AccountManager(root)
  const launcher = options.launcher || { isActive: () => false }
  const flows = { loginWithPasskey: async () => ({ success: false, error: 'Unconfirmed', cookies: ['secret'] }) }
  const app = new AutoKeyServer(manager, launcher, flows, { token })
  const server = await app.start(0, '127.0.0.1')
  t.after(async () => { await app.stop(); fs.rmSync(root, { recursive: true, force: true }) })
  const base = `http://127.0.0.1:${server.address().port}`
  const request = (url, options = {}) => fetch(base + url, { ...options, headers: { Authorization: `Bearer ${token}`, ...options.headers } })
  return { manager, app, base, request }
}

test('refuses unauthenticated public listening and rejects bad ports/tokens', async () => {
  const app = new AutoKeyServer(null, null, null, { token: '' })
  await assert.rejects(app.start(0, '0.0.0.0'), /AUTOKEY_TOKEN/)
  for (const port of [NaN, -1, 65536, 1.5]) await assert.rejects(app.start(port), /port/)
  const weak = new AutoKeyServer(null, null, null, { token: 'short' })
  await assert.rejects(weak.start(0), /32/)
})

test('HTTP/WS require authentication; cookie authentication is HttpOnly and SameSite', async t => {
  const { base, request } = await fixture(t)
  assert.equal((await fetch(base + '/api/accounts')).status, 401)
  assert.equal((await request('/api/accounts', { headers: { Authorization: 'Bearer wrong' } })).status, 401)
  const auth = await fetch(base + '/api/auth', { method: 'POST', body: JSON.stringify({ token }) })
  assert.equal(auth.status, 200)
  const cookie = auth.headers.get('set-cookie')
  assert.match(cookie, /HttpOnly; SameSite=Strict/)
  assert.equal((await fetch(base + '/api/accounts', { headers: { Cookie: cookie.split(';')[0] } })).status, 200)
  const ws = new WebSocket(base.replace('http:', 'ws:') + '/ws/screencast?accountId=missing')
  const status = await new Promise(resolve => { ws.on('unexpected-response', (_, res) => { res.resume(); ws.terminate(); resolve(res.statusCode) }); ws.on('error', () => {}) })
  assert.equal(status, 401)
})

test('blocks cross-origin reads/mutations and never sends wildcard CORS', async t => {
  const { request } = await fixture(t)
  const response = await request('/api/accounts', { headers: { Origin: 'https://evil.example' } })
  assert.equal(response.status, 403)
  assert.equal(response.headers.get('access-control-allow-origin'), null)
  assert.equal((await request('/api/accounts', { headers: { 'Sec-Fetch-Site': 'cross-site' } })).status, 403)
})

test('device and system APIs are authenticated, safe and do not start a browser', async t => {
  const { manager, base, request } = await fixture(t)
  const account = manager.createAccount({ email: 'device@example.com', password: 'hidden-password' })
  assert.equal((await fetch(base + '/api/system-info')).status, 401)
  assert.equal((await fetch(`${base}/api/accounts/${account.id}/device-info`)).status, 401)
  const system = await (await request('/api/system-info')).json()
  assert.equal(system.system.platform, process.platform)
  const device = await (await request(`/api/accounts/${account.id}/device-info`)).json()
  assert.equal(device.deviceInfo.accountId, account.id)
  assert.equal(device.deviceInfo.browser, null)
  assert.doesNotMatch(JSON.stringify(device), /hidden-password|privateKey/)
  assert.equal((await request('/api/accounts/missing/device-info')).status, 404)
})

test('API validates JSON, sizes, missing accounts, duplicate accounts and hides passwords', async t => {
  const { manager, request } = await fixture(t)
  for (const body of ['{bad', 'null', '[]', '42']) assert.equal((await request('/api/accounts', { method: 'POST', body })).status, 400)
  assert.equal((await request('/api/accounts', { method: 'POST', body: 'x'.repeat(65537) })).status, 413)
  const body = JSON.stringify({ email: 'one@example.com', password: 'secretPassword', proxy: 'http://user:secretProxy@proxy.example:8080' })
  const created = await request('/api/accounts', { method: 'POST', body })
  assert.equal(created.status, 201)
  assert.doesNotMatch(await created.text(), /secretPassword|secretProxy|"password"|"username"/)
  assert.equal((await request('/api/accounts', { method: 'POST', body })).status, 409)
  const listing = await request('/api/accounts')
  assert.doesNotMatch(await listing.text(), /secretPassword|secretProxy/)
  assert.equal(manager.getAccount('one@example.com').password, 'secretPassword')
  assert.equal((await request('/api/accounts/missing/passkey')).status, 404)
  assert.equal((await request('/api/accounts/missing', { method: 'DELETE' })).status, 404)
  assert.equal((await request('/api/accounts/%2e%2e%2fetc/passkey')).status, 400)
})

test('static allowlist prevents traversal or source/private-file exposure', async t => {
  const { request } = await fixture(t)
  for (const url of ['/../package.json', '/%2e%2e%2fconfig.mjs', '/app.js/../../README.md', '/missing.js']) assert.equal((await request(url)).status, 404)
  const response = await request('/')
  assert.equal(response.status, 200)
  assert.equal(response.headers.get('cache-control'), 'no-store')
  assert.match(await response.text(), /AutoKey/)
})

test('active-account deletion is rejected and unsuccessful login is not wrapped as success', async t => {
  const launcher = { isActive: () => true }
  const { manager, request } = await fixture(t, { launcher })
  manager.createAccount({ email: 'one@example.com' })
  assert.equal((await request('/api/accounts/one_example.com', { method: 'DELETE' })).status, 409)
  const login = await (await request('/api/accounts/one_example.com/login', { method: 'POST' })).json()
  assert.equal(login.success, false)
  assert.equal(login.result.cookies, undefined)
})

test('disconnection during browser startup closes the eventual browser and releases reservation', async t => {
  let completeLaunch
  let closed = 0
  const launcher = { isActive: () => false, launchAccountSession: () => new Promise(resolve => { completeLaunch = resolve }) }
  const { manager, app } = await fixture(t, { launcher })
  const account = manager.createAccount({ email: 'one@example.com' })
  const ws = new EventEmitter()
  Object.assign(ws, { readyState: 1, send() {}, close() {} })
  const starting = app.handleScreencastWs(ws, account.id)
  assert.equal(app.activeSessions.size, 1)
  ws.readyState = 3
  ws.emit('close')
  completeLaunch({ close: async () => { closed++ } })
  await starting
  assert.equal(closed, 1)
  assert.equal(app.activeSessions.size, 0)
})
