import test from 'node:test'
import assert from 'node:assert/strict'
import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'
import http from 'node:http'
import crypto from 'node:crypto'
import { once } from 'node:events'
import { AccountManager } from './src/account/AccountManager.mjs'
import { BrowserLauncher } from './src/core/BrowserLauncher.mjs'
import { writeJson } from './src/utils/storage.mjs'
import { AutoKeyServer } from './src/server/Server.mjs'
import { MicrosoftFlows } from './src/core/MicrosoftFlows.mjs'
import { getAccountDeviceInfo } from './src/core/DeviceInfo.mjs'
import { chromium } from 'patchright'
import { WebSocket } from 'ws'

test('real Chromium: registration, signature verification, persistence, isolation, remote control and dashboard', { timeout: 120000 }, async t => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'autokey-integration-'))
  const manager = new AccountManager(path.join(root, 'accounts'))
  const launcher = new BrowserLauncher(manager)
  const sessions = new Set()
  const open = async (id, options) => {
    const session = await launcher.launchAccountSession(id, options)
    sessions.add(session)
    return session
  }
  const fixtureServer = http.createServer((req, res) => {
    res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' })
    res.end('<!doctype html><html><head><title>AutoKey test fixture</title></head><body><h1>本地隔离测试</h1><input id="text"><button onclick="document.querySelector(\'#result\').textContent=\'clicked\'">Click</button><output id="result"></output></body></html>')
  })
  fixtureServer.listen(0, '127.0.0.1')
  await once(fixtureServer, 'listening')
  const origin = `http://localhost:${fixtureServer.address().port}`
  let dashboard
  let uiBrowser
  t.after(async () => {
    await uiBrowser?.close()
    await dashboard?.stop()
    for (const session of sessions) await session.close().catch(() => {})
    await new Promise(resolve => fixtureServer.close(resolve))
    // This exact absolute root was created by mkdtemp for this test, never a real account directory.
    assert.ok(root.startsWith(path.join(os.tmpdir(), 'autokey-integration-')))
    fs.rmSync(root, { recursive: true, force: true })
  })

  const alpha = manager.createAccount({ email: 'account_alpha@example.com' })
  const beta = manager.createAccount({ email: 'account_beta@example.com' })
  let credentialId
  let publicKey
  let alphaSession

  await t.test('registers a resident Passkey and persists its private key automatically', async () => {
    alphaSession = await open(alpha.id)
    await alphaSession.page.goto(origin)
    const registration = await alphaSession.page.evaluate(async () => {
      const credential = await navigator.credentials.create({ publicKey: {
        challenge: crypto.getRandomValues(new Uint8Array(32)), rp: { name: 'AutoKey local test', id: 'localhost' },
        user: { id: crypto.getRandomValues(new Uint8Array(16)), name: 'account_alpha@example.com', displayName: 'Alpha' },
        pubKeyCredParams: [{ alg: -7, type: 'public-key' }],
        authenticatorSelection: { authenticatorAttachment: 'platform', residentKey: 'required', userVerification: 'required' }, timeout: 5000
      } })
      return { id: credential.id, publicKey: Array.from(new Uint8Array(credential.response.getPublicKey())) }
    })
    credentialId = registration.id
    publicKey = crypto.createPublicKey({ key: Buffer.from(registration.publicKey), format: 'der', type: 'spki' })
    await alphaSession.flushCredentials()
    assert.equal(manager.getPasskey(alpha.id).length, 1)
    assert.ok(manager.getPasskey(alpha.id)[0].privateKey)
    await assert.rejects(open('account_alpha@example.com'), { statusCode: 409 })
    assert.throws(() => manager.deleteAccount(alpha.id), { statusCode: 409 })
    await alphaSession.page.evaluate(() => localStorage.setItem('isolation', 'alpha'))
    await alphaSession.context.addCookies([{ name: 'alpha_cookie', value: 'alpha', url: origin }])
    await alphaSession.close()
    assert.equal(fs.existsSync(manager.accountPath(alpha.id, '.session.lock')), false)
  })

  await t.test('re-injects a saved key, verifies the actual signature and preserves monotonically increasing signCount', async () => {
    for (let iteration = 0; iteration < 2; iteration++) {
      const session = await open(alpha.id)
      await session.page.goto(origin)
      const before = manager.getPasskey(alpha.id)[0].signCount
      const challenge = crypto.randomBytes(32)
      const assertion = await session.page.evaluate(async challenge => {
        const credential = await navigator.credentials.get({ publicKey: { challenge: Uint8Array.from(challenge), rpId: 'localhost', userVerification: 'required', timeout: 5000 } })
        return {
          id: credential.id,
          authenticatorData: Array.from(new Uint8Array(credential.response.authenticatorData)),
          clientDataJSON: Array.from(new Uint8Array(credential.response.clientDataJSON)),
          signature: Array.from(new Uint8Array(credential.response.signature))
        }
      }, [...challenge])
      assert.equal(assertion.id, credentialId)
      const clientDataJSON = Buffer.from(assertion.clientDataJSON)
      const clientData = JSON.parse(clientDataJSON.toString())
      assert.equal(clientData.type, 'webauthn.get')
      assert.equal(clientData.challenge, challenge.toString('base64url'))
      assert.equal(clientData.origin, origin)
      const authData = Buffer.from(assertion.authenticatorData)
      assert.deepEqual(authData.subarray(0, 32), crypto.createHash('sha256').update('localhost').digest())
      assert.equal(authData[32] & 5, 5, 'User presence and verification flags must be set')
      const signedData = Buffer.concat([authData, crypto.createHash('sha256').update(clientDataJSON).digest()])
      assert.equal(crypto.verify('sha256', signedData, publicKey, Buffer.from(assertion.signature)), true)
      await session.close()
      assert.ok(manager.getPasskey(alpha.id)[0].signCount > before)
      assert.equal(await (async () => {
        const state = JSON.parse(fs.readFileSync(manager.getStorageStatePath(alpha.id), 'utf8'))
        return state.cookies.some(c => c.name === 'alpha_cookie')
      })(), true)
    }
  })

  await t.test('another account cannot access Alpha credentials, cookies or localStorage', async () => {
    const session = await open(beta.id)
    await session.page.goto(origin)
    assert.deepEqual(await session.authenticator.getCredentials(), [])
    assert.equal((await session.context.cookies()).some(c => c.name === 'alpha_cookie'), false)
    assert.equal(await session.page.evaluate(() => localStorage.getItem('isolation')), null)
    const result = await session.page.evaluate(async () => {
      try {
        await navigator.credentials.get({ publicKey: { challenge: crypto.getRandomValues(new Uint8Array(32)), rpId: 'localhost', timeout: 1000 }, signal: AbortSignal.timeout(1500) })
        return 'unexpected success'
      } catch (err) { return err.name }
    })
    assert.ok(['NotAllowedError', 'TimeoutError', 'AbortError'].includes(result))
    await session.close()
  })

  await t.test('fresh persistent profiles restore imported cookies and localStorage', async () => {
    const account = manager.createAccount({ email: 'imported@example.com' })
    writeJson(manager.getStorageStatePath(account.id), {
      cookies: [{ name: 'imported_cookie', value: 'restored', domain: 'localhost', path: '/', expires: -1, httpOnly: false, secure: false, sameSite: 'Lax' }],
      origins: [{ origin, localStorage: [{ name: 'imported_state', value: 'restored' }] }]
    })
    const session = await open(account.id)
    await session.page.goto(origin)
    assert.equal(await session.page.evaluate(() => localStorage.getItem('imported_state')), 'restored')
    assert.ok((await session.context.cookies()).some(c => c.name === 'imported_cookie'))
    await session.close()
  })

  await t.test('invalid key injection fails closed and releases the browser/profile lock', async () => {
    const account = manager.createAccount({ email: 'broken@example.com' })
    manager.savePasskey(account.id, [{ credentialId: 'aWQ=', privateKey: 'invalid', rpId: 'localhost' }])
    await assert.rejects(open(account.id))
    assert.equal(launcher.isActive(account.id), false)
    const session = await open(account.id, { injectSavedPasskey: false })
    await session.close()
  })

  const token = 'integration-only-token-'.repeat(3)
  dashboard = new AutoKeyServer(manager, launcher, new MicrosoftFlows(launcher, manager), { token })
  const server = await dashboard.start(0, '127.0.0.1')
  const base = `http://127.0.0.1:${server.address().port}`

  await t.test('real WebSocket streams frames, forwards keyboard text and releases sessions', async () => {
    const ws = new WebSocket(`${base.replace('http:', 'ws:')}/ws/screencast?accountId=${beta.id}&startUrl=${encodeURIComponent(origin)}`, { headers: { Authorization: `Bearer ${token}` } })
    const messages = []
    ws.on('message', raw => messages.push(JSON.parse(raw.toString())))
    t.after(() => ws.terminate())
    await once(ws, 'open')
    const wait = async predicate => {
      const deadline = Date.now() + 10000
      while (!predicate()) { if (Date.now() > deadline) throw new Error('Screencast condition timed out'); await new Promise(resolve => setTimeout(resolve, 50)) }
    }
    await wait(() => messages.some(m => m.type === 'frame') && dashboard.activeSessions.get(beta.id)?.session.page.url() === origin + '/')
    const session = dashboard.activeSessions.get(beta.id).session
    await session.page.locator('#text').focus()
    ws.send(JSON.stringify({ type: 'text', text: '中文 & keyboard' }))
    await wait(() => messages.some(m => m.type === 'frame'))
    await session.page.waitForFunction(() => document.querySelector('#text').value === '中文 & keyboard')
    ws.send(JSON.stringify({ type: 'keyboard', eventType: 'keyDown', key: 'a', code: 'KeyA', modifiers: 2, windowsVirtualKeyCode: 65 }))
    ws.send(JSON.stringify({ type: 'keyboard', eventType: 'keyUp', key: 'a', code: 'KeyA', modifiers: 2, windowsVirtualKeyCode: 65 }))
    ws.send(JSON.stringify({ type: 'text', text: 'selected and replaced' }))
    await session.page.waitForFunction(() => document.querySelector('#text').value === 'selected and replaced')
    const response = await fetch(`${base}/api/accounts/${beta.id}`, { method: 'DELETE', headers: { Authorization: `Bearer ${token}` } })
    assert.equal(response.status, 409)
    ws.close()
    await once(ws, 'close')
    await wait(() => !dashboard.activeSessions.has(beta.id))
    assert.equal(launcher.isActive(beta.id), false)
  })

  await t.test('dashboard token login, creation, duplicate errors, search and XSS escaping', async () => {
    uiBrowser = await chromium.launch({ headless: true, ...(process.platform === 'linux' && process.getuid?.() === 0 ? { args: ['--no-sandbox'] } : {}) })
    const page = await uiBrowser.newPage({ viewport: { width: 1440, height: 1000 } })
    const errors = []
    page.on('pageerror', error => errors.push(error.message))
    await page.goto(base)
    await page.locator('#auth-modal.active').waitFor()
    await page.locator('#auth-token').fill(token)
    await page.getByRole('button', { name: '连接控制台', exact: true }).click()
    await page.locator('#auth-modal.active').waitFor({ state: 'hidden' })
    await page.getByRole('button', { name: '+ 添加账号', exact: true }).click()
    await page.locator('#acc-email').fill('dashboard@example.com')
    await page.getByRole('button', { name: '创建独立沙箱', exact: true }).click()
    await page.locator('#add-account-modal.active').waitFor({ state: 'hidden' })
    await page.getByRole('button', { name: '+ 添加账号', exact: true }).click()
    await page.locator('#acc-email').fill('dashboard@example.com')
    await page.getByRole('button', { name: '创建独立沙箱', exact: true }).click()
    await page.locator('#toast').filter({ hasText: '创建失败' }).waitFor()
    assert.equal(await page.locator('#add-account-modal.active').count(), 1)
    await page.getByRole('button', { name: '取消', exact: true }).click()
    await page.locator('#search-input').fill('dashboard@')
    assert.equal(await page.locator('#accounts-table-body tr').count(), 1)
    assert.match(await page.locator('#accounts-table-body').innerText(), /dashboard@example.com/)
    // Simulate legacy imported metadata: rendering it must remain text, never executable HTML.
    const file = manager.getAccountJsonPath('dashboard@example.com')
    const meta = JSON.parse(fs.readFileSync(file, 'utf8'))
    writeJson(file, { ...meta, email: '<img src=x onerror="window.__xss=true">@example.com' })
    await page.locator('#search-input').fill('')
    await page.getByRole('button', { name: '🔄 刷新列表', exact: true }).click()
    await page.getByText('<img src=x onerror="window.__xss=true">@example.com', { exact: true }).waitFor()
    assert.equal(await page.locator('#accounts-table-body img').count(), 0)
    assert.equal(await page.evaluate(() => window.__xss), undefined)
    assert.deepEqual(errors, [])
    const artifacts = path.resolve('artifacts')
    fs.mkdirSync(artifacts, { recursive: true })
    await page.screenshot({ path: path.join(artifacts, 'dashboard-smoke.png'), fullPage: true })
    await page.close()
  })

  await t.test('device information displays real browser/system data, public fingerprints and mobile layout without exporting keys', async () => {
    const info = getAccountDeviceInfo(manager, alpha.id)
    assert.match(info.browser.product, /Chrome/)
    assert.match(info.browser.environmentFingerprint, /^SHA256:/)
    assert.equal(info.browser.viewport.width, 1280)
    assert.equal(info.system.platform, process.platform)
    assert.match(info.credentials[0].publicKeyFingerprint, /^SHA256:/)
    const page = await uiBrowser.newPage({ viewport: { width: 1440, height: 1000 } })
    const requestedUrls = []
    page.on('request', request => requestedUrls.push(new URL(request.url()).pathname))
    await page.goto(base)
    await page.locator('#auth-modal.active').waitFor()
    await page.locator('#auth-token').fill(token)
    await page.getByRole('button', { name: '连接控制台', exact: true }).click()
    const row = page.locator('#accounts-table-body tr').filter({ hasText: alpha.email })
    await row.getByRole('button', { name: '🧬 设备信息', exact: true }).click()
    const modal = page.locator('#device-info-modal')
    await modal.getByText(info.credentials[0].publicKeyFingerprint, { exact: true }).waitFor()
    assert.ok((await modal.locator('.device-modal-content').boundingBox()).width > 1000, 'Desktop panel must not inherit the narrow account form width')
    assert.ok((await modal.locator('.device-info-list dd').first().boundingBox()).width > 200, 'Device values should not wrap into a narrow column')
    assert.match(await modal.innerText(), /纯软件虚拟认证器/)
    assert.match(await modal.innerText(), /signCount/)
    assert.equal(requestedUrls.some(url => url.endsWith('/passkey')), false)
    assert.equal(await modal.locator('img, script').count(), 0)
    const artifacts = path.resolve('artifacts')
    await page.screenshot({ path: path.join(artifacts, 'device-info-smoke.png'), fullPage: true })
    await modal.getByRole('button', { name: '关闭面板', exact: true }).click()
    await page.getByRole('button', { name: '⚙️ 系统信息', exact: true }).click()
    await modal.getByText('服务器系统 · 当前运行环境', { exact: true }).waitFor()
    await modal.getByRole('button', { name: '关闭面板', exact: true }).click()
    const emptyRow = page.locator('#accounts-table-body tr').filter({ hasText: beta.email })
    await emptyRow.getByRole('button', { name: '🧬 设备信息', exact: true }).click()
    await modal.getByText('尚无已保存的 Passkey；完成绑定后会显示公钥指纹和 RP 域名。', { exact: true }).waitFor()
    await page.setViewportSize({ width: 390, height: 844 })
    assert.equal(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth), true)
    await page.screenshot({ path: path.join(artifacts, 'device-info-mobile.png'), fullPage: true })
    await page.close()
  })
})
