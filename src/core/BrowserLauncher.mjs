import fs from 'node:fs'
import path from 'node:path'
import crypto from 'node:crypto'
import { chromium } from 'patchright'
import { PasskeyAuthenticator } from './Authenticator.mjs'
import { normalizeProxy } from './proxy.mjs'
import { appError, writeJson } from '../utils/storage.mjs'
import { captureBrowserInfo } from './DeviceInfo.mjs'

const activeProfiles = new Set()

export class BrowserLauncher {
  constructor(accountManager) { this.accountManager = accountManager }

  isActive(id) {
    return activeProfiles.has(this.accountManager.getAccountDir(id)) || fs.existsSync(this.accountManager.accountPath(id, '.session.lock'))
  }

  async launchAccountSession(id, options = {}) {
    const account = this.accountManager.getAccount(id)
    if (!account) throw appError('Account not found', 404)
    const accountDir = this.accountManager.getAccountDir(id)
    if (activeProfiles.has(accountDir)) throw appError('Account browser is busy; close the existing session first', 409)
    activeProfiles.add(accountDir) // reserve before the first await (also covers a browser still starting)
    let context
    let authenticator
    let lockPath
    const lockId = crypto.randomUUID()
    let ownsLock = false
    let reserved = true
    const releaseLock = () => {
      if (reserved) { activeProfiles.delete(accountDir); reserved = false }
      if (!ownsLock) return
      try {
        if (JSON.parse(fs.readFileSync(lockPath, 'utf8')).id === lockId) fs.unlinkSync(lockPath)
      } catch (err) { if (err.code !== 'ENOENT') console.error('[AutoKey] Unable to release session lock:', err.message) }
      ownsLock = false
    }
    try {
      lockPath = this.accountManager.accountPath(id, '.session.lock')
      let fd
      try { fd = fs.openSync(lockPath, 'wx', 0o600) }
      catch (err) {
        if (err.code === 'EEXIST') throw appError('Account is locked by another process; verify its PID before removing a stale .session.lock', 409)
        throw err
      }
      ownsLock = true
      try { fs.writeFileSync(fd, JSON.stringify({ id: lockId, pid: process.pid, createdAt: new Date().toISOString() })) }
      finally { fs.closeSync(fd) }
      const profileDir = this.accountManager.getProfileDir(id)
      const storagePath = this.accountManager.getStorageStatePath(id)
      const freshProfile = !fs.existsSync(path.join(profileDir, 'Default'))
      const executablePath = options.executablePath || process.env.CHROME_PATH
      if (executablePath && !fs.existsSync(executablePath)) throw appError('Configured Chrome executable does not exist')
      const args = ['--disable-dev-shm-usage', '--window-size=1280,800', '--no-first-run']
      // Root containers cannot use Chromium's sandbox. Do not disable it for ordinary users.
      if (process.platform === 'linux' && process.getuid?.() === 0) args.push('--no-sandbox')
      context = await chromium.launchPersistentContext(profileDir, {
        headless: options.headless !== false, args, viewport: { width: 1280, height: 800 },
        locale: 'en-US', ...(executablePath ? { executablePath } : {}),
        ...(options.proxy || account.proxy ? { proxy: normalizeProxy(options.proxy || account.proxy) } : {})
      })
      const page = context.pages()[0] || await context.newPage()
      // Chromium discards session cookies between launches even in a persistent profile.
      // Restore missing session cookies, but never overwrite newer live profile cookies.
      if (fs.existsSync(storagePath)) {
        const state = JSON.parse(fs.readFileSync(storagePath, 'utf8'))
        const cookieKey = cookie => `${cookie.domain}|${cookie.path}|${cookie.name}`
        const existingCookies = new Set((await context.cookies()).map(cookieKey))
        await context.addCookies((state.cookies || []).filter(cookie =>
          !existingCookies.has(cookieKey(cookie)) && (freshProfile || cookie.expires === -1)))
        for (const origin of freshProfile ? state.origins || [] : []) {
          if (!origin.localStorage?.length) continue
          const originUrl = new URL(origin.origin)
          if (!['https:', 'http:'].includes(originUrl.protocol)) throw appError('Invalid storage state origin')
          const bootstrap = await context.newPage()
          try {
            // Fulfill locally: importing localStorage must not depend on third-party availability.
            await bootstrap.route(`${originUrl.origin}/**`, route => route.fulfill({ contentType: 'text/html', body: '<!doctype html>' }))
            await bootstrap.goto(`${originUrl.origin}/`)
            await bootstrap.evaluate(items => { for (const { name, value } of items) localStorage.setItem(name, value) }, origin.localStorage)
          } finally { await bootstrap.close() }
        }
      }
      const client = await context.newCDPSession(page)
      authenticator = new PasskeyAuthenticator(client, { transport: options.transport || 'internal', autoPresence: true })
      await authenticator.initialize()
      if (options.injectSavedPasskey !== false) await authenticator.addCredentials(this.accountManager.getPasskey(id))
      writeJson(this.accountManager.getDeviceInfoPath(id), {
        capturedAt: new Date().toISOString(), authenticator: authenticator.getDeviceInfo(),
        browser: await captureBrowserInfo(client, page)
      })

      let pendingSave = Promise.resolve()
      let persistenceError = null
      const saveCredentials = async (enrolled = false) => {
        const credentials = await authenticator.getCredentials()
        if (!credentials.length) return
        // Never drop a saved key that wasn't injected into this session.
        const merged = new Map(this.accountManager.getPasskey(id).map(c => [c.credentialId, c]))
        for (const credential of credentials) {
          const previous = merged.get(credential.credentialId)
          merged.set(credential.credentialId, { ...credential, signCount: Math.max(previous?.signCount || 0, credential.signCount || 0) })
        }
        this.accountManager.savePasskey(id, [...merged.values()], { enrolled })
      }
      const queueSave = enrolled => {
        pendingSave = pendingSave.then(() => saveCredentials(enrolled)).catch(err => { persistenceError = err })
        return pendingSave
      }
      authenticator.onCredentialAdded(() => queueSave(true))
      authenticator.onCredentialAsserted(() => queueSave(false))
      let closing
      const close = () => {
        if (closing) return closing
        closing = (async () => {
          try {
            await pendingSave
            if (!page.isClosed()) {
              await saveCredentials(false)
              writeJson(storagePath, await context.storageState())
            }
            if (persistenceError) throw persistenceError
          } finally {
            try { await authenticator.close() }
            finally {
              try { await context.close() }
              finally { releaseLock() }
            }
          }
        })()
        return closing
      }
      context.on('close', releaseLock)
      return { context, page, client, authenticator, close, flushCredentials: async () => {
        await queueSave(false)
        if (persistenceError) throw persistenceError
      } }
    } catch (err) {
      try { await authenticator?.close() } catch {}
      try { await context?.close() } catch {}
      releaseLock()
      throw err
    }
  }
}
