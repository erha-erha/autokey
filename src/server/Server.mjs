import http from 'node:http'
import fs from 'node:fs'
import path from 'node:path'
import crypto from 'node:crypto'
import { fileURLToPath } from 'node:url'
import { WebSocketServer } from 'ws'
import { SERVER_CONFIG, MICROSOFT_ENDPOINTS } from '../config.mjs'
import { ScreencastSession, validateNavigationUrl } from './Screencast.mjs'
import { appError } from '../utils/storage.mjs'
import { normalizeProxy } from '../core/proxy.mjs'
import { getAccountDeviceInfo, getSystemInfo } from '../core/DeviceInfo.mjs'

const PUBLIC_DIR = path.join(path.dirname(fileURLToPath(import.meta.url)), 'public')
const STATIC_FILES = { '/': ['index.html', 'text/html'], '/index.html': ['index.html', 'text/html'], '/app.js': ['app.js', 'application/javascript'], '/style.css': ['style.css', 'text/css'] }
const LOOPBACK = new Set(['127.0.0.1', 'localhost', '::1', '[::1]'])
const sameSecret = (a, b) => typeof a === 'string' && Buffer.byteLength(a) === Buffer.byteLength(b) && crypto.timingSafeEqual(Buffer.from(a), Buffer.from(b))

function publicAccount(account) {
  const { password, proxy, ...safe } = account
  try { return { ...safe, proxy: proxy ? { server: normalizeProxy(proxy).server } : null } }
  catch { return { ...safe, proxy: { server: '代理配置无效' }, proxyError: true } }
}

export class AutoKeyServer {
  constructor(accountManager, launcher, flows, options = {}) {
    this.accountManager = accountManager
    this.launcher = launcher
    this.flows = flows
    this.token = options.token ?? SERVER_CONFIG.token
    this.cookieToken = crypto.randomBytes(32).toString('hex')
    this.activeSessions = new Map()
    this.authAttempts = new Map()
  }

  async start(port = SERVER_CONFIG.port, host = SERVER_CONFIG.host) {
    if (!Number.isInteger(port) || port < 0 || port > 65535) throw appError('Invalid server port')
    if (!LOOPBACK.has(host) && !this.token) throw appError('AUTOKEY_TOKEN is required when binding a non-loopback address')
    if (this.token && this.token.length < 32) throw appError('AUTOKEY_TOKEN must contain at least 32 characters')
    this.host = host
    const server = http.createServer((req, res) => {
      this.handleHttpRequest(req, res).catch(err => {
        if (!res.headersSent) this.sendJson(res, err.statusCode || 500, { success: false, error: err.statusCode ? err.message : 'Internal server error' })
        else res.end()
      })
    })
    this.server = server
    this.wss = new WebSocketServer({ noServer: true, maxPayload: 64 * 1024 })
    server.on('upgrade', (req, socket, head) => {
      try {
        this.validateRequest(req)
        if (!this.isAuthorized(req)) throw appError('Unauthorized', 401)
        const url = new URL(req.url, 'http://localhost')
        if (url.pathname !== '/ws/screencast') throw appError('Not found', 404)
        this.wss.handleUpgrade(req, socket, head, ws => {
          this.wss.emit('connection', ws, req)
          ws.on('error', () => {})
          this.handleScreencastWs(ws, url.searchParams.get('accountId'), url.searchParams.get('startUrl')).catch(() => ws.close(1011, 'Session failed'))
        })
      } catch (err) {
        socket.end(`HTTP/1.1 ${err.statusCode || 400} Rejected\r\nConnection: close\r\n\r\n`)
      }
    })
    this.heartbeat = setInterval(() => {
      for (const ws of this.wss.clients) {
        if (ws.isAlive === false) { ws.terminate(); continue }
        ws.isAlive = false
        ws.ping()
      }
    }, 30000)
    this.heartbeat.unref()
    this.wss.on('connection', ws => {
      ws.isAlive = true
      ws.on('pong', () => { ws.isAlive = true })
    })
    server.on('close', () => clearInterval(this.heartbeat))
    await new Promise((resolve, reject) => {
      server.once('error', reject)
      server.listen(port, host, () => { server.off('error', reject); resolve() })
    }).catch(err => { clearInterval(this.heartbeat); this.wss.close(); throw err })
    console.log(`[AutoKey] Dashboard and API running on ${host}:${server.address().port}`)
    return server
  }

  validateRequest(req) {
    let host
    try { host = new URL(`http://${req.headers.host}`).hostname } catch { throw appError('Invalid Host header') }
    if (!this.token && !LOOPBACK.has(host)) throw appError('Host not allowed', 403)
    if (req.headers['sec-fetch-site'] === 'cross-site') throw appError('Cross-site requests are forbidden', 403)
    if (req.headers.origin) {
      let origin
      try { origin = new URL(req.headers.origin) } catch { throw appError('Invalid Origin', 403) }
      if (!['http:', 'https:'].includes(origin.protocol) || origin.host !== req.headers.host) throw appError('Origin not allowed', 403)
    }
  }

  isAuthorized(req) {
    if (!this.token) return true
    const bearer = req.headers.authorization?.replace(/^Bearer /, '')
    const cookie = req.headers.cookie?.split(';').map(c => c.trim()).find(c => c.startsWith('autokey_session='))?.slice('autokey_session='.length)
    return sameSecret(bearer, this.token) || sameSecret(cookie, this.cookieToken)
  }

  async handleHttpRequest(req, res) {
    res.setHeader('Cache-Control', 'no-store')
    res.setHeader('X-Content-Type-Options', 'nosniff')
    res.setHeader('X-Frame-Options', 'DENY')
    res.setHeader('Referrer-Policy', 'no-referrer')
    this.validateRequest(req)
    const url = new URL(req.url, 'http://localhost')
    if (req.method === 'POST' && url.pathname === '/api/auth') {
      const address = req.socket.remoteAddress
      const now = Date.now()
      for (const [key, value] of this.authAttempts) if (now - value.started > 60000) this.authAttempts.delete(key)
      const attempts = this.authAttempts.get(address) || { started: now, count: 0 }
      if (++attempts.count > 10) throw appError('Too many authentication attempts; try again in one minute', 429)
      if (this.authAttempts.size < 1024 || this.authAttempts.has(address)) this.authAttempts.set(address, attempts)
      const body = await this.parseBody(req)
      if (this.token && !sameSecret(body.token, this.token)) throw appError('Invalid access token', 401)
      this.authAttempts.delete(address)
      if (this.token) res.setHeader('Set-Cookie', `autokey_session=${this.cookieToken}; HttpOnly; SameSite=Strict; Path=/; Max-Age=28800${req.socket.encrypted ? '; Secure' : ''}`)
      return this.sendJson(res, 200, { success: true })
    }
    if (url.pathname.startsWith('/api/')) {
      if (!this.isAuthorized(req)) throw appError('Access token required', 401)
      return this.handleApiRequest(req, res, url.pathname)
    }
    const entry = STATIC_FILES[url.pathname]
    if (!entry || !['GET', 'HEAD'].includes(req.method)) throw appError('Not found', 404)
    res.writeHead(200, { 'Content-Type': `${entry[1]}; charset=utf-8` })
    res.end(req.method === 'HEAD' ? undefined : fs.readFileSync(path.join(PUBLIC_DIR, entry[0])))
  }

  async parseBody(req) {
    let size = 0
    const chunks = []
    for await (const chunk of req) {
      size += chunk.length
      if (size > 64 * 1024) throw appError('Request body too large', 413)
      chunks.push(chunk)
    }
    try {
      const body = JSON.parse(Buffer.concat(chunks).toString() || '{}')
      if (!body || typeof body !== 'object' || Array.isArray(body)) throw new Error()
      return body
    } catch { throw appError('Invalid JSON object', 400) }
  }

  sendJson(res, status, data) {
    res.writeHead(status, { 'Content-Type': 'application/json; charset=utf-8' })
    res.end(JSON.stringify(data))
  }

  async handleApiRequest(req, res, pathname) {
    if (req.method === 'GET' && pathname === '/api/system-info') return this.sendJson(res, 200, { success: true, system: getSystemInfo() })
    if (pathname === '/api/accounts') {
      if (req.method === 'GET') return this.sendJson(res, 200, { success: true, accounts: this.accountManager.listAccounts().map(publicAccount) })
      if (req.method === 'POST') {
        const body = await this.parseBody(req)
        return this.sendJson(res, 201, { success: true, account: publicAccount(this.accountManager.createAccount(body)) })
      }
    }
    if (req.method === 'POST' && pathname === '/api/import-mrs') {
      const body = await this.parseBody(req)
      const result = this.accountManager.importFromMrs(body.dir || '/opt/microsoft-rewards-script')
      return this.sendJson(res, 200, { success: result.errors.length === 0, ...result })
    }
    const match = pathname.match(/^\/api\/accounts\/([^/]+)(?:\/(.*))?$/)
    if (match) {
      let id
      try { id = decodeURIComponent(match[1]) } catch { throw appError('Invalid account ID') }
      const action = match[2]
      const account = this.accountManager.getAccount(id)
      if (!account) throw appError('Account not found', 404)
      id = account.id
      if (req.method === 'GET' && !action) return this.sendJson(res, 200, { success: true, account: publicAccount(account) })
      if (req.method === 'GET' && action === 'device-info') {
        const authenticator = this.activeSessions.get(id)?.session?.authenticator.getDeviceInfo()
        return this.sendJson(res, 200, { success: true, deviceInfo: getAccountDeviceInfo(this.accountManager, id, { busy: this.launcher.isActive(id), authenticator }) })
      }
      if (req.method === 'DELETE' && !action) {
        if (this.activeSessions.has(id) || this.launcher.isActive(id)) throw appError('Close the active browser session before deleting this account', 409)
        this.accountManager.deleteAccount(id)
        return this.sendJson(res, 200, { success: true })
      }
      if (req.method === 'GET' && action === 'passkey') return this.sendJson(res, 200, { success: true, passkey: this.accountManager.getPasskey(id) })
      if (req.method === 'POST' && action === 'login') {
        const result = await this.flows.loginWithPasskey(id)
        const { cookies, ...safe } = result
        return this.sendJson(res, 200, { success: result.success === true, result: safe })
      }
      if (req.method === 'GET' && action === 'check') return this.sendJson(res, 200, { success: true, result: await this.flows.checkSession(id) })
    }
    throw appError('API endpoint not found', 404)
  }

  async handleScreencastWs(ws, accountId, customUrl) {
    let entry
    let id
    try {
      const account = this.accountManager.getAccount(accountId)
      if (!account) throw appError('Account not found', 404)
      id = account.id
      const startUrl = validateNavigationUrl(customUrl || MICROSOFT_ENDPOINTS.securityManage)
      if (this.activeSessions.has(id) || this.launcher.isActive(id)) throw appError('Account browser is busy', 409)
      entry = { ws, session: null, screencast: null, closed: false }
      entry.cleanup = async () => {
        entry.closed = true
        if (entry.closing) return entry.closing
        entry.closing = (async () => {
          if (!entry.session) {
            try { entry.session = await entry.startup }
            catch { if (this.activeSessions.get(id) === entry) this.activeSessions.delete(id); return }
          }
          try { await entry.screencast?.stop() }
          finally {
            try { await entry.session.close() }
            finally { if (this.activeSessions.get(id) === entry) this.activeSessions.delete(id) }
          }
        })()
        return entry.closing
      }
      this.activeSessions.set(id, entry)
      ws.once('close', () => { entry.cleanup().catch(err => console.error('[AutoKey] Session cleanup failed:', err.message)) })
      entry.startup = this.launcher.launchAccountSession(id, { headless: true, injectSavedPasskey: true })
      entry.session = await entry.startup
      if (entry.closed || ws.readyState !== 1) { await entry.cleanup(); return }
      entry.screencast = new ScreencastSession(entry.session.client, entry.session.page, entry.session.authenticator, ws, id)
      await entry.screencast.start()
      await entry.session.page.goto(startUrl, { waitUntil: 'domcontentloaded', timeout: 30000 })
    } catch (err) {
      if (entry) {
        await entry.cleanup().catch(() => {})
        if (this.activeSessions.get(id) === entry) this.activeSessions.delete(id)
      }
      if (ws.readyState === 1) { ws.send(JSON.stringify({ type: 'error', error: err.message })); ws.close(1008, 'Session unavailable') }
    }
  }

  async stop() {
    clearInterval(this.heartbeat)
    for (const ws of this.wss?.clients || []) ws.terminate()
    await Promise.allSettled([...this.activeSessions.values()].map(entry => entry.cleanup()))
    this.wss?.close()
    if (this.server?.listening) await new Promise(resolve => this.server.close(resolve))
  }
}
