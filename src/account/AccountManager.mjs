import fs from 'node:fs'
import path from 'node:path'
import { ACCOUNTS_DIR } from '../config.mjs'
import { appError, writeJson } from '../utils/storage.mjs'
import { normalizeProxy } from '../core/proxy.mjs'

const EMAIL = /^[a-z0-9._+-]+@[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?\.[a-z]{2,}$/i

export class AccountManager {
  constructor(baseDir = ACCOUNTS_DIR) {
    fs.mkdirSync(baseDir, { recursive: true, mode: 0o700 })
    this.baseDir = fs.realpathSync(baseDir)
  }

  getDirName(idOrEmail) {
    if (typeof idOrEmail !== 'string' || !idOrEmail.trim()) throw appError('Account ID or email required')
    const value = idOrEmail.trim().toLowerCase()
    if (value.includes('@') && !EMAIL.test(value)) throw appError('Invalid email')
    const id = value.replace(/[^a-z0-9._-]/g, '_')
    if (value.length > 200 || /[\\/\x00-\x20]/.test(value) ||
        (!value.includes('@') && value !== id) || !/^[a-z0-9_][a-z0-9._-]*$/.test(id) ||
        id.endsWith('.') || /^(con|prn|aux|nul|com[1-9]|lpt[1-9])(?:\.|$)/i.test(id)) throw appError('Invalid account ID')
    return id
  }

  getAccountDir(idOrEmail) {
    const dir = path.resolve(this.baseDir, this.getDirName(idOrEmail))
    if (path.dirname(dir) !== this.baseDir) throw appError('Account path escapes data directory')
    if (fs.existsSync(dir) && fs.lstatSync(dir).isSymbolicLink()) throw appError('Account directory cannot be a symbolic link')
    if (idOrEmail.includes('@')) {
      const metaPath = path.join(dir, 'account.json')
      if (fs.existsSync(metaPath)) {
        if (fs.lstatSync(metaPath).isSymbolicLink()) throw appError('Account metadata cannot be a symbolic link')
        const meta = JSON.parse(fs.readFileSync(metaPath, 'utf8'))
        if (meta.email?.toLowerCase() !== idOrEmail.trim().toLowerCase()) throw appError('Account directory name collision', 409)
      }
    }
    return dir
  }

  accountPath(idOrEmail, name) {
    const file = path.join(this.getAccountDir(idOrEmail), name)
    if (fs.existsSync(file) && fs.lstatSync(file).isSymbolicLink()) throw appError('Account data cannot be a symbolic link')
    return file
  }

  getAccountJsonPath(id) { return this.accountPath(id, 'account.json') }
  getPasskeyJsonPath(id) { return this.accountPath(id, 'passkey.json') }
  getStorageStatePath(id) { return this.accountPath(id, 'storage_state.json') }
  getDeviceInfoPath(id) { return this.accountPath(id, 'device_info.json') }
  getProfileDir(id) {
    const dir = this.accountPath(id, 'browser_profile')
    fs.mkdirSync(dir, { recursive: true, mode: 0o700 })
    return dir
  }

  getAccount(idOrEmail) {
    const file = this.getAccountJsonPath(idOrEmail)
    if (!fs.existsSync(file)) return null
    const meta = JSON.parse(fs.readFileSync(file, 'utf8'))
    if (idOrEmail.includes('@') && meta.email?.toLowerCase() !== idOrEmail.trim().toLowerCase()) {
      throw appError('Account directory name collision; refusing to access another account', 409)
    }
    let passkeyCount = 0
    let passkeyError = false
    try { passkeyCount = this.getPasskey(idOrEmail).length } catch { passkeyError = true }
    return {
      ...meta, id: this.getDirName(idOrEmail), hasPasskey: passkeyCount > 0,
      passkeyCount, passkeyError, hasSession: fs.existsSync(this.getStorageStatePath(idOrEmail))
    }
  }

  listAccounts() {
    return fs.readdirSync(this.baseDir, { withFileTypes: true })
      .filter(d => d.isDirectory() && !d.isSymbolicLink())
      .flatMap(d => {
        try { const account = this.getAccount(d.name); return account ? [account] : [] } catch { return [] }
      })
  }

  createAccount({ email, displayName, password, proxy } = {}) {
    if (typeof email !== 'string' || !EMAIL.test(email.trim()) || email.trim().length > 200) throw appError('Valid email is required')
    email = email.trim().toLowerCase()
    if (displayName != null && (typeof displayName !== 'string' || displayName.length > 200)) throw appError('Invalid display name')
    if (password != null && typeof password !== 'string') throw appError('Invalid password')
    if (proxy) normalizeProxy(proxy)
    const dir = this.getAccountDir(email)
    if (fs.existsSync(dir)) throw appError('Account already exists or its directory name collides with another account', 409)
    fs.mkdirSync(dir, { mode: 0o700 })
    const meta = {
      id: this.getDirName(email), email, displayName: displayName || email.split('@')[0],
      proxy: proxy || null, createdAt: new Date().toISOString(), lastLoginAt: null, status: 'initialized'
    }
    if (password) meta.password = password
    writeJson(this.getAccountJsonPath(email), meta)
    this.getProfileDir(email)
    return this.getAccount(email)
  }

  updateAccount(id, updates) {
    const account = this.getAccount(id)
    if (!account) throw appError('Account not found', 404)
    const { hasPasskey, passkeyCount, passkeyError, hasSession, ...meta } = account
    const updated = { ...meta, ...updates, id: meta.id, email: meta.email, updatedAt: new Date().toISOString() }
    writeJson(this.getAccountJsonPath(id), updated)
    return this.getAccount(id)
  }

  savePasskey(id, credentials, { enrolled = true } = {}) {
    if (!this.getAccount(id)) throw appError('Account not found', 404)
    const list = Array.isArray(credentials) ? credentials : [credentials]
    this.validateCredentials(list)
    writeJson(this.getPasskeyJsonPath(id), list)
    if (enrolled && list.length) this.updateAccount(id, { status: 'passkey_enrolled', lastEnrolledAt: new Date().toISOString() })
    return list
  }

  validateCredentials(list) {
    if (!Array.isArray(list) || list.some(c => !c || typeof c.credentialId !== 'string' || !c.credentialId ||
        typeof c.privateKey !== 'string' || !c.privateKey || typeof c.rpId !== 'string' || !c.rpId ||
        (c.signCount != null && (!Number.isInteger(c.signCount) || c.signCount < 0)))) throw appError('Invalid passkey credentials')
  }

  getPasskey(id) {
    const file = this.getPasskeyJsonPath(id)
    if (!fs.existsSync(file)) return []
    const data = JSON.parse(fs.readFileSync(file, 'utf8'))
    const list = Array.isArray(data) ? data : (Array.isArray(data?.credentials) ? data.credentials : [data])
    this.validateCredentials(list)
    return list
  }

  deleteAccount(id) {
    if (!this.getAccount(id)) return false
    if (fs.existsSync(this.accountPath(id, '.session.lock'))) throw appError('Account browser is locked by a running or interrupted session', 409)
    const dir = this.getAccountDir(id)
    if (path.dirname(dir) !== this.baseDir) throw appError('Unsafe delete target')
    fs.rmSync(dir, { recursive: true, force: true })
    return true
  }

  importFromMrs(mrsDir) {
    if (typeof mrsDir !== 'string' || !mrsDir.trim()) throw appError('Import directory required')
    const accountsDir = path.join(mrsDir, 'runtime', 'accounts')
    if (!fs.existsSync(accountsDir)) throw appError('Import accounts directory not found', 404)
    let imported = 0
    let skipped = 0
    const errors = []
    for (const ent of fs.readdirSync(accountsDir, { withFileTypes: true })) {
      if (!ent.isDirectory() || ent.isSymbolicLink()) continue
      try {
        const raw = ent.name.replace(/-[a-f0-9]{6,}$/i, '')
        const at = raw.lastIndexOf('_')
        const email = raw.includes('@') ? raw : `${raw.slice(0, at)}@${raw.slice(at + 1)}`
        const existing = this.getAccount(email)
        if (!existing) this.createAccount({ email })
        const src = path.join(accountsDir, ent.name, 'browser-profile', 'storage_state.desktop.json')
        const dest = this.getStorageStatePath(email)
        if (fs.existsSync(src) && !fs.existsSync(dest)) writeJson(dest, JSON.parse(fs.readFileSync(src, 'utf8')))
        if (existing) skipped++
        else imported++
      } catch (err) { errors.push({ directory: ent.name, error: err.message }) }
    }
    return { imported, skipped, errors }
  }
}
