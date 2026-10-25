import test from 'node:test'
import assert from 'node:assert/strict'
import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'
import { AccountManager } from '../src/account/AccountManager.mjs'
import { normalizeProxy } from '../src/core/proxy.mjs'

const credential = { credentialId: 'abc', privateKey: 'key', rpId: 'localhost', signCount: 0 }
function fixture(t) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'autokey-unit-'))
  t.after(() => fs.rmSync(root, { recursive: true, force: true }))
  return new AccountManager(path.join(root, 'accounts'))
}

test('rejects unsafe account paths before reading or recursively deleting', t => {
  const manager = fixture(t)
  manager.createAccount({ email: 'safe@example.com' })
  for (const id of ['.', '..', '../accounts', '..\\accounts', '/tmp', 'C:\\tmp', '%2e%2e', 'con', 'x.', 1, {}]) {
    assert.throws(() => manager.getAccountDir(id))
    assert.throws(() => manager.deleteAccount(id))
  }
  assert.equal(manager.listAccounts().length, 1)
})

test('duplicate creation never overwrites metadata and collisions never cross account boundaries', t => {
  const manager = fixture(t)
  manager.createAccount({ email: ' Alice+one@example.com ', displayName: 'Original' })
  assert.throws(() => manager.createAccount({ email: 'alice+one@example.com' }), { statusCode: 409 })
  assert.throws(() => manager.createAccount({ email: 'alice_one@example.com' }), { statusCode: 409 })
  assert.throws(() => manager.getAccount('alice_one@example.com'), { statusCode: 409 })
  assert.throws(() => manager.getPasskey('alice_one@example.com'), { statusCode: 409 })
  assert.throws(() => manager.getProfileDir('alice_one@example.com'), { statusCode: 409 })
  assert.equal(manager.getAccount('alice+one@example.com').displayName, 'Original')
})

test('validates input types and immutable account identity', t => {
  const manager = fixture(t)
  for (const email of [null, 1, {}, '..', '<img>@example.com', 'a/b@example.com', 'x@y']) assert.throws(() => manager.createAccount({ email }))
  const account = manager.createAccount({ email: 'one@example.com' })
  manager.updateAccount(account.id, { id: 'two', email: 'two@example.com', status: 'logged_in' })
  assert.equal(manager.getAccount(account.id).email, 'one@example.com')
  assert.equal(manager.getAccount(account.id).status, 'logged_in')
  assert.throws(() => manager.updateAccount('missing', {}), { statusCode: 404 })
})

test('supports legacy credential formats and does not report empty/corrupt keys as enrolled', t => {
  const manager = fixture(t)
  const account = manager.createAccount({ email: 'one@example.com' })
  const file = manager.getPasskeyJsonPath(account.id)
  for (const data of [credential, [credential], { version: 1, credentials: [credential] }]) {
    fs.writeFileSync(file, JSON.stringify(data))
    assert.deepEqual(manager.getPasskey(account.id), [credential])
    assert.equal(manager.getAccount(account.id).hasPasskey, true)
  }
  fs.writeFileSync(file, '[]')
  assert.equal(manager.getAccount(account.id).hasPasskey, false)
  fs.writeFileSync(file, '{broken')
  assert.throws(() => manager.getPasskey(account.id))
  assert.equal(manager.getAccount(account.id).passkeyError, true)
  assert.equal(manager.getAccount(account.id).hasPasskey, false)
})

test('assertion persistence preserves login status and uses restricted atomic files', t => {
  const manager = fixture(t)
  const account = manager.createAccount({ email: 'one@example.com' })
  manager.savePasskey(account.id, [credential])
  manager.updateAccount(account.id, { status: 'logged_in' })
  manager.savePasskey(account.id, [{ ...credential, signCount: 2 }], { enrolled: false })
  assert.equal(manager.getAccount(account.id).status, 'logged_in')
  assert.equal(manager.getPasskey(account.id)[0].signCount, 2)
  assert.equal(fs.readdirSync(manager.getAccountDir(account.id)).some(n => n.endsWith('.tmp')), false)
  if (process.platform !== 'win32') assert.equal(fs.statSync(manager.getPasskeyJsonPath(account.id)).mode & 0o777, 0o600)
})

test('rejects account directory symlinks/junctions', t => {
  const manager = fixture(t)
  const external = fs.mkdtempSync(path.join(os.tmpdir(), 'autokey-external-'))
  t.after(() => fs.rmSync(external, { recursive: true, force: true }))
  fs.writeFileSync(path.join(external, 'keep'), 'safe')
  fs.symlinkSync(external, path.join(manager.baseDir, 'linked'), process.platform === 'win32' ? 'junction' : 'dir')
  assert.throws(() => manager.getAccount('linked'))
  assert.throws(() => manager.deleteAccount('linked'))
  assert.equal(fs.readFileSync(path.join(external, 'keep'), 'utf8'), 'safe')
})

test('a session lock protects against deletion from a different process', t => {
  const manager = fixture(t)
  const account = manager.createAccount({ email: 'locked@example.com' })
  fs.writeFileSync(manager.accountPath(account.id, '.session.lock'), JSON.stringify({ pid: 12345 }))
  assert.throws(() => manager.deleteAccount(account.id), { statusCode: 409 })
  assert.ok(manager.getAccount(account.id))
})

test('MRS import preserves mailbox hyphens and underscores and reports real import counts', t => {
  const manager = fixture(t)
  const mrs = path.join(manager.baseDir, '..', 'mrs')
  const source = path.join(mrs, 'runtime', 'accounts', 'first-last_name_example.com-a1b2c3', 'browser-profile')
  fs.mkdirSync(source, { recursive: true })
  fs.writeFileSync(path.join(source, 'storage_state.desktop.json'), '{"cookies":[],"origins":[]}')
  assert.deepEqual(manager.importFromMrs(mrs), { imported: 1, skipped: 0, errors: [] })
  assert.equal(manager.getAccount('first-last_name@example.com').hasSession, true)
  assert.deepEqual(manager.importFromMrs(mrs), { imported: 0, skipped: 1, errors: [] })
  assert.throws(() => manager.importFromMrs(path.join(mrs, 'missing')), { statusCode: 404 })
})

test('proxy URL credentials become separate Chromium username/password fields', () => {
  assert.deepEqual(normalizeProxy('http://user:p%40ss@127.0.0.1:7890'), { server: 'http://127.0.0.1:7890', username: 'user', password: 'p@ss' })
  assert.deepEqual(normalizeProxy({ url: 'http://proxy.example', port: 3128 }), { server: 'http://proxy.example:3128' })
  assert.deepEqual(normalizeProxy('socks5://127.0.0.1:7890'), { server: 'socks5://127.0.0.1:7890' })
  for (const input of ['file:///etc/passwd', 'http://host/path', 'socks5://user:pass@host:1080', {}, 1]) assert.throws(() => normalizeProxy(input))
})
