import test from 'node:test'
import assert from 'node:assert/strict'
import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'
import crypto from 'node:crypto'
import { AccountManager } from '../src/account/AccountManager.mjs'
import { getAccountDeviceInfo, getSystemInfo } from '../src/core/DeviceInfo.mjs'
import { writeJson } from '../src/utils/storage.mjs'

function fixture(t) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'autokey-device-'))
  t.after(() => fs.rmSync(root, { recursive: true, force: true }))
  const manager = new AccountManager(root)
  manager.createAccount({ email: 'device@example.com', password: 'never-expose-password', proxy: 'http://user:never-expose-proxy@proxy.example:8080' })
  return manager
}

test('device metadata is read-only and distinguishes default configuration from observed hardware', t => {
  const manager = fixture(t)
  const before = fs.readdirSync(manager.getAccountDir('device@example.com'))
  const info = getAccountDeviceInfo(manager, 'device@example.com')
  assert.equal(info.authenticator.kind, 'cdp-virtual')
  assert.equal(info.authenticator.hardwareBacked, false)
  assert.equal(info.authenticator.aaguid, null)
  assert.equal(info.authenticator.source, 'configured')
  assert.equal(info.browser, null)
  assert.deepEqual(info.credentials, [])
  assert.deepEqual(fs.readdirSync(manager.getAccountDir('device@example.com')), before)
  assert.throws(() => getAccountDeviceInfo(manager, 'missing'), { statusCode: 404 })
})

test('public-key fingerprint is SHA-256 of SPKI and does not expose private data', t => {
  const manager = fixture(t)
  const { privateKey, publicKey } = crypto.generateKeyPairSync('ec', { namedCurve: 'prime256v1' })
  const encoded = privateKey.export({ type: 'pkcs8', format: 'der' }).toString('base64')
  manager.savePasskey('device@example.com', [{ credentialId: 'Y3JlZGVudGlhbA==', privateKey: encoded, rpId: 'live.com', signCount: 42, isResidentCredential: true }])
  const info = getAccountDeviceInfo(manager, 'device@example.com')
  assert.equal(info.credentials[0].publicKeyFingerprint, 'SHA256:' + crypto.createHash('sha256').update(publicKey.export({ type: 'spki', format: 'der' })).digest('base64url'))
  assert.equal(info.credentials[0].signCount, 42)
  assert.equal(info.credentials[0].rpId, 'live.com')
  assert.equal(info.credentials[0].keyType, 'ec')
  const json = JSON.stringify(info)
  assert.equal(json.includes(encoded), false)
  assert.doesNotMatch(json, /privateKey|never-expose-password|never-expose-proxy/)
})

test('historical snapshots use an allowlist and malformed key/cache files remain inspectable', t => {
  const manager = fixture(t)
  writeJson(manager.getDeviceInfoPath('device@example.com'), {
    capturedAt: '2026-10-25T00:00:00.000Z', password: 'cache-secret',
    browser: { product: 'Chrome/test', userAgent: { privateKey: 'nested-secret' }, privateKey: 'cache-private-key', viewport: { width: 1280, privateKey: 'nested-secret' } },
    authenticator: { protocol: { privateKey: 'nested-secret' }, transport: 'usb', hardwareBacked: true, privateKey: 'auth-secret' }
  })
  const info = getAccountDeviceInfo(manager, 'device@example.com', { busy: true })
  assert.equal(info.authenticator.transport, 'usb')
  assert.equal(info.authenticator.hardwareBacked, false)
  assert.equal(info.authenticator.source, 'observed')
  assert.equal(info.browser.product, 'Chrome/test')
  assert.equal(info.busy, true)
  assert.doesNotMatch(JSON.stringify(info), /cache-secret|cache-private-key|auth-secret|nested-secret|privateKey/)
  fs.writeFileSync(manager.getDeviceInfoPath('device@example.com'), '{broken')
  fs.writeFileSync(manager.getPasskeyJsonPath('device@example.com'), '{broken')
  const corrupted = getAccountDeviceInfo(manager, 'device@example.com')
  assert.ok(corrupted.snapshotError)
  assert.ok(corrupted.credentialsError)
  assert.deepEqual(corrupted.credentials, [])
})

test('system metadata reports the service host rather than inventing a Windows Hello device', () => {
  const system = getSystemInfo()
  assert.equal(system.platform, process.platform)
  assert.equal(system.architecture, process.arch)
  assert.equal(system.nodeVersion, process.version)
  assert.ok(system.logicalCpus > 0)
  assert.ok(system.totalMemoryBytes > 0)
})
