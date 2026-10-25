import fs from 'node:fs'
import os from 'node:os'
import crypto from 'node:crypto'
import { appError } from '../utils/storage.mjs'

const digest = value => `SHA256:${crypto.createHash('sha256').update(value).digest('base64url')}`
const text = (value, limit = 2048) => typeof value === 'string' ? value.slice(0, limit) : null
const number = value => typeof value === 'number' && Number.isFinite(value) ? value : null
const flag = (value, fallback = true) => typeof value === 'boolean' ? value : fallback

export function getSystemInfo() {
  return {
    platform: os.platform(), type: os.type(), release: os.release(), version: os.version(),
    architecture: os.arch(), nodeVersion: process.version,
    logicalCpus: os.cpus().length, totalMemoryBytes: os.totalmem()
  }
}

export async function captureBrowserInfo(client, page) {
  const version = await client.send('Browser.getVersion')
  const environment = await page.evaluate(() => ({
    userAgent: navigator.userAgent, platform: navigator.platform,
    languages: Array.from(navigator.languages), timeZone: Intl.DateTimeFormat().resolvedOptions().timeZone,
    viewport: { width: innerWidth, height: innerHeight }, devicePixelRatio,
    hardwareConcurrency: navigator.hardwareConcurrency,
    screen: { width: screen.width, height: screen.height, colorDepth: screen.colorDepth }
  }))
  const browser = { product: version.product, protocolVersion: version.protocolVersion, ...environment }
  return { ...browser, environmentFingerprint: digest(JSON.stringify(browser)) }
}

function credentialInfo(credential) {
  const result = {
    credentialFingerprint: digest(Buffer.from(credential.credentialId, 'base64')),
    rpId: credential.rpId, signCount: credential.signCount ?? 0,
    residentCredential: credential.isResidentCredential !== false,
    backupEligibility: credential.backupEligibility ?? null, backupState: credential.backupState ?? null
  }
  try {
    const privateKey = crypto.createPrivateKey({ key: Buffer.from(credential.privateKey, 'base64'), format: 'der', type: 'pkcs8' })
    const publicKey = crypto.createPublicKey(privateKey)
    return {
      ...result, publicKeyFingerprint: digest(publicKey.export({ type: 'spki', format: 'der' })),
      keyType: publicKey.asymmetricKeyType, curve: publicKey.asymmetricKeyDetails?.namedCurve || null
    }
  } catch { return { ...result, publicKeyFingerprint: null, fingerprintError: '公钥无法解析，请检查密钥备份' } }
}

export function getAccountDeviceInfo(manager, id, { busy = false, authenticator = null } = {}) {
  const account = manager.getAccount(id)
  if (!account) throw appError('Account not found', 404)
  let snapshot = null
  let snapshotError = null
  try {
    const file = manager.getDeviceInfoPath(id)
    if (fs.existsSync(file)) snapshot = JSON.parse(fs.readFileSync(file, 'utf8'))
  } catch { snapshotError = '历史设备信息损坏；下次启动浏览器时会重新采集' }
  let credentials = []
  let credentialsError = null
  try { credentials = manager.getPasskey(id).map(credentialInfo) }
  catch { credentialsError = '本地 Passkey 文件损坏，请恢复备份' }
  const observed = authenticator || snapshot?.authenticator
  // Whitelist every field: a historical JSON file must never become a secret export endpoint.
  const cached = snapshot?.browser
  const browser = cached && typeof cached === 'object' ? {
    product: text(cached.product), protocolVersion: text(cached.protocolVersion), userAgent: text(cached.userAgent),
    platform: text(cached.platform), timeZone: text(cached.timeZone),
    languages: Array.isArray(cached.languages) ? cached.languages.slice(0, 10).map(value => text(value, 100)).filter(Boolean) : [],
    viewport: { width: number(cached.viewport?.width), height: number(cached.viewport?.height) },
    screen: { width: number(cached.screen?.width), height: number(cached.screen?.height), colorDepth: number(cached.screen?.colorDepth) },
    devicePixelRatio: number(cached.devicePixelRatio), hardwareConcurrency: number(cached.hardwareConcurrency),
    environmentFingerprint: text(cached.environmentFingerprint, 128)
  } : null
  return {
    accountId: account.id, busy: busy === true, capturedAt: text(snapshot?.capturedAt, 100), snapshotError,
    system: getSystemInfo(), browser, credentials, credentialsError,
    authenticator: {
      kind: 'cdp-virtual', source: observed ? 'observed' : 'configured',
      protocol: 'ctap2', transport: ['internal', 'usb', 'nfc', 'ble', 'cable'].includes(observed?.transport) ? observed.transport : 'internal',
      hasResidentKey: flag(observed?.hasResidentKey), hasUserVerification: flag(observed?.hasUserVerification),
      isUserVerified: flag(observed?.isUserVerified), automaticPresenceSimulation: flag(observed?.automaticPresenceSimulation),
      hardwareBacked: false, authenticatorId: text(observed?.authenticatorId, 100), aaguid: null
    }
  }
}
