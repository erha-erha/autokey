import test from 'node:test'
import assert from 'node:assert/strict'
import { EventEmitter } from 'node:events'
import { PasskeyAuthenticator } from '../src/core/Authenticator.mjs'
import { MicrosoftFlows } from '../src/core/MicrosoftFlows.mjs'
import { ScreencastSession, validateNavigationUrl } from '../src/server/Screencast.mjs'

test('authenticator filters events by ID and removes CDP listeners on close', async () => {
  const client = new EventEmitter()
  client.send = async () => ({ authenticatorId: 'own' })
  const auth = new PasskeyAuthenticator(client)
  await auth.initialize()
  let count = 0
  const unsubscribe = auth.onCredentialAsserted(() => { count++ })
  client.emit('WebAuthn.credentialAsserted', { authenticatorId: 'other' })
  client.emit('WebAuthn.credentialAsserted', { authenticatorId: 'own' })
  assert.equal(count, 1)
  unsubscribe()
  client.emit('WebAuthn.credentialAsserted', { authenticatorId: 'own' })
  assert.equal(count, 1)
  await auth.close()
  assert.equal(client.listenerCount('WebAuthn.credentialAdded'), 0)
  await auth.initialize()
  assert.equal(client.listenerCount('WebAuthn.credentialAdded'), 1)
  await auth.close()
})

test('login confirmation rejects generic headers, spoofed hosts and the wrong account', async () => {
  const flows = new MicrosoftFlows(null, null)
  const page = (url, identities) => ({ url: () => url, locator: () => ({ allTextContents: async () => identities }) })
  for (const url of ['https://account.microsoft.com/', 'https://rewards.bing.com/']) {
    assert.equal(await flows.isLoggedIn(page(url, [])), false)
    assert.equal(await flows.isLoggedIn(page(url, ['other@example.com']), 'one@example.com'), false)
    assert.equal(await flows.isLoggedIn(page(url, ['ONE@example.com']), 'one@example.com'), true)
  }
  for (const url of ['https://account.microsoft.com.evil.example/', 'https://evil.example/?account.microsoft.com', 'https://login.live.com/', 'http://account.microsoft.com/', 'https://account.microsoft.com/auth/']) {
    assert.equal(await flows.isLoggedIn(page(url, ['one@example.com'])), false)
  }
})

test('screencast registers frame listener before starting, acknowledges dropped frames and detaches listeners', async () => {
  const client = new EventEmitter()
  const calls = []
  client.send = async (method, params) => {
    calls.push([method, params])
    if (method === 'Page.startScreencast') client.emit('Page.screencastFrame', { data: 'frame', sessionId: 1 })
  }
  const messages = []
  const ws = new EventEmitter()
  Object.assign(ws, { readyState: 1, bufferedAmount: 0, send: message => messages.push(JSON.parse(message)) })
  const auth = { onCredentialAdded: () => () => {}, onCredentialAsserted: () => () => {}, getCredentials: async () => [{ privateKey: 'secret' }] }
  const cast = new ScreencastSession(client, { url: () => 'https://example.com/' }, auth, ws, 'one')
  await cast.start()
  assert.equal(messages[0].data, 'frame')
  ws.bufferedAmount = 3 * 1024 * 1024
  client.emit('Page.screencastFrame', { data: 'drop', sessionId: 2 })
  await Promise.resolve()
  assert.equal(messages.length, 1)
  assert.ok(calls.some(([method, params]) => method === 'Page.screencastFrameAck' && params.sessionId === 2))
  await cast.handleClientMessage({ type: 'save_passkey' })
  assert.equal(messages.at(-1).credentials, undefined)
  await cast.handleClientMessage({ type: 'keyboard', eventType: 'keyDown', key: 'a', code: 'KeyA', modifiers: 2, windowsVirtualKeyCode: 65 })
  assert.equal(calls.at(-1)[1].modifiers, 2)
  await cast.handleClientMessage({ type: 'text', text: '中文输入' })
  assert.equal(calls.at(-1)[0], 'Input.insertText')
  await assert.rejects(cast.handleClientMessage({ type: 'mouse', eventType: 'mousePressed', x: -1, y: 1 }), /mouse/)
  await cast.stop()
  assert.equal(client.listenerCount('Page.screencastFrame'), 0)
  assert.equal(ws.listenerCount('message'), 0)
})

test('remote navigation allows only HTTP(S)', () => {
  assert.equal(validateNavigationUrl('https://example.com'), 'https://example.com/')
  for (const url of ['file:///etc/passwd', 'javascript:alert(1)', 'chrome://settings', 'data:text/html,x', 'https://user:pass@example.com']) assert.throws(() => validateNavigationUrl(url))
})
