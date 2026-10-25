import { appError } from '../utils/storage.mjs'

export function validateNavigationUrl(value) {
  let url
  try { url = new URL(value) } catch { throw appError('Invalid navigation URL') }
  if (!['https:', 'http:'].includes(url.protocol) || url.username || url.password) throw appError('Only HTTP(S) navigation is allowed')
  return url.href
}

export class ScreencastSession {
  constructor(client, page, authenticator, ws, accountId) {
    Object.assign(this, { client, page, authenticator, ws, accountId })
    this.active = false
    this.unsubscribers = []
    this.queue = Promise.resolve()
  }

  send(message) {
    if (this.ws.readyState === 1) this.ws.send(JSON.stringify(message))
  }

  async start() {
    this.active = true
    this.onFrame = async ({ data, sessionId }) => {
      try {
        // Dropping a frame is preferable to unbounded memory growth on a slow link.
        if (this.active && this.ws.bufferedAmount < 2 * 1024 * 1024) this.send({ type: 'frame', data, url: this.page.url() })
      } finally {
        await this.client.send('Page.screencastFrameAck', { sessionId }).catch(() => {})
      }
    }
    this.onMessage = raw => {
      this.queue = this.queue.then(async () => {
        if (!this.active) return
        const message = JSON.parse(raw.toString())
        await this.handleClientMessage(message)
      }).catch(err => this.send({ type: 'error', error: err.message }))
    }
    this.client.on('Page.screencastFrame', this.onFrame)
    this.ws.on('message', this.onMessage)
    for (const [subscribe, action] of [['onCredentialAdded', 'created'], ['onCredentialAsserted', 'asserted']]) {
      this.unsubscribers.push(this.authenticator[subscribe](() => this.send({
        type: 'passkey_event', action,
        message: action === 'created' ? '已生成本地 Passkey，请继续完成微软页面确认。' : 'Passkey 已签名，登录结果需由微软页面确认。'
      })))
    }
    // Register the frame handler before requesting frames (the first frame may arrive immediately).
    await this.client.send('Page.startScreencast', { format: 'jpeg', quality: 75, maxWidth: 1280, maxHeight: 800, everyNthFrame: 1 })
  }

  async handleClientMessage(msg) {
    if (!msg || typeof msg !== 'object') throw appError('Invalid input message')
    switch (msg.type) {
      case 'mouse': {
        const { eventType, x, y, button = 'none', clickCount = 1, deltaX = 0, deltaY = 0, modifiers = 0 } = msg
        if (!['mousePressed', 'mouseReleased', 'mouseMoved', 'mouseWheel'].includes(eventType) ||
            ![x, y, deltaX, deltaY].every(Number.isFinite) || x < 0 || y < 0 || x > 1280 || y > 800 ||
            !['none', 'left', 'middle', 'right'].includes(button) || !Number.isInteger(clickCount) || clickCount < 0 || clickCount > 3 ||
            !Number.isInteger(modifiers) || modifiers < 0 || modifiers > 15) throw appError('Invalid mouse event')
        await this.client.send('Input.dispatchMouseEvent', {
          type: eventType, x: Math.round(x), y: Math.round(y), modifiers,
          ...(eventType === 'mouseWheel' ? { deltaX, deltaY } : { button, clickCount })
        })
        break
      }
      case 'keyboard': {
        const { eventType, key, code, text, modifiers = 0, windowsVirtualKeyCode } = msg
        if (!['keyDown', 'keyUp', 'char'].includes(eventType) || typeof key !== 'string' || key.length > 100 ||
            typeof code !== 'string' || code.length > 100 || (text != null && (typeof text !== 'string' || text.length > 100)) ||
            !Number.isInteger(modifiers) || modifiers < 0 || modifiers > 15 ||
            (windowsVirtualKeyCode != null && (!Number.isInteger(windowsVirtualKeyCode) || windowsVirtualKeyCode < 0 || windowsVirtualKeyCode > 255))) throw appError('Invalid keyboard event')
        await this.client.send('Input.dispatchKeyEvent', { type: eventType, key, code, text, modifiers, windowsVirtualKeyCode })
        break
      }
      case 'text': {
        if (typeof msg.text !== 'string' || msg.text.length > 16000) throw appError('Invalid text input')
        await this.client.send('Input.insertText', { text: msg.text })
        break
      }
      case 'navigate':
        await this.page.goto(validateNavigationUrl(msg.url), { waitUntil: 'domcontentloaded', timeout: 30000 })
        break
      case 'save_passkey': {
        const credentials = await this.authenticator.getCredentials()
        this.send({ type: 'credentials_status', count: credentials.length }) // never stream private keys with the video
        break
      }
      default: throw appError('Unsupported input message')
    }
  }

  async stop() {
    this.active = false
    this.client.off('Page.screencastFrame', this.onFrame)
    this.ws.off('message', this.onMessage)
    for (const unsubscribe of this.unsubscribers) unsubscribe()
    this.unsubscribers = []
    await this.client.send('Page.stopScreencast').catch(() => {})
  }
}
