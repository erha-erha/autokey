/**
 * AutoKey - WebAuthn / Passkey Virtual Authenticator Manager
 * Uses Chrome DevTools Protocol (CDP) to emulate CTAP2/FIDO2 hardware & platform authenticators
 * directly inside Chromium on headless/remote Linux servers.
 */

export class PasskeyAuthenticator {
  /**
   * @param {import('patchright').CDPSession} client - CDP session attached to the target page/context
   * @param {object} [options]
   * @param {'internal'|'usb'|'nfc'|'ble'} [options.transport='internal'] - 'internal' simulates Windows Hello / platform passkey, 'usb' simulates physical YubiKey
   * @param {boolean} [options.autoPresence=true] - automatically sign challenges without user interaction
   */
  constructor(client, options = {}) {
    this.client = client
    this.transport = options.transport || 'internal'
    this.autoPresence = options.autoPresence !== false
    this.authenticatorId = null
    this.enabled = false
    this._listeners = {
      credentialAdded: [],
      credentialAsserted: []
    }
    this._eventHandlers = new Map()
  }

  /**
   * Initialize and attach the virtual authenticator to the browser
   */
  getDeviceInfo() {
    return {
      kind: 'cdp-virtual', protocol: 'ctap2', transport: this.transport,
      hasResidentKey: true, hasUserVerification: true, isUserVerified: true,
      automaticPresenceSimulation: this.autoPresence, hardwareBacked: false,
      authenticatorId: this.authenticatorId, aaguid: null
    }
  }

  async initialize() {
    if (this.enabled) return this.authenticatorId

    // 1. Enable the CDP WebAuthn domain
    await this.client.send('WebAuthn.enable')

    // 2. Add Virtual Authenticator
    const result = await this.client.send('WebAuthn.addVirtualAuthenticator', {
      options: {
        protocol: 'ctap2',
        transport: this.transport,
        hasResidentKey: true,
        hasUserVerification: true,
        isUserVerified: true,
        automaticPresenceSimulation: this.autoPresence
      }
    })

    this.authenticatorId = result.authenticatorId
    this.enabled = true

    // 3. Set up event hooks
    for (const name of Object.keys(this._listeners)) {
      const handler = (params) => {
        if (params.authenticatorId !== this.authenticatorId) return
        for (const listener of this._listeners[name]) {
          try { Promise.resolve(listener(params)).catch(err => console.error(`[AutoKey] ${name} listener failed:`, err.message)) }
          catch (err) { console.error(`[AutoKey] ${name} listener failed:`, err.message) }
        }
      }
      this._eventHandlers.set(`WebAuthn.${name}`, handler)
      this.client.on(`WebAuthn.${name}`, handler)
    }

    return this.authenticatorId
  }

  /**
   * Retrieve all credentials currently stored in the virtual authenticator
   * @returns {Promise<Array<object>>}
   */
  async getCredentials() {
    if (!this.enabled || !this.authenticatorId) {
      throw new Error('Authenticator not initialized')
    }
    const res = await this.client.send('WebAuthn.getCredentials', {
      authenticatorId: this.authenticatorId
    })
    return res.credentials || []
  }

  /**
   * Inject a saved passkey credential into the virtual authenticator
   * @param {object} credential
   * @param {string} credential.credentialId - Base64 encoded credential ID
   * @param {string} credential.privateKey - Base64 encoded PKCS#8 private key
   * @param {string} credential.rpId - Relying Party ID (e.g. 'live.com')
   * @param {string} [credential.userHandle] - Base64 encoded user handle
   * @param {number} [credential.signCount=0]
   * @param {boolean} [credential.isResidentCredential=true]
   */
  async addCredential(credential) {
    if (!this.enabled || !this.authenticatorId) {
      throw new Error('Authenticator not initialized')
    }

    await this.client.send('WebAuthn.addCredential', {
      authenticatorId: this.authenticatorId,
      credential: {
        credentialId: credential.credentialId,
        isResidentCredential: credential.isResidentCredential !== false,
        rpId: credential.rpId,
        privateKey: credential.privateKey,
        userHandle: credential.userHandle || '',
        signCount: credential.signCount ?? 0,
        ...(credential.backupEligibility != null ? { backupEligibility: credential.backupEligibility } : {}),
        ...(credential.backupState != null ? { backupState: credential.backupState } : {})
      }
    })
  }

  /**
   * Inject multiple credentials (e.g. For multiple domains or accounts)
   * @param {Array<object>} credentials
   */
  async addCredentials(credentials) {
    for (const cred of credentials) {
      await this.addCredential(cred)
    }
  }

  /**
   * Clear all credentials from this virtual authenticator
   */
  async clearCredentials() {
    if (!this.enabled || !this.authenticatorId) return
    await this.client.send('WebAuthn.clearCredentials', {
      authenticatorId: this.authenticatorId
    })
  }

  /**
   * Register a callback when a new passkey is registered
   */
  onCredentialAdded(cb) {
    this._listeners.credentialAdded.push(cb)
    return () => { this._listeners.credentialAdded = this._listeners.credentialAdded.filter(fn => fn !== cb) }
  }

  /**
   * Register a callback when a passkey assertion (login) occurs
   */
  onCredentialAsserted(cb) {
    this._listeners.credentialAsserted.push(cb)
    return () => { this._listeners.credentialAsserted = this._listeners.credentialAsserted.filter(fn => fn !== cb) }
  }

  /**
   * Destroy and remove the virtual authenticator
   */
  async close() {
    for (const [event, handler] of this._eventHandlers) this.client.off(event, handler)
    this._eventHandlers.clear()
    if (this.enabled && this.authenticatorId) {
      try {
        await this.client.send('WebAuthn.removeVirtualAuthenticator', {
          authenticatorId: this.authenticatorId
        })
      } catch {}
      try {
        await this.client.send('WebAuthn.disable')
      } catch {}
      this.enabled = false
      this.authenticatorId = null
    }
  }
}
