import { MICROSOFT_ENDPOINTS } from '../config.mjs'
import { appError } from '../utils/storage.mjs'

export class MicrosoftFlows {
  constructor(launcher, accountManager) { Object.assign(this, { launcher, accountManager }) }

  async isLoggedIn(page, expectedEmail) {
    let url
    try { url = new URL(page.url()) } catch { return false }
    if (url.protocol !== 'https:' || !['account.microsoft.com', 'rewards.bing.com'].includes(url.hostname) ||
        /\/(login|signin|auth|interrupt)(\/|$)/i.test(url.pathname)) return false
    // Public landing pages also have headers/avatars. Require an actual signed-in identity,
    // and verify it belongs to the requested sandbox rather than trusting the destination URL.
    const identities = await page.locator('#mectrl_currentAccount_primary, #mectrl_currentAccount_secondary, [data-testid="account-email"]').allTextContents().catch(() => [])
    const emails = identities.flatMap(text => text.toLowerCase().match(/[a-z0-9._+-]+@[a-z0-9.-]+\.[a-z]{2,}/g) || [])
    return expectedEmail ? emails.includes(expectedEmail.toLowerCase()) : emails.length > 0
  }

  async loginWithPasskey(id, options = {}) {
    const account = this.accountManager.getAccount(id)
    if (!account) throw appError('Account not found', 404)
    if (!this.accountManager.getPasskey(id).length) throw appError('No enrolled Passkey; register one first')
    const timeout = options.timeout ?? 45000
    if (!Number.isFinite(timeout) || timeout <= 0) throw appError('Invalid login timeout')
    const target = new URL(options.targetUrl || MICROSOFT_ENDPOINTS.accountHome)
    if (target.protocol !== 'https:' || !['account.microsoft.com', 'rewards.bing.com'].includes(target.hostname)) throw appError('Unsupported login target')
    const deadline = Date.now() + timeout
    const remaining = () => Math.max(1, deadline - Date.now())
    const session = await this.launcher.launchAccountSession(id, { headless: options.headless !== false, injectSavedPasskey: true })
    const { page } = session
    let asserted = false
    const unsubscribe = session.authenticator.onCredentialAsserted(() => { asserted = true })
    try {
      await page.goto(target.href, { waitUntil: 'domcontentloaded', timeout: Math.min(30000, remaining()) })
      let usernameEntered = false
      let signInClicked = false
      const clickedOptions = new Set()
      while (Date.now() < deadline) {
        if (await this.isLoggedIn(page, account.email)) {
          this.accountManager.updateAccount(id, { status: 'logged_in', lastLoginAt: new Date().toISOString() })
          return { success: true, alreadyLoggedIn: !asserted, method: asserted ? 'passkey' : 'existing_session' }
        }
        const host = new URL(page.url()).hostname
        if (['account.microsoft.com', 'rewards.bing.com'].includes(host) && !signInClicked) {
          const signIn = page.getByRole('link', { name: /^(sign in|登录)$/i }).first()
          if (await signIn.isVisible().catch(() => false)) {
            signInClicked = true
            await signIn.click({ timeout: Math.min(3000, remaining()) })
          }
        }
        if (['login.live.com', 'login.microsoftonline.com'].includes(host)) {
          const username = page.locator('input[type="email"], input[name="loginfmt"]').first()
          if (!usernameEntered && await username.isVisible().catch(() => false)) {
            usernameEntered = true
            await username.fill(account.email, { timeout: Math.min(3000, remaining()) })
            await page.locator('#idSIButton9, button[type="submit"], input[type="submit"]').first().click({ timeout: Math.min(3000, remaining()) })
          } else {
            for (const [name, selector] of [
              ['picker', '#idA_PWD_SwitchToCredPicker, #signInAnotherWay'],
              ['passkey', 'button:has-text("Face, fingerprint, PIN, or security key"), button:has-text("Windows Hello"), button:has-text("Passkey"), button:has-text("通行密钥"), [role="button"]:has-text("security key")']
            ]) {
              const option = page.locator(selector).first()
              if (!clickedOptions.has(name) && await option.isVisible().catch(() => false)) {
                clickedOptions.add(name)
                await option.click({ timeout: Math.min(3000, remaining()) })
                break
              }
            }
            // #idSIButton9 is also the password submit button. Only click it on a real KMSI screen.
            if (await page.getByText(/Stay signed in\?|保持登录状态|是否保持登录/i).first().isVisible().catch(() => false)) {
              await page.locator('#idSIButton9').click({ timeout: Math.min(3000, remaining()) })
            }
          }
        }
        await page.waitForTimeout(Math.min(250, remaining()))
      }
      return { success: false, url: page.url(), error: 'Login not confirmed for this account; complete additional verification in the remote browser' }
    } catch (err) {
      return { success: false, url: page.url(), error: err.message }
    } finally {
      unsubscribe()
      await session.close()
    }
  }

  async checkSession(id) {
    const account = this.accountManager.getAccount(id)
    if (!account) throw appError('Account not found', 404)
    const session = await this.launcher.launchAccountSession(id, { headless: true, injectSavedPasskey: true })
    try {
      await session.page.goto(MICROSOFT_ENDPOINTS.accountHome, { waitUntil: 'domcontentloaded', timeout: 30000 })
      const deadline = Date.now() + 5000
      do {
        if (await this.isLoggedIn(session.page, account.email)) return { valid: true, url: session.page.url() }
        await session.page.waitForTimeout(250)
      } while (Date.now() < deadline)
      return { valid: false, url: session.page.url() }
    } catch (err) { return { valid: false, error: err.message } }
    finally { await session.close() }
  }
}
