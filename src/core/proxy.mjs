import { appError } from '../utils/storage.mjs'

export function normalizeProxy(config) {
  if (!config) return undefined
  const input = typeof config === 'string' ? { server: config } : config
  if (!input || typeof input !== 'object') throw appError('Invalid proxy configuration')
  const server = input.server || input.url
  if (typeof server !== 'string') throw appError('Proxy server is required')
  let url
  try { url = new URL(server) } catch { throw appError('Proxy must be an HTTP, HTTPS or SOCKS5 URL') }
  if (!['http:', 'https:', 'socks5:'].includes(url.protocol) || !url.hostname ||
      (url.pathname !== '/' && url.pathname !== '') || url.search || url.hash) throw appError('Invalid proxy URL')
  if (input.port && !url.port) url.port = String(input.port)
  const username = input.username ?? (url.username ? decodeURIComponent(url.username) : undefined)
  const password = input.password ?? (url.password ? decodeURIComponent(url.password) : undefined)
  if (url.protocol === 'socks5:' && (username || password)) throw appError('Chromium does not support authenticated SOCKS5 proxies')
  return { server: `${url.protocol}//${url.host}`, ...(username ? { username } : {}), ...(password ? { password } : {}) }
}
