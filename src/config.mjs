import path from 'node:path'
import { fileURLToPath } from 'node:url'

const __dirname = path.dirname(fileURLToPath(import.meta.url))
export const ROOT_DIR = path.resolve(__dirname, '..')

export const DATA_DIR = process.env.AUTOKEY_DATA_DIR || path.join(ROOT_DIR, 'data')
export const ACCOUNTS_DIR = path.join(DATA_DIR, 'accounts')

export const SERVER_CONFIG = {
  host: process.env.AUTOKEY_HOST || '127.0.0.1',
  port: Number(process.env.AUTOKEY_PORT || '8080'),
  token: process.env.AUTOKEY_TOKEN || ''
}

export const MICROSOFT_ENDPOINTS = {
  login: 'https://login.live.com/',
  securityManage: 'https://account.live.com/proofs/manage/additional',
  passkeyEnroll: 'https://account.live.com/interrupt/passkey/enroll',
  rewards: 'https://rewards.bing.com/',
  accountHome: 'https://account.microsoft.com/'
}

export const DEFAULT_RP_IDS = ['live.com', 'login.live.com', 'microsoft.com', 'login.microsoft.com']
