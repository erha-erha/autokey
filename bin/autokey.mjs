#!/usr/bin/env node
import { AccountManager } from '../src/account/AccountManager.mjs'
import { BrowserLauncher } from '../src/core/BrowserLauncher.mjs'
import { MicrosoftFlows } from '../src/core/MicrosoftFlows.mjs'
import { AutoKeyServer } from '../src/server/Server.mjs'
import { SERVER_CONFIG } from '../src/config.mjs'

const accountManager = new AccountManager()
const launcher = new BrowserLauncher(accountManager)
const flows = new MicrosoftFlows(launcher, accountManager)

const args = process.argv.slice(2)
const command = args[0] || 'help'

async function main() {
  switch (command) {
    case 'serve':
    case 'server': {
      let port = SERVER_CONFIG.port
      let host = SERVER_CONFIG.host
      for (let i = 1; i < args.length; i++) {
        if (args[i] === '--port' || args[i] === '-p') port = parseInt(args[++i], 10)
        if (args[i] === '--host' || args[i] === '-h') host = args[++i]
      }
      const server = new AutoKeyServer(accountManager, launcher, flows)
      await server.start(port, host)
      const shutdown = () => server.stop().then(() => { process.exitCode = 0 }).catch(err => { console.error(err.message); process.exitCode = 1 })
      process.once('SIGINT', shutdown)
      process.once('SIGTERM', shutdown)
      break
    }

    case 'list':
    case 'ls': {
      const list = accountManager.listAccounts()
      console.log(`\n=== AutoKey 账号列表 (${list.length} 个) ===\n`)
      if (list.length === 0) {
        console.log('暂无账号。使用 `autokey add <email>` 创建新账号。')
      } else {
        for (const a of list) {
          const pk = a.hasPasskey ? `\x1b[32m[Passkey 已绑定 (${a.passkeyCount})]\x1b[0m` : '\x1b[33m[无 Passkey]\x1b[0m'
          const sess = a.hasSession ? '\x1b[36m[本地会话文件，未验证]\x1b[0m' : '\x1b[90m[无会话]\x1b[0m'
          const proxy = a.proxy ? '已配置独立代理' : '直连'
          console.log(`• ${a.email} (${a.id}) - ${pk} ${sess} - ${proxy}`)
        }
      }
      console.log('')
      break
    }

    case 'add': {
      const email = args[1]
      if (!email) {
        console.error('错误: 请指定账号邮箱。例如: autokey add test@example.com')
        process.exit(1)
      }
      let proxy = null
      let name = null
      for (let i = 2; i < args.length; i++) {
        if (args[i] === '--proxy') proxy = args[++i]
        if (args[i] === '--name') name = args[++i]
      }
      const acc = accountManager.createAccount({ email, displayName: name, proxy })
      console.log(`\x1b[32m[AutoKey] 账号沙箱创建成功!\x1b[0m 目录: data/accounts/${acc.id}`)
      break
    }

    case 'login': {
      const email = args[1]
      if (!email) {
        console.error('错误: 请指定账号邮箱。例如: autokey login test@example.com')
        process.exit(1)
      }
      console.log(`[AutoKey] 正在对 ${email} 执行 Passkey 静默无感登录...`)
      const res = await flows.loginWithPasskey(email, { headless: true })
      if (res.success) {
        console.log(`\x1b[32m[AutoKey] 登录成功!\x1b[0m 会话已落盘至 data/accounts/${accountManager.getDirName(email)}/storage_state.json`)
      } else {
        console.error(`\x1b[31m[AutoKey] 登录失败: ${res.error || '未能确认登录态'}\x1b[0m`)
        process.exit(1)
      }
      break
    }

    case 'check': {
      const email = args[1]
      if (!email) {
        console.error('错误: 请指定账号邮箱。例如: autokey check test@example.com')
        process.exit(1)
      }
      console.log(`[AutoKey] 正在检测 ${email} 会话有效性...`)
      const res = await flows.checkSession(email)
      if (res.valid) {
        console.log(`\x1b[32m[AutoKey] 会话有效! 当前页面: ${res.url}\x1b[0m`)
      } else {
        console.log(`\x1b[33m[AutoKey] 会话失效或需重新登录: ${res.url}\x1b[0m`)
      }
      break
    }

    case 'export': {
      const email = args[1]
      if (!email) {
        console.error('错误: 请指定账号邮箱。例如: autokey export test@example.com')
        process.exit(1)
      }
      const pk = accountManager.getPasskey(email)
      console.log(JSON.stringify(pk, null, 2))
      break
    }

    case 'import-mrs': {
      const dir = args[1] || '/opt/microsoft-rewards-script'
      console.log(`[AutoKey] 从 ${dir} 扫描并同步账号...`)
      const res = accountManager.importFromMrs(dir)
      if (res.errors.length) { console.error(res.errors); process.exitCode = 1 }
      console.log(`\x1b[32m[AutoKey] 同步完成! 共导入 ${res.imported} 个账号。\x1b[0m`)
      break
    }

    case 'help':
    default: {
      console.log(`
=== AutoKey - 微软软件密钥 & Passkey 隔离认证管理器 ===

常用命令:
  autokey serve [-p 8080] [-h 127.0.0.1] 启动 Web 控制台与远程交互服务器
  autokey list                           查看所有账号及其 Passkey/会话状态
  autokey add <email> [--proxy <url>]    新建独立账号沙箱目录
  autokey login <email>                  使用已绑定的 Passkey 执行一键静默登录
  autokey check <email>                  探活账号当前 Cookie 会话有效性
  autokey export <email>                 导出账号的 Passkey 密钥 JSON
  autokey import-mrs [path]              从 microsoft-rewards-script 批量同步账号
      `)
      break
    }
  }
}

main().catch(err => {
  console.error('[AutoKey Fatal Error]', err)
  process.exit(1)
})
