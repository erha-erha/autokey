# AutoKey

面向远程 Linux 的微软个人账号 Passkey 管理工具。通过 Patchright / Chromium 的 CDP WebAuthn 虚拟认证器，为每个账号维护独立的凭据文件、浏览器 Profile 和代理配置，并提供远程浏览器画面与 CLI。

## 能力与边界

- 实现的是 **FIDO2 / WebAuthn 软件 Passkey**，不是 TOTP，也不是 Microsoft Authenticator 推送协议、Windows Hello for Business / NGC 或 PRT。
- CDP 虚拟认证器原本是浏览器测试能力，不等同于 TPM、实体安全密钥或经过认证的生产级密码管理器。`automaticPresenceSimulation` 会自动满足用户在场和验证条件。
- Profile / 凭据分目录可以隔离本地状态，**不能保证账号在服务端不可关联，也不能绕过风控、MFA、设备合规或认证器策略**。
- 微软可能要求补充验证。自动登录仅在可信微软页面中找到与目标账号一致的身份后报告成功；仅跳离登录页或完成本地签名不代表登录成功。
- 本地生成 Passkey 后，仍须完成微软页面的注册确认。私钥文件存在不代表微软已接受该凭据。
- 控制台的“本地会话文件”只代表快照存在，不代表会话当前有效。

## 快速开始

需要 Node.js 22+；推荐 Node.js 24 LTS。Linux 和 Windows 均可运行，远程无头使用场景以 Linux 为主。

```bash
npm ci
npx patchright install --with-deps chromium
npm start
```

默认仅监听 `127.0.0.1:8080`，打开 [本地控制台](http://127.0.0.1:8080)。Windows 安装浏览器可使用 `npx patchright install chromium`。

访问远程服务器时，在本机运行：

```bash
ssh -N -L 8080:127.0.0.1:8080 root@<server>
```

### 配置

| 环境变量 | 默认值 / 含义 |
| --- | --- |
| `AUTOKEY_HOST` | `127.0.0.1` |
| `AUTOKEY_PORT` | `8080` |
| `AUTOKEY_DATA_DIR` | 项目目录下 `data` |
| `AUTOKEY_TOKEN` | 可选访问令牌，至少 32 字符；监听非回环地址时强制要求 |
| `CHROME_PATH` | 可选浏览器可执行文件；默认由 Patchright 选择匹配版本 |
| `PLAYWRIGHT_BROWSERS_PATH` | 可选独立浏览器安装目录；安装和运行时必须保持一致 |

生成随机令牌：`node -e "console.log(require('node:crypto').randomBytes(32).toString('hex'))"`。

配置令牌后，网页会提示认证，使用 HttpOnly / SameSite Cookie 连接 API 和 WebSocket。程序调用可使用 `Authorization: Bearer <token>`。令牌不放在 WebSocket URL、页面 localStorage 或日志里。HTTP 与 WebSocket 均拒绝跨来源请求，账号列表不返回密码或代理密码，私钥导出接口仍为敏感操作。

**不要通过公网明文 HTTP 传输令牌、私钥或浏览器画面**。使用 SSH 隧道，或正确配置 HTTPS 反向代理；代理应保留 Host 与 WebSocket Upgrade 头。即使配置令牌，也优先仅本机监听。不要把静态文件目录映射到整个项目。

## 使用

```bash
node bin/autokey.mjs add test@example.com --name "测试账号"
node bin/autokey.mjs add other@example.com --proxy "http://user:pass@host:port"
node bin/autokey.mjs list
node bin/autokey.mjs login test@example.com
node bin/autokey.mjs check test@example.com
node bin/autokey.mjs export test@example.com
node bin/autokey.mjs import-mrs /opt/microsoft-rewards-script
```

在控制台中选择“绑定 Passkey”或“远程桌面”，手动完成微软身份验证并添加通行密钥。支持鼠标、键盘修饰键、Enter/Tab 和粘贴文本。仅允许 HTTP(S) 导航。当前交互流绑定主标签页；新弹窗/新标签页不会自动接管，需要在主标签页继续操作。

HTTP(S) 代理的 URL 用户名/密码会拆分为 Chromium 所需字段。支持不带认证的 SOCKS5；Chromium 不支持 SOCKS5 用户名/密码认证，配置时会明确报错。不同账号的代理不会从其他账号或全局代理中隐式继承。

同一账号同时只能运行一个浏览器会话（包括正在启动的会话）。请先关闭远程桌面再执行后台登录、探活或删除，忙碌时返回 `409`，不会强行关闭另一个连接。

账号目录内的 `.session.lock` 同时保护 CLI 和服务进程。异常断电/强制终止可能留下锁文件；先检查其中 PID 及该 Profile 对应的浏览器进程，确认已经退出，再手动移除锁文件。程序不会自动抢占不明来源的锁，也不会删除仍持锁的账号。

### 数据布局与备份

```text
data/accounts/<account_id>/
  account.json          # 元数据、可选密码、代理配置
  passkey.json          # CDP 凭据，包含可用来签名的私钥
  browser_profile/      # 账号独立的 Chromium Profile
  storage_state.json    # Cookie / localStorage 快照
```

保留现有账号 ID 命名以兼容旧数据；不同邮箱若规范化后发生目录碰撞，拒绝访问/创建，不会合并或覆盖。拒绝路径越界和账号目录/关键文件符号链接。重复添加账号返回 `409`，不会重置元数据。

凭据和会话使用同目录临时文件加原子替换，POSIX 文件权限为 `0600`，新目录为 `0700`。签名后自动保存 `signCount`，关闭前再次刷新；无法注入或持久化密钥时明确失败。会话快照可为新 Profile 恢复 Cookie / localStorage；已有 Profile 只补回缺失的会话 Cookie，不覆盖较新的状态。

**这些文件没有应用层加密**。请使用加密磁盘、最小权限和受保护的离线备份；不要提交或分享 `data/`、导出的私钥、备份包、环境令牌或浏览器 Profile。拥有控制台访问权的人可以导出密钥。建议专用低权限系统用户；root 启动 Chromium 时才添加 `--no-sandbox`。

MRS 导入支持 `runtime/accounts/<mailbox>_<domain>-<hex-hash>/browser-profile/storage_state.desktop.json` 布局。只移除末尾十六进制哈希，保留邮箱中的连字符和下划线；其他布局不保证兼容。返回实际新增、跳过和失败数量，不覆盖已有快照。

## 测试

### 设备与系统信息

工具栏的“系统信息”显示服务器操作系统、内核/系统版本、架构、Node.js、CPU 核数和内存。每行账号的“设备信息”额外显示：

- 虚拟认证器的 CTAP2 协议、传输类型、可发现凭据、模拟用户验证与自动用户在场配置。
- 每个凭据的 **公钥 SPKI SHA-256 指纹**、凭据 ID 摘要、RP 域名、算法、签名计数和备份状态，不返回私钥。
- 最近启动的实际 Chromium 版本、UA、平台、语言、时区、视口、屏幕与环境摘要。

浏览器快照在该账号启动时保存到 `device_info.json`；尚未启动的账号明确显示“未采集”，查看面板不会隐式启动浏览器或登录。服务器系统信息是当前值，浏览器信息是带时间戳的最近快照。公钥指纹不是生物指纹，环境摘要不是物理设备 ID，也不保证不同账号间唯一。CDP 凭据未提供 AAGUID / 厂商型号，不虚构实体指纹硬件信息。

只读接口 `GET /api/system-info` 和 `GET /api/accounts/:id/device-info` 遵循同一控制台鉴权与跨域限制。

### 回归测试

```bash
npm test                   # 安全、目录边界、代理、API、事件清理、断线竞争测试
npm run test:integration   # 真实 Chromium；无需微软账号，无需外网
npm run test:all
```

集成测试使用系统临时目录和本机 HTTP fixture，验证：

1. resident Passkey 注册和自动保存。
2. 重启后注入、实际 ECDSA 签名验证、RP 哈希、challenge、origin、UP/UV 标志和计数递增。
3. 两个账号间私钥、Cookie、localStorage 隔离。
4. 导入会话恢复、错误密钥启动失败后的资源释放。
5. WebSocket 帧流、文本输入、忙碌账号删除保护和断线清理。
6. 网页令牌认证、添加/搜索账号、旧元数据 HTML 转义和浏览器脚本异常检查。

截图写到 `artifacts/dashboard-smoke.png`，不纳入 Git。测试不会使用、覆盖或删除真实账号；旧入口 `node test_passkey.cjs` 转发到同一套集成测试。

**本地 WebAuthn 测试通过，不等于真实微软账号注册/登录已经通过**。后者需要本人授权的账号实际验证，且可能受微软页面和策略变化影响。

## 部署

### systemd 示例

```ini
[Unit]
Description=AutoKey
After=network.target

[Service]
Type=simple
WorkingDirectory=/opt/autokey
Environment=AUTOKEY_HOST=127.0.0.1
Environment=AUTOKEY_PORT=8080
Environment=AUTOKEY_DATA_DIR=/opt/autokey/data
# 可选：root 可读的环境文件，内含 AUTOKEY_TOKEN=<random-token>
# EnvironmentFile=/etc/autokey.env
ExecStart=/absolute/path/to/node /opt/autokey/bin/autokey.mjs serve
Restart=on-failure
UMask=0077
TimeoutStopSec=45

[Install]
WantedBy=multi-user.target
```

将 Node 路径替换为服务器真实路径，并配置服务所需的依赖路径。退出信号会停止画面流、保存状态并关闭浏览器。升级前停服务，备份源代码、依赖锁文件、服务配置和账号数据；验证后再恢复服务。不要在浏览器运行时拷贝 Profile 作为一致性备份。

### Docker

先在本地环境或不提交的 `.env` 中设置至少 32 字符的 `AUTOKEY_TOKEN`，然后：

```bash
docker compose up -d --build
docker compose logs -f
```

容器内监听 `0.0.0.0` 以支持映射，宿主机只发布 `127.0.0.1:8080`。镜像使用 `npm ci` 和同一 Patchright 包安装 Chromium；`.dockerignore` 排除账号、令牌和本地依赖。

## 公开仓库与脱敏

仓库仅包含源码、通用配置示例和使用保留域名 `example.com` / `.example` 的虚构测试数据。测试私钥在运行时临时生成，不包含真实账号凭据。原始需求对话、测试机连接信息、部署脚本、账号数据、浏览器缓存、会话快照、截图、备份与环境变量文件不应上传。

`.gitignore` / `.dockerignore` 同时排除上述数据。提交前检查 `git diff --cached`，并使用 [Gitleaks](https://github.com/gitleaks/gitleaks) 扫描待发布文件和 Git 历史。若真实令牌、密码或私钥曾公开，删除文件或改写历史不能替代吊销/轮换凭据。

## 实现参考

- [Patchright](https://github.com/Kaliiiiiiiiii-Vinyzu/patchright) / [Node.js 包](https://github.com/Kaliiiiiiiiii-Vinyzu/patchright-nodejs)：沿用现有浏览器驱动，不硬编码第三方项目的安装路径。
- [Playwright persistent context](https://playwright.dev/docs/api/class-browsertype#browser-type-launch-persistent-context)：独立 Profile 与并发限制。
- [CDP WebAuthn](https://chromedevtools.github.io/devtools-protocol/tot/WebAuthn/)：凭据导入、导出和 `credentialAsserted` 事件。
- [ws](https://github.com/websockets/ws#client-authentication)：握手前鉴权和心跳模式。
- [SimpleWebAuthn](https://github.com/MasterKale/SimpleWebAuthn)：成熟的站点侧 WebAuthn 注册/验证库；本项目是认证器驱动，不是微软的 relying party，故不引入其服务端注册逻辑。
