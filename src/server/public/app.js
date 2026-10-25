let accounts = []
let activeWs = null
let currentAccountId = null
let canvas = null
let ctx = null
let currentPasskeyData = null
let currentPasskeyAccountId = null
let currentDeviceAccountId = null
let deviceRequestSequence = 0

function escapeHtml(value) {
  return String(value ?? '').replace(/[&<>"']/g, char => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[char]))
}

async function apiFetch(url, options) {
  const res = await fetch(url, options)
  if (res.status === 401) {
    document.getElementById('auth-modal').classList.add('active')
    throw new Error('请输入控制台访问令牌')
  }
  return res
}

async function submitAuth(event) {
  event.preventDefault()
  const input = document.getElementById('auth-token')
  try {
    const res = await fetch('/api/auth', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ token: input.value }) })
    const data = await res.json()
    if (!res.ok) throw new Error(data.error)
    input.value = ''
    document.getElementById('toast').style.display = 'none'
    document.getElementById('auth-modal').classList.remove('active')
    await loadAccounts()
  } catch (err) { showToast('认证失败: ' + err.message) }
}

document.addEventListener('DOMContentLoaded', () => {
  canvas = document.getElementById('screencast-canvas')
  ctx = canvas.getContext('2d')
  setupCanvasEvents()
  loadAccounts()
})

function showToast(msg, duration = 3000) {
  const t = document.getElementById('toast')
  t.textContent = msg
  t.style.display = 'block'
  setTimeout(() => { t.style.display = 'none' }, duration)
}

async function loadAccounts() {
  try {
    const res = await apiFetch('/api/accounts')
    const data = await res.json()
    if (data.success) {
      accounts = data.accounts
      filterAccounts()
      updateStats(accounts)
    } else throw new Error(data.error || '请求失败')
  } catch (err) {
    showToast('加载账号列表失败: ' + err.message)
  }
}

function updateStats(list) {
  document.getElementById('stat-total').textContent = list.length
  document.getElementById('stat-passkeys').textContent = list.filter(a => a.hasPasskey).length
  document.getElementById('stat-sessions').textContent = list.filter(a => a.hasSession).length
}

function renderAccountsTable(list) {
  const tbody = document.getElementById('accounts-table-body')
  if (list.length === 0) {
    tbody.innerHTML = '<tr><td colspan="6" class="text-center py-4" style="text-align:center;color:#94a3b8;">暂无账号数据，请点击上方「+ 添加账号」或「从服务器同步」</td></tr>'
    return
  }

  tbody.innerHTML = list.map(acc => {
    const passkeyBadge = acc.passkeyError
      ? '<span class="badge badge-warning">⚠️ 密钥文件损坏，请恢复备份</span>'
      : acc.hasPasskey
      ? `<span class="badge badge-success">✅ 本地已保存 (${acc.passkeyCount || 1} 密钥)</span>`
      : `<span class="badge badge-warning">⚠️ 未绑定 Passkey</span>`

    const sessionBadge = acc.hasSession
      ? `<span class="badge badge-info">🟢 已有本地会话</span>`
      : `<span class="badge badge-secondary">⚪ 未登录</span>`

    const proxyText = acc.proxy
      ? (typeof acc.proxy === 'string' ? acc.proxy : (acc.proxy.server || `${acc.proxy.url}:${acc.proxy.port}`))
      : '直连 (无代理)'

    const lastLogin = acc.lastLoginAt ? new Date(acc.lastLoginAt).toLocaleString() : '从未'

    return `
      <tr>
        <td>
          <div style="font-weight:600;">${escapeHtml(acc.email)}</div>
          <div style="font-size:11px;color:#94a3b8;">ID: ${escapeHtml(acc.id)}</div>
        </td>
        <td>${passkeyBadge}</td>
        <td>${sessionBadge}</td>
        <td style="font-size:12px;max-width:200px;overflow:hidden;text-overflow:ellipsis;">${escapeHtml(proxyText)}</td>
        <td style="font-size:12px;color:#94a3b8;">${lastLogin}</td>
        <td>
          <div class="actions-group">
            ${acc.hasPasskey ? `
              <button class="btn btn-sm btn-primary" onclick="silentLogin('${acc.id}')" title="一键全自动静默无感登录">⚡ Passkey 登录</button>
            ` : `
              <button class="btn btn-sm btn-secondary" onclick="openScreencast('${acc.id}', 'https://account.live.com/proofs/manage/additional')" title="打开远程浏览器窗口绑定 Passkey">🛡️ 绑定 Passkey</button>
            `}
            <button class="btn btn-sm btn-outline" onclick="openScreencast('${acc.id}')" title="打开交互式远程浏览器">🖥️ 远程桌面</button>
            <button class="btn btn-sm btn-outline" onclick="viewDeviceInfo('${acc.id}')" title="查看 Passkey 设备、公钥指纹和系统环境">🧬 设备信息</button>
            ${acc.hasPasskey ? `
              <button class="btn btn-sm btn-outline" onclick="viewPasskey('${acc.id}')" title="查看导出的公私钥凭据">🔑 密钥</button>
            ` : ''}
            <button class="btn btn-sm btn-danger" onclick="deleteAccount('${acc.id}')" title="删除账号沙箱">🗑️</button>
          </div>
        </td>
      </tr>
    `
  }).join('')
}

function filterAccounts() {
  const query = document.getElementById('search-input').value.toLowerCase().trim()
  const filtered = accounts.filter(a => a.email.toLowerCase().includes(query) || a.id.toLowerCase().includes(query))
  renderAccountsTable(filtered)
}

// --- Read-only device and system information (never requests private-key export) ---
function infoRows(rows) {
  return '<dl class="device-info-list">' + rows.map(([label, value, code = false]) =>
    `<div><dt>${escapeHtml(label)}</dt><dd${code ? ' class="device-code"' : ''}>${escapeHtml(value ?? '未采集')}</dd></div>`
  ).join('') + '</dl>'
}

function systemInfoCard(system) {
  return `<section class="device-card"><h3>服务器系统 · 当前运行环境</h3>${infoRows([
    ['系统', `${system.type} ${system.release}`], ['系统版本', system.version],
    ['架构 / 运行时', `${system.architecture} · Node.js ${system.nodeVersion}`],
    ['逻辑 CPU / 内存', `${system.logicalCpus} 核 · ${(system.totalMemoryBytes / 1024 ** 3).toFixed(1)} GiB`]
  ])}</section>`
}

function renderDeviceInfo(info) {
  const auth = info.authenticator
  const yesNo = value => value == null ? '未知' : value ? '是' : '否'
  const transport = { internal: 'internal（平台认证器）', usb: 'USB（模拟）', nfc: 'NFC（模拟）', ble: '蓝牙（模拟）', cable: '混合传输（模拟）' }[auth.transport] || auth.transport
  const notice = `<div class="device-notice">这是 CDP 纯软件虚拟认证器，不是真实指纹传感器或 TPM。用户在场 / 用户验证由浏览器模拟；公钥指纹不是生物指纹，也不代表物理设备唯一 ID。</div>`
  const authenticator = `<section class="device-card"><h3>Passkey 认证器 <span class="badge badge-info">${info.busy ? '浏览器忙碌 / 运行中' : '当前未运行'}</span></h3>${infoRows([
    ['设备类型', 'CDP 虚拟认证器 · 非硬件保护'],
    ['协议 / 传输', `${String(auth.protocol).toUpperCase()} / ${transport}`],
    ['可发现凭据 / 用户验证', `${yesNo(auth.hasResidentKey)} / ${yesNo(auth.hasUserVerification)}（模拟）`],
    ['自动用户在场', yesNo(auth.automaticPresenceSimulation)],
    ['参数来源', auth.source === 'observed' ? '最近会话实测配置' : '默认配置，尚未启动浏览器'],
    ['最近虚拟设备 ID', auth.authenticatorId || '未创建（每次启动会变化）', true],
    ['AAGUID / 厂商型号', 'CDP 凭据未提供，无法据此识别实体设备']
  ])}</section>`
  const browser = info.browser
  const browserCard = browser
    ? `<section class="device-card device-card-wide"><h3>浏览器环境 · 最近一次启动快照</h3>${infoRows([
      ['浏览器 / CDP', `${info.browser.product} / ${info.browser.protocolVersion}`],
      ['平台 / 语言 / 时区', `${browser.platform} · ${(browser.languages || []).join(', ')} · ${browser.timeZone}`],
      ['视口 / 屏幕 / 像素比', `${browser.viewport?.width} × ${browser.viewport?.height} / ${browser.screen?.width} × ${browser.screen?.height} / ${browser.devicePixelRatio}`],
      ['User-Agent', browser.userAgent, true],
      ['环境摘要', browser.environmentFingerprint, true],
      ['采集时间', info.capturedAt ? new Date(info.capturedAt).toLocaleString() : '未采集']
    ])}<p class="device-help">环境摘要仅用于比较参数；不同账号可能相同，分目录隔离不等于设备指纹唯一。关闭会话后仍显示最近快照。</p></section>`
    : '<section class="device-card device-card-wide"><h3>浏览器环境</h3><p class="device-help">尚未采集实际浏览器。打开一次该账号的远程桌面，再点击“刷新信息”；查看本面板本身不会启动浏览器或登录账号。</p></section>'
  const credentials = `<section class="device-card device-card-wide"><h3>Passkey 公钥指纹 <span class="badge badge-secondary">${info.credentials.length} 个本地凭据</span></h3>${info.credentials.length
    ? info.credentials.map((credential, index) => `<div class="credential-device-info"><h4>凭据 ${index + 1} · ${escapeHtml(credential.rpId)}</h4>${infoRows([
      ['公钥指纹 · SHA-256/SPKI', credential.publicKeyFingerprint || credential.fingerprintError, true],
      ['凭据 ID 摘要', credential.credentialFingerprint, true],
      ['算法 / 签名计数', `${credential.keyType || '未知'}${credential.curve ? ' / ' + credential.curve : ''} · signCount ${credential.signCount}`],
      ['可发现 / 可备份 / 已备份', `${yesNo(credential.residentCredential)} / ${yesNo(credential.backupEligibility)} / ${yesNo(credential.backupState)}`]
    ])}</div>`).join('')
    : '<p class="device-help">尚无已保存的 Passkey；完成绑定后会显示公钥指纹和 RP 域名。</p>'}</section>`
  const errors = [info.snapshotError, info.credentialsError].filter(Boolean).map(message => `<p class="device-notice">${escapeHtml(message)}</p>`).join('')
  return notice + errors + `<div class="device-grid">${authenticator}${systemInfoCard(info.system)}${browserCard}${credentials}</div>`
}

function viewDeviceInfo(accountId = null) {
  currentDeviceAccountId = accountId
  document.getElementById('device-info-title').textContent = accountId ? `设备与系统信息 · ${accountId}` : '服务器系统信息'
  document.getElementById('device-info-modal').classList.add('active')
  refreshDeviceInfo()
}

async function refreshDeviceInfo() {
  const sequence = ++deviceRequestSequence
  const content = document.getElementById('device-info-content')
  content.textContent = '正在读取设备信息...'
  try {
    const url = currentDeviceAccountId ? `/api/accounts/${encodeURIComponent(currentDeviceAccountId)}/device-info` : '/api/system-info'
    const res = await apiFetch(url)
    const data = await res.json()
    if (sequence !== deviceRequestSequence) return
    if (!res.ok || !data.success) throw new Error(data.error || '读取失败')
    content.innerHTML = data.deviceInfo ? renderDeviceInfo(data.deviceInfo) : systemInfoCard(data.system)
  } catch (err) {
    if (sequence === deviceRequestSequence) content.textContent = '读取失败: ' + err.message
  }
}

function closeDeviceInfo() {
  deviceRequestSequence++
  document.getElementById('device-info-modal').classList.remove('active')
  document.getElementById('device-info-content').textContent = ''
  currentDeviceAccountId = null
}

// --- Silent Login ---
async function silentLogin(accountId) {
  showToast(`[${accountId}] 正在通过 Passkey 启动全自动静默认证...`, 5000)
  try {
    const res = await apiFetch(`/api/accounts/${encodeURIComponent(accountId)}/login`, {
      method: 'POST'
    })
    const data = await res.json()
    if (data.success && data.result.success) {
      showToast(`🎉 [${accountId}] Passkey 认证成功！会话已更新。`)
      loadAccounts()
    } else {
      showToast(`❌ [${accountId}] 登录失败: ${data.result?.error || data.error || '未知错误'}`)
    }
  } catch (err) {
    showToast(`❌ 登录异常: ${err.message}`)
  }
}

// --- Interactive Screencast ---
function openScreencast(accountId, startUrl = null) {
  if (activeWs) { activeWs.close(); activeWs = null }
  currentAccountId = accountId
  document.getElementById('screencast-title').textContent = `远程交互浏览器 · [${accountId}]`
  document.getElementById('screencast-modal').classList.add('active')
  document.getElementById('passkey-badge').classList.add('hidden')
  document.getElementById('screencast-status').textContent = '连接云端浏览器中...'

  // Clear canvas
  ctx.fillStyle = '#000'
  ctx.fillRect(0, 0, canvas.width, canvas.height)
  ctx.fillStyle = '#38bdf8'
  ctx.font = '18px monospace'
  ctx.fillText('正在连接并拉起远程隔离浏览器，请稍候...', 50, 400)

  const proto = location.protocol === 'https:' ? 'wss:' : 'ws:'
  let wsUrl = `${proto}//${location.host}/ws/screencast?accountId=${encodeURIComponent(accountId)}`
  if (startUrl) {
    wsUrl += `&startUrl=${encodeURIComponent(startUrl)}`
  }

  const ws = new WebSocket(wsUrl)
  activeWs = ws
  let frameSequence = 0

  ws.onopen = () => {
    if (activeWs !== ws) return
    document.getElementById('screencast-status').textContent = '🟢 实时同步中 (CDP 流)'
  }

  ws.onmessage = (event) => {
    if (activeWs !== ws) return
    try {
      const msg = JSON.parse(event.data)
      if (msg.type === 'frame') {
        const img = new Image()
        const sequence = ++frameSequence
        img.onload = () => {
          if (activeWs === ws && sequence === frameSequence) ctx.drawImage(img, 0, 0, canvas.width, canvas.height)
        }
        img.src = 'data:image/jpeg;base64,' + msg.data
      } else if (msg.type === 'passkey_event') {
        const badge = document.getElementById('passkey-badge')
        badge.classList.remove('hidden')
        badge.textContent = `✅ ${msg.message}`
        showToast(msg.message)
        loadAccounts()
      } else if (msg.type === 'error') {
        showToast('远程浏览器错误: ' + msg.error)
      }
    } catch (e) {
      console.error(e)
    }
  }

  ws.onerror = () => {
    if (activeWs === ws) showToast('连接失败：请检查访问令牌或网络，然后刷新页面重试')
  }
  ws.onclose = () => {
    if (activeWs !== ws) return
    activeWs = null
    document.getElementById('screencast-status').textContent = '🔴 会话已断开'
    loadAccounts()
  }
}

function closeScreencast() {
  if (activeWs) {
    activeWs.close()
    activeWs = null
  }
  document.getElementById('screencast-modal').classList.remove('active')
  loadAccounts()
}

function quickNav(url) {
  if (activeWs && activeWs.readyState === WebSocket.OPEN) {
    activeWs.send(JSON.stringify({ type: 'navigate', url }))
  }
}

function setupCanvasEvents() {
  const modifiers = e => (e.altKey ? 1 : 0) | (e.ctrlKey ? 2 : 0) | (e.metaKey ? 4 : 0) | (e.shiftKey ? 8 : 0)
  const getCanvasCoords = (e) => {
    const rect = canvas.getBoundingClientRect()
    const scaleX = canvas.width / rect.width
    const scaleY = canvas.height / rect.height
    return {
      x: (e.clientX - rect.left) * scaleX,
      y: (e.clientY - rect.top) * scaleY
    }
  }

  canvas.addEventListener('mousedown', (e) => {
    canvas.focus({ preventScroll: true })
    e.preventDefault()
    if (!activeWs || activeWs.readyState !== WebSocket.OPEN) return
    const { x, y } = getCanvasCoords(e)
    const btn = e.button === 2 ? 'right' : (e.button === 1 ? 'middle' : 'left')
    activeWs.send(JSON.stringify({
      type: 'mouse',
      eventType: 'mousePressed',
      x, y,
      button: btn,
      clickCount: Math.min(e.detail || 1, 3), modifiers: modifiers(e)
    }))
  })

  canvas.addEventListener('mouseup', (e) => {
    if (!activeWs || activeWs.readyState !== WebSocket.OPEN) return
    const { x, y } = getCanvasCoords(e)
    const btn = e.button === 2 ? 'right' : (e.button === 1 ? 'middle' : 'left')
    activeWs.send(JSON.stringify({
      type: 'mouse',
      eventType: 'mouseReleased',
      x, y,
      button: btn,
      clickCount: Math.min(e.detail || 1, 3), modifiers: modifiers(e)
    }))
  })

  canvas.addEventListener('mousemove', (e) => {
    if (!activeWs || activeWs.readyState !== WebSocket.OPEN) return
    const { x, y } = getCanvasCoords(e)
    activeWs.send(JSON.stringify({
      type: 'mouse',
      eventType: 'mouseMoved',
      x, y, modifiers: modifiers(e)
    }))
  })

  canvas.addEventListener('wheel', (e) => {
    if (!activeWs || activeWs.readyState !== WebSocket.OPEN) return
    const { x, y } = getCanvasCoords(e)
    activeWs.send(JSON.stringify({
      type: 'mouse',
      eventType: 'mouseWheel',
      x, y,
      deltaX: e.deltaX,
      deltaY: e.deltaY, modifiers: modifiers(e)
    }))
    e.preventDefault()
  }, { passive: false })

  canvas.addEventListener('contextmenu', e => e.preventDefault())

  canvas.addEventListener('keydown', (e) => {
    if (!activeWs || activeWs.readyState !== WebSocket.OPEN) return
    if (e.isComposing) return
    activeWs.send(JSON.stringify({
      type: 'keyboard',
      eventType: 'keyDown',
      key: e.key,
      code: e.code,
      modifiers: modifiers(e), windowsVirtualKeyCode: e.keyCode,
      text: !e.ctrlKey && !e.metaKey && !e.altKey ? (e.key === 'Enter' ? '\r' : e.key.length === 1 ? e.key : undefined) : undefined
    }))
    if (!((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === 'v')) {
      e.preventDefault()
    }
  })

  canvas.addEventListener('keyup', (e) => {
    if (!activeWs || activeWs.readyState !== WebSocket.OPEN) return
    activeWs.send(JSON.stringify({
      type: 'keyboard',
      eventType: 'keyUp',
      key: e.key,
      code: e.code, modifiers: modifiers(e), windowsVirtualKeyCode: e.keyCode
    }))
  })
  canvas.addEventListener('paste', e => {
    if (!activeWs || activeWs.readyState !== WebSocket.OPEN) return
    e.preventDefault()
    activeWs.send(JSON.stringify({ type: 'text', text: e.clipboardData.getData('text/plain').slice(0, 16000) }))
  })
}

// --- Add Account ---
function openAddAccountModal() {
  document.getElementById('add-account-modal').classList.add('active')
}
function closeAddAccountModal() {
  document.getElementById('add-account-modal').classList.remove('active')
}

async function submitAddAccount(e) {
  e.preventDefault()
  const email = document.getElementById('acc-email').value.trim()
  const name = document.getElementById('acc-name').value.trim()
  const proxy = document.getElementById('acc-proxy').value.trim()

  try {
    const res = await apiFetch('/api/accounts', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email, displayName: name, proxy: proxy || null })
    })
    const data = await res.json()
    if (data.success) {
      showToast('账号沙箱创建成功！')
      closeAddAccountModal()
      document.getElementById('add-account-form').reset()
      loadAccounts()
    } else {
      showToast('创建失败: ' + data.error)
    }
  } catch (err) {
    showToast('提交失败: ' + err.message)
  }
}

// --- MRS Server Import ---
async function importFromMrs() {
  if (!confirm('将从服务器 /opt/microsoft-rewards-script 自动扫描并同步已有账号，是否继续？')) return
  showToast('正在从服务器同步账号...')
  try {
    const res = await apiFetch('/api/import-mrs', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ dir: '/opt/microsoft-rewards-script' })
    })
    const data = await res.json()
    if (data.success) {
      showToast(`同步完成！共读取 ${data.imported} 个账号目录`)
      loadAccounts()
    } else {
      showToast('同步失败: ' + (data.error || data.errors?.map(e => e.error).join('; ')))
    }
  } catch (err) {
    showToast('同步失败: ' + err.message)
  }
}

// --- View Passkey Details ---
async function viewPasskey(accountId) {
  try {
    const res = await apiFetch(`/api/accounts/${encodeURIComponent(accountId)}/passkey`)
    const data = await res.json()
    if (data.success) {
      currentPasskeyData = data.passkey
      currentPasskeyAccountId = accountId
      document.getElementById('passkey-json-viewer').textContent = JSON.stringify(data.passkey, null, 2)
      document.getElementById('passkey-details-modal').classList.add('active')
    } else throw new Error(data.error || '获取失败')
  } catch (err) {
    showToast('获取 Passkey 失败: ' + err.message)
  }
}

function closePasskeyModal() {
  document.getElementById('passkey-details-modal').classList.remove('active')
  document.getElementById('passkey-json-viewer').textContent = ''
  currentPasskeyData = null
  currentPasskeyAccountId = null
}

function downloadPasskeyJson() {
  if (!currentPasskeyData) return
  const blob = new Blob([JSON.stringify(currentPasskeyData, null, 2)], { type: 'application/json' })
  const url = URL.createObjectURL(blob)
  const a = document.createElement('a')
  a.href = url
  a.download = `passkey_${currentPasskeyAccountId || 'export'}.json`
  a.click()
  setTimeout(() => URL.revokeObjectURL(url), 1000)
}

// --- Delete Account ---
async function deleteAccount(accountId) {
  if (!confirm(`确定要彻底删除账号 [${accountId}] 的所有本地沙箱文件（含浏览器配置与 Passkey 私钥）吗？`)) return
  try {
    const res = await apiFetch(`/api/accounts/${encodeURIComponent(accountId)}`, { method: 'DELETE' })
    const data = await res.json()
    if (data.success) {
      showToast('账号沙箱已删除')
      loadAccounts()
    } else showToast('删除失败: ' + data.error)
  } catch (err) {
    showToast('删除失败: ' + err.message)
  }
}
