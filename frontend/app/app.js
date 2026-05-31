import { CipherSuite, DhkemX25519HkdfSha256, HkdfSha256 }
  from 'https://esm.sh/@hpke/core@1.7.1'
import { Chacha20Poly1305 }
  from 'https://esm.sh/@hpke/chacha20poly1305@1.7.1'

const API = '/api'
const HPKE_INFO = new TextEncoder().encode('eternal-blue-msg-v1')

const S = {
  token: null, userId: null, username: null,
  privateKey: null, publicKey: null,
  suite: null,
  currentConvId: null, currentPeer: null,
  forwardTargetMsgId: null,
}

// Decrypted plaintext keyed by message_id — never put message content into HTML attributes
const plaintextCache = new Map()

// ── HPKE suite ────────────────────────────────────────────────────────────
function makeSuite() {
  return new CipherSuite({
    kem:  new DhkemX25519HkdfSha256(),
    kdf:  new HkdfSha256(),
    aead: new Chacha20Poly1305(),
  })
}

// ── Base64url helpers ─────────────────────────────────────────────────────
function toB64u(buf) {
  return btoa(String.fromCharCode(...new Uint8Array(buf)))
    .replace(/\+/g,'-').replace(/\//g,'_').replace(/=/g,'')
}
function fromB64u(str) {
  const b64 = str.replace(/-/g,'+').replace(/_/g,'/')
  const pad = b64 + '='.repeat((4 - b64.length % 4) % 4)
  return Uint8Array.from(atob(pad), c => c.charCodeAt(0))
}

// ── PBKDF2 key wrapping ───────────────────────────────────────────────────
async function derivePbkdf2Key(password, salt) {
  const raw = await crypto.subtle.importKey(
    'raw', new TextEncoder().encode(password), 'PBKDF2', false, ['deriveKey']
  )
  return crypto.subtle.deriveKey(
    { name: 'PBKDF2', salt, iterations: 600000, hash: 'SHA-256' },
    raw,
    { name: 'AES-GCM', length: 256 },
    false, ['encrypt', 'decrypt']
  )
}

async function encryptPrivKey(privKeyBytes, password) {
  const salt = crypto.getRandomValues(new Uint8Array(16))
  const iv   = crypto.getRandomValues(new Uint8Array(12))
  const key  = await derivePbkdf2Key(password, salt)
  const ct   = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, privKeyBytes)
  return { salt, iv, ct: new Uint8Array(ct) }
}

async function decryptPrivKey(salt, iv, ct, password) {
  const key = await derivePbkdf2Key(password, salt)
  const pt  = await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, key, ct)
  return new Uint8Array(pt)
}

// ── Local key store ───────────────────────────────────────────────────────
function saveKeyStore(username, pubBytes, wrapped) {
  localStorage.setItem(`eb_key:${username}`, JSON.stringify({
    pub:  toB64u(pubBytes),
    salt: toB64u(wrapped.salt),
    iv:   toB64u(wrapped.iv),
    ct:   toB64u(wrapped.ct),
  }))
}

function loadKeyStore(username) {
  const raw = localStorage.getItem(`eb_key:${username}`)
  if (!raw) return null
  const d = JSON.parse(raw)
  return { pub: fromB64u(d.pub), salt: fromB64u(d.salt), iv: fromB64u(d.iv), ct: fromB64u(d.ct) }
}

// ── TOFU pinning ──────────────────────────────────────────────────────────
function pinKey(username, pubBytes, keyVersion) {
  const store = JSON.parse(localStorage.getItem('eb_tofu') || '{}')
  store[username] = { pub: toB64u(pubBytes), kv: keyVersion, at: new Date().toISOString() }
  localStorage.setItem('eb_tofu', JSON.stringify(store))
}

function getPinnedKey(username) {
  const store = JSON.parse(localStorage.getItem('eb_tofu') || '{}')
  const e = store[username]
  if (!e) return null
  return { pub: fromB64u(e.pub), kv: e.kv, at: e.at }
}

async function fetchPeerKey(username) {
  let data
  try {
    data = await api('GET', `/keys/${username}`)
  } catch (e) {
    if (e.message === 'Not found.') throw new Error(`User "${username}" not found.`)
    throw e
  }
  const newPubBytes = fromB64u(data.public_key)
  const pinned = getPinnedKey(username)
  let warned = false
  if (pinned && toB64u(pinned.pub) !== toB64u(newPubBytes)) {
    warned = true
  }
  pinKey(username, newPubBytes, data.key_version)
  const pubKey = await S.suite.kem.deserializePublicKey(newPubBytes)
  return { pubKey, userId: data.user_id, warned }
}

// ── HPKE encrypt ──────────────────────────────────────────────────────────
async function hpkeEncrypt(plaintext, recipientUsername) {
  const { pubKey: recipPubKey, userId: recipId, warned } = await fetchPeerKey(recipientUsername)
  const sentAtMs = Date.now()
  const aad = new TextEncoder().encode(`${S.userId}|${recipId}|${sentAtMs}`)
  const senderCtx = await S.suite.createSenderContext({
    recipientPublicKey: recipPubKey,
    senderKey: { publicKey: S.publicKey, privateKey: S.privateKey },
    info: HPKE_INFO,
  })
  const ct  = await senderCtx.seal(new TextEncoder().encode(plaintext), aad)
  const enc = senderCtx.enc
  return {
    recipientUsername,
    recipientId:      recipId,
    ciphertext:       toB64u(new Uint8Array(ct)),
    encapsulated_key: toB64u(new Uint8Array(enc)),
    sentAtMs,
    warned,
  }
}

// ── HPKE decrypt ──────────────────────────────────────────────────────────
async function hpkeDecrypt(msg) {
  const enc      = fromB64u(msg.encapsulated_key)
  const ct       = fromB64u(msg.ciphertext)
  const sentAtMs = msg.sent_at_ms ?? Math.round(new Date(msg.sent_at).getTime())
  const aad      = new TextEncoder().encode(`${msg.sender_id}|${msg.recipient_id}|${sentAtMs}`)

  let senderPubKey
  if (msg.sender_username === S.username) {
    senderPubKey = S.publicKey
  } else {
    const pinned = getPinnedKey(msg.sender_username)
    if (pinned) {
      senderPubKey = await S.suite.kem.deserializePublicKey(pinned.pub)
    } else {
      const { pubKey } = await fetchPeerKey(msg.sender_username)
      senderPubKey = pubKey
    }
  }

  const recipCtx = await S.suite.createRecipientContext({
    recipientKey: { publicKey: S.publicKey, privateKey: S.privateKey },
    enc,
    senderPublicKey: senderPubKey,
    info: HPKE_INFO,
  })
  const plain = await recipCtx.open(ct, aad)
  return new TextDecoder().decode(plain)
}

// ── Sent message cache ────────────────────────────────────────────────────
function cacheSentMsg(messageId, plaintext, recipientUsername) {
  const store = JSON.parse(localStorage.getItem('eb_sent') || '{}')
  store[messageId] = { t: plaintext, r: recipientUsername, ts: Date.now() }
  localStorage.setItem('eb_sent', JSON.stringify(store))
}

function getCachedSentMsg(messageId) {
  const store = JSON.parse(localStorage.getItem('eb_sent') || '{}')
  return store[messageId] || null
}

// ── API helper ────────────────────────────────────────────────────────────
// Maps HTTP status codes to safe user-facing messages — never surfaces raw
// backend strings, which can expose internal schema, access-control logic, etc.
const API_ERRORS = {
  400: 'Invalid request.',
  401: 'Incorrect username or password.',
  403: 'Permission denied.',
  404: 'Not found.',
  409: 'Username already taken.',
  429: 'Too many attempts. Please wait a moment and try again.',
}

async function api(method, path, body, auth = true) {
  const headers = {}
  if (body) headers['Content-Type'] = 'application/json'
  if (auth && S.token) headers['Authorization'] = `Bearer ${S.token}`

  let res, data
  try {
    res  = await fetch(API + path, {
      method, headers,
      body: body ? JSON.stringify(body) : undefined,
    })
    data = await res.json()
  } catch {
    throw new Error('Network error. Please check your connection.')
  }

  if (!res.ok) {
    // Expired or invalid token on an authenticated call — force re-login
    if (auth && res.status === 401) {
      doLogout()
      throw new Error('Your session has expired. Please log in again.')
    }
    throw new Error(API_ERRORS[res.status] || 'Something went wrong. Please try again.')
  }
  return data
}

// ── Auth flows ────────────────────────────────────────────────────────────
async function doLogin() {
  const username = id('l-user').value.trim()
  const password = id('l-pass').value
  const errEl    = id('login-err')
  const btn      = id('login-btn')
  errEl.style.display = 'none'
  if (!username || !password) return showErr(errEl, 'Please fill in all fields.')
  btn.disabled = true; btn.textContent = 'Logging in…'
  try {
    const data = await api('POST', '/auth/login', { username, password }, false)
    S.token    = data.token
    S.userId   = data.user_id
    S.username = username

    let ks = loadKeyStore(username)
    if (!ks && data.encrypted_private_key && data.public_key) {
      try {
        const blob = JSON.parse(data.encrypted_private_key)
        ks = {
          pub:  fromB64u(data.public_key),
          salt: fromB64u(blob.salt),
          iv:   fromB64u(blob.iv),
          ct:   fromB64u(blob.ct),
        }
        saveKeyStore(username, ks.pub, { salt: ks.salt, iv: ks.iv, ct: ks.ct })
      } catch {
        throw new Error('Your account key data is corrupted. Please re-register.')
      }
    }
    if (!ks) throw new Error('No key found on this device. Please log in from the device you registered on, or re-register.')

    let privBytes
    try {
      privBytes = await decryptPrivKey(ks.salt, ks.iv, ks.ct, password)
    } catch {
      throw new Error('Could not decrypt your key. Your stored key may be corrupted — please re-register.')
    }

    S.suite      = makeSuite()
    S.privateKey = await S.suite.kem.deserializePrivateKey(privBytes)
    S.publicKey  = await S.suite.kem.deserializePublicKey(ks.pub)
    pinKey(username, ks.pub, 1)
    showApp()
  } catch (e) {
    showErr(errEl, e.message)
  } finally {
    btn.disabled = false; btn.textContent = 'Login'
  }
}

async function doRegister() {
  const username = id('r-user').value.trim()
  const password = id('r-pass').value
  const errEl    = id('reg-err')
  const btn      = id('reg-btn')
  errEl.style.display = 'none'
  if (!username || !password) return showErr(errEl, 'Please fill in all fields.')
  if (!/^[a-zA-Z0-9_]{3,32}$/.test(username)) return showErr(errEl, 'Username: 3–32 chars, letters/numbers/_ only.')
  if (password.length < 12) return showErr(errEl, 'Password must be at least 12 characters.')
  btn.disabled = true; btn.textContent = 'Generating keys…'
  try {
    S.suite = makeSuite()
    const kp        = await S.suite.kem.generateKeyPair()
    const pubBytes  = await S.suite.kem.serializePublicKey(kp.publicKey)
    const privBytes = await S.suite.kem.serializePrivateKey(kp.privateKey)

    const wrapped = await encryptPrivKey(privBytes, password)
    saveKeyStore(username, pubBytes, wrapped)

    btn.textContent = 'Registering…'
    await api('POST', '/auth/register', {
      username,
      password,
      public_key: toB64u(pubBytes),
      encrypted_private_key: JSON.stringify({
        salt: toB64u(wrapped.salt),
        iv:   toB64u(wrapped.iv),
        ct:   toB64u(wrapped.ct),
      }),
    }, false)

    btn.textContent = 'Logging in…'
    const loginData = await api('POST', '/auth/login', { username, password }, false)
    S.token      = loginData.token
    S.userId     = loginData.user_id
    S.username   = username
    S.privateKey = kp.privateKey
    S.publicKey  = kp.publicKey
    pinKey(username, pubBytes, 1)
    showApp()
  } catch (e) {
    showErr(errEl, e.message)
  } finally {
    btn.disabled = false; btn.textContent = 'Create account'
  }
}

// ── Password management ───────────────────────────────────────────────────
function openChangePassModal() {
  id('cp-current').value = ''
  id('cp-new').value     = ''
  id('cp-confirm').value = ''
  id('change-pass-err').style.display = 'none'
  id('change-pass-modal').hidden = false
}

function closeChangePassModal() {
  id('change-pass-modal').hidden = true
}

async function doChangePassword() {
  const currentPass = id('cp-current').value
  const newPass     = id('cp-new').value
  const confirmPass = id('cp-confirm').value
  const errEl       = id('change-pass-err')
  errEl.style.display = 'none'

  if (!currentPass || !newPass || !confirmPass) return showErr(errEl, 'Please fill in all fields.')
  if (newPass.length < 12) return showErr(errEl, 'New password must be at least 12 characters.')
  if (newPass !== confirmPass) return showErr(errEl, 'New passwords do not match.')
  if (currentPass === newPass) return showErr(errEl, 'New password must differ from current password.')

  const btn = id('do-change-pass-btn')
  btn.disabled = true; btn.textContent = 'Updating…'
  try {
    // Re-wrap the in-memory private key under the new password
    const privBytes = await S.suite.kem.serializePrivateKey(S.privateKey)
    const pubBytes  = await S.suite.kem.serializePublicKey(S.publicKey)
    const wrapped   = await encryptPrivKey(privBytes, newPass)
    const newBlob   = JSON.stringify({
      salt: toB64u(wrapped.salt),
      iv:   toB64u(wrapped.iv),
      ct:   toB64u(wrapped.ct),
    })

    // Update server: password hash + re-wrapped key blob in one call
    await api('PATCH', '/auth/password', {
      current_password:      currentPass,
      new_password:          newPass,
      encrypted_private_key: newBlob,
    })

    // Persist new wrapper locally too
    saveKeyStore(S.username, pubBytes, wrapped)

    closeChangePassModal()
    toast('Password updated.')
  } catch (e) {
    // 403 here means wrong current password (session is valid, just the old password is wrong)
    const msg = e.message === 'Permission denied.' ? 'Current password is incorrect.' : e.message
    showErr(errEl, msg)
  } finally {
    btn.disabled = false; btn.textContent = 'Update password'
  }
}

function doLogout() {
  plaintextCache.clear()
  S.token = null; S.userId = null; S.username = null
  S.privateKey = null; S.publicKey = null; S.suite = null
  S.currentConvId = null; S.currentPeer = null
  id('auth').style.display = 'flex'
  id('app').style.display  = 'none'
  id('l-user').value = ''; id('l-pass').value = ''
  id('login-err').style.display = 'none'
}

// ── App shell ─────────────────────────────────────────────────────────────
function showApp() {
  id('auth').style.display = 'none'
  id('app').style.display  = 'flex'
  id('header-user').textContent = S.username
  loadConversations()
}

async function loadConversations() {
  const listEl = id('conv-list')
  listEl.innerHTML = '<div class="loading-row"><span class="spinner"></span> Loading…</div>'
  try {
    const { conversations } = await api('GET', '/conversations')
    renderConvList(conversations)
  } catch {
    listEl.innerHTML = `<div class="loading-row" style="color:#f87171">Failed to load conversations.</div>`
  }
}

function renderConvList(convs) {
  const listEl = id('conv-list')
  if (!convs.length) {
    listEl.innerHTML = '<div class="loading-row" style="color:#555">No conversations yet</div>'
    return
  }
  listEl.innerHTML = convs.map(c => {
    const initial = esc(c.with_username[0].toUpperCase())
    const time    = c.last_message_at ? relTime(new Date(c.last_message_at)) : ''
    const unread  = c.unread_count > 0
      ? `<span class="unread">${c.unread_count}</span>` : ''
    const active  = c.conversation_id === S.currentConvId ? ' active' : ''
    return `
      <div class="conv-item${active}" data-id="${c.conversation_id}" data-peer="${esc(c.with_username)}">
        <div class="avatar">${initial}</div>
        <div class="conv-info">
          <div class="conv-name">${esc(c.with_username)}</div>
          <div class="conv-preview">End-to-end encrypted</div>
        </div>
        <div class="conv-right">
          <span class="conv-time">${time}</span>
          ${unread}
        </div>
      </div>`
  }).join('')
}

async function openConv(convId, peerUsername) {
  S.currentConvId = convId
  S.currentPeer   = peerUsername
  document.querySelectorAll('.conv-item').forEach(el => {
    el.classList.toggle('active', el.dataset.id === convId)
  })
  id('empty-state').style.display = 'none'
  const chatView = id('chat-view')
  chatView.style.display = 'flex'
  id('chat-avatar').textContent = peerUsername[0].toUpperCase()
  id('chat-name').textContent   = peerUsername
  id('messages-area').innerHTML =
    '<div class="loading-row"><span class="spinner"></span> Decrypting messages…</div>'
  try {
    const data = await api('GET', `/conversations/${convId}/messages?limit=50`)
    api('POST', `/conversations/${convId}/read`).catch(() => {})
    loadConversations()
    renderMessages(data.messages)
  } catch {
    id('messages-area').innerHTML =
      `<div class="loading-row" style="color:#f87171">Failed to load messages. Please try again.</div>`
  }
}

async function buildMsgHtml(msg) {
  const mine = msg.sender_username === S.username
  let plaintext
  let hasRealPlaintext = false

  if (mine) {
    const cached = getCachedSentMsg(msg.message_id)
    if (cached) {
      plaintext = cached.t
      hasRealPlaintext = true
    } else {
      plaintext = '[Sent from another device — ciphertext only]'
    }
  } else {
    try {
      plaintext = await hpkeDecrypt(msg)
      hasRealPlaintext = true
    } catch {
      plaintext = null
    }
  }

  if (hasRealPlaintext && plaintext !== null) {
    plaintextCache.set(msg.message_id, plaintext)
  }

  const fwdTag      = msg.is_forwarded ? `<div class="msg-forwarded-tag">↪ Forwarded</div>` : ''
  const bubbleClass = plaintext === null ? 'error' : (mine ? 'mine' : 'theirs')
  const displayText = plaintext === null
    ? '[Decryption failed — key mismatch or tampered message]'
    : esc(plaintext)

  // All action buttons use data attributes — no user content in HTML attributes
  let actions = ''
  if (hasRealPlaintext) {
    actions += `<button class="act-btn" data-action="download" data-msg-id="${msg.message_id}">Download</button>`
  }
  if (hasRealPlaintext) {
    actions += `<button class="act-btn" data-action="forward" data-msg-id="${msg.message_id}">Forward</button>`
  }
  if (mine) {
    actions += `<button class="act-btn danger" data-action="revoke" data-msg-id="${msg.message_id}">Revoke</button>`
  }
  actions += `<button class="act-btn danger" data-action="delete" data-msg-id="${msg.message_id}">Delete</button>`

  return `
    <div class="msg ${bubbleClass}" id="msg-${msg.message_id}">
      ${fwdTag}
      <div class="msg-bubble">${displayText}</div>
      <div class="msg-meta">
        <span>${fmtTime(new Date(msg.sent_at))}</span>
        ${hasRealPlaintext && !mine ? '<span class="lock" title="Sender authenticated">🔒</span>' : ''}
      </div>
      <div class="msg-actions">${actions}</div>
    </div>
  `
}

async function renderMessages(msgs) {
  const area = id('messages-area')
  if (!msgs.length) {
    area.innerHTML = '<div class="loading-row" style="color:#555">No messages yet</div>'
    return
  }
  area.innerHTML = '<div class="loading-row"><span class="spinner"></span> Decrypting…</div>'

  const rendered = []
  for (const msg of msgs) {
    rendered.push(await buildMsgHtml(msg))
  }

  area.innerHTML = rendered.join('')
  area.scrollTop = area.scrollHeight
}

// ── Auto-refresh polling ──────────────────────────────────────────────────
let pollTimer = null

function startPolling() {
  stopPolling()
  pollTimer = setInterval(pollNewMessages, 3000)
}

function stopPolling() {
  clearInterval(pollTimer)
  pollTimer = null
}

async function pollNewMessages() {
  if (!S.currentConvId) return
  const convId = S.currentConvId

  try {
    const data = await api('GET', `/conversations/${convId}/messages?limit=50`)
    if (convId !== S.currentConvId) return  // conversation changed while request was in flight

    const area = id('messages-area')
    if (area.querySelector('.spinner')) return  // still doing initial decrypt

    let hasNew = false
    for (const msg of data.messages) {
      if (document.getElementById(`msg-${msg.message_id}`)) continue
      hasNew = true
      const html = await buildMsgHtml(msg)
      if (convId !== S.currentConvId) return  // guard again after async decrypt
      // Remove "No messages yet" placeholder if present before appending
      const placeholder = area.querySelector('.loading-row')
      if (placeholder) placeholder.remove()
      area.insertAdjacentHTML('beforeend', html)
    }

    if (hasNew) {
      area.scrollTop = area.scrollHeight
      api('POST', `/conversations/${convId}/read`).catch(() => {})
      loadConversations()
    }
  } catch {
    // silently ignore poll errors — next tick will retry
  }
}

// ── Send ──────────────────────────────────────────────────────────────────
async function doSend() {
  const input = id('compose-input')
  const text  = input.value.trim()
  if (!text || !S.currentPeer) return
  const btn = id('send-btn')
  btn.disabled = true
  try {
    const encrypted = await hpkeEncrypt(text, S.currentPeer)
    if (encrypted.warned) toast(`⚠ Key changed for ${S.currentPeer} — TOFU warning`, true)
    const res = await api('POST', '/messages', {
      recipient_username: encrypted.recipientUsername,
      ciphertext:         encrypted.ciphertext,
      encapsulated_key:   encrypted.encapsulated_key,
      sent_at_ms:         encrypted.sentAtMs,
    })
    cacheSentMsg(res.message_id, text, S.currentPeer)
    input.value = ''
    input.style.height = ''
    const { conversations } = await api('GET', '/conversations')
    renderConvList(conversations)
    if (!S.currentConvId) {
      const conv = conversations.find(c => c.with_username === S.currentPeer)
      if (conv) S.currentConvId = conv.conversation_id
    }
    if (S.currentConvId) await openConv(S.currentConvId, S.currentPeer)
  } catch (e) {
    // fetchPeerKey throws a user-friendly "User not found" — pass that through;
    // all other errors from the API helper are already safe generic strings
    toast(e.message, true)
  } finally {
    btn.disabled = false
  }
}

// ── Message actions ───────────────────────────────────────────────────────
async function doDelete(msgId) {
  try {
    await api('DELETE', `/messages/${msgId}`)
    plaintextCache.delete(msgId)
    document.getElementById(`msg-${msgId}`)?.remove()
    toast('Message deleted')
  } catch {
    toast('Could not delete message. Please try again.', true)
  }
}

async function doRevoke(msgId) {
  try {
    await api('DELETE', `/messages/${msgId}/revoke`)
    toast('Access revoked')
  } catch {
    toast('Could not revoke access. Please try again.', true)
  }
}

function doDownload(msgId) {
  const text = plaintextCache.get(msgId)
  if (!text) { toast('Message content not available', true); return }
  const blob = new Blob([text], { type: 'text/plain' })
  const url  = URL.createObjectURL(blob)
  const a    = document.createElement('a')
  a.href     = url
  a.download = `message-${msgId.slice(0, 8)}.txt`
  document.body.appendChild(a)
  a.click()
  document.body.removeChild(a)
  URL.revokeObjectURL(url)
}

// ── Forward ───────────────────────────────────────────────────────────────
function openForwardModal(msgId) {
  S.forwardTargetMsgId = msgId
  id('fwd-user').value = ''
  id('fwd-err').style.display = 'none'
  id('forward-modal').hidden = false
}

function closeForwardModal() {
  id('forward-modal').hidden = true
  S.forwardTargetMsgId = null
}

async function doForward() {
  const targetUser = id('fwd-user').value.trim()
  const errEl      = id('fwd-err')
  errEl.style.display = 'none'
  if (!targetUser) return showErr(errEl, 'Enter a username.')
  const plaintext = plaintextCache.get(S.forwardTargetMsgId)
  if (!plaintext) return showErr(errEl, 'Message content not available.')
  try {
    const encrypted = await hpkeEncrypt(plaintext, targetUser)
    if (encrypted.warned) toast(`⚠ Key changed for ${targetUser}`, true)
    await api('POST', `/messages/${S.forwardTargetMsgId}/forward`, {
      forward_to_username: targetUser,
      ciphertext:          encrypted.ciphertext,
      encapsulated_key:    encrypted.encapsulated_key,
      sent_at_ms:          encrypted.sentAtMs,
    })
    cacheSentMsg(`fwd-${Date.now()}`, plaintext, targetUser)
    closeForwardModal()
    toast('Message forwarded')
    loadConversations()
  } catch (e) {
    showErr(errEl, e.message)
  }
}

// ── New conversation ──────────────────────────────────────────────────────
function openNewConvModal() {
  id('new-conv-user').value = ''
  id('new-conv-err').style.display = 'none'
  id('new-conv-modal').hidden = false
}

function closeNewConvModal() {
  id('new-conv-modal').hidden = true
}

async function startNewConv() {
  const username = id('new-conv-user').value.trim()
  const errEl    = id('new-conv-err')
  errEl.style.display = 'none'
  if (!username) return showErr(errEl, 'Enter a username.')
  if (username === S.username) return showErr(errEl, 'Cannot message yourself.')
  try {
    const { warned } = await fetchPeerKey(username)
    if (warned) toast(`Key changed for ${username} since last contact — TOFU warning`, true)
    closeNewConvModal()
    const existing = document.querySelector(`.conv-item[data-peer="${username}"]`)
    if (existing) {
      openConv(existing.dataset.id, username)
      return
    }
    S.currentConvId = null
    S.currentPeer   = username
    id('empty-state').style.display = 'none'
    id('chat-view').style.display   = 'flex'
    id('chat-avatar').textContent   = username[0].toUpperCase()
    id('chat-name').textContent     = username
    id('messages-area').innerHTML   =
      '<div class="loading-row" style="color:#555">Send a message to start this conversation.</div>'
    id('compose-input').focus()
  } catch (e) {
    showErr(errEl, e.message)
  }
}

// ── UI helpers ────────────────────────────────────────────────────────────
function id(x) { return document.getElementById(x) }

function esc(s) {
  return String(s)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
}

function showErr(el, msg) { el.textContent = msg; el.style.display = 'block' }

let toastTimer
function toast(msg, isErr = false) {
  const el = id('toast')
  el.textContent = msg
  el.className   = isErr ? 'err' : 'ok'
  el.style.display = 'block'
  clearTimeout(toastTimer)
  toastTimer = setTimeout(() => { el.style.display = 'none' }, 3000)
}

function relTime(d) {
  const diff = Date.now() - d.getTime()
  const min  = Math.floor(diff / 60000)
  if (min < 1)  return 'just now'
  if (min < 60) return `${min}m ago`
  const hr = Math.floor(min / 60)
  if (hr < 24)  return `${hr}h ago`
  return d.toLocaleDateString()
}

function fmtTime(d) {
  return d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })
}

function autoResize(el) {
  el.style.height = 'auto'
  el.style.height = Math.min(el.scrollHeight, 120) + 'px'
}

function showTab(tab) {
  id('form-login').style.display    = tab === 'login'    ? 'block' : 'none'
  id('form-register').style.display = tab === 'register' ? 'block' : 'none'
  id('tab-login').classList.toggle('active',    tab === 'login')
  id('tab-register').classList.toggle('active', tab === 'register')
}

// ── Event delegation: conversation list ──────────────────────────────────
id('conv-list').addEventListener('click', e => {
  const item = e.target.closest('.conv-item')
  if (!item) return
  openConv(item.dataset.id, item.dataset.peer)
})

// ── Event delegation: message actions ────────────────────────────────────
id('messages-area').addEventListener('click', e => {
  const btn = e.target.closest('[data-action]')
  if (!btn) return
  const { action, msgId } = btn.dataset
  if (action === 'download') doDownload(msgId)
  else if (action === 'forward') openForwardModal(msgId)
  else if (action === 'revoke') doRevoke(msgId)
  else if (action === 'delete') doDelete(msgId)
})

// ── Static element listeners ──────────────────────────────────────────────
id('tab-login').addEventListener('click', () => showTab('login'))
id('tab-register').addEventListener('click', () => showTab('register'))
id('login-btn').addEventListener('click', doLogin)
id('reg-btn').addEventListener('click', doRegister)
id('logout-btn').addEventListener('click', doLogout)
id('change-pass-btn').addEventListener('click', openChangePassModal)
id('cancel-change-pass-btn').addEventListener('click', closeChangePassModal)
id('do-change-pass-btn').addEventListener('click', doChangePassword)
id('cp-confirm').addEventListener('keydown', e => e.key === 'Enter' && doChangePassword())
id('change-pass-modal').addEventListener('click', e => {
  if (e.target === id('change-pass-modal')) closeChangePassModal()
})
id('new-conv-btn').addEventListener('click', openNewConvModal)
id('cancel-new-conv-btn').addEventListener('click', closeNewConvModal)
id('start-conv-btn').addEventListener('click', startNewConv)
id('cancel-fwd-btn').addEventListener('click', closeForwardModal)
id('do-fwd-btn').addEventListener('click', doForward)
id('send-btn').addEventListener('click', doSend)
id('compose-input').addEventListener('keydown', e => {
  if (e.key === 'Enter' && !e.shiftKey) { e.preventDefault(); doSend() }
})
id('compose-input').addEventListener('input', e => autoResize(e.target))
id('l-pass').addEventListener('keydown', e => e.key === 'Enter' && doLogin())
id('r-pass').addEventListener('keydown', e => e.key === 'Enter' && doRegister())
id('new-conv-user').addEventListener('keydown', e => e.key === 'Enter' && startNewConv())
id('fwd-user').addEventListener('keydown', e => e.key === 'Enter' && doForward())

id('new-conv-modal').addEventListener('click', e => {
  if (e.target === id('new-conv-modal')) closeNewConvModal()
})
id('forward-modal').addEventListener('click', e => {
  if (e.target === id('forward-modal')) closeForwardModal()
})
