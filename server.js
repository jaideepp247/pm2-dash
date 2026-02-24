const express = require('express');
const http = require('http');
const WebSocket = require('ws');
const pm2 = require('pm2');
const si = require('systeminformation');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const bcrypt = require('bcrypt');
const { EventEmitter } = require('events');

const app = express();
const server = http.createServer(app);
const wss = new WebSocket.Server({ server });

const PORT = process.env.PORT || 3099;
const LOG_LINES = 200;
const SESSION_TTL = parseInt(process.env.SESSION_TTL_HOURS || '24', 10) * 3600_000;
const USERS_FILE  = path.resolve(__dirname, 'users.json');

// ── Auth ──────────────────────────────────────────────────────────────────────
const sessions = new Map();

function loadUsers() {
  if (!fs.existsSync(USERS_FILE)) {
    console.error('\n✖  users.json not found. Run: node setup.js\n');
    process.exit(1);
  }
  return JSON.parse(fs.readFileSync(USERS_FILE, 'utf8'));
}

async function findUser(username, password) {
  const users = loadUsers();
  const user = users.find(u => u.username === username);
  if (!user) return null;
  const ok = await bcrypt.compare(password, user.passwordHash);
  return ok ? { username: user.username, readonly: !!user.readonly } : null;
}

function createSession(user) {
  const token = crypto.randomBytes(32).toString('hex');
  sessions.set(token, { ...user, expiresAt: Date.now() + SESSION_TTL });
  return token;
}

function getSession(token) {
  if (!token) return null;
  const s = sessions.get(token);
  if (!s) return null;
  if (Date.now() > s.expiresAt) { sessions.delete(token); return null; }
  s.expiresAt = Date.now() + SESSION_TTL;
  return s;
}

function parseCookies(req) {
  const c = {};
  (req.headers.cookie || '').split(';').forEach(part => {
    const [k, ...v] = part.trim().split('=');
    if (k) c[k.trim()] = decodeURIComponent(v.join('='));
  });
  return c;
}

app.use(express.urlencoded({ extended: false }));

app.get('/login', (req, res) => {
  if (getSession(parseCookies(req).sid)) return res.redirect('/');
  res.send(loginPage());
});

app.post('/login', async (req, res) => {
  const user = await findUser(req.body.username || '', req.body.password || '');
  if (!user) return res.send(loginPage('Invalid username or password'));
  const token = createSession(user);
  res.setHeader('Set-Cookie', `sid=${token}; HttpOnly; Path=/; Max-Age=${SESSION_TTL / 1000}`);
  res.redirect('/');
});

app.get('/logout', (req, res) => {
  sessions.delete(parseCookies(req).sid);
  res.setHeader('Set-Cookie', 'sid=; HttpOnly; Path=/; Max-Age=0');
  res.redirect('/login');
});

// Main dashboard — injects session token into page so WS can use it in URL
// (cookies are unreliable on WS upgrades over plain HTTP to an IP address)
app.get('/', (req, res) => {
  const session = getSession(parseCookies(req).sid);
  if (!session) return res.redirect('/login');
  res.send(getFrontend({ ...session, token: parseCookies(req).sid }));
});

// ── PM2 log tailer ────────────────────────────────────────────────────────────
class LogTailer extends EventEmitter {
  constructor() {
    super();
    this._watchers = {};
    this._buffers = {};
  }

  start(procs) {
    Object.keys(this._watchers).forEach(id => {
      if (!procs.find(p => String(p.pm_id) === id)) this._stopWatcher(id);
    });

    procs.forEach(proc => {
      const id = String(proc.pm_id);
      const logFile = proc.pm2_env && proc.pm2_env.pm_out_log_path;
      const errFile = proc.pm2_env && proc.pm2_env.pm_err_log_path;
      if (logFile) this._watchFile(id, proc.name, logFile, 'out');
      if (errFile && errFile !== logFile) this._watchFile(id, proc.name, errFile, 'err');
    });
  }

  _watchFile(id, name, filePath, stream) {
    if (!fs.existsSync(filePath)) return;

    const key = `${id}:${stream}`;
    if (this._watchers[key]) return;

    if (!this._buffers[id]) this._buffers[id] = [];

    try {
      const content = fs.readFileSync(filePath, 'utf8');
      const lines = content.split('\n').filter(Boolean).slice(-LOG_LINES);
      lines.forEach(line => {
        const entry = { id, name, stream, line, ts: Date.now() };
        this._buffers[id].push(entry);
      });
      if (this._buffers[id].length > LOG_LINES) {
        this._buffers[id] = this._buffers[id].slice(-LOG_LINES);
      }
    } catch (_) {}

    let size = 0;
    try { size = fs.statSync(filePath).size; } catch (_) {}

    const watcher = fs.watch(filePath, () => {
      try {
        const stat = fs.statSync(filePath);
        if (stat.size < size) { size = 0; }
        const diff = stat.size - size;
        if (diff <= 0) return;
        const buf = Buffer.alloc(diff);
        const fd = fs.openSync(filePath, 'r');
        fs.readSync(fd, buf, 0, diff, size);
        fs.closeSync(fd);
        size = stat.size;
        const text = buf.toString('utf8');
        text.split('\n').filter(Boolean).forEach(line => {
          const entry = { id, name, stream, line, ts: Date.now() };
          this._buffers[id].push(entry);
          if (this._buffers[id].length > LOG_LINES) this._buffers[id].shift();
          this.emit('log', entry);
        });
      } catch (_) {}
    });

    this._watchers[key] = watcher;
  }

  _stopWatcher(id) {
    Object.keys(this._watchers).forEach(key => {
      if (key.startsWith(id + ':')) {
        try { this._watchers[key].close(); } catch (_) {}
        delete this._watchers[key];
      }
    });
    delete this._buffers[id];
  }

  getBuffer(id) {
    return this._buffers[id] || [];
  }
}

const tailer = new LogTailer();

// ── PM2 helpers ───────────────────────────────────────────────────────────────
function connectPm2() {
  return new Promise((resolve, reject) => {
    pm2.connect(err => err ? reject(err) : resolve());
  });
}

function listProcs() {
  return new Promise((resolve, reject) => {
    pm2.list((err, list) => err ? reject(err) : resolve(list));
  });
}

function mapProc(p) {
  return {
    id: p.pm_id,
    name: p.name,
    status: p.pm2_env ? p.pm2_env.status : 'unknown',
    cpu: p.monit ? p.monit.cpu : 0,
    mem: p.monit ? p.monit.memory : 0,
    uptime: p.pm2_env ? p.pm2_env.pm_uptime : null,
    restarts: p.pm2_env ? p.pm2_env.restart_time : 0,
    pid: p.pid,
    instances: p.pm2_env ? p.pm2_env.instances : 1,
  };
}

// ── Broadcast ─────────────────────────────────────────────────────────────────
function broadcast(data) {
  const msg = JSON.stringify(data);
  wss.clients.forEach(ws => {
    if (ws.readyState === WebSocket.OPEN) ws.send(msg);
  });
}

// ── Polling loops ─────────────────────────────────────────────────────────────
async function pollProcs() {
  try {
    const list = await listProcs();
    tailer.start(list);
    broadcast({ type: 'procs', data: list.map(mapProc) });
  } catch (_) {}
}

async function pollSystem() {
  try {
    const [cpu, mem, disk] = await Promise.all([
      si.currentLoad(),
      si.mem(),
      si.fsSize(),
    ]);
    broadcast({
      type: 'system',
      data: {
        cpuLoad: cpu.currentLoad.toFixed(1),
        memTotal: mem.total,
        memUsed: mem.active,
        disk: disk.slice(0, 4).map(d => ({
          fs: d.fs, mount: d.mount, size: d.size, used: d.used, use: d.use,
        })),
      },
    });
  } catch (_) {}
}

// ── WebSocket — token from URL query param (works on plain HTTP + IP) ─────────
wss.on('connection', async (ws, req) => {
  const url = new URL(req.url, 'http://x');
  const token = url.searchParams.get('token') || parseCookies(req).sid;
  const session = getSession(token);
  if (!session) { ws.close(); return; }

  ws._readonly = session.readonly;

  try {
    const list = await listProcs();
    ws.send(JSON.stringify({ type: 'procs', data: list.map(mapProc) }));

    list.forEach(p => {
      const id = String(p.pm_id);
      const buf = tailer.getBuffer(id);
      buf.forEach(entry => {
        if (ws.readyState === WebSocket.OPEN)
          ws.send(JSON.stringify({ type: 'log', data: entry }));
      });
    });
  } catch (_) {}

  ws.on('message', raw => {
    try {
      const msg = JSON.parse(raw);
      if (msg.type === 'action' && !ws._readonly) {
        const { action, id } = msg;
        if (action === 'restart') pm2.restart(id, () => {});
        if (action === 'stop')    pm2.stop(id, () => {});
        if (action === 'delete')  pm2.delete(id, () => {});
        if (action === 'flush')   pm2.flush(id, () => {});
      }
    } catch (_) {}
  });
});

tailer.on('log', entry => broadcast({ type: 'log', data: entry }));

// ── Boot ──────────────────────────────────────────────────────────────────────
(async () => {
  await connectPm2();
  console.log('✓ Connected to PM2');
  await pollProcs();
  await pollSystem();
  setInterval(pollProcs,  2000);
  setInterval(pollSystem, 3000);
  server.listen(PORT, () => {
    console.log(`\n  PM2 Dashboard → http://localhost:${PORT}\n`);
  });
})();

// ── Login page ────────────────────────────────────────────────────────────────
function loginPage(error = '') {
  return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"/><meta name="viewport" content="width=device-width,initial-scale=1"/>
<title>PM2 Dashboard — Login</title>
<link href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;600&family=Syne:wght@800&display=swap" rel="stylesheet"/>
<style>
*{box-sizing:border-box;margin:0;padding:0}
body{min-height:100vh;background:#080c10;display:flex;align-items:center;justify-content:center;font-family:'JetBrains Mono',monospace}
.card{background:#0d1117;border:1px solid #1e2d3d;border-radius:12px;padding:40px;width:340px}
h1{font-family:'Syne',sans-serif;font-size:22px;font-weight:800;color:#00d4ff;margin-bottom:6px}
.sub{font-size:11px;color:#4a6070;margin-bottom:28px}
label{display:block;font-size:10px;color:#4a6070;text-transform:uppercase;letter-spacing:1px;margin-bottom:5px}
input{width:100%;background:#0a0f14;border:1px solid #1e2d3d;border-radius:6px;padding:10px 12px;color:#e2e8f0;font-family:'JetBrains Mono',monospace;font-size:13px;outline:none;margin-bottom:18px}
input:focus{border-color:#00d4ff}
button{width:100%;background:#00d4ff;color:#000;border:none;border-radius:6px;padding:11px;font-family:'JetBrains Mono',monospace;font-size:13px;font-weight:600;cursor:pointer}
button:hover{opacity:.85}
.err{background:rgba(255,23,68,.1);border:1px solid rgba(255,23,68,.3);border-radius:6px;padding:9px 12px;color:#ff1744;font-size:12px;margin-bottom:18px}
</style>
</head>
<body>
<div class="card">
  <h1>pm2dash</h1>
  <div class="sub">Sign in to continue</div>
  ${error ? `<div class="err">${error}</div>` : ''}
  <form method="POST" action="/login">
    <label>Username</label><input type="text" name="username" autofocus autocomplete="username"/>
    <label>Password</label><input type="password" name="password" autocomplete="current-password"/>
    <button type="submit">Sign in →</button>
  </form>
</div>
</body></html>`;
}

// ── Dashboard ─────────────────────────────────────────────────────────────────
function getFrontend({ username, readonly, token }) {
  return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"/>
<meta name="viewport" content="width=device-width,initial-scale=1"/>
<title>PM2 Dashboard</title>
<link rel="preconnect" href="https://fonts.googleapis.com"/>
<link href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@300;400;600&family=Syne:wght@400;700;800&display=swap" rel="stylesheet"/>
<style>
*,*::before,*::after{box-sizing:border-box;margin:0;padding:0}
:root{
  --bg:#080c10;
  --surface:#0d1117;
  --surface2:#131920;
  --border:#1e2d3d;
  --accent:#00d4ff;
  --accent2:#7c3aed;
  --green:#00e676;
  --red:#ff1744;
  --yellow:#ffd740;
  --text:#e2e8f0;
  --muted:#4a6070;
  --font-mono:'JetBrains Mono',monospace;
  --font-sans:'Syne',sans-serif;
}
html,body{height:100%;background:var(--bg);color:var(--text);font-family:var(--font-mono);font-size:13px;overflow:hidden}

#app{display:grid;grid-template-rows:56px 1fr;height:100vh}
#topbar{display:flex;align-items:center;gap:16px;padding:0 24px;border-bottom:1px solid var(--border);background:var(--surface);z-index:10}
#topbar h1{font-family:var(--font-sans);font-size:18px;font-weight:800;letter-spacing:-0.5px;color:var(--accent)}
#topbar h1 span{color:var(--muted)}
.conn-dot{width:8px;height:8px;border-radius:50%;background:var(--red);transition:background .3s}
.conn-dot.ok{background:var(--green);box-shadow:0 0 8px var(--green)}
.badge{font-size:9px;padding:2px 7px;border-radius:20px;border:1px solid;text-transform:uppercase;letter-spacing:.5px}
.badge.ro{color:var(--yellow);border-color:var(--yellow)}.badge.rw{color:var(--green);border-color:var(--green)}
.logout{font-size:10px;color:var(--muted);text-decoration:none;padding:3px 9px;border:1px solid var(--border);border-radius:4px;transition:all .15s}
.logout:hover{color:var(--text);border-color:var(--accent)}

#body{display:grid;grid-template-columns:280px 1fr;overflow:hidden}

#sidebar{border-right:1px solid var(--border);background:var(--surface);display:flex;flex-direction:column;overflow:hidden}
#sys-stats{padding:16px;border-bottom:1px solid var(--border);display:flex;flex-direction:column;gap:10px}
.stat-label{font-size:10px;color:var(--muted);text-transform:uppercase;letter-spacing:1px;margin-bottom:4px}
.stat-value{font-size:18px;font-weight:600;color:var(--text)}
.bar-wrap{height:4px;background:var(--border);border-radius:2px;overflow:hidden;margin-top:4px}
.bar-fill{height:100%;border-radius:2px;transition:width .5s ease;background:var(--accent)}
.bar-fill.warn{background:var(--yellow)}.bar-fill.danger{background:var(--red)}
#disk-list{padding:0 16px 8px;display:flex;flex-direction:column;gap:6px}
.disk-item{font-size:10px;color:var(--muted)}.disk-item b{color:var(--text)}

#proc-list{flex:1;overflow-y:auto;padding:8px}
#proc-list::-webkit-scrollbar{width:4px}
#proc-list::-webkit-scrollbar-thumb{background:var(--border)}
.proc-card{padding:10px 12px;border-radius:6px;border:1px solid transparent;cursor:pointer;transition:all .15s;margin-bottom:4px;background:var(--surface2)}
.proc-card:hover{border-color:var(--border)}.proc-card.active{border-color:var(--accent);background:#0a1929}
.proc-header{display:flex;align-items:center;gap:8px;margin-bottom:6px}
.proc-dot{width:7px;height:7px;border-radius:50%;flex-shrink:0}
.proc-dot.online{background:var(--green);box-shadow:0 0 6px var(--green)}
.proc-dot.stopped,.proc-dot.stopping{background:var(--muted)}
.proc-dot.errored,.proc-dot.error{background:var(--red);box-shadow:0 0 6px var(--red)}
.proc-dot.launching{background:var(--yellow);animation:pulse 1s infinite}
@keyframes pulse{0%,100%{opacity:1}50%{opacity:.4}}
.proc-name{font-weight:600;font-size:12px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;flex:1}
.proc-id{font-size:10px;color:var(--muted)}
.proc-meta{display:flex;gap:8px;font-size:10px;color:var(--muted)}
.proc-meta span{display:flex;align-items:center;gap:3px}
.proc-actions{display:flex;gap:4px;margin-top:8px}
.btn{padding:3px 8px;border-radius:4px;border:1px solid var(--border);background:transparent;color:var(--muted);font-family:var(--font-mono);font-size:10px;cursor:pointer;transition:all .15s}
.btn:hover{color:var(--text);border-color:var(--accent)}.btn.danger:hover{color:var(--red);border-color:var(--red)}

#main{display:flex;flex-direction:column;overflow:hidden;background:var(--bg)}
#log-header{display:flex;align-items:center;gap:12px;padding:12px 20px;border-bottom:1px solid var(--border);background:var(--surface);flex-shrink:0}
#log-title{font-family:var(--font-sans);font-size:14px;font-weight:700;color:var(--text)}
#log-filter{margin-left:auto;display:flex;gap:6px;align-items:center}
#log-search{background:var(--surface2);border:1px solid var(--border);border-radius:4px;padding:4px 10px;color:var(--text);font-family:var(--font-mono);font-size:11px;width:180px;outline:none;transition:border .15s}
#log-search:focus{border-color:var(--accent)}
.filter-btn{padding:3px 10px;border-radius:4px;border:1px solid var(--border);background:transparent;color:var(--muted);font-family:var(--font-mono);font-size:10px;cursor:pointer;transition:all .15s}
.filter-btn.active{background:var(--accent);color:#000;border-color:var(--accent)}
.filter-btn.err-active{background:var(--red);color:#fff;border-color:var(--red)}
#clear-btn{padding:3px 8px;border-radius:4px;border:1px solid var(--border);background:transparent;color:var(--muted);font-family:var(--font-mono);font-size:10px;cursor:pointer}
#clear-btn:hover{color:var(--red);border-color:var(--red)}
#autoscroll-toggle{display:flex;align-items:center;gap:5px;font-size:10px;color:var(--muted);cursor:pointer;user-select:none}
#autoscroll-toggle input{accent-color:var(--accent)}

#log-wrap{flex:1;overflow-y:auto;padding:8px 0;scroll-behavior:auto}
#log-wrap::-webkit-scrollbar{width:4px}
#log-wrap::-webkit-scrollbar-thumb{background:var(--border)}

.log-line{display:flex;gap:10px;padding:1px 20px;line-height:1.6;font-size:12px;animation:fadein .1s ease}
@keyframes fadein{from{opacity:0}to{opacity:1}}
.log-line:hover{background:rgba(255,255,255,.02)}
.log-line.is-err{background:rgba(255,23,68,.04)}
.log-ts{color:var(--muted);flex-shrink:0;font-size:10px;padding-top:2px;width:75px}
.log-proc{color:var(--accent2);flex-shrink:0;width:100px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;font-weight:600}
.log-stream{font-size:9px;flex-shrink:0;width:24px;text-align:center;padding-top:2px;border-radius:2px}
.log-stream.out{color:#1a5c1a;background:rgba(0,230,118,.07)}
.log-stream.err{color:var(--red);background:rgba(255,23,68,.12)}
.log-text{color:var(--text);word-break:break-all;white-space:pre-wrap}
.log-text.err{color:#ff8a80}

#empty-state{display:flex;flex-direction:column;align-items:center;justify-content:center;height:100%;color:var(--muted);gap:12px}
#empty-state svg{opacity:.3}
#empty-state p{font-size:12px}
</style>
</head>
<body>
<div id="app">
  <div id="topbar">
    <h1>pm2<span>dash</span></h1>
    <span class="badge ${readonly ? 'ro' : 'rw'}">${readonly ? 'read-only' : 'admin'}</span>
    <div id="proc-count" style="font-size:11px;color:var(--muted)">connecting...</div>
    <div class="conn-dot" id="conn-dot"></div>
    <span style="font-size:10px;color:var(--muted);margin-left:auto">${username}</span>
    <a href="/logout" class="logout">logout</a>
  </div>
  <div id="body">
    <div id="sidebar">
      <div id="sys-stats">
        <div>
          <div class="stat-label">CPU</div>
          <div style="display:flex;align-items:baseline;gap:6px">
            <div class="stat-value" id="cpu-val">—</div>
            <div style="font-size:10px;color:var(--muted)">%</div>
          </div>
          <div class="bar-wrap"><div class="bar-fill" id="cpu-bar" style="width:0%"></div></div>
        </div>
        <div>
          <div class="stat-label">RAM</div>
          <div style="display:flex;align-items:baseline;gap:6px">
            <div class="stat-value" id="mem-val">—</div>
            <div style="font-size:10px;color:var(--muted)" id="mem-total"></div>
          </div>
          <div class="bar-wrap"><div class="bar-fill" id="mem-bar" style="width:0%"></div></div>
        </div>
        <div id="disk-list"></div>
      </div>
      <div style="padding:8px 16px 4px;font-size:10px;color:var(--muted);text-transform:uppercase;letter-spacing:1px">Processes</div>
      <div id="proc-list"></div>
    </div>
    <div id="main">
      <div id="log-header">
        <div id="log-title">All processes</div>
        <div id="log-filter">
          <input id="log-search" type="text" placeholder="filter logs..."/>
          <button class="filter-btn active" data-stream="all">all</button>
          <button class="filter-btn" data-stream="out">stdout</button>
          <button class="filter-btn" data-stream="err">stderr</button>
          <button id="clear-btn">clear</button>
          <label id="autoscroll-toggle"><input type="checkbox" id="autoscroll" checked/> autoscroll</label>
        </div>
      </div>
      <div id="log-wrap">
        <div id="empty-state">
          <svg width="48" height="48" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="1" d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z"/></svg>
          <p>No logs yet — waiting for processes...</p>
        </div>
        <div id="log-lines"></div>
      </div>
    </div>
  </div>
</div>

<script>
const READONLY = ${JSON.stringify(readonly)};
const WS_TOKEN = ${JSON.stringify(token)};
const MAX_LINES = 500;
let logs = [];
let procs = {};
let activeProcId = null;
let streamFilter = 'all';
let searchText = '';
let autoScroll = true;

const $procList   = document.getElementById('proc-list');
const $logLines   = document.getElementById('log-lines');
const $emptyState = document.getElementById('empty-state');
const $logWrap    = document.getElementById('log-wrap');
const $logTitle   = document.getElementById('log-title');
const $connDot    = document.getElementById('conn-dot');
const $procCount  = document.getElementById('proc-count');

// ── WebSocket — token in URL, reliable on plain HTTP + IP ────────────────────
let ws, reconnectTimer;
function connect() {
  const proto = location.protocol === 'https:' ? 'wss' : 'ws';
  ws = new WebSocket(\`\${proto}://\${location.host}/?token=\${WS_TOKEN}\`);

  ws.onopen = () => {
    $connDot.classList.add('ok');
    clearTimeout(reconnectTimer);
  };
  ws.onclose = () => {
    $connDot.classList.remove('ok');
    reconnectTimer = setTimeout(connect, 2000);
  };
  ws.onmessage = e => {
    const msg = JSON.parse(e.data);
    if (msg.type === 'procs')  handleProcs(msg.data);
    if (msg.type === 'log')    handleLog(msg.data);
    if (msg.type === 'system') handleSystem(msg.data);
  };
}
connect();

function send(obj) { if (ws && ws.readyState === 1) ws.send(JSON.stringify(obj)); }

// ── System stats ──────────────────────────────────────────────────────────────
function handleSystem({cpuLoad, memTotal, memUsed, disk}) {
  const cpu = parseFloat(cpuLoad);
  document.getElementById('cpu-val').textContent = cpu.toFixed(1);
  setBar('cpu-bar', cpu);

  const memPct = (memUsed / memTotal * 100);
  document.getElementById('mem-val').textContent = fmt(memUsed);
  document.getElementById('mem-total').textContent = '/ ' + fmt(memTotal);
  setBar('mem-bar', memPct);

  const \$dl = document.getElementById('disk-list');
  \$dl.innerHTML = disk.map(d => \`
    <div class="disk-item">
      <b>\${d.mount}</b> — \${fmt(d.used)} / \${fmt(d.size)}
      <div class="bar-wrap"><div class="bar-fill\${d.use>85?' danger':d.use>65?' warn':''}" style="width:\${d.use}%"></div></div>
    </div>
  \`).join('');
}

function setBar(id, pct) {
  const el = document.getElementById(id);
  el.style.width = Math.min(pct, 100) + '%';
  el.className = 'bar-fill' + (pct > 85 ? ' danger' : pct > 65 ? ' warn' : '');
}

function fmt(bytes) {
  if (bytes >= 1e9) return (bytes/1e9).toFixed(1) + ' GB';
  if (bytes >= 1e6) return (bytes/1e6).toFixed(0) + ' MB';
  return (bytes/1e3).toFixed(0) + ' KB';
}

// ── Processes ─────────────────────────────────────────────────────────────────
function handleProcs(list) {
  procs = {};
  list.forEach(p => { procs[p.id] = p; });
  $procCount.textContent = list.length + ' process' + (list.length !== 1 ? 'es' : '');
  renderProcList(list);
}

function renderProcList(list) {
  const scrollY = $procList.scrollTop;
  $procList.innerHTML = list.map(p => {
    const mem = fmt(p.mem || 0);
    const uptime = p.uptime ? elapsed(Date.now() - p.uptime) : '—';
    const active = activeProcId == p.id;
    const actions = READONLY ? '' : \`
      <div class="proc-actions" onclick="event.stopPropagation()">
        <button class="btn" onclick="action('restart',\${p.id})">restart</button>
        <button class="btn" onclick="action('stop',\${p.id})">stop</button>
        <button class="btn danger" onclick="action('delete',\${p.id})">delete</button>
      </div>\`;
    return \`
      <div class="proc-card\${active?' active':''}" data-id="\${p.id}" onclick="selectProc(\${p.id})">
        <div class="proc-header">
          <div class="proc-dot \${p.status}"></div>
          <div class="proc-name">\${p.name}</div>
          <div class="proc-id">#\${p.id}</div>
        </div>
        <div class="proc-meta">
          <span>CPU: \${(p.cpu||0).toFixed(1)}%</span>
          <span>MEM: \${mem}</span>
          <span>\${p.status}</span>
        </div>
        <div class="proc-meta" style="margin-top:2px">
          <span>↑ \${uptime}</span>
          <span>restarts: \${p.restarts}</span>
        </div>
        \${actions}
      </div>\`;
  }).join('');
  $procList.scrollTop = scrollY;
}

function selectProc(id) {
  activeProcId = (activeProcId === id) ? null : id;
  $logTitle.textContent = activeProcId !== null ? (procs[activeProcId]?.name || 'Process '+id) : 'All processes';
  renderProcList(Object.values(procs));
  renderLogs();
}

function action(type, id) {
  send({ type: 'action', action: type, id });
}

// ── Logs ──────────────────────────────────────────────────────────────────────
function handleLog(entry) {
  $emptyState.style.display = 'none';
  logs.push(entry);
  if (logs.length > MAX_LINES * 2) logs = logs.slice(-MAX_LINES);
  if (matchesFilter(entry)) {
    appendLogLine(entry);
    if (autoScroll) $logWrap.scrollTop = $logWrap.scrollHeight;
  }
}

function matchesFilter(entry) {
  if (activeProcId !== null && String(entry.id) !== String(activeProcId)) return false;
  if (streamFilter !== 'all' && entry.stream !== streamFilter) return false;
  if (searchText && !entry.line.toLowerCase().includes(searchText)) return false;
  return true;
}

function appendLogLine(entry) {
  const el = document.createElement('div');
  const isErr = entry.stream === 'err';
  el.className = 'log-line' + (isErr ? ' is-err' : '');
  const ts = new Date(entry.ts).toTimeString().slice(0, 8);
  el.innerHTML = \`
    <span class="log-ts">\${ts}</span>
    <span class="log-proc" title="\${entry.name}">\${entry.name}</span>
    <span class="log-stream \${entry.stream}">\${entry.stream}</span>
    <span class="log-text\${isErr?' err':''}">\${escHtml(entry.line)}</span>
  \`;
  $logLines.appendChild(el);
  while ($logLines.children.length > MAX_LINES) {
    $logLines.removeChild($logLines.firstChild);
  }
}

function renderLogs() {
  $logLines.innerHTML = '';
  const filtered = logs.filter(matchesFilter).slice(-MAX_LINES);
  if (filtered.length) $emptyState.style.display = 'none';
  filtered.forEach(appendLogLine);
  if (autoScroll) $logWrap.scrollTop = $logWrap.scrollHeight;
}

function escHtml(s) {
  return s.replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');
}

// ── Controls ──────────────────────────────────────────────────────────────────
document.querySelectorAll('.filter-btn').forEach(btn => {
  btn.addEventListener('click', () => {
    document.querySelectorAll('.filter-btn').forEach(b => b.classList.remove('active', 'err-active'));
    btn.classList.add(btn.dataset.stream === 'err' ? 'err-active' : 'active');
    streamFilter = btn.dataset.stream;
    renderLogs();
  });
});

document.getElementById('log-search').addEventListener('input', e => {
  searchText = e.target.value.toLowerCase();
  renderLogs();
});

document.getElementById('clear-btn').addEventListener('click', () => {
  logs = [];
  $logLines.innerHTML = '';
  $emptyState.style.display = 'flex';
});

document.getElementById('autoscroll').addEventListener('change', e => {
  autoScroll = e.target.checked;
});

$logWrap.addEventListener('scroll', () => {
  const atBottom = $logWrap.scrollHeight - $logWrap.scrollTop - $logWrap.clientHeight < 50;
  if (!atBottom && autoScroll) {
    document.getElementById('autoscroll').checked = false;
    autoScroll = false;
  }
});

// ── Utils ─────────────────────────────────────────────────────────────────────
function elapsed(ms) {
  const s = Math.floor(ms/1000);
  if (s < 60) return s + 's';
  const m = Math.floor(s/60);
  if (m < 60) return m + 'm';
  const h = Math.floor(m/60);
  if (h < 24) return h + 'h';
  return Math.floor(h/24) + 'd';
}
</script>
</body>
</html>`;
}
