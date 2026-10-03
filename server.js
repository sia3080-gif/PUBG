// PUBG 온라인 서버 — 외부 패키지 없이 Node.js(18+)만으로 동작합니다.
//   실행:  node server.js        (기본 포트 3000, PORT 환경변수로 변경)
//   접속:  http://localhost:3000  (같은 주소가 게임 화면 + API + 웹소켓을 모두 제공)
'use strict';
const http = require('http');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const zlib = require('zlib');

const PORT = +process.env.PORT || 3000;
const DATA_FILE = process.env.DATA_FILE || path.join(__dirname, 'data.json');
const PUBLIC = path.join(__dirname, 'public');
const MAX_PARTY = 4;

/* ───────────── 저장소 (JSON 파일) ───────────── */
let DB = { users: {} };
try { DB = JSON.parse(fs.readFileSync(DATA_FILE, 'utf8')); if (!DB.users) DB.users = {}; } catch (e) { /* 첫 실행 */ }
let saveTimer = null;
function save() {
  if (saveTimer) return;
  saveTimer = setTimeout(() => {
    saveTimer = null;
    fs.writeFile(DATA_FILE + '.tmp', JSON.stringify(DB), err => {
      if (!err) fs.rename(DATA_FILE + '.tmp', DATA_FILE, () => {});
    });
  }, 500);
}
const NAME_RE = /^[A-Za-z0-9_가-힣]{2,16}$/;
const hashPw = (pw, salt) => crypto.scryptSync(pw, salt, 32).toString('hex');
const userByToken = tok => {
  if (typeof tok !== 'string') return null;
  for (const [n, u] of Object.entries(DB.users)) if (u.tokens && u.tokens.includes(tok)) return n;
  return null;
};
function newToken(name) {
  const u = DB.users[name], t = crypto.randomBytes(24).toString('hex');
  u.tokens = (u.tokens || []).concat(t).slice(-5);
  save();
  return t;
}

/* ───────────── HTTP API ───────────── */
const MIME = { '.html': 'text/html; charset=utf-8', '.js': 'text/javascript', '.css': 'text/css', '.png': 'image/png', '.jpg': 'image/jpeg', '.ico': 'image/x-icon', '.json': 'application/json' };
const GZ = new Map();     // 압축된 정적 파일 캐시
const failBy = new Map(); // 로그인 무차별 대입 방지 (IP별)
function api(p, b, ip) {
  b = b || {};
  if (p === '/api/signup') {
    const u = String(b.u || ''), pw = String(b.p || '');
    if (!NAME_RE.test(u) || pw.length < 4 || pw.length > 100) return { e: '아이디는 2~16자, 비밀번호는 4자 이상이에요' };
    if (DB.users[u]) return { e: '이미 있는 아이디예요' };
    const salt = crypto.randomBytes(16).toString('hex');
    DB.users[u] = { salt, h: hashPw(pw, salt), st: { games: 0, kills: 0, wins: 0 }, fr: [], tokens: [] };
    return { token: newToken(u), u };
  }
  if (p === '/api/login') {
    const u = String(b.u || ''), x = DB.users[u], now = Date.now(), f = failBy.get(ip) || { n: 0, t: now };
    if (f.n >= 8 && now - f.t < 60000) return { e: '잠시 후 다시 시도해 주세요' };
    if (!x || hashPw(String(b.p || ''), x.salt) !== x.h) { failBy.set(ip, { n: now - f.t < 60000 ? f.n + 1 : 1, t: now }); return { e: '아이디 또는 비밀번호가 틀렸어요' }; }
    failBy.delete(ip);
    return { token: newToken(u), u };
  }
  const u = userByToken(b.token);
  if (!u) return { e: 'auth' };
  if (p === '/api/me') return { u, stats: DB.users[u].st };
  if (p === '/api/save') {
    const st = DB.users[u].st, s = b.stats || {};
    for (const k of ['games', 'kills', 'wins']) if (Number.isFinite(s[k]) && s[k] > 0 && s[k] < 200) st[k] = (st[k] || 0) + (s[k] | 0);
    save();
    return { ok: 1, stats: st };
  }
  return { e: 'not found' };
}

const server = http.createServer((req, res) => {
  const url = req.url.split('?')[0];
  const cors = { 'Access-Control-Allow-Origin': '*', 'Access-Control-Allow-Headers': '*', 'Access-Control-Allow-Methods': 'GET,POST,OPTIONS' };
  if (req.method === 'OPTIONS') { res.writeHead(204, cors); return res.end(); }
  if (req.method === 'POST' && url.startsWith('/api/')) {
    let body = '';
    req.on('data', c => { body += c; if (body.length > 20000) req.destroy(); });
    req.on('end', () => {
      let b = {}; try { b = JSON.parse(body || '{}'); } catch (e) { /* 빈 요청 */ }
      let out; try { out = api(url, b, req.socket.remoteAddress); } catch (e) { console.error(e); out = { e: '서버 오류' }; }
      res.writeHead(200, { 'Content-Type': 'application/json', ...cors });
      res.end(JSON.stringify(out));
    });
    return;
  }
  if (url === '/healthz') { res.writeHead(200, cors); return res.end('ok'); }
  // 정적 파일 (public 폴더). / 는 index.html
  let f = url === '/' ? '/index.html' : decodeURIComponent(url);
  // public 폴더가 없으면 server.js 와 같은 폴더의 index.html 을 사용 (휴대폰에서 파일 3개만 올려도 되게)
  const ROOT = fs.existsSync(path.join(PUBLIC, 'index.html')) ? PUBLIC : __dirname;
  f = path.normalize(path.join(ROOT, f));
  if (!f.startsWith(ROOT) || (ROOT === __dirname && path.basename(f) !== 'index.html')) { res.writeHead(404); return res.end(); }
  fs.stat(f, (err, st) => {
    if (err || !st.isFile()) { res.writeHead(404, { 'Content-Type': 'text/plain; charset=utf-8' }); return res.end('게임 파일이 없어요. public/index.html 에 게임 HTML을 넣어 주세요.'); }
    const h = { 'Content-Type': MIME[path.extname(f)] || 'application/octet-stream', 'Cache-Control': 'no-cache', Vary: 'Accept-Encoding' };
    const gz = /\bgzip\b/.test(req.headers['accept-encoding'] || '') && /\.(html|js|css|json)$/.test(f);
    if (!gz) { res.writeHead(200, h); return fs.createReadStream(f).pipe(res); }
    // 8MB짜리 게임 HTML은 한 번만 압축해서 메모리에 보관 (파일이 바뀌면 다시 압축)
    const c = GZ.get(f);
    if (c && c.m === st.mtimeMs) { res.writeHead(200, { ...h, 'Content-Encoding': 'gzip' }); return res.end(c.d); }
    fs.readFile(f, (e2, data) => {
      if (e2) { res.writeHead(500); return res.end(); }
      zlib.gzip(data, { level: 6 }, (e3, z) => {
        if (e3) { res.writeHead(500); return res.end(); }
        GZ.set(f, { m: st.mtimeMs, d: z });
        res.writeHead(200, { ...h, 'Content-Encoding': 'gzip' }); res.end(z);
      });
    });
  });
});

/* ───────────── 최소 WebSocket 구현 (RFC 6455) ───────────── */
const GUID = '258EAFA5-E914-47DA-95CA-C5AB0DC85B11';
class Sock {
  constructor(socket) { this.s = socket; this.buf = Buffer.alloc(0); this.open = true; this.frag = null; this.onmessage = null; this.onclose = null; this.alive = true;
    socket.on('data', d => this.feed(d)); socket.on('close', () => this.fin()); socket.on('error', () => this.fin()); socket.setNoDelay(true); }
  fin() { if (!this.open) return; this.open = false; try { this.s.destroy(); } catch (e) { /* 이미 닫힘 */ } this.onclose && this.onclose(); }
  feed(d) {
    this.buf = Buffer.concat([this.buf, d]);
    if (this.buf.length > 1 << 20) return this.fin();
    for (;;) {
      const b = this.buf; if (b.length < 2) return;
      const fin = !!(b[0] & 0x80), op = b[0] & 15, masked = !!(b[1] & 0x80); let len = b[1] & 127, off = 2;
      if (len === 126) { if (b.length < 4) return; len = b.readUInt16BE(2); off = 4; }
      else if (len === 127) { if (b.length < 10) return; len = Number(b.readBigUInt64BE(2)); off = 10; }
      if (len > 1 << 20) return this.fin();
      const need = off + (masked ? 4 : 0) + len; if (b.length < need) return;
      let p = b.subarray(off + (masked ? 4 : 0), need);
      if (masked) { const m = b.subarray(off, off + 4); p = Buffer.from(p); for (let i = 0; i < p.length; i++) p[i] ^= m[i & 3]; }
      this.buf = b.subarray(need);
      if (op === 8) { this.send(Buffer.alloc(0), 8); return this.fin(); }
      if (op === 9) { this.send(p, 10); continue; }
      if (op === 10) { this.alive = true; continue; }
      if (op === 0 || op === 1) {
        this.frag = op === 1 ? [p] : (this.frag ? (this.frag.push(p), this.frag) : null);
        if (fin && this.frag) { const msg = Buffer.concat(this.frag).toString('utf8'); this.frag = null; try { this.onmessage && this.onmessage(msg); } catch (e) { console.error('msg error', e); } }
      }
    }
  }
  send(data, op = 1) {
    if (!this.open) return;
    const p = Buffer.isBuffer(data) ? data : Buffer.from(String(data)), n = p.length; let h;
    if (n < 126) h = Buffer.from([0x80 | op, n]);
    else if (n < 65536) { h = Buffer.alloc(4); h[0] = 0x80 | op; h[1] = 126; h.writeUInt16BE(n, 2); }
    else { h = Buffer.alloc(10); h[0] = 0x80 | op; h[1] = 127; h.writeBigUInt64BE(BigInt(n), 2); }
    try { this.s.write(Buffer.concat([h, p])); } catch (e) { this.fin(); }
  }
}
server.on('upgrade', (req, socket) => {
  const key = req.headers['sec-websocket-key'];
  if (!key || String(req.headers.upgrade).toLowerCase() !== 'websocket') return socket.destroy();
  socket.write('HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: ' +
    crypto.createHash('sha1').update(key + GUID).digest('base64') + '\r\n\r\n');
  handle(new Sock(socket));
});

/* ───────────── 게임 로직: 접속 / 친구 / 파티 / 중계 ───────────── */
const online = new Map();  // 이름 -> Sock
const grace = new Map();   // 끊긴 사용자의 파티 유지 타이머
const partyOf = new Map(); // 이름 -> party
// party = { leader, members:[이름...] }

const send = (n, o) => { const c = online.get(n); if (c) c.send(JSON.stringify(o)); };
const msg = (n, s) => send(n, { t: 'msg', s });
function partyView(p) { return { t: 'party', leader: p.leader, members: p.members.map(n => ({ n, on: online.has(n) ? 1 : 0 })) }; }
function pushParty(p) { for (const n of p.members) send(n, partyView(p)); }
function pushFriends(n) {
  const u = DB.users[n]; if (!u) return;
  send(n, { t: 'friends', f: u.fr.map(f => ({ n: f, on: online.has(f) ? 1 : 0 })) });
}
function pushFriendsOfFriends(n) { for (const [m, u] of Object.entries(DB.users)) if (u.fr.includes(n) && online.has(m)) pushFriends(m); }
function leaveParty(n) {
  const p = partyOf.get(n); if (!p) return;
  partyOf.delete(n);
  p.members = p.members.filter(x => x !== n);
  for (const m of p.members) send(m, { t: 'left', n }); // 게임 중이면 팀원 표시 제거용
  if (p.members.length <= 1) { for (const m of p.members) partyOf.delete(m); if (p.members[0]) send(p.members[0], { t: 'party', leader: p.members[0], members: [{ n: p.members[0], on: 1 }] }); return; }
  if (p.leader === n) p.leader = p.members[0];
  pushParty(p);
}
const RELAY = new Set(['pos', 'shot', 'hit', 'bots', 'kill', 'dmg', 'dead', 'ev']); // 파티 안에서만 전달되는 게임 메시지

function handle(ws) {
  let me = null;
  ws.onmessage = raw => {
    let m; try { m = JSON.parse(raw); } catch (e) { return; }
    if (!m || typeof m.t !== 'string') return;
    if (m.t === 'auth') {
      const u = userByToken(m.token);
      if (!u) return ws.send(JSON.stringify({ t: 'bad' })), ws.fin();
      const old = online.get(u); if (old && old !== ws) { try { old.send(JSON.stringify({ t: 'bad' })); old.fin(); } catch (e) { /* 무시 */ } }
      me = u; online.set(u, ws); clearTimeout(grace.get(u)); grace.delete(u);
      send(u, { t: 'hello', u, stats: DB.users[u].st });
      pushFriends(u); pushFriendsOfFriends(u);
      const p = partyOf.get(u); if (p) pushParty(p); else send(u, { t: 'party', leader: u, members: [{ n: u, on: 1 }] });
      return;
    }
    if (!me) return;
    const p = partyOf.get(me);
    if (RELAY.has(m.t)) {                       // 게임 중 실시간 데이터: 같은 파티원에게만 전달
      if (!p) return;
      m.n = me;
      const out = JSON.stringify(m);
      if (m.to) { if (p.members.includes(m.to) && m.to !== me) { const c = online.get(m.to); if (c) c.send(out); } }
      else for (const x of p.members) if (x !== me) { const c = online.get(x); if (c) c.send(out); }
      return;
    }
    switch (m.t) {
      case 'friends': pushFriends(me); break;
      case 'addf': {
        const f = String(m.n || '');
        if (!DB.users[f]) return msg(me, '그런 아이디가 없어요');
        if (f === me) return msg(me, '나 자신은 추가할 수 없어요');
        const a = DB.users[me], b = DB.users[f];
        if (!a.fr.includes(f)) a.fr.push(f);
        if (!b.fr.includes(me)) b.fr.push(me);   // 서로 친구로 바로 등록
        save(); pushFriends(me); pushFriends(f); msg(me, f + '님과 친구가 됐어요'); msg(f, me + '님이 친구로 추가했어요');
        break;
      }
      case 'invite': {
        const f = String(m.n || '');
        if (!DB.users[me].fr.includes(f)) return msg(me, '친구만 초대할 수 있어요');
        if (!online.has(f)) return msg(me, f + '님은 접속 중이 아니에요');
        if (p && p.leader !== me) return msg(me, '파티장만 초대할 수 있어요');
        if (p && p.members.length >= MAX_PARTY) return msg(me, '파티가 가득 찼어요 (최대 ' + MAX_PARTY + '명)');
        send(f, { t: 'invite', from: me }); msg(me, f + '님에게 초대를 보냈어요');
        break;
      }
      case 'join': {
        const from = String(m.from || '');
        if (!online.has(from)) return msg(me, '초대한 사람이 접속 중이 아니에요');
        let q = partyOf.get(from);
        if (q && q === p) return;
        if (q && q.leader !== from) q = null;
        if (q && q.members.length >= MAX_PARTY) return msg(me, '파티가 가득 찼어요');
        if (p) leaveParty(me);
        if (!q) { q = { leader: from, members: [from] }; partyOf.set(from, q); }
        q.members.push(me); partyOf.set(me, q);
        pushParty(q);
        break;
      }
      case 'leave': leaveParty(me); send(me, { t: 'party', leader: me, members: [{ n: me, on: 1 }] }); break;
      case 'start': {
        if (!p || p.leader !== me) return msg(me, '파티장만 시작할 수 있어요');
        const seed = crypto.randomInt(1, 2 ** 31);
        for (const n of p.members) send(n, { t: 'start', seed, host: p.leader, members: p.members.slice() });
        break;
      }
    }
  };
  ws.onclose = () => {
    if (!me) return;
    if (online.get(me) === ws) {
      online.delete(me); pushFriendsOfFriends(me);
      const who = me;   // 휴대폰은 앱 전환/화면 꺼짐으로 연결이 자주 끊김 -> 20초 안에 다시 오면 파티 유지
      clearTimeout(grace.get(who));
      grace.set(who, setTimeout(() => { grace.delete(who); if (!online.has(who)) leaveParty(who); }, 20000));
    }
  };
}

// 연결 유지(프록시 유휴 종료 방지) + 죽은 연결 정리
setInterval(() => {
  for (const ws of online.values()) { if (!ws.alive) { ws.fin(); continue; } ws.alive = false; ws.send(Buffer.alloc(0), 9); }
}, 25000);

server.listen(PORT, () => console.log('PUBG 온라인 서버 시작: http://localhost:' + PORT));
