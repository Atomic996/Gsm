const express = require('express');
const { Pool } = require('pg');
const path = require('path');
const crypto = require('crypto');
const { promisify } = require('util');
const scrypt = promisify(crypto.scrypt);

const app = express();
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.DATABASE_SSL === 'false' ? false : { rejectUnauthorized: false },
});
const PW = process.env.APP_PASSWORD || '';

const w = (f) => (req, res) => f(req, res).catch((e) => { console.error(e); res.status(500).send('server error'); });

app.use(express.json({ limit: '1mb' }));
app.use(express.static(path.join(__dirname, 'public')));

// ===================== الحسابات والصلاحيات =====================
// كلمة APP_PASSWORD تبقى بوابة الجهاز. فوقها حسابات الموظفين بالرمز السري.
const SECRET = process.env.SESSION_SECRET ||
  crypto.createHash('sha256').update('pos-session|' + (process.env.DATABASE_URL || '') + '|' + PW).digest('hex');
const TTL = 12 * 3600 * 1000; // مدة الجلسة: 12 ساعة
const ROLES = ['owner', 'manager', 'cashier'];
let staff = new Map(); // id -> {id,name,role,active,salt,hash}
const tries = new Map(); // محاولات الدخول الفاشلة لكل حساب

const pwOk = (v) => {
  const a = Buffer.from(String(v || '')), b = Buffer.from(PW);
  return a.length === b.length && crypto.timingSafeEqual(a, b);
};
const sign = (p) => {
  const body = Buffer.from(JSON.stringify(p)).toString('base64url');
  return body + '.' + crypto.createHmac('sha256', SECRET).update(body).digest('base64url');
};
const verify = (t) => {
  if (typeof t !== 'string') return null;
  const [body, sig] = t.split('.');
  if (!body || !sig) return null;
  const ok = crypto.createHmac('sha256', SECRET).update(body).digest('base64url');
  const a = Buffer.from(sig), b = Buffer.from(ok);
  if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) return null;
  try { const p = JSON.parse(Buffer.from(body, 'base64url').toString()); return p.e > Date.now() ? p : null; }
  catch (e) { return null; }
};
const validName = (n) => typeof n === 'string' && n.trim().length >= 1 && n.trim().length <= 40;
const validPin = (p) => typeof p === 'string' && /^\d{4,8}$/.test(p);
async function mkHash(pin) {
  const salt = crypto.randomBytes(16).toString('hex');
  return { salt, hash: (await scrypt(pin, salt, 32)).toString('hex') };
}
async function pinOk(u, pin) {
  if (typeof pin !== 'string' || !pin) return false;
  const h = await scrypt(pin, u.salt, 32), e = Buffer.from(u.hash, 'hex');
  return h.length === e.length && crypto.timingSafeEqual(h, e);
}
async function loadStaff() {
  const x = await pool.query('select id,name,role,active,salt,hash from staff');
  staff = new Map(x.rows.map((u) => [u.id, u]));
}
const pub = (u) => ({ id: u.id, name: u.name, role: u.role });
const session = (u) => ({ token: sign({ u: u.id, e: Date.now() + TTL }), user: pub(u) });
async function checkLogin(u, pin) {
  const t = tries.get(u.id) || { n: 0, until: 0 };
  if (t.until > Date.now()) return 'محاولات كثيرة. حاول بعد 5 دقائق.';
  if (await pinOk(u, pin)) { tries.delete(u.id); return ''; }
  t.n++;
  if (t.n >= 5) { t.until = Date.now() + 5 * 60 * 1000; t.n = 0; }
  tries.set(u.id, t);
  return 'الرمز غير صحيح';
}

const gate = (req, res, next) => {
  if (PW && !pwOk(req.get('x-pw'))) return res.status(401).send('unauthorized');
  next();
};
const authn = (req, res, next) => {
  if (staff.size === 0) { req.user = { id: '', name: '', role: 'owner' }; return next(); } // قبل إنشاء أول حساب
  const m = /^Bearer (.+)$/.exec(req.get('authorization') || '');
  const p = m && verify(m[1]);
  const u = p && staff.get(p.u);
  if (!u || !u.active) return res.status(401).send('login');
  req.user = u;
  next();
};
const ownerOnly = (req, res, next) =>
  staff.size > 0 && req.user.role === 'owner' ? next() : res.status(403).send('للمالك فقط');

// صلاحيات الكاشير: بيع وعملاء فقط. المالك والمدير: كل شيء (والموظفون للمالك فقط).
function can(u, method, col, id, body) {
  if (u.role !== 'cashier') return true;
  if (method === 'GET') return ['products', 'sales', 'customers', 'payments', 'settings'].includes(col);
  if (method === 'POST') return id === '' && ['sales', 'customers', 'payments', 'cashlog'].includes(col);
  if (method === 'PATCH') {
    if (col === 'customers') return true;
    if (col === 'products') return !!body && typeof body === 'object' && Object.keys(body).every((k) => k === 'stock');
    return false;
  }
  if (method === 'PUT') return col === 'settings' && id === 'treasury';
  return false;
}

app.get('/auth/state', gate, (q, r) => r.json({ setup: staff.size === 0 }));
app.get('/auth/staff', gate, (q, r) =>
  r.json([...staff.values()].filter((u) => u.active).map((u) => ({ id: u.id, name: u.name }))
    .sort((a, b) => a.name.localeCompare(b.name, 'ar'))));
app.post('/auth/setup', gate, w(async (q, r) => {
  if (staff.size > 0) return r.status(403).send('تم الإعداد مسبقاً');
  const { name, pin } = q.body || {};
  if (!validName(name)) return r.status(400).send('اكتب الاسم');
  if (!validPin(pin)) return r.status(400).send('الرمز من 4 إلى 8 أرقام');
  const id = crypto.randomUUID(), h = await mkHash(pin);
  await pool.query('insert into staff(id,name,role,salt,hash) values($1,$2,$3,$4,$5)', [id, name.trim(), 'owner', h.salt, h.hash]);
  await loadStaff();
  r.json(session(staff.get(id)));
}));
app.post('/auth/login', gate, w(async (q, r) => {
  const { id, pin } = q.body || {};
  const u = staff.get(id);
  if (!u || !u.active) return r.status(400).send('الحساب غير متاح');
  const bad = await checkLogin(u, pin);
  if (bad) return r.status(bad.startsWith('محاولات') ? 429 : 400).send(bad);
  r.json(session(u));
}));
app.get('/auth/me', gate, authn, (q, r) => r.json({ user: q.user.id ? pub(q.user) : null, setup: staff.size === 0 }));
app.post('/auth/pin', gate, authn, w(async (q, r) => {
  const u = q.user;
  if (!u.id) return r.status(400).send('لا يوجد حساب');
  const { old, next } = q.body || {};
  if (!validPin(next)) return r.status(400).send('الرمز الجديد من 4 إلى 8 أرقام');
  const bad = await checkLogin(u, old);
  if (bad) return r.status(400).send(bad);
  const h = await mkHash(next);
  await pool.query('update staff set salt=$2,hash=$3 where id=$1', [u.id, h.salt, h.hash]);
  await loadStaff();
  r.sendStatus(204);
}));

// إدارة الموظفين (المالك فقط)
app.get('/auth/admin/staff', gate, authn, ownerOnly, (q, r) =>
  r.json([...staff.values()].map((u) => ({ id: u.id, name: u.name, role: u.role, active: u.active }))));
app.post('/auth/admin/staff', gate, authn, ownerOnly, w(async (q, r) => {
  const { name, role, pin } = q.body || {};
  if (!validName(name)) return r.status(400).send('اكتب الاسم');
  if (!ROLES.includes(role)) return r.status(400).send('صلاحية غير صحيحة');
  if (!validPin(pin)) return r.status(400).send('الرمز من 4 إلى 8 أرقام');
  const id = crypto.randomUUID(), h = await mkHash(pin);
  await pool.query('insert into staff(id,name,role,salt,hash) values($1,$2,$3,$4,$5)', [id, name.trim(), role, h.salt, h.hash]);
  await loadStaff();
  r.json({ id });
}));
app.patch('/auth/admin/staff/:id', gate, authn, ownerOnly, w(async (q, r) => {
  const u = staff.get(q.params.id);
  if (!u) return r.status(404).send('غير موجود');
  const b = q.body || {}, m = { ...u };
  if (b.name !== undefined) { if (!validName(b.name)) return r.status(400).send('اسم غير صحيح'); m.name = b.name.trim(); }
  if (b.role !== undefined) { if (!ROLES.includes(b.role)) return r.status(400).send('صلاحية غير صحيحة'); m.role = b.role; }
  if (b.active !== undefined) m.active = !!b.active;
  if (b.pin) { if (!validPin(b.pin)) return r.status(400).send('الرمز من 4 إلى 8 أرقام'); Object.assign(m, await mkHash(b.pin)); }
  const owners = [...staff.values()].map((x) => (x.id === u.id ? m : x)).filter((x) => x.active && x.role === 'owner').length;
  if (owners < 1) return r.status(400).send('يجب أن يبقى مالك واحد نشط على الأقل');
  await pool.query('update staff set name=$2,role=$3,active=$4,salt=$5,hash=$6 where id=$1', [u.id, m.name, m.role, m.active, m.salt, m.hash]);
  tries.delete(u.id);
  await loadStaff();
  r.sendStatus(204);
}));

app.use('/api', gate, authn);
app.use('/api/:col', (req, res, next) =>
  /^[a-z_]{1,30}$/.test(req.params.col) ? next() : res.status(400).send('bad collection'));
app.use('/api/:col', (req, res, next) => {
  const id = req.path.split('/')[1] || '';
  if (!can(req.user, req.method, req.params.col, id, req.body)) return res.status(403).send('غير مصرح لك بهذه العملية');
  next();
});


app.get('/api/:col', w(async (q, r) => {
  const x = await pool.query('select id, data from docs where col=$1 order by created desc limit 2000', [q.params.col]);
  r.json(x.rows);
}));
app.post('/api/:col', w(async (q, r) => {
  const id = crypto.randomUUID();
  const d = q.body && typeof q.body === 'object' && !Array.isArray(q.body) && q.user.id
    ? { ...q.body, by: q.user.id, byn: q.user.name } : q.body;
  await pool.query('insert into docs(col,id,data) values($1,$2,$3)', [q.params.col, id, d]);
  r.json({ id });
}));
// استيراد دفعة واحدة (upsert مع دمج الحقول) داخل معاملة واحدة
app.post('/api/:col/_bulk', w(async (q, r) => {
  const rows = Array.isArray(q.body) ? q.body : null;
  if (!rows) return r.status(400).send('array expected');
  if (rows.length > 1000) return r.status(400).send('too many rows');
  const c = await pool.connect();
  try {
    await c.query('begin');
    for (const x of rows) {
      const id = x && typeof x.id === 'string' && /^[\w-]{1,64}$/.test(x.id) ? x.id : crypto.randomUUID();
      const data = x && x.data && typeof x.data === 'object' ? x.data : {};
      await c.query(
        'insert into docs(col,id,data) values($1,$2,$3) on conflict (col,id) do update set data = docs.data || excluded.data',
        [q.params.col, id, data]);
    }
    await c.query('commit');
  } catch (e) {
    await c.query('rollback');
    throw e;
  } finally {
    c.release();
  }
  r.json({ n: rows.length });
}));
app.put('/api/:col/:id', w(async (q, r) => {
  await pool.query(
    'insert into docs(col,id,data) values($1,$2,$3) on conflict (col,id) do update set data=excluded.data',
    [q.params.col, q.params.id, q.body]);
  r.sendStatus(204);
}));
app.patch('/api/:col/:id', w(async (q, r) => {
  await pool.query('update docs set data = data || $3::jsonb where col=$1 and id=$2', [q.params.col, q.params.id, JSON.stringify(q.body)]);
  r.sendStatus(204);
}));
app.delete('/api/:col/:id', w(async (q, r) => {
  await pool.query('delete from docs where col=$1 and id=$2', [q.params.col, q.params.id]);
  r.sendStatus(204);
}));

(async () => {
  await pool.query(`create table if not exists docs(
    col text not null, id text not null, data jsonb not null default '{}',
    created timestamptz not null default now(), primary key (col, id))`);
  await pool.query(`create table if not exists staff(
    id text primary key, name text not null, role text not null, salt text not null, hash text not null,
    active boolean not null default true, created timestamptz not null default now())`);
  await loadStaff();
  const port = process.env.PORT || 3000;
  app.listen(port, () => console.log('POS running on port ' + port));
})().catch((e) => { console.error(e); process.exit(1); });
