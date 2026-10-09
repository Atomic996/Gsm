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
  await logRow(staff.get(id), 'AUTH', 'auth', id, 'إنشاء حساب المالك');
  r.json(session(staff.get(id)));
}));
app.post('/auth/login', gate, w(async (q, r) => {
  const { id, pin } = q.body || {};
  const u = staff.get(id);
  if (!u || !u.active) return r.status(400).send('الحساب غير متاح');
  const bad = await checkLogin(u, pin);
  if (bad) {
    if (!bad.startsWith('محاولات')) await logRow(u, 'AUTH', 'auth', u.id, 'محاولة دخول فاشلة');
    return r.status(bad.startsWith('محاولات') ? 429 : 400).send(bad);
  }
  await logRow(u, 'AUTH', 'auth', u.id, 'تسجيل دخول');
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
  await logRow(u, 'AUTH', 'auth', u.id, 'تغيير الرمز السري');
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
  await logRow(q.user, 'AUTH', 'staff', id, 'إضافة موظف: ' + name.trim() + ' (' + role + ')');
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
  await logRow(q.user, 'AUTH', 'staff', u.id, 'تعديل موظف: ' + m.name + (b.role !== undefined ? ' (صلاحية: ' + m.role + ')' : '') +
    (b.active !== undefined ? (m.active ? ' (تفعيل)' : ' (تعطيل)') : '') + (b.pin ? ' (رمز جديد)' : ''));
  r.sendStatus(204);
}));

// ===================== بيع ذرّي =====================
// الفاتورة + خصم المخزون + رصيد العميل + الخزينة في معاملة واحدة: تنجح كلها أو تفشل كلها.
// opid مفتاح يمنع تسجيل الفاتورة مرتين إذا أُعيد الإرسال بعد انقطاع الاتصال.
const num = (v) => (typeof v === 'number' && isFinite(v) ? v : NaN);
const M2 = (n) => Math.round(n * 100) / 100;
app.post('/pos/sale', gate, authn, w(async (q, r) => {
  const b = q.body || {};
  const bad = (m) => r.status(400).send(m);
  const op = typeof b.opid === 'string' && /^[\w-]{8,64}$/.test(b.opid) ? b.opid : '';
  if (!op) return bad('مفتاح العملية مطلوب');
  if (!['cash', 'card', 'transfer', 'credit'].includes(b.method)) return bad('طريقة دفع غير صحيحة');
  if (!Array.isArray(b.items) || b.items.length < 1 || b.items.length > 200) return bad('بنود الفاتورة غير صحيحة');
  const items = [];
  for (const i of b.items) {
    const price = num(i && i.price), cost = num(i && i.cost), qty = num(i && i.qty);
    if (!i || typeof i.id !== 'string' || typeof i.name !== 'string' || !(price >= 0) || !(cost >= 0) || !(qty > 0)) return bad('بند غير صحيح');
    items.push({ id: i.id, name: i.name.slice(0, 120), price, cost, qty, unit: i.unit === 'kg' ? 'kg' : 'pc' });
  }
  const sub = num(b.sub), disc = num(b.disc), tax = num(b.tax), total = num(b.total), paid = num(b.paid);
  if (![sub, disc, tax, total, paid].every((x) => x >= 0)) return bad('مبالغ غير صحيحة');
  if (Math.abs(items.reduce((a, i) => a + M2(i.price * i.qty), 0) - sub) > 0.05) return bad('المجموع لا يطابق البنود');
  if (Math.abs(sub - disc + tax - total) > 0.02) return bad('الإجمالي لا يطابق المجموع والخصم والضريبة');
  const credit = b.method === 'credit';
  if (credit) {
    if (typeof b.cid !== 'string' || !b.cid) return bad('اختر العميل');
    if (paid > total + 0.001) return bad('المدفوع أكبر من الإجمالي');
  } else if (paid < total - 0.001) return bad('المبلغ غير كافٍ');
  const now = Date.now();
  let ts = num(b.ts);
  if (!(ts > now - 30 * 864e5 && ts < now + 10 * 60 * 1000)) ts = now;
  const no = String(b.no || '').slice(0, 12) || String(ts).slice(-6);

  const c = await pool.connect();
  let open = false;
  const stop = async (sql) => { if (open) { open = false; await c.query(sql); } };
  try {
    await c.query('begin'); open = true;
    const dup = await c.query("select id, data from docs where col='sales' and data->>'opid'=$1", [op]);
    if (dup.rows[0]) { await stop('rollback'); return r.json({ id: dup.rows[0].id, no: dup.rows[0].data.no, dup: true }); }
    const need = new Map();
    items.forEach((i) => need.set(i.id, (need.get(i.id) || 0) + i.qty));
    for (const [pid, qty] of [...need].sort((x, y) => (x[0] < y[0] ? -1 : 1))) {
      await c.query(
        `update docs set data = jsonb_set(data,'{stock}',to_jsonb(greatest(0, round(coalesce((data->>'stock')::numeric,0) - $2::numeric, 3))))
         where col='products' and id=$1`, [pid, qty]);
    }
    let cname = '';
    if (credit) {
      const cu = await c.query(
        `update docs set data = jsonb_set(data,'{bal}',to_jsonb(round(coalesce((data->>'bal')::numeric,0) + $2::numeric, 2)))
         where col='customers' and id=$1 returning data->>'name' as name`, [b.cid, M2(total - paid)]);
      if (!cu.rows[0]) { await stop('rollback'); return bad('العميل غير موجود'); }
      cname = cu.rows[0].name || '';
    }
    const id = crypto.randomUUID();
    const sale = { ts, no, sub: M2(sub), disc: M2(disc), tax: M2(tax), total: M2(total), paid: M2(paid), method: b.method, items, opid: op };
    if (credit) { sale.cid = b.cid; sale.cname = cname; }
    if (b.ws === true) sale.ws = true;
    if (q.user.id) { sale.by = q.user.id; sale.byn = q.user.name; }
    await c.query('insert into docs(col,id,data) values($1,$2,$3)', ['sales', id, sale]);
    const delta = M2(credit ? paid : total);
    let bal = null;
    if (delta) {
      const t = await c.query(
        `insert into docs(col,id,data) values('settings','treasury',jsonb_build_object('bal',$1::numeric))
         on conflict (col,id) do update set data = jsonb_set(docs.data,'{bal}',to_jsonb(round(coalesce((docs.data->>'bal')::numeric,0) + $1::numeric, 2)))
         returning (data->>'bal')::numeric as bal`, [delta]);
      bal = Number(t.rows[0].bal);
      await c.query('insert into docs(col,id,data) values($1,$2,$3)', ['cashlog', crypto.randomUUID(), { ts: Date.now(), d: delta, why: 'بيع #' + no, bal }]);
    }
    await stop('commit');
    await logRow(q.user, 'POST', 'sales', id, '#' + no + ' · المبلغ ' + M2(total));
    r.json({ id, no, bal });
  } catch (e) {
    try { await stop('rollback'); } catch (e2) { /* connection already lost */ }
    if (e && e.code === '23505') { // سباق: وصل طلبان بنفس المفتاح معاً
      const d2 = await pool.query("select id, data from docs where col='sales' and data->>'opid'=$1", [op]);
      if (d2.rows[0]) return r.json({ id: d2.rows[0].id, no: d2.rows[0].data.no, dup: true });
    }
    throw e;
  } finally {
    c.release();
  }
}));

app.use('/api', gate, authn);
app.use('/api/:col', (req, res, next) =>
  /^[a-z_]{1,30}$/.test(req.params.col) ? next() : res.status(400).send('bad collection'));
app.use('/api/:col', (req, res, next) => {
  const id = req.path.split('/')[1] || '';
  if (!can(req.user, req.method, req.params.col, id, req.body)) return res.status(403).send('غير مصرح لك بهذه العملية');
  next();
});


// ===================== سجل العمليات =====================
// يُسجَّل كل تعديل (إضافة/تعديل/حذف/استيراد) تلقائياً باسم المستخدم. القراءة للمالك فقط، ولا كتابة من الواجهة.
async function logRow(u, m, col, rid, d) {
  try {
    await pool.query('insert into docs(col,id,data) values($1,$2,$3)',
      ['oplog', crypto.randomUUID(), { ts: Date.now(), u: (u && u.id) || '', un: (u && u.name) || '', m, col, rid, d }]);
  } catch (e) { console.error(e); }
}
async function audit(req, col, id, old) {
  const b = req.body, bulk = id === '_bulk';
  const x = { ...(old || {}), ...(b && typeof b === 'object' && !Array.isArray(b) ? b : {}) };
  let d;
  if (bulk) d = 'استيراد ' + (Array.isArray(b) ? b.length : 0) + ' سجل';
  else {
    const n = x.name || x.note || x.supplier || x.cname || (x.no ? '#' + x.no : '') || '';
    const amt = x.total != null ? x.total : x.amt != null ? x.amt : null;
    d = [n, amt != null ? 'المبلغ ' + amt : ''].filter(Boolean).join(' · ');
  }
  await logRow(req.user, bulk ? 'BULK' : req.method, col, bulk ? '' : id, d.slice(0, 160));
}
app.use('/api/:col', async (req, res, next) => {
  const col = req.params.col;
  if (col === 'oplog') {
    return req.method === 'GET' && (staff.size === 0 || req.user.role === 'owner') ? next() : res.status(403).send('للمالك فقط');
  }
  if (req.method === 'GET') return next();
  try {
    const id = req.path.split('/')[1] || '', b = req.body;
    const bk = b && typeof b === 'object' && !Array.isArray(b) ? Object.keys(b) : [];
    // نتجاهل الحركات التلقائية المتكررة: رصيد الخزينة، وخصم المخزون/رصيد العميل مع كل بيع
    const noise = col === 'cashlog' || (col === 'settings' && id === 'treasury') ||
      (req.method === 'PATCH' && bk.length > 0 &&
        ((col === 'products' && bk.every((k) => k === 'stock')) || (col === 'customers' && bk.every((k) => k === 'bal'))));
    if (!noise) {
      let old = null;
      if (id && id !== '_bulk' && req.method !== 'POST') {
        const x = await pool.query('select data from docs where col=$1 and id=$2', [col, id]);
        old = x.rows[0] ? x.rows[0].data : null;
      }
      res.on('finish', () => { if (res.statusCode < 300) audit(req, col, id, old); });
    }
  } catch (e) { console.error(e); }
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
  await pool.query(`create unique index if not exists docs_sale_opid on docs ((data->>'opid')) where col='sales' and data->>'opid' is not null`);
  await loadStaff();
  const prune = () => pool.query("delete from docs where col='oplog' and created < now() - interval '180 days'").catch((e) => console.error(e));
  prune(); setInterval(prune, 24 * 3600 * 1000);
  const port = process.env.PORT || 3000;
  app.listen(port, () => console.log('POS running on port ' + port));
})().catch((e) => { console.error(e); process.exit(1); });
  
