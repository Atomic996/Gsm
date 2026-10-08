const express = require('express');
const { Pool } = require('pg');
const path = require('path');
const crypto = require('crypto');

const app = express();
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.DATABASE_SSL === 'false' ? false : { rejectUnauthorized: false },
});
const PW = process.env.APP_PASSWORD || '';

app.use(express.json({ limit: '1mb' }));
app.use(express.static(path.join(__dirname, 'public')));

app.use('/api', (req, res, next) => {
  if (PW && req.get('x-pw') !== PW) return res.status(401).send('unauthorized');
  next();
});
app.use('/api/:col', (req, res, next) =>
  /^[a-z_]{1,30}$/.test(req.params.col) ? next() : res.status(400).send('bad collection'));

const w = (f) => (req, res) => f(req, res).catch((e) => { console.error(e); res.status(500).send('server error'); });

app.get('/api/:col', w(async (q, r) => {
  const x = await pool.query('select id, data from docs where col=$1 order by created desc limit 2000', [q.params.col]);
  r.json(x.rows);
}));
app.post('/api/:col', w(async (q, r) => {
  const id = crypto.randomUUID();
  await pool.query('insert into docs(col,id,data) values($1,$2,$3)', [q.params.col, id, q.body]);
  r.json({ id });
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
  const port = process.env.PORT || 3000;
  app.listen(port, () => console.log('POS running on port ' + port));
})().catch((e) => { console.error(e); process.exit(1); });
