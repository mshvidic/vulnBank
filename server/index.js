// VulnBank API. A deliberately vulnerable training server: local use only.
// Every intentional flaw is marked with "FLAW:" and listed in VULNERABILITIES.md.
import fs from 'node:fs';
import http from 'node:http';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const [major, minor] = process.versions.node.split('.').map(Number);
if (major < 22 || (major === 22 && minor < 5)) {
  console.error(`VulnBank needs Node.js 22.5 or newer (it uses the built-in SQLite). You have ${process.version}.`);
  process.exit(1);
}

const { db, md5 } = await import('./db.js');

const ROOT = path.dirname(fileURLToPath(import.meta.url));
const STATEMENTS_DIR = path.join(ROOT, 'statements');
const PORT = Number(process.env.PORT ?? 4000);
const HOST = '127.0.0.1'; // never exposed on the network, on purpose
const REPORTING_THRESHOLD = 10000;

class HttpError extends Error {
  constructor(status, message) {
    super(message);
    this.status = status;
  }
}

// ---------- helpers ----------

function send(res, status, data, headers = {}) {
  const body = typeof data === 'string' ? data : JSON.stringify(data);
  res.writeHead(status, {
    'Content-Type': typeof data === 'string' ? 'text/plain; charset=utf-8' : 'application/json',
    ...headers,
  });
  res.end(body);
}

/** Runs a query built by string concatenation. Used by the injectable endpoints. */
function rawAll(sql) {
  try {
    return db.prepare(sql).all();
  } catch (error) {
    error.query = sql; // FLAW: the failing SQL is sent back to the client
    throw error;
  }
}

async function readBody(req) {
  const chunks = [];
  for await (const chunk of req) chunks.push(chunk);
  const raw = Buffer.concat(chunks).toString('utf8');
  if (!raw) return {};
  // FLAW: the body is parsed as JSON or as a form no matter what Content-Type says,
  // which lets a plain HTML form (text/plain or urlencoded) trigger JSON endpoints (CSRF).
  try {
    return JSON.parse(raw);
  } catch {
    return Object.fromEntries(new URLSearchParams(raw));
  }
}

function parseCookies(req) {
  return Object.fromEntries(
    (req.headers.cookie ?? '')
      .split(';')
      .map((part) => part.trim().split('='))
      .filter(([name]) => name),
  );
}

// FLAW: the session token is just base64 of the user's claims. It is not signed, so anyone can forge one.
function makeToken(user) {
  return Buffer.from(JSON.stringify({ id: user.id, username: user.username, role: user.role })).toString('base64');
}

function currentUser(req) {
  const header = req.headers.authorization;
  const token = header?.startsWith('Bearer ') ? header.slice(7) : parseCookies(req).session;
  if (!token) return null;
  try {
    return JSON.parse(Buffer.from(token, 'base64').toString('utf8'));
  } catch {
    return null;
  }
}

function requireLogin(req) {
  const user = currentUser(req);
  if (!user) throw new HttpError(401, 'Not logged in');
  return user;
}

const publicUser = ({ password: _password, ...rest }) => rest;

// ---------- routes ----------

const routes = [];
const route = (method, pattern, handler) => routes.push({ method, regex: new RegExp(`^${pattern}$`), handler });

route('GET', '/api/health', ({ res }) => send(res, 200, { status: 'ok' }));

route('POST', '/api/register', ({ res, body }) => {
  const { username, password, fullName = '', email = '' } = body;
  if (!username || !password) throw new HttpError(400, 'Username and password are required');
  // FLAW: no password policy at all ("1" is accepted).
  // FLAW: user enumeration, the error names the existing username.
  if (db.prepare('SELECT id FROM users WHERE username = ?').get(username)) {
    throw new HttpError(409, `Username "${username}" is already taken`);
  }
  const { lastInsertRowid } = db
    .prepare('INSERT INTO users (username, password, full_name, email) VALUES (?, ?, ?, ?)')
    .run(username, md5(String(password)), fullName, email);
  db.prepare('INSERT INTO accounts (user_id, number, type, balance) VALUES (?, ?, ?, ?)').run(
    lastInsertRowid,
    `VB-${1000 + Number(lastInsertRowid)}-CHK`,
    'checking',
    100,
  );
  send(res, 201, { id: Number(lastInsertRowid), username });
});

route('POST', '/api/login', ({ res, body }) => {
  const { username = '', password = '' } = body;
  // FLAW: SQL injection. Try  admin'--  as the username.
  // FLAW: no rate limiting or lockout, so passwords can be brute-forced.
  const sql = `SELECT * FROM users WHERE username = '${username}' AND password = '${md5(String(password))}'`;
  const user = rawAll(sql)[0];
  if (!user) {
    // FLAW: different messages reveal which usernames exist.
    const exists = db.prepare('SELECT 1 AS found FROM users WHERE username = ?').get(String(username));
    throw new HttpError(401, exists ? 'Wrong password' : 'Unknown user');
  }
  const token = makeToken(user);
  // FLAW: the cookie has no HttpOnly, Secure or SameSite attributes.
  // FLAW: the response contains the whole user row, including the password hash.
  send(res, 200, { token, user }, { 'Set-Cookie': `session=${token}; Path=/` });
});

route('POST', '/api/logout', ({ res }) => {
  send(res, 200, { ok: true }, { 'Set-Cookie': 'session=; Path=/; Max-Age=0' });
});

route('GET', '/api/me', ({ req, res }) => {
  const claims = requireLogin(req);
  const user = db.prepare('SELECT * FROM users WHERE id = ?').get(claims.id);
  if (!user) throw new HttpError(401, 'Unknown user');
  send(res, 200, publicUser(user));
});

route('PUT', '/api/profile', ({ req, res, body }) => {
  const claims = requireLogin(req);
  const columns = ['username', 'password', 'full_name', 'email', 'role'];
  // FLAW: mass assignment. Every known column in the body is written, including "role".
  const fields = Object.keys(body).filter((key) => columns.includes(key));
  if (fields.length === 0) throw new HttpError(400, 'Nothing to update');
  const values = fields.map((key) => (key === 'password' ? md5(String(body[key])) : body[key]));
  db.prepare(`UPDATE users SET ${fields.map((f) => `${f} = ?`).join(', ')} WHERE id = ?`).run(...values, claims.id);
  const user = db.prepare('SELECT * FROM users WHERE id = ?').get(claims.id);
  send(res, 200, publicUser(user));
});

route('GET', '/api/accounts', ({ req, res }) => {
  const claims = requireLogin(req);
  send(res, 200, db.prepare('SELECT * FROM accounts WHERE user_id = ? ORDER BY id').all(claims.id));
});

route('GET', '/api/accounts/(\\d+)', ({ req, res, params }) => {
  requireLogin(req);
  // FLAW: broken object-level authorization (IDOR). Any logged-in user can read any account by id,
  // and the response includes the owner's personal details.
  const account = db
    .prepare(
      `SELECT a.*, u.full_name AS owner_name, u.email AS owner_email
       FROM accounts a JOIN users u ON u.id = a.user_id WHERE a.id = ?`,
    )
    .get(Number(params[0]));
  if (!account) throw new HttpError(404, 'Account not found');
  send(res, 200, account);
});

route('GET', '/api/accounts/(\\d+)/transactions', ({ req, res, url, params }) => {
  requireLogin(req); // FLAW: no ownership check here either (IDOR)
  const id = Number(params[0]);
  const q = url.searchParams.get('q') ?? '';
  // FLAW: SQL injection in the memo search. Try  '  and then a UNION SELECT.
  const sql = `SELECT * FROM transactions WHERE (from_account = ${id} OR to_account = ${id}) AND memo LIKE '%${q}%' ORDER BY id DESC`;
  send(res, 200, rawAll(sql));
});

route('GET', '/api/transactions/(\\d+)', ({ req, res, params }) => {
  requireLogin(req); // FLAW: IDOR, any transaction can be read by id
  const tx = db.prepare('SELECT * FROM transactions WHERE id = ?').get(Number(params[0]));
  if (!tx) throw new HttpError(404, 'Transaction not found');
  send(res, 200, tx);
});

route('POST', '/api/transfer', ({ req, res, body }) => {
  requireLogin(req); // FLAW: no CSRF protection, the session cookie alone authorises the transfer
  const from = Number(body.fromAccount);
  const to = Number(body.toAccount);
  const amount = Number(body.amount);
  const memo = String(body.memo ?? '');
  if (![from, to, amount].every(Number.isFinite)) throw new HttpError(400, 'fromAccount, toAccount and amount are required');

  const source = db.prepare('SELECT * FROM accounts WHERE id = ?').get(from);
  const target = db.prepare('SELECT * FROM accounts WHERE id = ?').get(to);
  if (!source || !target) throw new HttpError(404, 'Account not found');

  // FLAW: the source account is never checked against the logged-in user (BOLA): you can move other people's money.
  // FLAW: negative amounts are accepted. A transfer of -500 pulls 500 from the target into the source.
  if (amount > source.balance) throw new HttpError(400, 'Insufficient funds');

  db.prepare('UPDATE accounts SET balance = balance - ? WHERE id = ?').run(amount, from);
  db.prepare('UPDATE accounts SET balance = balance + ? WHERE id = ?').run(amount, to);
  // FLAW: the memo is stored exactly as sent (stored XSS when the UI renders it as HTML).
  const { lastInsertRowid } = db
    .prepare('INSERT INTO transactions (from_account, to_account, amount, memo) VALUES (?, ?, ?, ?)')
    .run(from, to, amount, memo);

  // FLAW: only a single large transfer is flagged. Splitting it into several smaller ones avoids detection ("structuring").
  if (amount >= REPORTING_THRESHOLD) {
    db.prepare('INSERT INTO risk_alerts (account_id, reason, severity) VALUES (?, ?, ?)').run(
      from,
      `Large transfer of ${amount.toFixed(2)} to account ${to}`,
      'high',
    );
  }
  send(res, 201, { id: Number(lastInsertRowid), fromAccount: from, toAccount: to, amount, memo });
});

route('POST', '/api/support', ({ req, res, body }) => {
  const claims = requireLogin(req);
  const subject = String(body.subject ?? '').trim();
  const message = String(body.message ?? '');
  if (!subject || !message) throw new HttpError(400, 'Subject and message are required');
  // FLAW: stored as is, the admin console renders the message as HTML (stored XSS).
  db.prepare('INSERT INTO support_tickets (user_id, subject, message) VALUES (?, ?, ?)').run(claims.id, subject, message);
  send(res, 201, { ok: true });
});

// FLAW: broken function-level authorization. The admin endpoints only check that you are logged in, not that you are an admin.
route('GET', '/api/admin/users', ({ req, res }) => {
  requireLogin(req);
  // FLAW: sensitive data exposure, the MD5 password hashes are returned.
  send(res, 200, db.prepare('SELECT * FROM users ORDER BY id').all());
});

route('GET', '/api/admin/alerts', ({ req, res }) => {
  requireLogin(req);
  send(res, 200, db.prepare('SELECT * FROM risk_alerts ORDER BY id DESC').all());
});

route('GET', '/api/admin/support', ({ req, res }) => {
  requireLogin(req);
  send(
    res,
    200,
    db
      .prepare(
        `SELECT t.*, u.username FROM support_tickets t JOIN users u ON u.id = t.user_id ORDER BY t.id DESC`,
      )
      .all(),
  );
});

route('GET', '/api/statements', ({ req, res }) => {
  const claims = requireLogin(req);
  const files = fs.readdirSync(STATEMENTS_DIR).filter((name) => name.startsWith(`${claims.username}-`));
  send(res, 200, files);
});

route('GET', '/api/statements/download', ({ req, res, url }) => {
  requireLogin(req);
  const file = url.searchParams.get('file') ?? '';
  // FLAW: path traversal. "file" is joined to the statements folder without being cleaned,
  // so ../secrets/config.env works. (Reads are jailed to the server/ folder so real files on your computer stay safe.)
  const target = path.join(STATEMENTS_DIR, file);
  if (!target.startsWith(ROOT)) throw new HttpError(403, 'Outside the training sandbox');
  if (!fs.existsSync(target) || fs.statSync(target).isDirectory()) throw new HttpError(404, `File not found: ${target}`);
  send(res, 200, fs.readFileSync(target, 'utf8'));
});

// FLAW: security misconfiguration. A debug endpoint with no authentication that leaks (fake) secrets.
route('GET', '/api/debug/config', ({ res }) => {
  send(res, 200, {
    node: process.version,
    environment: 'development',
    jwtSecret: 'FAKE-super-secret-signing-key',
    databasePassword: 'FAKE-db-password-123',
    adminContact: 'admin@vulnbank.local',
  });
});

// FLAW: open redirect, "to" can be any URL.
route('GET', '/api/redirect', ({ res, url }) => {
  const to = url.searchParams.get('to') ?? '/';
  res.writeHead(302, { Location: to });
  res.end();
});

// ---------- server ----------

const server = http.createServer(async (req, res) => {
  // FLAW: the server announces what it is running.
  res.setHeader('Server', 'VulnBank/1.0 (node)');
  res.setHeader('X-Powered-By', 'VulnBank');
  // FLAW: CORS reflects any Origin and allows credentials, so any web page can call the API as the logged-in user.
  const origin = req.headers.origin;
  if (origin) {
    res.setHeader('Access-Control-Allow-Origin', origin);
    res.setHeader('Access-Control-Allow-Credentials', 'true');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');
    res.setHeader('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS');
  }
  // FLAW: no Content-Security-Policy, X-Frame-Options or other security headers.

  if (req.method === 'OPTIONS') {
    res.writeHead(204);
    return res.end();
  }

  const url = new URL(req.url ?? '/', `http://${req.headers.host ?? 'localhost'}`);
  try {
    for (const { method, regex, handler } of routes) {
      const match = regex.exec(url.pathname);
      if (method === req.method && match) {
        const body = req.method === 'GET' ? {} : await readBody(req);
        return await handler({ req, res, url, body, params: match.slice(1) });
      }
    }
    throw new HttpError(404, 'Not found');
  } catch (error) {
    const status = error instanceof HttpError ? error.status : 500;
    // FLAW: verbose errors. The message, the failing SQL and the stack trace are all returned.
    send(res, status, { error: error.message, query: error.query, stack: status === 500 ? error.stack : undefined });
  }
});

server.listen(PORT, HOST, () => {
  console.log('');
  console.log('  VulnBank API (intentionally vulnerable, training use only)');
  console.log(`  Listening on http://${HOST}:${PORT}  (this computer only)`);
  console.log('  Data is in memory and resets every time the server restarts.');
  console.log('');
});
