// VulnBank database: SQLite, in memory. Every restart of the server resets all data to the seed below.
// WARNING: intentionally insecure training app. Do not reuse any of this code in a real system.
import { createHash } from 'node:crypto';
import { DatabaseSync } from 'node:sqlite';

// FLAW: passwords are stored as unsalted MD5 hashes.
export const md5 = (text) => createHash('md5').update(text).digest('hex');

export const db = new DatabaseSync(':memory:');

db.exec(`
  CREATE TABLE users (
    id INTEGER PRIMARY KEY,
    username TEXT UNIQUE NOT NULL,
    password TEXT NOT NULL,
    full_name TEXT,
    email TEXT,
    role TEXT NOT NULL DEFAULT 'customer',
    created_at TEXT DEFAULT CURRENT_TIMESTAMP
  );
  CREATE TABLE accounts (
    id INTEGER PRIMARY KEY,
    user_id INTEGER NOT NULL,
    number TEXT NOT NULL,
    type TEXT NOT NULL,
    balance REAL NOT NULL
  );
  CREATE TABLE transactions (
    id INTEGER PRIMARY KEY,
    from_account INTEGER NOT NULL,
    to_account INTEGER NOT NULL,
    amount REAL NOT NULL,
    memo TEXT,
    created_at TEXT DEFAULT CURRENT_TIMESTAMP
  );
  CREATE TABLE risk_alerts (
    id INTEGER PRIMARY KEY,
    account_id INTEGER,
    reason TEXT NOT NULL,
    severity TEXT NOT NULL,
    created_at TEXT DEFAULT CURRENT_TIMESTAMP
  );
  CREATE TABLE support_tickets (
    id INTEGER PRIMARY KEY,
    user_id INTEGER NOT NULL,
    subject TEXT NOT NULL,
    message TEXT NOT NULL,
    created_at TEXT DEFAULT CURRENT_TIMESTAMP
  );
`);

const addUser = db.prepare(
  'INSERT INTO users (id, username, password, full_name, email, role) VALUES (?, ?, ?, ?, ?, ?)',
);
// Deliberately weak passwords, for brute-force and dictionary exercises.
addUser.run(1, 'admin', md5('admin123'), 'Ada Admin', 'admin@vulnbank.local', 'admin');
addUser.run(2, 'alice', md5('password1'), 'Alice Anders', 'alice@example.test', 'customer');
addUser.run(3, 'bob', md5('qwerty'), 'Bob Brown', 'bob@example.test', 'customer');
addUser.run(4, 'carol', md5('letmein'), 'Carol Chen', 'carol@example.test', 'customer');

const addAccount = db.prepare('INSERT INTO accounts (id, user_id, number, type, balance) VALUES (?, ?, ?, ?, ?)');
addAccount.run(1, 1, 'VB-TREASURY-0001', 'treasury', 1000000);
addAccount.run(2, 2, 'VB-1001-CHK', 'checking', 5230.5);
addAccount.run(3, 2, 'VB-1002-SAV', 'savings', 12000);
addAccount.run(4, 3, 'VB-2001-CHK', 'checking', 1800);
addAccount.run(5, 4, 'VB-3001-CHK', 'checking', 25000);

const addTx = db.prepare(
  'INSERT INTO transactions (from_account, to_account, amount, memo, created_at) VALUES (?, ?, ?, ?, ?)',
);
addTx.run(2, 4, 120, 'Dinner split', '2025-09-02 19:30:00');
addTx.run(5, 2, 2500, 'Invoice 1042', '2025-09-05 10:12:00');
addTx.run(4, 2, 45.5, 'Concert tickets', '2025-09-11 08:45:00');
addTx.run(2, 3, 1000, 'Monthly savings', '2025-09-30 23:59:00');
// Two transfers just under the 10,000 reporting threshold on the same day: no alert was raised for them.
addTx.run(5, 4, 9900, 'Equipment purchase', '2025-10-03 09:05:00');
addTx.run(5, 4, 9950, 'Equipment purchase (2)', '2025-10-03 09:41:00');

const addAlert = db.prepare('INSERT INTO risk_alerts (account_id, reason, severity, created_at) VALUES (?, ?, ?, ?)');
addAlert.run(5, 'Large transfer of 15000.00 to an external account', 'high', '2025-09-20 14:00:00');
addAlert.run(3, 'Dormant savings account became active', 'low', '2025-09-30 23:59:30');
addAlert.run(4, 'Multiple transfers just under the reporting threshold', 'medium', '2025-10-03 10:00:00');

db.prepare('INSERT INTO support_tickets (user_id, subject, message, created_at) VALUES (?, ?, ?, ?)').run(
  3,
  'Card declined',
  'My card was declined at the store yesterday, please check my account.',
  '2025-10-04 12:00:00',
);
