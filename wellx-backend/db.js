const sqlite3 = require("sqlite3").verbose();
const path = require("path");
const DB_PATH = process.env.DB_PATH || path.join(__dirname, "wellx.db");
const db = new sqlite3.Database(DB_PATH);

function run(sql, params = []) {
  return new Promise((resolve, reject) => db.run(sql, params, function(err){ err ? reject(err) : resolve(this); }));
}
function get(sql, params = []) {
  return new Promise((resolve, reject) => db.get(sql, params, function(err,row){ err ? reject(err) : resolve(row); }));
}
function all(sql, params = []) {
  return new Promise((resolve, reject) => db.all(sql, params, function(err,rows){ err ? reject(err) : resolve(rows); }));
}

async function initDb() {
  await run(`CREATE TABLE IF NOT EXISTS records (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    well_id TEXT NOT NULL,
    payload_json TEXT NOT NULL,
    sha256_hash TEXT NOT NULL,
    xrpl_tx_hash TEXT,
    xrpl_explorer_url TEXT,
    status TEXT NOT NULL,
    created_at_utc TEXT NOT NULL
  )`);
  await run(`CREATE TABLE IF NOT EXISTS events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    record_id INTEGER NOT NULL,
    event_type TEXT NOT NULL,
    message TEXT,
    created_at_utc TEXT NOT NULL,
    FOREIGN KEY(record_id) REFERENCES records(id)
  )`);
  await run(`CREATE TABLE IF NOT EXISTS app_kv (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL,
    updated_at_utc TEXT NOT NULL
  )`);
  await run(`CREATE TABLE IF NOT EXISTS rule_evaluations (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    record_id INTEGER NOT NULL,
    state_json TEXT NOT NULL,
    rule_results_json TEXT NOT NULL,
    evaluation_trace_json TEXT NOT NULL,
    final_outcome TEXT NOT NULL,
    decision_hash TEXT NOT NULL,
    rule_set_version TEXT,
    created_at_utc TEXT NOT NULL,
    FOREIGN KEY(record_id) REFERENCES records(id)
  )`);
  await run(`CREATE TABLE IF NOT EXISTS rule_sets (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    version TEXT NOT NULL UNIQUE,
    rules_json TEXT NOT NULL,
    is_active INTEGER NOT NULL,
    approval_status TEXT NOT NULL DEFAULT 'APPROVED',
    submitted_by TEXT,
    approved_by TEXT,
    created_at_utc TEXT NOT NULL,
    approved_at_utc TEXT,
    created_by TEXT,
    notes TEXT
  )`);
  await run(`CREATE TABLE IF NOT EXISTS rule_set_history (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    rule_set_version TEXT NOT NULL,
    action_type TEXT NOT NULL,
    actor_id TEXT,
    details_json TEXT,
    created_at_utc TEXT NOT NULL
  )`);
  await run(`CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    email TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    role TEXT NOT NULL,
    is_active INTEGER NOT NULL DEFAULT 1,
    created_at_utc TEXT NOT NULL
  )`);
}

async function setKv(key, value) {
  const now = new Date().toISOString();
  await run("INSERT INTO app_kv(key,value,updated_at_utc) VALUES(?,?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value, updated_at_utc=excluded.updated_at_utc", [key, value, now]);
}
async function getKv(key) {
  const row = await get("SELECT value FROM app_kv WHERE key = ?", [key]);
  return row ? row.value : null;
}


  await run(`CREATE TABLE IF NOT EXISTS audit_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    actor TEXT,
    action TEXT,
    entity TEXT,
    entity_id TEXT,
    details_json TEXT,
    created_at_utc TEXT NOT NULL
  )`);
module.exports = { db, run, get, all, initDb, setKv, getKv };
