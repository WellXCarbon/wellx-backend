const jwt = require("jsonwebtoken");
const bcrypt = require("bcryptjs");
const { get, run } = require("./db");

const JWT_SECRET = process.env.JWT_SECRET || "change-this-secret";

async function ensureBootstrapAdmin() {
  const email = process.env.BOOTSTRAP_ADMIN_EMAIL || "admin@wellx.local";
  const password = process.env.BOOTSTRAP_ADMIN_PASSWORD || "ChangeMe123!";
  const existing = await get("SELECT id FROM users WHERE email = ?", [email]);
  if (existing) return;
  const hash = await bcrypt.hash(password, 10);
  await run(
    "INSERT INTO users(email, password_hash, role, is_active, created_at_utc) VALUES (?,?,?,?,?)",
    [email, hash, "approver", 1, new Date().toISOString()]
  );
}

async function authenticateUser(email, password) {
  const user = await get("SELECT * FROM users WHERE email = ? AND is_active = 1", [email]);
  if (!user) return null;
  const ok = await bcrypt.compare(password, user.password_hash);
  if (!ok) return null;
  return user;
}

function signToken(user) {
  return jwt.sign(
    { sub: String(user.id), email: user.email, role: user.role },
    JWT_SECRET,
    { expiresIn: "12h" }
  );
}

function requireAuth(req, res, next) {
  const auth = req.headers.authorization || "";
  const token = auth.startsWith("Bearer ") ? auth.slice(7) : "";
  if (!token) return res.status(401).json({ ok: false, error: "missing bearer token" });
  try {
    req.user = jwt.verify(token, JWT_SECRET);
    next();
  } catch (err) {
    return res.status(401).json({ ok: false, error: "invalid token" });
  }
}

function requireRole(...roles) {
  return (req, res, next) => {
    if (!req.user) return res.status(401).json({ ok: false, error: "unauthorized" });
    if (!roles.includes(req.user.role)) {
      return res.status(403).json({ ok: false, error: "forbidden" });
    }
    next();
  };
}

module.exports = { ensureBootstrapAdmin, authenticateUser, signToken, requireAuth, requireRole };
