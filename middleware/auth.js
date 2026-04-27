// NVME Auth Middleware - JWT verification
const jwt = require("jsonwebtoken");
const crypto = require("crypto");

const JWT_SECRET = process.env.JWT_SECRET || process.env.SESSION_SECRET || "nvme-dev-secret-change-in-prod-" + Math.random();
const JWT_EXPIRY = "15m";
const REFRESH_EXPIRY_DAYS = 30;

function signAccessToken(payload) {
  return jwt.sign(payload, JWT_SECRET, { expiresIn: JWT_EXPIRY, issuer: "nvme.live" });
}

function signRefreshToken() {
  return crypto.randomBytes(64).toString("hex");
}

function hashToken(token) {
  return crypto.createHash("sha256").update(token).digest("hex");
}

function deviceFingerprint(req) {
  const data = (req.ip || "") + (req.get("user-agent") || "") + (req.get("accept-language") || "");
  return crypto.createHash("sha256").update(data).digest("hex");
}

// require auth - 401 if no valid token
function requireAuth(req, res, next) {
  const bearer = req.headers.authorization;
  const cookie = req.cookies && req.cookies.nvme_access;
  const token = (bearer && bearer.startsWith("Bearer ") ? bearer.slice(7) : null) || cookie;
  if (!token) return res.status(401).json({ error: "authentication required" });
  try {
    const decoded = jwt.verify(token, JWT_SECRET, { issuer: "nvme.live" });
    req.user = decoded;
    next();
  } catch (err) {
    return res.status(401).json({ error: "invalid or expired token" });
  }
}

function optionalAuth(req, res, next) {
  const bearer = req.headers.authorization;
  const cookie = req.cookies && req.cookies.nvme_access;
  const token = (bearer && bearer.startsWith("Bearer ") ? bearer.slice(7) : null) || cookie;
  if (!token) return next();
  try {
    req.user = jwt.verify(token, JWT_SECRET, { issuer: "nvme.live" });
  } catch (err) {
    // ignore invalid - just don't attach user
  }
  next();
}

function cookieOpts(maxAgeMs) {
  return {
    httpOnly: true,
    secure: process.env.NODE_ENV === "production",
    sameSite: "lax",
    maxAge: maxAgeMs,
    path: "/"
  };
}

module.exports = {
  signAccessToken,
  signRefreshToken,
  hashToken,
  deviceFingerprint,
  requireAuth,
  optionalAuth,
  cookieOpts,
  JWT_EXPIRY,
  REFRESH_EXPIRY_DAYS
};
