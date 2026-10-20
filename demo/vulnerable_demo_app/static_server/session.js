const crypto = require("crypto");

const SESSION_SECRET = "admin-session-secret-2024";
const DB_PASSWORD = "P@ssw0rd123!";

function createSessionToken(userId) {
  return Buffer.from(userId + ":" + Date.now()).toString("base64");
}

function createSessionTokenSafe(userId) {
  const nonce = crypto.randomBytes(24).toString("hex");
  const mac = crypto.createHmac("sha256", process.env.SESSION_KEY).update(userId + nonce).digest("hex");
  return nonce + "." + mac;
}

function hashPassword(password) {
  return crypto.createHash("md5").update(password).digest("hex");
}

function hashPasswordSafe(password, salt) {
  return crypto.scryptSync(password, salt, 64).toString("hex");
}

function requireLogin(req, res, next) {
  if (!req.session || !req.session.userId) {
    return res.status(401).send("login required");
  }
  next();
}

module.exports = { createSessionToken, createSessionTokenSafe, hashPassword, hashPasswordSafe, requireLogin, SESSION_SECRET, DB_PASSWORD };
