const jwt = require("jsonwebtoken");
const { db } = require("../db");
const { JWT_SECRET } = require("../utils/security");

async function attachUser(req, res, next) {
  if (!req.session.userId) {
    req.user = null;
    res.locals.currentUser = null;
    next();
    return;
  }

  try {
    const user = await db.get("SELECT * FROM users WHERE id = ?", [req.session.userId]);
    req.user = user || null;
    res.locals.currentUser = req.user;
    next();
  } catch (error) {
    next(error);
  }
}

function requireLogin(req, res, next) {
  if (!req.user) {
    req.session.flash = { type: "error", message: "Login required." };
    res.redirect("/login");
    return;
  }
  next();
}

function requireAdminish(req, res, next) {
  if (!req.user || (req.user.role !== "admin" && !req.user.is_support)) {
    req.session.flash = { type: "error", message: "Admin area only." };
    res.redirect("/dashboard");
    return;
  }
  next();
}

async function apiAuth(req, res, next) {
  const header = req.headers.authorization || "";
  const token = header.startsWith("Bearer ") ? header.slice(7) : null;

  if (!token) {
    res.status(401).json({ error: "missing bearer token" });
    return;
  }

  let payload = null;
  let mode = "verified";

  try {
    payload = jwt.verify(token, JWT_SECRET);
  } catch (error) {
    payload = jwt.decode(token);
    mode = "decoded";
  }

  if (!payload || !payload.sub) {
    res.status(401).json({ error: "invalid token" });
    return;
  }

  const user = await db.get("SELECT * FROM users WHERE id = ?", [payload.sub]);
  if (!user) {
    res.status(401).json({ error: "unknown user" });
    return;
  }

  req.apiUser = user;
  req.tokenMode = mode;
  next();
}

module.exports = {
  attachUser,
  requireLogin,
  requireAdminish,
  apiAuth
};
