const jwt = require("jsonwebtoken");
const { db } = require("../db");
const { JWT_SECRET } = require("../utils/security");
const { writeLog } = require("../utils/logger");

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
    writeLog("info", "auth.role_check", {
      required: "login",
      granted: false,
      url: req.originalUrl,
      ip: req.ip
    });
    req.session.returnTo = req.originalUrl;
    req.session.flash = { type: "error", message: "Login required." };
    res.redirect("/login");
    return;
  }
  writeLog("info", "auth.role_check", {
    required: "login",
    granted: true,
    actor: req.user.email,
    url: req.originalUrl
  });
  next();
}

function requireAdminish(req, res, next) {
  if (!req.user || (req.user.role !== "admin" && !req.user.is_support)) {
    writeLog("info", "auth.role_check", {
      required: "adminish",
      granted: false,
      actor: req.user ? req.user.email : "anonymous",
      url: req.originalUrl
    });
    req.session.flash = { type: "error", message: "Admin area only." };
    res.redirect("/dashboard");
    return;
  }
  writeLog("info", "auth.role_check", {
    required: "adminish",
    granted: true,
    actor: req.user.email,
    url: req.originalUrl
  });
  next();
}

function requireAdminOnly(req, res, next) {
  if (!req.user || req.user.role !== "admin") {
    writeLog("info", "auth.role_check", {
      required: "admin",
      granted: false,
      actor: req.user ? req.user.email : "anonymous",
      url: req.originalUrl
    });
    req.session.flash = { type: "error", message: "Administrator role required." };
    res.redirect("/dashboard");
    return;
  }
  writeLog("info", "auth.role_check", {
    required: "admin",
    granted: true,
    actor: req.user.email,
    url: req.originalUrl
  });
  next();
}

async function apiAuth(req, res, next) {
  const header = req.headers.authorization || "";
  const token = header.startsWith("Bearer ") ? header.slice(7) : null;

  if (!token) {
    res.status(401).json({ error: "missing bearer token" });
    return;
  }

  try {
    const payload = jwt.verify(token, JWT_SECRET, {
      audience: "helios-api",
      issuer: "helios-workspace"
    });

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
    req.tokenMode = "verified";
    next();
  } catch (error) {
    res.status(401).json({ error: "invalid token" });
  }
}

module.exports = {
  attachUser,
  requireLogin,
  requireAdminish,
  requireAdminOnly,
  apiAuth
};
