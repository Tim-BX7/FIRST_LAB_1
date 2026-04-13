const express = require("express");
const path = require("path");
const fs = require("fs");
const crypto = require("crypto");
const { execFile } = require("child_process");
const cookieParser = require("cookie-parser");
const session = require("express-session");
const SQLiteStore = require("connect-sqlite3")(session);
const multer = require("multer");
const { promisify } = require("util");
const { db, initDb } = require("./src/db");
const { APP_LOG, audit, writeLog } = require("./src/utils/logger");
const { hashPassword, issueApiToken, verifyPassword, SESSION_SECRET } = require("./src/utils/security");
const { renderTemplateString } = require("./src/utils/templateEngine");
const { attachUser, requireLogin, requireAdminish, requireAdminOnly, apiAuth } = require("./src/middleware/auth");
const { FLAGS } = require("./src/flags");

const asyncExecFile = promisify(execFile);
const app = express();
const PORT = process.env.PORT || 3000;
const UPLOAD_DIR = path.join(process.cwd(), "storage", "uploads");
const TRUSTED_ORIGIN = process.env.APP_ORIGIN || "";
const VALID_PLANS = new Set(["starter", "business", "enterprise"]);
const SAFE_UPLOAD_MIME_TYPES = new Set(["image/png", "image/jpeg", "image/gif", "image/webp"]);
const SAFE_UPLOAD_EXTENSIONS = new Set([".png", ".jpg", ".jpeg", ".gif", ".webp"]);

fs.mkdirSync(UPLOAD_DIR, { recursive: true });

// ✅ FIX 1: Trust the proxy on Render so secure cookies work over HTTPS
app.set("trust proxy", 1);

const upload = multer({
  storage: multer.diskStorage({
    destination(req, file, cb) {
      cb(null, UPLOAD_DIR);
    },
    filename(req, file, cb) {
      const extension = getUploadExtension(file);
      cb(null, `${Date.now()}-${crypto.randomBytes(8).toString("hex")}${extension || ""}`);
    }
  }),
  limits: {
    fileSize: 5 * 1024 * 1024
  },
  fileFilter(req, file, cb) {
    if (!getUploadExtension(file)) {
      cb(new Error("Only PNG, JPG, GIF, and WEBP images are allowed."));
      return;
    }
    cb(null, true);
  }
});

app.set("view engine", "ejs");
app.set("views", path.join(process.cwd(), "views"));

app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.use(cookieParser());

// ✅ FIX 2: Use persistent SQLiteStore so sessions survive between requests on Render
app.use(
  session({
    store: new SQLiteStore({
      db: "sessions.sqlite",
      dir: path.join(process.cwd(), "storage")
    }),
    secret: SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
    cookie: {
      httpOnly: true,
      sameSite: "lax",
      secure: process.env.NODE_ENV === "production" // ✅ FIX 3: secure=true on production (HTTPS)
    }
  })
);

app.use((req, res, next) => {
  const origin = safeBodyValue(req.headers.origin);

  if (TRUSTED_ORIGIN && origin && origin === TRUSTED_ORIGIN) {
    res.setHeader("Vary", "Origin");
    res.setHeader("Access-Control-Allow-Origin", TRUSTED_ORIGIN);
    res.setHeader("Access-Control-Allow-Credentials", "true");
    res.setHeader("Access-Control-Allow-Headers", "Content-Type, Authorization, X-CSRF-Token");
    res.setHeader("Access-Control-Allow-Methods", "GET,POST,PATCH");
  }

  if (req.method === "OPTIONS") {
    res.sendStatus(TRUSTED_ORIGIN && origin === TRUSTED_ORIGIN ? 204 : 403);
    return;
  }

  res.setHeader(
    "Content-Security-Policy",
    "default-src 'self'; base-uri 'self'; form-action 'self'; frame-ancestors 'none'; img-src 'self' data: blob:; object-src 'none'; script-src 'self'; style-src 'self' 'unsafe-inline'"
  );
  res.setHeader("Referrer-Policy", "same-origin");
  res.setHeader("X-Content-Type-Options", "nosniff");
  res.setHeader("X-Frame-Options", "DENY");
  res.setHeader("Cross-Origin-Resource-Policy", "same-origin");
  next();
});

app.use("/uploads", (req, res) => {
  res.status(404).send("Not found");
});
app.use(express.static(path.join(process.cwd(), "public")));
app.use(ensureCsrfToken);
app.use((req, res, next) => {
  const contentType = String(req.headers["content-type"] || "").toLowerCase();
  if (contentType.startsWith("multipart/form-data")) {
    next();
    return;
  }
  verifyCsrfToken(req, res, next);
});
app.use(attachUser);

app.locals.formatMoney = (cents) => `$${(Number(cents) / 100).toFixed(2)}`;
app.locals.flagKeys = Object.keys(FLAGS || {});

app.use((req, res, next) => {
  if (!req.session.csrfToken) {
    req.session.csrfToken = crypto.randomBytes(32).toString("hex");
  }
  res.locals.csrfToken = req.session.csrfToken;
  res.locals.flash = req.session.flash || null;
  delete req.session.flash;
  next();
});

function setFlash(req, type, message) {
  req.session.flash = { type, message };
}

function renderPage(res, view, locals = {}) {
  res.render(view, {
    csrfToken: res.locals.csrfToken || "",
    ...locals
  });
}

function safeBodyValue(input) {
  return typeof input === "string" ? input.trim() : "";
}

function normalizeText(input, maxLength = 1000) {
  return String(input ?? "").trim().slice(0, maxLength);
}

function normalizeEmail(input) {
  return safeBodyValue(input).toLowerCase();
}

function isValidEmail(email) {
  return /^[^\s@]+@[^\s@]+$/.test(email);
}

function isStrongEnoughPassword(password) {
  return String(password || "").length >= 8;
}

function parsePositiveInteger(value, fallback = 1) {
  const parsed = Number.parseInt(String(value ?? ""), 10);
  return Number.isFinite(parsed) && parsed > 0 ? parsed : fallback;
}

function getUploadExtension(file) {
  const extension = path.extname(String(file.originalname || "")).toLowerCase();
  const mimeType = String(file.mimetype || "").toLowerCase();
  if (!SAFE_UPLOAD_EXTENSIONS.has(extension) || !SAFE_UPLOAD_MIME_TYPES.has(mimeType)) {
    return null;
  }
  return extension === ".jpeg" ? ".jpg" : extension;
}

function sanitizeFilename(filename) {
  const original = String(filename || "download");
  const extension = path.extname(original).replace(/[^a-zA-Z0-9.]/g, "");
  const base = path
    .basename(original, path.extname(original))
    .replace(/[^a-zA-Z0-9._ -]/g, "_")
    .slice(0, 80);

  return `${base || "download"}${extension}`;
}

function isSafeHost(host) {
  return /^(localhost|(?:\d{1,3}\.){3}\d{1,3}|(?=.{1,253}$)[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*)$/.test(host);
}

function ensureCsrfToken(req, res, next) {
  if (!req.session.csrfToken) {
    req.session.csrfToken = crypto.randomBytes(32).toString("hex");
  }

  res.locals.csrfToken = req.session.csrfToken;
  next();
}

function verifyCsrfToken(req, res, next) {
  if (["GET", "HEAD", "OPTIONS"].includes(req.method) || req.originalUrl.startsWith("/api/") || req.originalUrl.startsWith("/internal/")) {
    next();
    return;
  }

  const token = safeBodyValue(req.body?._csrf) || safeBodyValue(req.headers["x-csrf-token"]);
  if (token && token === req.session.csrfToken) {
    next();
    return;
  }

  const error = new Error("Invalid CSRF token.");
  error.status = 403;
  next(error);
}

app.get("/", async (req, res) => {
  const stats = await db.get(
    "SELECT (SELECT COUNT(*) FROM projects) AS projectCount, (SELECT COUNT(*) FROM users) AS userCount, (SELECT COUNT(*) FROM files) AS fileCount"
  );
  renderPage(res, "index", { title: "Helios Workspace", stats });
});

app.get("/register", (req, res) => {
  renderPage(res, "auth/register", { title: "Register" });
});

app.post("/register", async (req, res, next) => {
  try {
    const email = normalizeEmail(req.body.email);
    const displayName = safeBodyValue(req.body.display_name) || "New User";
    const password = safeBodyValue(req.body.password);

    if (!isValidEmail(email)) {
      setFlash(req, "error", "Please enter a valid email address.");
      res.redirect("/register");
      return;
    }

    if (!isStrongEnoughPassword(password)) {
      setFlash(req, "error", "Password must be at least 8 characters.");
      res.redirect("/register");
      return;
    }

    await db.run(
      "INSERT INTO users (tenant_id, email, password_hash, display_name, role, is_support, plan, credits) VALUES (?, ?, ?, ?, 'user', 0, 'starter', 0)",
      [1, email, hashPassword(password), displayName]
    );

    setFlash(req, "success", "Account created. Log in to continue.");
    res.redirect("/login");
  } catch (error) {
    if (String(error.message).includes("UNIQUE constraint failed: users.email")) {
      setFlash(req, "error", "That email address is already in use.");
      res.redirect("/register");
      return;
    }
    next(error);
  }
});

app.get("/login", (req, res) => {
  renderPage(res, "auth/login", { title: "Login" });
});

app.post("/login", async (req, res, next) => {
  try {
    const email = normalizeEmail(req.body.email);
    const password = safeBodyValue(req.body.password);
    const user = await db.get("SELECT * FROM users WHERE email = ? LIMIT 1", [email]);

    if (!user || !verifyPassword(password, user.password_hash)) {
      setFlash(req, "error", "Invalid email or password.");
      res.redirect("/login");
      return;
    }

    req.session.userId = user.id;
    await audit(db, user.id, user.tenant_id, "login", "Interactive login", req.ip);
    setFlash(req, "success", "Welcome back.");
    const returnTo = req.session.returnTo || "/dashboard";
    delete req.session.returnTo;
    res.redirect(returnTo);
  } catch (error) {
    next(error);
  }
});

app.post("/logout", (req, res) => {
  req.session.destroy(() => {
    res.redirect("/");
  });
});

app.get("/dashboard", requireLogin, async (req, res, next) => {
  try {
    const projects = await db.all(
      "SELECT * FROM projects WHERE tenant_id = ? ORDER BY id DESC",
      [req.user.tenant_id]
    );
    const tickets = await db.all(
      "SELECT * FROM support_tickets WHERE tenant_id = ? ORDER BY id DESC LIMIT 5",
      [req.user.tenant_id]
    );
    const files = await db.all(
      "SELECT * FROM files WHERE tenant_id = ? ORDER BY id DESC LIMIT 5",
      [req.user.tenant_id]
    );
    const logs = await db.all(
      "SELECT * FROM audit_logs WHERE tenant_id = ? ORDER BY id DESC LIMIT 5",
      [req.user.tenant_id]
    );

    renderPage(res, "dashboard", {
      title: "Dashboard",
      projects,
      tickets,
      files,
      logs
    });
  } catch (error) {
    next(error);
  }
});

app.get("/profile", requireLogin, async (req, res) => {
  const token = issueApiToken(req.user);
  renderPage(res, "profile", { title: "Profile", token });
});

app.post("/profile", requireLogin, async (req, res, next) => {
  try {
    await db.run(
      "UPDATE users SET display_name = ?, bio = ?, default_filter = ?, email_template = ? WHERE id = ?",
      [
        safeBodyValue(req.body.display_name) || req.user.display_name,
        normalizeText(req.body.bio, 1500),
        safeBodyValue(req.body.default_filter) || "open",
        normalizeText(req.body.email_template, 2000),
        req.user.id
      ]
    );
    await audit(db, req.user.id, req.user.tenant_id, "profile-update", "Updated profile settings", req.ip);
    setFlash(req, "success", "Profile updated.");
    res.redirect("/profile");
  } catch (error) {
    next(error);
  }
});

app.post("/account/email", requireLogin, async (req, res, next) => {
  try {
    const email = normalizeEmail(req.body.email);

    if (!isValidEmail(email)) {
      setFlash(req, "error", "Please enter a valid email address.");
      res.redirect("/profile");
      return;
    }

    await db.run("UPDATE users SET email = ? WHERE id = ?", [
      email,
      req.user.id
    ]);
    await audit(db, req.user.id, req.user.tenant_id, "email-change", "Email address updated", req.ip);
    setFlash(req, "success", "Email address changed.");
    res.redirect("/profile");
  } catch (error) {
    if (String(error.message).includes("UNIQUE constraint failed: users.email")) {
      setFlash(req, "error", "That email address is already in use.");
      res.redirect("/profile");
      return;
    }
    next(error);
  }
});

app.post("/account/password", requireLogin, async (req, res, next) => {
  try {
    const password = safeBodyValue(req.body.password);

    if (!isStrongEnoughPassword(password)) {
      setFlash(req, "error", "Password must be at least 8 characters.");
      res.redirect("/profile");
      return;
    }

    await db.run("UPDATE users SET password_hash = ? WHERE id = ?", [
      hashPassword(password),
      req.user.id
    ]);
    await audit(db, req.user.id, req.user.tenant_id, "password-change", "Password changed from settings form", req.ip);
    setFlash(req, "success", "Password changed.");
    res.redirect("/profile");
  } catch (error) {
    next(error);
  }
});

app.get("/billing", requireLogin, async (req, res) => {
  renderPage(res, "billing", { title: "Billing" });
});

app.post("/billing/upgrade", requireLogin, async (req, res, next) => {
  try {
    const requestedPlan = safeBodyValue(req.body.plan);
    const plan = VALID_PLANS.has(requestedPlan) ? requestedPlan : "starter";
    const seatCount = Math.min(parsePositiveInteger(req.body.seats, 1), 100);
    const coupon = safeBodyValue(req.body.coupon).toUpperCase().replace(/[^A-Z0-9-]/g, "");
    const basePrice = plan === "enterprise" ? 6900 : plan === "business" ? 2900 : 990;
    const subtotal = basePrice * seatCount;
    let discount = 0;

    if (coupon.startsWith("PARTNER-")) {
      discount += Math.round(subtotal * 0.2);
    }

    if (coupon === "WELCOME100") {
      discount += 10000;
    }

    discount = Math.min(discount, subtotal);

    const remainingAfterCoupon = Math.max(0, subtotal - discount);
    const creditsToApply = req.body.use_credits
      ? Math.min(req.user.credits, Math.ceil(remainingAfterCoupon / 100))
      : 0;

    if (req.body.use_credits) {
      discount += creditsToApply * 100;
    }

    const total = Math.max(0, subtotal - discount);

    await db.run("UPDATE users SET plan = ?, credits = credits - ? WHERE id = ?", [
      plan,
      creditsToApply,
      req.user.id
    ]);

    await audit(
      db,
      req.user.id,
      req.user.tenant_id,
      "plan-upgrade",
      `plan=${plan};seats=${seatCount};total=${total};credits_used=${creditsToApply}`,
      req.ip
    );

    setFlash(
      req,
      "success",
      total === 0
        ? "Upgrade applied with no remaining balance."
        : `Upgrade request submitted. Estimated charge ${app.locals.formatMoney(total)}`
    );
    res.redirect("/billing");
  } catch (error) {
    next(error);
  }
});

app.get("/search", requireLogin, async (req, res, next) => {
  try {
    const query = safeBodyValue(req.query.q);
    const results = query
      ? await db.all(
          "SELECT * FROM projects WHERE tenant_id = ? AND name LIKE ? ORDER BY id DESC",
          [req.user.tenant_id, `%${query}%`]
        )
      : [];

    renderPage(res, "search", {
      title: "Search",
      query,
      results
    });
  } catch (error) {
    next(error);
  }
});

app.get("/projects/:id", requireLogin, async (req, res, next) => {
  try {
    const project = await db.get("SELECT * FROM projects WHERE id = ? AND tenant_id = ?", [
      req.params.id,
      req.user.tenant_id
    ]);
    if (!project) {
      res.status(404);
      renderPage(res, "error", { title: "Not found", message: "Project not found." });
      return;
    }

    const comments = await db.all(
      "SELECT project_comments.*, users.display_name FROM project_comments JOIN users ON users.id = project_comments.user_id WHERE project_comments.project_id = ? AND users.tenant_id = ? ORDER BY project_comments.id ASC",
      [req.params.id, req.user.tenant_id]
    );

    renderPage(res, "project", { title: project.name, project, comments });
  } catch (error) {
    next(error);
  }
});

app.post("/projects/:id/comments", requireLogin, async (req, res, next) => {
  try {
    const project = await db.get("SELECT id FROM projects WHERE id = ? AND tenant_id = ?", [
      req.params.id,
      req.user.tenant_id
    ]);
    if (!project) {
      res.status(404);
      renderPage(res, "error", { title: "Not found", message: "Project not found." });
      return;
    }

    await db.run(
      "INSERT INTO project_comments (project_id, user_id, body) VALUES (?, ?, ?)",
      [req.params.id, req.user.id, normalizeText(req.body.body, 2000)]
    );
    await audit(db, req.user.id, req.user.tenant_id, "comment-create", "Project comment added", req.ip);
    res.redirect(`/projects/${req.params.id}`);
  } catch (error) {
    next(error);
  }
});

app.get("/messages/:threadId", requireLogin, async (req, res, next) => {
  try {
    const thread = await db.get("SELECT * FROM threads WHERE id = ? AND tenant_id = ?", [
      req.params.threadId,
      req.user.tenant_id
    ]);
    if (!thread) {
      res.status(404);
      renderPage(res, "error", { title: "Not found", message: "Thread missing." });
      return;
    }

    const messages = await db.all(
      "SELECT messages.*, users.display_name FROM messages JOIN users ON users.id = messages.sender_id WHERE thread_id = ? ORDER BY messages.id ASC",
      [req.params.threadId]
    );
    renderPage(res, "messages", { title: thread.subject, thread, messages });
  } catch (error) {
    next(error);
  }
});

app.post("/messages/:threadId", requireLogin, async (req, res, next) => {
  try {
    const thread = await db.get("SELECT id FROM threads WHERE id = ? AND tenant_id = ?", [
      req.params.threadId,
      req.user.tenant_id
    ]);
    if (!thread) {
      res.status(404);
      renderPage(res, "error", { title: "Not found", message: "Thread missing." });
      return;
    }

    await db.run("INSERT INTO messages (thread_id, sender_id, body) VALUES (?, ?, ?)", [
      req.params.threadId,
      req.user.id,
      normalizeText(req.body.body, 2000)
    ]);
    res.redirect(`/messages/${req.params.threadId}`);
  } catch (error) {
    next(error);
  }
});

app.get("/files", requireLogin, async (req, res, next) => {
  try {
    const files = await db.all(
      "SELECT * FROM files WHERE tenant_id = ? ORDER BY id DESC",
      [req.user.tenant_id]
    );
    renderPage(res, "files", { title: "Files", files });
  } catch (error) {
    next(error);
  }
});

app.post("/files/upload", requireLogin, upload.single("document"), verifyCsrfToken, async (req, res, next) => {
  try {
    if (!req.file) {
      setFlash(req, "error", "No file uploaded.");
      res.redirect("/files");
      return;
    }

    let projectId = null;
    if (req.body.project_id) {
      projectId = parsePositiveInteger(req.body.project_id, 0) || null;
      if (projectId) {
        const project = await db.get("SELECT id FROM projects WHERE id = ? AND tenant_id = ?", [
          projectId,
          req.user.tenant_id
        ]);
        if (!project) {
          const removePath = path.join(UPLOAD_DIR, path.basename(req.file.filename));
          if (fs.existsSync(removePath)) {
            fs.unlinkSync(removePath);
          }
          setFlash(req, "error", "Selected project does not belong to your workspace.");
          res.redirect("/files");
          return;
        }
      }
    }

    await db.run(
      "INSERT INTO files (tenant_id, owner_id, project_id, original_name, stored_name, mime_type, size, note) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
      [
        req.user.tenant_id,
        req.user.id,
        projectId,
        sanitizeFilename(req.file.originalname),
        path.basename(req.file.filename),
        req.file.mimetype,
        req.file.size,
        normalizeText(req.body.note, 1000)
      ]
    );

    setFlash(req, "success", "File uploaded.");
    res.redirect("/files");
  } catch (error) {
    next(error);
  }
});

app.get("/files/:id/download", requireLogin, async (req, res, next) => {
  try {
    const file = await db.get("SELECT * FROM files WHERE id = ? AND tenant_id = ?", [
      req.params.id,
      req.user.tenant_id
    ]);
    if (!file) {
      res.status(404);
      renderPage(res, "error", { title: "Not found", message: "File missing." });
      return;
    }

    const storedName = path.basename(String(file.stored_name || ""));
    const filePath = path.join(UPLOAD_DIR, storedName);
    if (!fs.existsSync(filePath)) {
      res.status(404);
      renderPage(res, "error", { title: "Not found", message: "File missing." });
      return;
    }

    res.download(filePath, sanitizeFilename(file.original_name));
  } catch (error) {
    next(error);
  }
});

app.get("/admin", requireAdminish, async (req, res, next) => {
  try {
    const users = await db.all("SELECT * FROM users ORDER BY tenant_id, id");
    const recentLogs = await db.all("SELECT * FROM audit_logs ORDER BY id DESC LIMIT 10");
    renderPage(res, "admin/index", {
      title: "Admin Panel",
      users,
      recentLogs
    });
  } catch (error) {
    next(error);
  }
});

app.get("/admin/users/:id", requireAdminish, async (req, res, next) => {
  try {
    const target = await db.get("SELECT * FROM users WHERE id = ?", [req.params.id]);
    if (!target) {
      res.status(404);
      renderPage(res, "error", { title: "Not found", message: "User missing." });
      return;
    }

    const unsafeFilter = target.default_filter || "open";
    const tickets = await db.all(
      "SELECT * FROM support_tickets WHERE tenant_id = ? AND status LIKE ? ORDER BY id DESC",
      [target.tenant_id, `%${unsafeFilter}%`]
    );
    const comments = await db.all(
      "SELECT project_comments.*, projects.name AS project_name FROM project_comments JOIN projects ON projects.id = project_comments.project_id WHERE user_id = ? ORDER BY project_comments.id DESC",
      [target.id]
    );

    renderPage(res, "admin/user", {
      title: `User ${target.display_name}`,
      target,
      tickets,
      comments
    });
  } catch (error) {
    next(error);
  }
});

app.get("/admin/tools", requireAdminOnly, async (req, res) => {
  renderPage(res, "admin/tools", {
    title: "Diagnostics",
    output: "",
    host: "",
    logSample: fs.existsSync(APP_LOG) ? fs.readFileSync(APP_LOG, "utf8").split("\n").slice(-8).join("\n") : ""
  });
});

app.post("/admin/tools/trace", requireAdminOnly, async (req, res) => {
  const host = safeBodyValue(req.body.host) || "127.0.0.1";
  writeLog("info", "network-trace-request", { actor: req.user.email, host });

  if (!isSafeHost(host)) {
    res.status(400);
    renderPage(res, "admin/tools", {
      title: "Diagnostics",
      output: "Host must be a valid hostname or IPv4 address.",
      host,
      logSample: fs.existsSync(APP_LOG) ? fs.readFileSync(APP_LOG, "utf8").split("\n").slice(-8).join("\n") : ""
    });
    return;
  }

  try {
    const { stdout, stderr } = await asyncExecFile("ping", ["-n", "1", host], {
      timeout: 5000,
      windowsHide: true
    });
    renderPage(res, "admin/tools", {
      title: "Diagnostics",
      output: `${stdout}${stderr ? `\n${stderr}` : ""}`.trim(),
      host,
      logSample: fs.existsSync(APP_LOG) ? fs.readFileSync(APP_LOG, "utf8").split("\n").slice(-8).join("\n") : ""
    });
  } catch (error) {
    renderPage(res, "admin/tools", {
      title: "Diagnostics",
      output: error.message,
      host,
      logSample: fs.existsSync(APP_LOG) ? fs.readFileSync(APP_LOG, "utf8").split("\n").slice(-8).join("\n") : ""
    });
  }
});

app.get("/admin/email", requireAdminOnly, (req, res) => {
  renderPage(res, "admin/email", {
    title: "Email Preview",
    preview: "",
    template: req.user.email_template || "Hello {{ user.display_name }}"
  });
});

app.post("/admin/email/preview", requireAdminOnly, async (req, res) => {
  const template = normalizeText(req.body.template, 2000);
  const preview = renderTemplateString(template, {
    user: req.user,
    company: "Helios Workspace"
  });

  await audit(db, req.user.id, req.user.tenant_id, "mail-preview", "Previewed email template", req.ip);
  renderPage(res, "admin/email", {
    title: "Email Preview",
    preview,
    template
  });
});

app.get("/internal/health", async (req, res) => {
  const widgetMode = req.query.widget === "1";
  const projectCount = await db.get("SELECT COUNT(*) AS count FROM projects");
  res.json({
    service: "helios-workspace",
    status: "ok",
    widgetMode,
    projects: projectCount.count
  });
});

app.post("/api/auth/token", async (req, res, next) => {
  try {
    if (req.user) {
      res.json({ token: issueApiToken(req.user), hint: "interactive-session" });
      return;
    }

    const email = normalizeEmail(req.body.email);
    const password = safeBodyValue(req.body.password);
    const user = await db.get("SELECT * FROM users WHERE email = ?", [email]);
    if (!user || !verifyPassword(password, user.password_hash)) {
      res.status(401).json({ error: "invalid credentials" });
      return;
    }
    res.json({ token: issueApiToken(user), hint: "mobile-client" });
  } catch (error) {
    next(error);
  }
});

app.get("/api/reports/usage", apiAuth, async (req, res, next) => {
  try {
    const requestedTenantId = parsePositiveInteger(req.query.tenant, req.apiUser.tenant_id);
    const tenantId = req.apiUser.role === "admin" ? requestedTenantId : req.apiUser.tenant_id;
    const summary = await db.get(
      "SELECT (SELECT COUNT(*) FROM users WHERE tenant_id = ?) AS users, (SELECT COUNT(*) FROM files WHERE tenant_id = ?) AS files, (SELECT COUNT(*) FROM projects WHERE tenant_id = ?) AS projects",
      [tenantId, tenantId, tenantId]
    );
    res.json({
      tenant: tenantId,
      summary
    });
  } catch (error) {
    next(error);
  }
});

app.get("/api/me", apiAuth, async (req, res) => {
  res.json({
    id: req.apiUser.id,
    email: req.apiUser.email,
    role: req.apiUser.role,
    tokenMode: req.tokenMode
  });
});

app.patch("/api/profile", apiAuth, async (req, res, next) => {
  try {
    const normalizers = {
      display_name: (value) => safeBodyValue(value).slice(0, 80),
      bio: (value) => normalizeText(value, 1500),
      default_filter: (value) => safeBodyValue(value).slice(0, 40) || "open",
      email_template: (value) => normalizeText(value, 2000)
    };

    const provided = Object.keys(normalizers).filter((key) => Object.prototype.hasOwnProperty.call(req.body, key));
    if (!provided.length) {
      res.status(400).json({ error: "no accepted fields supplied" });
      return;
    }

    const assignments = provided.map((field) => `${field} = ?`).join(", ");
    const values = provided.map((field) => normalizers[field](req.body[field]));
    values.push(req.apiUser.id);

    await db.run(`UPDATE users SET ${assignments} WHERE id = ?`, values);
    const updated = await db.get("SELECT * FROM users WHERE id = ?", [req.apiUser.id]);

    res.json({
      message: "profile updated",
      user: updated
    });
  } catch (error) {
    next(error);
  }
});

app.get("/api/projects/:id", apiAuth, async (req, res, next) => {
  try {
    const project = await db.get("SELECT * FROM projects WHERE id = ? AND tenant_id = ?", [
      req.params.id,
      req.apiUser.tenant_id
    ]);
    if (!project) {
      res.status(404).json({ error: "not found" });
      return;
    }
    res.json({ project });
  } catch (error) {
    next(error);
  }
});

app.get("/api/files/:id", apiAuth, async (req, res, next) => {
  try {
    const file = await db.get("SELECT * FROM files WHERE id = ? AND tenant_id = ?", [
      req.params.id,
      req.apiUser.tenant_id
    ]);
    if (!file) {
      res.status(404).json({ error: "not found" });
      return;
    }
    res.json({
      file,
      download: `/files/${file.id}/download`
    });
  } catch (error) {
    next(error);
  }
});

app.get("/api/invoices/status", apiAuth, async (req, res, next) => {
  try {
    const reference = safeBodyValue(req.query.reference || "");
    const rows = await db.all(
      "SELECT id FROM invoices WHERE tenant_id = ? AND reference = ?",
      [req.apiUser.tenant_id, reference]
    );
    res.json({
      exists: rows.length > 0,
      checkedAt: new Date().toISOString()
    });
  } catch (error) {
    next(error);
  }
});

app.post("/api/preferences/import", apiAuth, async (req, res, next) => {
  try {
    const blob = req.body.blob || "";
    if (String(blob).length > 16384) {
      res.status(400).json({ error: "payload too large" });
      return;
    }

    const decoded = Buffer.from(blob, "base64").toString("utf8");
    const imported = JSON.parse(decoded);
    if (!imported || Array.isArray(imported) || typeof imported !== "object") {
      res.status(400).json({ error: "invalid import payload" });
      return;
    }

    const nextTemplate = imported.email_template
      ? normalizeText(imported.email_template, 2000)
      : req.apiUser.email_template;
    const nextFilter = imported.default_filter
      ? safeBodyValue(imported.default_filter).slice(0, 40)
      : req.apiUser.default_filter;
    await db.run("UPDATE users SET email_template = ?, default_filter = ? WHERE id = ?", [
      nextTemplate,
      nextFilter,
      req.apiUser.id
    ]);
    res.json({
      imported: {
        email_template: nextTemplate,
        default_filter: nextFilter
      }
    });
  } catch (error) {
    if (error instanceof SyntaxError) {
      res.status(400).json({ error: "invalid import payload" });
      return;
    }
    next(error);
  }
});

app.use((req, res) => {
  res.status(404);
  renderPage(res, "error", {
    title: "Not found",
    message: "The requested page does not exist."
  });
});

app.use((error, req, res, next) => {
  writeLog("error", error.message, { stack: error.stack, url: req.originalUrl });
  const status = error.status || (error.name === "MulterError" ? 400 : 500);
  const message = status >= 500 ? "Unexpected server error." : error.message;
  if (req.originalUrl.startsWith("/api/")) {
    res.status(status).json({ error: message });
    return;
  }
  res.status(status);
  renderPage(res, "error", {
    title: "Error",
    message
  });
});

initDb()
  .then(() => {
    const seedAvatar = path.join(UPLOAD_DIR, "admin-avatar.png");
    const seedFinance = path.join(UPLOAD_DIR, "northstar-finance-export.png");
    const seedGuide = path.join(UPLOAD_DIR, "seed-brand-guide.png");

    if (!fs.existsSync(seedAvatar)) {
      fs.writeFileSync(
        seedAvatar,
        Buffer.from("iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mP8/x8AAwMCAO7Z0MsAAAAASUVORK5CYII=", "base64")
      );
    }
    if (!fs.existsSync(seedFinance)) {
      fs.writeFileSync(
        seedFinance,
        Buffer.from("iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mP8/x8AAwMCAO7Z0MsAAAAASUVORK5CYII=", "base64")
      );
    }
    if (!fs.existsSync(seedGuide)) {
      fs.writeFileSync(
        seedGuide,
        Buffer.from("iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mP8/x8AAwMCAO7Z0MsAAAAASUVORK5CYII=", "base64")
      );
    }

    if (process.argv.includes("--seed-only")) {
      console.log(`Seed complete at ${path.join("storage", "lab.sqlite")}`);
      process.exit(0);
    }

    app.listen(PORT, () => {
      console.log("Server running on port " + PORT);
    });
  })
  .catch((error) => {
    console.error(error);
    process.exit(1);
  });