const express = require("express");
const path = require("path");
const fs = require("fs");
const { exec } = require("child_process");
const cookieParser = require("cookie-parser");
const session = require("express-session");
const multer = require("multer");
const { promisify } = require("util");
const { db, initDb } = require("./src/db");
const { FLAGS } = require("./src/flags");
const { APP_LOG, audit, writeLog } = require("./src/utils/logger");
const { hashPassword, issueApiToken, SESSION_SECRET } = require("./src/utils/security");
const { renderTemplateString } = require("./src/utils/templateEngine");
const { attachUser, requireLogin, requireAdminish, apiAuth } = require("./src/middleware/auth");

const asyncExec = promisify(exec);
const app = express();
const PORT = process.env.PORT || 3000;

fs.mkdirSync(path.join(process.cwd(), "public", "uploads"), { recursive: true });

const upload = multer({
  storage: multer.diskStorage({
    destination(req, file, cb) {
      cb(null, path.join(process.cwd(), "public", "uploads"));
    },
    filename(req, file, cb) {
      cb(null, `${Date.now()}-${file.originalname}`);
    }
  }),
  fileFilter(req, file, cb) {
    const allowed = /\.(svg|png|jpg|jpeg|gif|html?)$/i.test(file.originalname) ||
      String(file.mimetype).startsWith("image/");
    cb(null, allowed);
  }
});

app.set("view engine", "ejs");
app.set("views", path.join(process.cwd(), "views"));

app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.use(cookieParser());
app.use(
  session({
    secret: SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
    cookie: {
      httpOnly: false,
      sameSite: "lax"
    }
  })
);

app.use((req, res, next) => {
  res.setHeader("Access-Control-Allow-Origin", req.headers.origin || "*");
  res.setHeader("Access-Control-Allow-Credentials", "true");
  res.setHeader("Access-Control-Allow-Headers", "Content-Type, Authorization, X-Debug-Widget");
  res.setHeader(
    "Content-Security-Policy",
    "default-src 'self' data: blob:; script-src 'self' 'unsafe-inline' 'unsafe-eval'; style-src 'self' 'unsafe-inline'"
  );
  next();
});

app.use(express.static(path.join(process.cwd(), "public")));
app.use(attachUser);

app.locals.formatMoney = (cents) => `$${(Number(cents) / 100).toFixed(2)}`;
app.locals.flagKeys = Object.keys(FLAGS || {});

app.use((req, res, next) => {
  res.locals.flash = req.session.flash || null;
  delete req.session.flash;
  res.locals.flags = FLAGS;
  next();
});

function setFlash(req, type, message) {
  req.session.flash = { type, message };
}

function safeBodyValue(input) {
  return typeof input === "string" ? input.trim() : "";
}

app.get("/", async (req, res) => {
  const stats = await db.get(
    "SELECT (SELECT COUNT(*) FROM projects) AS projectCount, (SELECT COUNT(*) FROM users) AS userCount, (SELECT COUNT(*) FROM files) AS fileCount"
  );
  res.render("index", { title: "Helios Workspace", stats });
});

app.get("/register", (req, res) => {
  res.render("auth/register", { title: "Register" });
});

app.post("/register", async (req, res, next) => {
  try {
    const email = safeBodyValue(req.body.email).toLowerCase();
    const displayName = safeBodyValue(req.body.display_name) || "New User";
    const password = safeBodyValue(req.body.password);

    await db.run(
      "INSERT INTO users (tenant_id, email, password_hash, display_name, role, is_support, plan, credits) VALUES (?, ?, ?, ?, 'user', 0, 'starter', 0)",
      [1, email, hashPassword(password), displayName]
    );

    setFlash(req, "success", "Account created. Log in to continue.");
    res.redirect("/login");
  } catch (error) {
    next(error);
  }
});

app.get("/login", (req, res) => {
  res.render("auth/login", { title: "Login" });
});

app.post("/login", async (req, res, next) => {
  try {
    const email = safeBodyValue(req.body.email);
    const passwordHash = hashPassword(safeBodyValue(req.body.password));
    const query = `SELECT * FROM users WHERE email = '${email}' AND password_hash = '${passwordHash}' LIMIT 1`;
    const user = await db.get(query);

    if (!user) {
      setFlash(req, "error", "Invalid email or password.");
      res.redirect("/login");
      return;
    }

    req.session.userId = user.id;
    await audit(db, user.id, user.tenant_id, "login", "Interactive login", req.ip);
    setFlash(req, "success", "Welcome back.");
    res.redirect("/dashboard");
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

    res.render("dashboard", {
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
  res.render("profile", { title: "Profile", token });
});

app.post("/profile", requireLogin, async (req, res, next) => {
  try {
    await db.run(
      "UPDATE users SET display_name = ?, bio = ?, default_filter = ?, email_template = ? WHERE id = ?",
      [
        safeBodyValue(req.body.display_name),
        req.body.bio || "",
        safeBodyValue(req.body.default_filter) || "open",
        req.body.email_template || "",
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
    await db.run("UPDATE users SET email = ? WHERE id = ?", [
      safeBodyValue(req.body.email),
      req.user.id
    ]);
    await audit(db, req.user.id, req.user.tenant_id, "email-change", FLAGS.csrf, req.ip);
    setFlash(req, "success", "Email address changed.");
    res.redirect("/profile");
  } catch (error) {
    next(error);
  }
});

app.post("/account/password", requireLogin, async (req, res, next) => {
  try {
    await db.run("UPDATE users SET password_hash = ? WHERE id = ?", [
      hashPassword(safeBodyValue(req.body.password)),
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
  res.render("billing", { title: "Billing" });
});

app.post("/billing/upgrade", requireLogin, async (req, res, next) => {
  try {
    const plan = safeBodyValue(req.body.plan) || "starter";
    const seatCount = Number(req.body.seats || 1);
    const coupon = safeBodyValue(req.body.coupon).toUpperCase();
    const basePrice = plan === "enterprise" ? 6900 : plan === "business" ? 2900 : 990;
    const subtotal = basePrice * seatCount;
    let discount = 0;

    if (coupon.startsWith("PARTNER-")) {
      discount += subtotal;
    }

    if (coupon === "WELCOME100") {
      discount += 10000;
    }

    if (req.body.use_credits) {
      discount += req.user.credits * 100;
    }

    const total = subtotal - discount;

    await db.run("UPDATE users SET plan = ?, credits = credits + 5 WHERE id = ?", [
      plan,
      req.user.id
    ]);

    await audit(
      db,
      req.user.id,
      req.user.tenant_id,
      "plan-upgrade",
      `plan=${plan};total=${total};note=${total <= 0 ? FLAGS.business_logic : "normal-flow"}`,
      req.ip
    );

    setFlash(
      req,
      "success",
      total <= 0
        ? `Upgrade applied with balance $0.00. ${FLAGS.business_logic}`
        : `Upgrade request submitted. Estimated charge ${app.locals.formatMoney(total)}`
    );
    res.redirect("/billing");
  } catch (error) {
    next(error);
  }
});

app.get("/search", requireLogin, async (req, res, next) => {
  try {
    const query = req.query.q || "";
    const results = query
      ? await db.all(
          "SELECT * FROM projects WHERE tenant_id = ? AND name LIKE ? ORDER BY id DESC",
          [req.user.tenant_id, `%${query}%`]
        )
      : [];

    res.render("search", {
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
    const project = await db.get("SELECT * FROM projects WHERE id = ?", [req.params.id]);
    const comments = await db.all(
      "SELECT project_comments.*, users.display_name FROM project_comments JOIN users ON users.id = project_comments.user_id WHERE project_id = ? ORDER BY project_comments.id ASC",
      [req.params.id]
    );

    if (!project) {
      res.status(404).render("error", { title: "Not found", message: "Project not found." });
      return;
    }

    res.render("project", { title: project.name, project, comments });
  } catch (error) {
    next(error);
  }
});

app.post("/projects/:id/comments", requireLogin, async (req, res, next) => {
  try {
    await db.run(
      "INSERT INTO project_comments (project_id, user_id, body) VALUES (?, ?, ?)",
      [req.params.id, req.user.id, req.body.body || ""]
    );
    await audit(db, req.user.id, req.user.tenant_id, "comment-create", "Project comment added", req.ip);
    res.redirect(`/projects/${req.params.id}`);
  } catch (error) {
    next(error);
  }
});

app.get("/messages/:threadId", requireLogin, async (req, res, next) => {
  try {
    const thread = await db.get("SELECT * FROM threads WHERE id = ?", [req.params.threadId]);
    const messages = await db.all(
      "SELECT messages.*, users.display_name FROM messages JOIN users ON users.id = messages.sender_id WHERE thread_id = ? ORDER BY messages.id ASC",
      [req.params.threadId]
    );
    if (!thread) {
      res.status(404).render("error", { title: "Not found", message: "Thread missing." });
      return;
    }
    res.render("messages", { title: thread.subject, thread, messages });
  } catch (error) {
    next(error);
  }
});

app.post("/messages/:threadId", requireLogin, async (req, res, next) => {
  try {
    await db.run("INSERT INTO messages (thread_id, sender_id, body) VALUES (?, ?, ?)", [
      req.params.threadId,
      req.user.id,
      req.body.body || ""
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
    res.render("files", { title: "Files", files });
  } catch (error) {
    next(error);
  }
});

app.post("/files/upload", requireLogin, upload.single("document"), async (req, res, next) => {
  try {
    if (!req.file) {
      setFlash(req, "error", "No file uploaded.");
      res.redirect("/files");
      return;
    }

    await db.run(
      "INSERT INTO files (tenant_id, owner_id, project_id, original_name, stored_name, mime_type, size, note) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
      [
        req.user.tenant_id,
        req.user.id,
        req.body.project_id || null,
        req.file.originalname,
        req.file.filename,
        req.file.mimetype,
        req.file.size,
        req.body.note || ""
      ]
    );

    const banner = /\.(svg|html?)$/i.test(req.file.originalname)
      ? `${FLAGS.file_upload} uploaded via branding workflow.`
      : "File uploaded.";
    setFlash(req, "success", banner);
    res.redirect("/files");
  } catch (error) {
    next(error);
  }
});

app.get("/files/:id/download", requireLogin, async (req, res, next) => {
  try {
    const file = await db.get("SELECT * FROM files WHERE id = ?", [req.params.id]);
    if (!file) {
      res.status(404).render("error", { title: "Not found", message: "File missing." });
      return;
    }
    res.sendFile(path.join(process.cwd(), "public", "uploads", file.stored_name));
  } catch (error) {
    next(error);
  }
});

app.get("/admin", requireAdminish, async (req, res, next) => {
  try {
    const users = await db.all("SELECT * FROM users ORDER BY tenant_id, id");
    const recentLogs = await db.all("SELECT * FROM audit_logs ORDER BY id DESC LIMIT 10");
    res.render("admin/index", {
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
      res.status(404).render("error", { title: "Not found", message: "User missing." });
      return;
    }

    const unsafeFilter = target.default_filter || "open";
    const ticketQuery = `SELECT * FROM support_tickets WHERE tenant_id = ${target.tenant_id} AND status LIKE '%${unsafeFilter}%' ORDER BY id DESC`;
    const tickets = await db.all(ticketQuery);
    const comments = await db.all(
      "SELECT project_comments.*, projects.name AS project_name FROM project_comments JOIN projects ON projects.id = project_comments.project_id WHERE user_id = ? ORDER BY project_comments.id DESC",
      [target.id]
    );

    res.render("admin/user", {
      title: `User ${target.display_name}`,
      target,
      tickets,
      comments
    });
  } catch (error) {
    next(error);
  }
});

app.get("/admin/tools", requireAdminish, async (req, res) => {
  res.render("admin/tools", {
    title: "Diagnostics",
    output: "",
    host: "",
    logSample: fs.existsSync(APP_LOG) ? fs.readFileSync(APP_LOG, "utf8").split("\n").slice(-8).join("\n") : ""
  });
});

app.post("/admin/tools/trace", requireAdminish, async (req, res) => {
  const host = safeBodyValue(req.body.host) || "127.0.0.1";
  writeLog("info", "network-trace-request", { actor: req.user.email, host });

  try {
    const { stdout, stderr } = await asyncExec(`ping -n 1 ${host}`);
    res.render("admin/tools", {
      title: "Diagnostics",
      output: `${stdout}\n${stderr}\n${FLAGS.command_injection}`,
      host,
      logSample: fs.existsSync(APP_LOG) ? fs.readFileSync(APP_LOG, "utf8").split("\n").slice(-8).join("\n") : ""
    });
  } catch (error) {
    res.render("admin/tools", {
      title: "Diagnostics",
      output: `${error.message}\n${FLAGS.command_injection}`,
      host,
      logSample: fs.existsSync(APP_LOG) ? fs.readFileSync(APP_LOG, "utf8").split("\n").slice(-8).join("\n") : ""
    });
  }
});

app.get("/admin/email", requireAdminish, (req, res) => {
  res.render("admin/email", {
    title: "Email Preview",
    preview: "",
    template: req.user.email_template || "Hello {{ user.display_name }}"
  });
});

app.post("/admin/email/preview", requireAdminish, async (req, res) => {
  const template = req.body.template || "";
  const preview = renderTemplateString(template, {
    user: req.user,
    company: "Helios Workspace",
    flags: FLAGS,
    Math,
    Date,
    process
  });

  await audit(db, req.user.id, req.user.tenant_id, "mail-preview", "Previewed email template", req.ip);
  res.render("admin/email", {
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

    const email = safeBodyValue(req.body.email).toLowerCase();
    const user = await db.get("SELECT * FROM users WHERE email = ?", [email]);
    if (!user || user.password_hash !== hashPassword(safeBodyValue(req.body.password))) {
      res.status(401).json({ error: "invalid credentials" });
      return;
    }
    res.json({ token: issueApiToken(user), hint: "mobile-client" });
  } catch (error) {
    next(error);
  }
});

app.get("/api/reports/usage", async (req, res, next) => {
  try {
    const tenantId = Number(req.query.tenant || 1);
    const summary = await db.get(
      "SELECT (SELECT COUNT(*) FROM users WHERE tenant_id = ?) AS users, (SELECT COUNT(*) FROM files WHERE tenant_id = ?) AS files, (SELECT COUNT(*) FROM projects WHERE tenant_id = ?) AS projects",
      [tenantId, tenantId, tenantId]
    );
    res.json({
      tenant: tenantId,
      summary,
      widgetKey: FLAGS.api_missing_auth
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
    tokenMode: req.tokenMode,
    flag: req.tokenMode === "decoded" ? FLAGS.jwt : null
  });
});

app.patch("/api/profile", apiAuth, async (req, res, next) => {
  try {
    const allowedFields = [
      "display_name",
      "bio",
      "avatar_path",
      "plan",
      "credits",
      "role",
      "is_support",
      "default_filter",
      "email_template"
    ];

    const provided = Object.keys(req.body).filter((key) => allowedFields.includes(key));
    if (!provided.length) {
      res.status(400).json({ error: "no accepted fields supplied" });
      return;
    }

    const assignments = provided.map((field) => `${field} = ?`).join(", ");
    const values = provided.map((field) => req.body[field]);
    values.push(req.apiUser.id);

    await db.run(`UPDATE users SET ${assignments} WHERE id = ?`, values);
    const updated = await db.get("SELECT * FROM users WHERE id = ?", [req.apiUser.id]);

    res.json({
      message: "profile updated",
      user: updated,
      flag:
        provided.includes("role") || provided.includes("is_support")
          ? FLAGS.api_mass_assignment
          : null
    });
  } catch (error) {
    next(error);
  }
});

app.get("/api/projects/:id", apiAuth, async (req, res, next) => {
  try {
    const project = await db.get("SELECT * FROM projects WHERE id = ?", [req.params.id]);
    if (!project) {
      res.status(404).json({ error: "not found" });
      return;
    }
    res.json({ project, flag: project.tenant_id !== req.apiUser.tenant_id ? FLAGS.idor : null });
  } catch (error) {
    next(error);
  }
});

app.get("/api/files/:id", async (req, res, next) => {
  try {
    const file = await db.get("SELECT * FROM files WHERE id = ?", [req.params.id]);
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
    const query = `SELECT id FROM invoices WHERE tenant_id = ${req.apiUser.tenant_id} AND reference = '${reference}'`;
    const rows = await db.all(query);
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
    const decoded = Buffer.from(blob, "base64").toString("utf8");
    const imported = eval(`(${decoded})`);
    const nextTemplate = imported.email_template || req.apiUser.email_template;
    const nextFilter = imported.default_filter || req.apiUser.default_filter;
    await db.run("UPDATE users SET email_template = ?, default_filter = ? WHERE id = ?", [
      nextTemplate,
      nextFilter,
      req.apiUser.id
    ]);
    res.json({
      imported,
      flag: FLAGS.insecure_deserialization
    });
  } catch (error) {
    next(error);
  }
});

app.use((req, res) => {
  res.status(404).render("error", {
    title: "Not found",
    message: "The requested page does not exist."
  });
});

app.use((error, req, res, next) => {
  writeLog("error", error.message, { stack: error.stack, url: req.originalUrl });
  const status = error.status || 500;
  if (req.originalUrl.startsWith("/api/")) {
    res.status(status).json({ error: error.message });
    return;
  }
  res.status(status).render("error", {
    title: "Error",
    message: error.message
  });
});

initDb()
  .then(() => {
    const seedAvatar = path.join(process.cwd(), "public", "uploads", "admin-avatar.svg");
    const seedHtml = path.join(process.cwd(), "public", "uploads", "northstar-finance-export.html");
    const seedGuide = path.join(process.cwd(), "public", "uploads", "seed-brand-guide.svg");

    if (!fs.existsSync(seedAvatar)) {
      fs.writeFileSync(
        seedAvatar,
        `<svg xmlns="http://www.w3.org/2000/svg" width="96" height="96"><rect width="96" height="96" fill="#153243"/><text x="14" y="52" fill="#f4f3ee" font-size="18">MH</text></svg>`
      );
    }
    if (!fs.existsSync(seedGuide)) {
      fs.writeFileSync(
        seedGuide,
        `<svg xmlns="http://www.w3.org/2000/svg" width="180" height="80"><rect width="180" height="80" fill="#284b63"/><text x="14" y="44" fill="#ffffff" font-size="18">Helios Brand</text></svg>`
      );
    }
    if (!fs.existsSync(seedHtml)) {
      fs.writeFileSync(
        seedHtml,
        `<html><body><h1>Northstar Export</h1><p>${FLAGS.file_upload}</p></body></html>`
      );
    }

    if (process.argv.includes("--seed-only")) {
      console.log(`Seed complete at ${path.join("storage", "lab.sqlite")}`);
      process.exit(0);
    }

    app.listen(PORT, () => {
      console.log(`Helios Workspace listening on http://localhost:${PORT}`);
    });
  })
  .catch((error) => {
    console.error(error);
    process.exit(1);
  });
