const fs = require("fs");
const path = require("path");
const initSqlJs = require("sql.js");
const { FLAGS } = require("./flags");
const { hashPassword } = require("./utils/security");

const DB_PATH = path.join(process.cwd(), "storage", "lab.sqlite");

fs.mkdirSync(path.dirname(DB_PATH), { recursive: true });

let SQL = null;
let rawDb = null;

function persist() {
  if (!rawDb) {
    return;
  }
  const data = rawDb.export();
  fs.writeFileSync(DB_PATH, Buffer.from(data));
}

function prepareAndBind(sql, params = []) {
  const statement = rawDb.prepare(sql);
  statement.bind(params);
  return statement;
}

const db = {
  async run(sql, params = []) {
    const statement = prepareAndBind(sql, params);
    try {
      while (statement.step()) {
        // Intentionally ignore result rows for run operations.
      }
    } finally {
      statement.free();
    }
    persist();
    return { ok: true };
  },

  async get(sql, params = []) {
    const rows = await this.all(sql, params);
    return rows[0];
  },

  async all(sql, params = []) {
    const statement = prepareAndBind(sql, params);
    const rows = [];
    try {
      while (statement.step()) {
        rows.push(statement.getAsObject());
      }
    } finally {
      statement.free();
    }
    return rows;
  },

  async exec(sql) {
    rawDb.exec(sql);
    persist();
  }
};

async function initDb() {
  SQL = await initSqlJs({});
  rawDb = fs.existsSync(DB_PATH)
    ? new SQL.Database(fs.readFileSync(DB_PATH))
    : new SQL.Database();

  await db.exec(`
    PRAGMA foreign_keys = ON;

    CREATE TABLE IF NOT EXISTS tenants (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      name TEXT NOT NULL,
      slug TEXT NOT NULL,
      plan TEXT NOT NULL DEFAULT 'starter'
    );

    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      tenant_id INTEGER NOT NULL,
      email TEXT NOT NULL UNIQUE,
      password_hash TEXT NOT NULL,
      display_name TEXT NOT NULL,
      bio TEXT DEFAULT '',
      role TEXT NOT NULL DEFAULT 'user',
      is_support INTEGER NOT NULL DEFAULT 0,
      plan TEXT NOT NULL DEFAULT 'starter',
      credits INTEGER NOT NULL DEFAULT 0,
      default_filter TEXT DEFAULT 'open',
      email_template TEXT DEFAULT 'Hello {{ user.display_name }}, your current plan is {{ user.plan }}.',
      avatar_path TEXT DEFAULT '',
      created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY (tenant_id) REFERENCES tenants(id)
    );

    CREATE TABLE IF NOT EXISTS projects (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      tenant_id INTEGER NOT NULL,
      owner_id INTEGER NOT NULL,
      name TEXT NOT NULL,
      description TEXT NOT NULL,
      status TEXT NOT NULL,
      budget_cents INTEGER NOT NULL DEFAULT 0,
      FOREIGN KEY (tenant_id) REFERENCES tenants(id),
      FOREIGN KEY (owner_id) REFERENCES users(id)
    );

    CREATE TABLE IF NOT EXISTS project_comments (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      project_id INTEGER NOT NULL,
      user_id INTEGER NOT NULL,
      body TEXT NOT NULL,
      created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY (project_id) REFERENCES projects(id),
      FOREIGN KEY (user_id) REFERENCES users(id)
    );

    CREATE TABLE IF NOT EXISTS threads (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      tenant_id INTEGER NOT NULL,
      subject TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS messages (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      thread_id INTEGER NOT NULL,
      sender_id INTEGER NOT NULL,
      body TEXT NOT NULL,
      created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY (thread_id) REFERENCES threads(id),
      FOREIGN KEY (sender_id) REFERENCES users(id)
    );

    CREATE TABLE IF NOT EXISTS files (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      tenant_id INTEGER NOT NULL,
      owner_id INTEGER NOT NULL,
      project_id INTEGER,
      original_name TEXT NOT NULL,
      stored_name TEXT NOT NULL,
      mime_type TEXT NOT NULL,
      size INTEGER NOT NULL DEFAULT 0,
      note TEXT DEFAULT '',
      created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY (tenant_id) REFERENCES tenants(id),
      FOREIGN KEY (owner_id) REFERENCES users(id)
    );

    CREATE TABLE IF NOT EXISTS invoices (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      tenant_id INTEGER NOT NULL,
      user_id INTEGER NOT NULL,
      reference TEXT NOT NULL,
      status TEXT NOT NULL,
      total_cents INTEGER NOT NULL,
      notes TEXT DEFAULT '',
      created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY (tenant_id) REFERENCES tenants(id),
      FOREIGN KEY (user_id) REFERENCES users(id)
    );

    CREATE TABLE IF NOT EXISTS support_tickets (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      tenant_id INTEGER NOT NULL,
      reporter_id INTEGER NOT NULL,
      title TEXT NOT NULL,
      status TEXT NOT NULL,
      internal_note TEXT DEFAULT '',
      created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY (tenant_id) REFERENCES tenants(id),
      FOREIGN KEY (reporter_id) REFERENCES users(id)
    );

    CREATE TABLE IF NOT EXISTS audit_logs (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      tenant_id INTEGER,
      actor_id INTEGER,
      action TEXT NOT NULL,
      details TEXT NOT NULL,
      ip TEXT DEFAULT '127.0.0.1',
      created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
    );

    CREATE TABLE IF NOT EXISTS flags (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      flag_key TEXT NOT NULL UNIQUE,
      flag_value TEXT NOT NULL,
      location_hint TEXT NOT NULL
    );
  `);

  const tenant = await db.get("SELECT id FROM tenants LIMIT 1");
  if (!tenant) {
    await seedDb();
  }
}

async function seedDb() {
  await db.run("INSERT INTO tenants (name, slug, plan) VALUES (?, ?, ?)", [
    "Acme Projects",
    "acme-projects",
    "business"
  ]);
  await db.run("INSERT INTO tenants (name, slug, plan) VALUES (?, ?, ?)", [
    "Northstar Retail",
    "northstar-retail",
    "starter"
  ]);

  await db.run(
    "INSERT INTO users (tenant_id, email, password_hash, display_name, bio, role, is_support, plan, credits, default_filter, avatar_path) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
    [
      1,
      "owner@acme.local",
      hashPassword("Summer2026!"),
      "Morgan Hale",
      "Founder dashboard owner. <em>Migration note:</em> " + FLAGS.xss_stored,
      "admin",
      1,
      "enterprise",
      250,
      "open",
      "/uploads/admin-avatar.svg"
    ]
  );
  await db.run(
    "INSERT INTO users (tenant_id, email, password_hash, display_name, bio, role, is_support, plan, credits, default_filter, avatar_path) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
    [
      1,
      "analyst@acme.local",
      hashPassword("Analyst2026!"),
      "Tariq Nasser",
      "Customer ops lead tracking migration blockers.",
      "user",
      0,
      "starter",
      25,
      "open",
      ""
    ]
  );
  await db.run(
    "INSERT INTO users (tenant_id, email, password_hash, display_name, bio, role, is_support, plan, credits, default_filter, avatar_path) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
    [
      2,
      "finance@northstar.local",
      hashPassword("Finance2026!"),
      "Dana Cole",
      "Watching billing drift and partner invoices.",
      "user",
      0,
      "starter",
      10,
      "pending",
      ""
    ]
  );

  await db.run(
    "INSERT INTO projects (tenant_id, owner_id, name, description, status, budget_cents) VALUES (?, ?, ?, ?, ?, ?)",
    [1, 1, "Q3 Rollout", "Tenant-wide rollout planning board.", "active", 540000]
  );
  await db.run(
    "INSERT INTO projects (tenant_id, owner_id, name, description, status, budget_cents) VALUES (?, ?, ?, ?, ?, ?)",
    [1, 2, "Client Success Revamp", "Ops dashboard clean-up sprint.", "draft", 220000]
  );
  await db.run(
    "INSERT INTO projects (tenant_id, owner_id, name, description, status, budget_cents) VALUES (?, ?, ?, ?, ?, ?)",
    [2, 3, "Retail Expansion", "Cross-tenant planning notes. Recovery token: " + FLAGS.idor, "active", 910000]
  );

  await db.run("INSERT INTO project_comments (project_id, user_id, body) VALUES (?, ?, ?)", [
    1,
    1,
    "Ship the dashboard before month end."
  ]);
  await db.run("INSERT INTO project_comments (project_id, user_id, body) VALUES (?, ?, ?)", [
    1,
    2,
    "Customer feedback is trending better after last sprint."
  ]);

  await db.run("INSERT INTO threads (tenant_id, subject) VALUES (?, ?)", [1, "Welcome Checklist"]);
  await db.run("INSERT INTO threads (tenant_id, subject) VALUES (?, ?)", [2, "Northstar Finance Escalation"]);

  await db.run("INSERT INTO messages (thread_id, sender_id, body) VALUES (?, ?, ?)", [
    1,
    1,
    "Make sure we keep admin diagnostics hidden from customers."
  ]);
  await db.run("INSERT INTO messages (thread_id, sender_id, body) VALUES (?, ?, ?)", [
    2,
    3,
    "Internal handoff token: " + FLAGS.api_missing_auth
  ]);

  await db.run(
    "INSERT INTO files (tenant_id, owner_id, project_id, original_name, stored_name, mime_type, size, note) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
    [1, 1, 1, "brand-guide.svg", "seed-brand-guide.svg", "image/svg+xml", 512, "Legacy branding asset."]
  );
  await db.run(
    "INSERT INTO files (tenant_id, owner_id, project_id, original_name, stored_name, mime_type, size, note) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
    [2, 3, 3, "finance-export.html", "northstar-finance-export.html", "text/html", 1204, "Cross-tenant export marker: " + FLAGS.file_upload]
  );

  await db.run(
    "INSERT INTO invoices (tenant_id, user_id, reference, status, total_cents, notes) VALUES (?, ?, ?, ?, ?, ?)",
    [1, 1, "AC-1001", "paid", 12900, "Normal renewal invoice."]
  );
  await db.run(
    "INSERT INTO invoices (tenant_id, user_id, reference, status, total_cents, notes) VALUES (?, ?, ?, ?, ?, ?)",
    [1, 2, "AC-1002", "open", 25900, "Partner credit pending."]
  );
  await db.run(
    "INSERT INTO invoices (tenant_id, user_id, reference, status, total_cents, notes) VALUES (?, ?, ?, ?, ?, ?)",
    [2, 3, "NS-7781-ALPHA", "overdue", 88000, "Escalation note: " + FLAGS.sqli_blind]
  );

  await db.run(
    "INSERT INTO support_tickets (tenant_id, reporter_id, title, status, internal_note) VALUES (?, ?, ?, ?, ?)",
    [1, 2, "Workspace export bug", "open", "Escalate if coupon stack breaks billing."]
  );
  await db.run(
    "INSERT INTO support_tickets (tenant_id, reporter_id, title, status, internal_note) VALUES (?, ?, ?, ?, ?)",
    [2, 3, "Invoice mismatch", "pending", "Second-order breadcrumb: " + FLAGS.sqli_second_order]
  );

  await db.run("INSERT INTO audit_logs (tenant_id, actor_id, action, details, ip) VALUES (?, ?, ?, ?, ?)", [
    1,
    1,
    "seed",
    "Legacy auth note: " + FLAGS.sqli_login,
    "127.0.0.1"
  ]);
  await db.run("INSERT INTO audit_logs (tenant_id, actor_id, action, details, ip) VALUES (?, ?, ?, ?, ?)", [
    1,
    1,
    "csrf-note",
    "Profile flow reminder: " + FLAGS.csrf,
    "127.0.0.1"
  ]);
  await db.run("INSERT INTO audit_logs (tenant_id, actor_id, action, details, ip) VALUES (?, ?, ?, ?, ?)", [
    1,
    1,
    "bac-note",
    "Support access marker: " + FLAGS.broken_access,
    "127.0.0.1"
  ]);

  for (const [flagKey, flagValue] of Object.entries(FLAGS)) {
    await db.run("INSERT INTO flags (flag_key, flag_value, location_hint) VALUES (?, ?, ?)", [
      flagKey,
      flagValue,
      `Recover via the ${flagKey} path.`
    ]);
  }
}

module.exports = { db, initDb, DB_PATH };
