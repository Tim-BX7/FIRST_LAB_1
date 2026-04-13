const fs = require("fs");
const path = require("path");
const initSqlJs = require("sql.js");
const { SCENARIOS, getFlagValue } = require("./flags");
const { hashPassword } = require("./utils/security");

const DB_PATH = path.join(process.cwd(), "storage", "lab.sqlite");
const SCHEMA_VERSION = "training-lab-v2";

fs.mkdirSync(path.dirname(DB_PATH), { recursive: true });

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
        // No-op for write statements.
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
  const SQL = await initSqlJs({});
  rawDb = fs.existsSync(DB_PATH)
    ? new SQL.Database(fs.readFileSync(DB_PATH))
    : new SQL.Database();

  await db.exec(`
    PRAGMA foreign_keys = ON;

    CREATE TABLE IF NOT EXISTS app_meta (
      key TEXT PRIMARY KEY,
      value TEXT NOT NULL
    );

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
      email_template TEXT DEFAULT 'Hello {{user.display_name}}, your workspace plan is {{user.plan}}.',
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

  const version = await db.get("SELECT value FROM app_meta WHERE key = 'schema_version'");
  if (!version || version.value !== SCHEMA_VERSION) {
    await resetData();
    await seedDb();
    await db.run("DELETE FROM app_meta WHERE key = 'schema_version'");
    await db.run("INSERT INTO app_meta (key, value) VALUES (?, ?)", ["schema_version", SCHEMA_VERSION]);
  }
}

async function resetData() {
  await db.exec(`
    DELETE FROM flags;
    DELETE FROM audit_logs;
    DELETE FROM support_tickets;
    DELETE FROM invoices;
    DELETE FROM files;
    DELETE FROM messages;
    DELETE FROM threads;
    DELETE FROM project_comments;
    DELETE FROM projects;
    DELETE FROM users;
    DELETE FROM tenants;
  `);
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
    "INSERT INTO users (tenant_id, email, password_hash, display_name, bio, role, is_support, plan, credits, default_filter, email_template, avatar_path) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
    [
      1,
      "owner@acme.local",
      hashPassword("Summer2026!"),
      "Morgan Hale",
      "Operations owner reviewing training scenarios and release readiness.",
      "admin",
      1,
      "enterprise",
      250,
      "open",
      "Hello {{user.display_name}}, the current plan is {{user.plan}}.",
      ""
    ]
  );
  await db.run(
    "INSERT INTO users (tenant_id, email, password_hash, display_name, bio, role, is_support, plan, credits, default_filter, email_template, avatar_path) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
    [
      1,
      "analyst@acme.local",
      hashPassword("Analyst2026!"),
      "Tariq Nasser",
      "Customer operations lead testing safe rendering of pasted snippets like <strong>launch window</strong>.",
      "user",
      0,
      "starter",
      25,
      "open",
      "Hello {{user.display_name}}, your triage filter is {{user.default_filter}}.",
      ""
    ]
  );
  await db.run(
    "INSERT INTO users (tenant_id, email, password_hash, display_name, bio, role, is_support, plan, credits, default_filter, email_template, avatar_path) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
    [
      1,
      "support@acme.local",
      hashPassword("Support2026!"),
      "Lena Cross",
      "Support reviewer with read-only access to the hidden operations console.",
      "support",
      1,
      "business",
      40,
      "pending",
      "Hello {{user.display_name}}, support queue focus is {{user.default_filter}}.",
      ""
    ]
  );
  await db.run(
    "INSERT INTO users (tenant_id, email, password_hash, display_name, bio, role, is_support, plan, credits, default_filter, email_template, avatar_path) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
    [
      2,
      "finance@northstar.local",
      hashPassword("Finance2026!"),
      "Dana Cole",
      "Billing contact for the second tenant. Cross-tenant data should never leak from this account.",
      "user",
      0,
      "starter",
      10,
      "pending",
      "Hello {{user.display_name}}, your workspace plan is {{user.plan}}.",
      ""
    ]
  );

  await db.run(
    "INSERT INTO projects (tenant_id, owner_id, name, description, status, budget_cents) VALUES (?, ?, ?, ?, ?, ?)",
    [1, 1, "Q3 Rollout", "Tenant-wide rollout planning board for internal launch readiness.", "active", 540000]
  );
  await db.run(
    "INSERT INTO projects (tenant_id, owner_id, name, description, status, budget_cents) VALUES (?, ?, ?, ?, ?, ?)",
    [1, 2, "Client Success Revamp", "Ops dashboard clean-up sprint with safe rendering experiments.", "draft", 220000]
  );
  await db.run(
    "INSERT INTO projects (tenant_id, owner_id, name, description, status, budget_cents) VALUES (?, ?, ?, ?, ?, ?)",
    [2, 4, "Retail Expansion", "Northstar planning notes used for access-control training previews.", "active", 910000]
  );

  await db.run("INSERT INTO project_comments (project_id, user_id, body) VALUES (?, ?, ?)", [
    1,
    1,
    "Ship the dashboard before month end."
  ]);
  await db.run("INSERT INTO project_comments (project_id, user_id, body) VALUES (?, ?, ?)", [
    1,
    2,
    "Pasted example for rendering review: <em>launch status</em>."
  ]);

  await db.run("INSERT INTO threads (tenant_id, subject) VALUES (?, ?)", [1, "Welcome Checklist"]);
  await db.run("INSERT INTO threads (tenant_id, subject) VALUES (?, ?)", [2, "Northstar Finance Escalation"]);

  await db.run("INSERT INTO messages (thread_id, sender_id, body) VALUES (?, ?, ?)", [
    1,
    1,
    "Remember that the operations console exists, but it is not linked from the new navigation."
  ]);
  await db.run("INSERT INTO messages (thread_id, sender_id, body) VALUES (?, ?, ?)", [
    2,
    4,
    "Tenant separation review is scheduled for this afternoon."
  ]);

  await db.run(
    "INSERT INTO files (tenant_id, owner_id, project_id, original_name, stored_name, mime_type, size, note) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
    [1, 1, 1, "brand-guide.svg", "seed-brand-guide.svg", "image/svg+xml", 512, "Static asset review: <strong>keep this inert</strong>."]
  );
  await db.run(
    "INSERT INTO files (tenant_id, owner_id, project_id, original_name, stored_name, mime_type, size, note) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
    [2, 4, 3, "finance-export.html", "northstar-finance-export.html", "text/html", 1204, "Attachment should download safely even when the extension looks active."]
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
    [2, 4, "NS-7781-ALPHA", "overdue", 88000, "Cross-tenant requests should return a safe preview, not the full record."]
  );

  await db.run(
    "INSERT INTO support_tickets (tenant_id, reporter_id, title, status, internal_note) VALUES (?, ?, ?, ?, ?)",
    [1, 2, "Workspace export bug", "open", "Use the demo tools to compare safe and unsafe rendering assumptions."]
  );
  await db.run(
    "INSERT INTO support_tickets (tenant_id, reporter_id, title, status, internal_note) VALUES (?, ?, ?, ?, ?)",
    [2, 4, "Invoice mismatch", "pending", "Cross-tenant previews in this lab are intentionally redacted."]
  );

  await db.run("INSERT INTO audit_logs (tenant_id, actor_id, action, details, ip) VALUES (?, ?, ?, ?, ?)", [
    1,
    1,
    "seed",
    "Training lab reset to safe simulation mode.",
    "127.0.0.1"
  ]);
  await db.run("INSERT INTO audit_logs (tenant_id, actor_id, action, details, ip) VALUES (?, ?, ?, ?, ?)", [
    1,
    1,
    "hint",
    "One admin route still exists even though the navigation no longer links to it.",
    "127.0.0.1"
  ]);

  for (const scenario of Object.values(SCENARIOS)) {
    await db.run("INSERT INTO flags (flag_key, flag_value, location_hint) VALUES (?, ?, ?)", [
      scenario.id,
      getFlagValue(scenario.id),
      scenario.ownerNote
    ]);
  }
}

module.exports = { db, initDb, DB_PATH };
