const fs = require("fs");
const path = require("path");

const LOG_DIR = path.join(process.cwd(), "storage", "logs");
const APP_LOG = path.join(LOG_DIR, "app.log");

function ensureLogs() {
  fs.mkdirSync(LOG_DIR, { recursive: true });
}

function writeLog(level, message, meta = {}) {
  ensureLogs();
  const entry = {
    ts: new Date().toISOString(),
    level,
    message,
    meta
  };
  fs.appendFileSync(APP_LOG, `${JSON.stringify(entry)}\n`);
}

function readRecentLogs(limit = 50) {
  ensureLogs();
  if (!fs.existsSync(APP_LOG)) {
    return [];
  }

  return fs
    .readFileSync(APP_LOG, "utf8")
    .split("\n")
    .filter(Boolean)
    .slice(-limit)
    .reverse()
    .map((line) => {
      try {
        return JSON.parse(line);
      } catch (error) {
        return {
          ts: new Date().toISOString(),
          level: "error",
          message: "log-parse-failure",
          meta: { raw: line, error: error.message }
        };
      }
    });
}

async function audit(db, actorId, tenantId, action, details, ip) {
  try {
    await db.run(
      "INSERT INTO audit_logs (tenant_id, actor_id, action, details, ip, created_at) VALUES (?, ?, ?, ?, ?, datetime('now'))",
      [tenantId || null, actorId || null, action, details, ip || "127.0.0.1"]
    );
  } catch (error) {
    writeLog("error", "failed-to-write-audit", { error: error.message, action });
  }
}

module.exports = { APP_LOG, writeLog, readRecentLogs, audit };
