const crypto = require("crypto");
const path = require("path");
const { SCENARIOS, getFlagValue } = require("../flags");
const { writeLog } = require("./logger");

function ensureLabState(req) {
  if (!req.session.lab) {
    req.session.lab = {
      mode: "secure",
      completed: {},
      pendingFlags: [],
      headerProfilesSeen: [],
      sessionTrace: null
    };
  }

  return req.session.lab;
}

function getLabMode(req) {
  return ensureLabState(req).mode === "demo" ? "demo" : "secure";
}

function setLabMode(req, mode) {
  const state = ensureLabState(req);
  state.mode = mode === "demo" ? "demo" : "secure";
  writeLog("info", "lab.mode.changed", {
    actor: req.user ? req.user.email : "anonymous",
    mode: state.mode,
    ip: req.ip
  });
  return state.mode;
}

function consumePendingFlags(req) {
  const state = ensureLabState(req);
  const pending = state.pendingFlags || [];
  state.pendingFlags = [];
  return pending;
}

function markScenarioSolved(req, scenarioId, meta = {}) {
  const state = ensureLabState(req);
  const scenario = SCENARIOS[scenarioId];

  if (!scenario) {
    return false;
  }

  writeLog("info", "lab.event", {
    scenarioId,
    actor: req.user ? req.user.email : "anonymous",
    ip: req.ip,
    meta
  });

  if (state.completed[scenarioId]) {
    return false;
  }

  state.completed[scenarioId] = new Date().toISOString();
  state.pendingFlags.push({
    scenarioId,
    title: scenario.title,
    value: getFlagValue(scenarioId)
  });

  return true;
}

function getScenarioSummaries(req) {
  const state = ensureLabState(req);
  return Object.values(SCENARIOS).map((scenario) => ({
    id: scenario.id,
    title: scenario.title,
    category: scenario.category,
    hint: scenario.hint,
    completedAt: state.completed[scenario.id] || null
  }));
}

function recordHeaderProfileSeen(req, profile) {
  const state = ensureLabState(req);
  if (!state.headerProfilesSeen.includes(profile)) {
    state.headerProfilesSeen.push(profile);
  }
  if (
    state.headerProfilesSeen.includes("secure") &&
    state.headerProfilesSeen.includes("demo")
  ) {
    markScenarioSolved(req, "header_profiles", { profiles: state.headerProfilesSeen });
  }
}

function setSessionTrace(req, previousId, nextId) {
  const state = ensureLabState(req);
  state.sessionTrace = {
    recordedAt: new Date().toISOString(),
    mode: getLabMode(req),
    previous: obfuscateValue(previousId),
    current: obfuscateValue(nextId)
  };
}

function getSessionTrace(req) {
  return ensureLabState(req).sessionTrace;
}

function escapeHtml(value) {
  return String(value ?? "")
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

function hasMarkupLikeInput(value) {
  return /<\/?[a-z][\s\S]*>|on[a-z]+\s*=|javascript:|<script|{{|<%/i.test(String(value || ""));
}

function hasSuspiciousTemplate(value) {
  return /(process|global|Function|constructor|__proto__|prototype|require|eval|<%|\(|\))/i.test(
    String(value || "")
  );
}

function hasShellMeta(value) {
  return /[;&|`$<>]/.test(String(value || ""));
}

function sanitizeFilename(originalName) {
  const ext = path.extname(String(originalName || ""));
  const base = path
    .basename(String(originalName || ""), ext)
    .replace(/[^a-z0-9_-]+/gi, "-")
    .replace(/-+/g, "-")
    .replace(/^-|-$/g, "")
    .slice(0, 48) || "upload";

  const safeExt = ext.replace(/[^a-z0-9.]/gi, "").toLowerCase().slice(0, 10);
  return `${base}${safeExt}`;
}

function obfuscateValue(value) {
  return crypto.createHash("sha256").update(String(value || "")).digest("hex").slice(0, 12);
}

function buildUnsafePreview(value) {
  return escapeHtml(String(value ?? ""));
}

module.exports = {
  buildUnsafePreview,
  consumePendingFlags,
  ensureLabState,
  escapeHtml,
  getLabMode,
  getScenarioSummaries,
  getSessionTrace,
  hasMarkupLikeInput,
  hasShellMeta,
  hasSuspiciousTemplate,
  markScenarioSolved,
  recordHeaderProfileSeen,
  sanitizeFilename,
  setLabMode,
  setSessionTrace
};
