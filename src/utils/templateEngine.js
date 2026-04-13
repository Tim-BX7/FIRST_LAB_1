function getValue(context, dottedPath) {
  return String(dottedPath)
    .split(".")
    .filter(Boolean)
    .reduce((current, part) => (current && current[part] !== undefined ? current[part] : ""), context);
}

function analyzeTemplate(template) {
  const raw = String(template || "");
  const blockedTokens = [];
  const blocklist = [
    "process",
    "global",
    "Function",
    "constructor",
    "__proto__",
    "prototype",
    "require",
    "eval",
    "<%",
    "(",
    ")"
  ];

  for (const token of blocklist) {
    if (raw.includes(token)) {
      blockedTokens.push(token);
    }
  }

  const placeholders = [...raw.matchAll(/\{\{\s*([^}]+?)\s*\}\}/g)].map((match) => match[1].trim());
  const invalidPlaceholders = placeholders.filter((value) => !/^[a-zA-Z0-9_.]+$/.test(value));

  return {
    blocked: blockedTokens.length > 0 || invalidPlaceholders.length > 0,
    blockedTokens,
    invalidPlaceholders,
    placeholders
  };
}

function renderTemplateString(template, context) {
  return String(template || "").replace(/\{\{\s*([^}]+?)\s*\}\}/g, (_, expression) => {
    const path = String(expression || "").trim();
    if (!/^[a-zA-Z0-9_.]+$/.test(path)) {
      return "[blocked-placeholder]";
    }
    const value = getValue(context, path);
    return value === undefined || value === null ? "" : String(value);
  });
}

module.exports = { analyzeTemplate, renderTemplateString };
