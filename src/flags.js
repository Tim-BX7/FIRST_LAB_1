const crypto = require("crypto");

const FLAG_SEED = "helios-workspace-training-lab-v2";

const SCENARIOS = {
  hidden_admin: {
    id: "hidden_admin",
    title: "Hidden Admin Console",
    category: "Discovery and RBAC",
    hint: "One operations route still exists after the navigation redesign, but only authorized roles can use it.",
    ownerNote: "Unlocked when an authorized learner discovers and opens the hidden admin area."
  },
  access_control: {
    id: "access_control",
    title: "Access Control Preview",
    category: "Object-Level Authorization",
    hint: "Try requesting an object that belongs to a different tenant and notice what the lab shows instead of leaking data.",
    ownerNote: "Unlocked when a learner reaches a cross-tenant resource preview through the intended training flow."
  },
  output_encoding: {
    id: "output_encoding",
    title: "Output Encoding Comparison",
    category: "Rendering User Content",
    hint: "Markup-like input should stay inert. Compare how the app displays the same value in safe and simulated-unsafe views.",
    ownerNote: "Unlocked when a learner submits or views markup-like content on a page that demonstrates safe vs demo rendering."
  },
  input_handling: {
    id: "input_handling",
    title: "Input Handling Pitfalls",
    category: "Parsing and Interpretation",
    hint: "Some inputs look harmless until a parser or template engine gives them special meaning. The lab detects those patterns safely.",
    ownerNote: "Unlocked when a learner submits a suspicious parser or template payload to a simulation route."
  },
  session_edges: {
    id: "session_edges",
    title: "Session Edge Cases",
    category: "Authentication Flow",
    hint: "Switch to demo mode, re-authenticate, and compare what the lab records before and after login.",
    ownerNote: "Unlocked after a demo-mode login rotation is observed in the session training panel."
  },
  header_profiles: {
    id: "header_profiles",
    title: "Header Profile Diff",
    category: "Configuration Review",
    hint: "Compare secure mode and demo mode headers. The lab never removes the protections, but it will explain what weaker settings would imply.",
    ownerNote: "Unlocked when a learner views the headers page in both secure and demo profiles."
  }
};

function getFlagValue(scenarioId) {
  const digest = crypto
    .createHash("sha256")
    .update(`${FLAG_SEED}:${scenarioId}`)
    .digest("hex")
    .slice(0, 16)
    .toUpperCase();

  return `FLAG{${scenarioId.toUpperCase()}_${digest}}`;
}

const FLAG_KEYS = [
  "command_injection",
  "sqli_login",
  "sqli_blind",
  "sqli_second_order",
  "xss_reflected",
  "xss_stored",
  "ssti",
  "idor",
  "csrf",
  "broken_access",
  "business_logic",
  "file_upload",
  "insecure_deserialization",
  "jwt",
  "api_mass_assignment",
  "api_missing_auth"
];

const FLAGS = FLAG_KEYS.reduce((acc, key) => {
  acc[key] = getFlagValue(key);
  return acc;
}, {});

module.exports = {
  SCENARIOS,
  getFlagValue,
  FLAGS
};
