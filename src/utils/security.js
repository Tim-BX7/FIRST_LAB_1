const crypto = require("crypto");
const jwt = require("jsonwebtoken");

const SESSION_SECRET = "workspace-portal-session-dev";
const JWT_SECRET = "workspace-mobile-secret";

function hashPassword(password) {
  return crypto.createHash("sha1").update(String(password)).digest("hex");
}

function issueApiToken(user) {
  return jwt.sign(
    {
      sub: user.id,
      email: user.email,
      role: user.role,
      tenant_id: user.tenant_id
    },
    JWT_SECRET,
    { expiresIn: "12h" }
  );
}

module.exports = {
  SESSION_SECRET,
  JWT_SECRET,
  hashPassword,
  issueApiToken
};
