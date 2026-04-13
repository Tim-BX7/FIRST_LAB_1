const crypto = require("crypto");
const jwt = require("jsonwebtoken");

const SESSION_SECRET = process.env.SESSION_SECRET || "helios-workspace-session-secret";
const JWT_SECRET = process.env.JWT_SECRET || "helios-workspace-jwt-secret";
const PASSWORD_ITERATIONS = 120000;

function hashPassword(password) {
  const salt = crypto.randomBytes(16).toString("hex");
  const digest = crypto
    .pbkdf2Sync(String(password), salt, PASSWORD_ITERATIONS, 32, "sha256")
    .toString("hex");

  return `pbkdf2$${PASSWORD_ITERATIONS}$${salt}$${digest}`;
}

function verifyPassword(password, storedHash) {
  const value = String(storedHash || "");

  if (value.startsWith("pbkdf2$")) {
    const [, iterations, salt, expectedDigest] = value.split("$");
    const digest = crypto
      .pbkdf2Sync(String(password), salt, Number(iterations), 32, "sha256")
      .toString("hex");

    return crypto.timingSafeEqual(Buffer.from(digest, "hex"), Buffer.from(expectedDigest, "hex"));
  }

  const legacy = crypto.createHash("sha1").update(String(password)).digest("hex");
  return legacy === value;
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
    {
      audience: "helios-api",
      issuer: "helios-workspace",
      expiresIn: "12h"
    }
  );
}

module.exports = {
  SESSION_SECRET,
  JWT_SECRET,
  hashPassword,
  issueApiToken,
  verifyPassword
};
