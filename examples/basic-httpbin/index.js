"use strict";

const https = require("node:https");
const vaultFactory = require("node-vault-ebpf");

const allowedHost = process.env.DEMO_ALLOWED_HOST || "httpbin.org";
const blockedHost = process.env.DEMO_BLOCKED_HOST || "postman-echo.com";

async function fetchHeaders(host, token) {
  const url = `https://${host}/headers`;
  return new Promise((resolve, reject) => {
    const req = https.request(
      url,
      {
        method: "GET",
        headers: {
          Authorization: `Bearer ${token}`,
        },
      },
      (res) => {
        let body = "";
        res.on("data", (c) => (body += c));
        res.on("end", () => {
          try {
            resolve(JSON.parse(body));
          } catch {
            resolve({ raw: body, statusCode: res.statusCode });
          }
        });
      },
    );
    req.on("error", reject);
    req.end();
  });
}

async function main() {
  const vault = vaultFactory({
    endpoint: process.env.VAULT_ADDR || "http://127.0.0.1:8200",
    agentSocket:
      process.env.NVE_AGENT_SOCKET || "/var/run/node-vault-ebpf.sock",
    allowedHosts: [allowedHost],
  });

  const secret = await vault.read("secret/data/demo");
  const token = secret.data.data.token;
  console.log("[APP] Secret from vault.read():", token);
  console.log("[APP] Length:", token.length);

  if (!String(token).startsWith("nve:")) {
    console.error("[APP] ERROR: expected placeholder prefix nve:");
    process.exit(2);
  }

  const allowed = await fetchHeaders(allowedHost, token);
  const authAllowed =
    allowed.headers?.Authorization ||
    allowed.headers?.authorization ||
    "(missing)";
  console.log(`[NETWORK] ${allowedHost} saw:`, authAllowed);

  try {
    const blocked = await fetchHeaders(blockedHost, token);
    const authBlocked =
      blocked.headers?.Authorization ||
      blocked.headers?.authorization ||
      "(missing)";
    console.log(`[NETWORK] ${blockedHost} saw:`, authBlocked);
  } catch (e) {
    console.log(`[NETWORK] ${blockedHost} request failed:`, e.message);
  }

  const health = await vault.health();
  console.log("[AGENT] health:", JSON.stringify(health));
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
