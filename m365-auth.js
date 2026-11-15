/**
 * m365-auth.js — Microsoft 365 (Entra ID) sign-in, shared by the GR apps.
 *
 * OpenID Connect authorisation-code flow with PKCE, no packages beyond Node's own
 * (Node 18+: global fetch, crypto JWK import). The app keeps its own session model:
 * once Microsoft confirms who the user is, this module asks the app to issue the same
 * session token a password login would, and hands it to the browser via a one-time code.
 *
 *   GET  /auth/config          → { m365, password, appName }        (public)
 *   GET  /auth/m365/login      → redirect to Microsoft sign-in      (public)
 *   GET  /auth/m365/callback   → Microsoft returns here             (public)
 *   POST /auth/m365/exchange   → { code } → { token, username, role } (public, one-time)
 *
 * Who gets in, and with what role, is decided in Entra: the app registration defines
 * App roles with values  admin | editor | viewer, and users (or groups) are assigned to
 * them under Enterprise applications. A user with no role assigned is refused.
 *
 * Environment:
 *   M365_TENANT_ID      Directory (tenant) ID — the GUID, not the domain name
 *   M365_CLIENT_ID      Application (client) ID of the app registration
 *   M365_CLIENT_SECRET  Client secret VALUE (not the secret ID)
 *   APP_BASE_URL        e.g. https://gr-project-control-production.up.railway.app
 *                       (optional — otherwise derived from the request; set it to be safe)
 *
 *   An app whose M365_* variables are already used for something else (GR Pipeline's
 *   mailer) passes  envPrefix: "M365_LOGIN_"  and reads M365_LOGIN_CLIENT_ID etc. instead;
 *   the tenant falls back to M365_TENANT_ID. opts.baseUrl overrides APP_BASE_URL.
 *   PASSWORD_LOGIN      on | off   (default on). "off" hides and disables the
 *                       username/password form once Microsoft sign-in is working.
 *                       Set back to "on" as the break-glass route if Microsoft is unavailable.
 *
 * Mount BEFORE the app's auth gate:
 *   const m365 = require("./m365-auth")(app, { appName: "InvoiceDesk", issueSession });
 *   // issueSession({ username, name, role, via, email, oid }) → session token string
 *   // (it may throw an Error; its message is shown to the user on the login screen)
 */
"use strict";
const crypto = require("crypto");

const ROLE_RANK = { viewer: 1, editor: 2, admin: 3 };
const b64url = buf => Buffer.from(buf).toString("base64").replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
const fromB64url = s => Buffer.from(String(s).replace(/-/g, "+").replace(/_/g, "/"), "base64");

module.exports = function mountM365Auth(app, opts) {
  const appName = opts.appName || "App";
  const issueSession = opts.issueSession;
  const pre = opts.envPrefix || "M365_";
  const env = k => (process.env[pre + k] || "").trim();
  const tenant = env("TENANT_ID") || (process.env.M365_TENANT_ID || "").trim();
  const clientId = env("CLIENT_ID");
  const clientSecret = env("CLIENT_SECRET");
  const enabled = !!(tenant && clientId && clientSecret);
  // Password login stays on unless explicitly switched off — and can never be off when
  // Microsoft sign-in isn't configured, so nobody is ever locked out by a typo.
  const passwordLogin = !enabled || String(process.env.PASSWORD_LOGIN || "on").toLowerCase() !== "off";
  // M365_LOGIN_HOST exists only so the flow can be tested against a local mock; leave unset.
  const loginHost = (process.env.M365_LOGIN_HOST || "https://login.microsoftonline.com").replace(/\/+$/, "");
  const authority = `${loginHost}/${encodeURIComponent(tenant)}`;
  const issuer = `${loginHost}/${tenant}/v2.0`;

  if (enabled) console.log(`[m365] Microsoft 365 sign-in enabled for ${appName}; password login ${passwordLogin ? "ON" : "OFF"}`);
  else if (clientId || clientSecret || env("TENANT_ID")) console.warn(`[m365] Partly configured — need ${pre}TENANT_ID, ${pre}CLIENT_ID and ${pre}CLIENT_SECRET. Microsoft sign-in is OFF.`);

  // Short-lived, single-use state: login attempts (10 min) and hand-over codes (2 min).
  const pending = new Map();   // state -> { nonce, verifier, at }
  const handover = new Map();  // code  -> { token, username, role, at }
  setInterval(() => {
    const now = Date.now();
    for (const [k, v] of pending) if (now - v.at > 10 * 60000) pending.delete(k);
    for (const [k, v] of handover) if (now - v.at > 2 * 60000) handover.delete(k);
  }, 60000).unref();

  function redirectUri(req) {
    const base = (opts.baseUrl || process.env.APP_BASE_URL || "").replace(/\/+$/, "") ||
      `${(req.headers["x-forwarded-proto"] || req.protocol).split(",")[0]}://${req.headers["x-forwarded-host"] || req.headers.host}`;
    return `${base}/auth/m365/callback`;
  }
  const fail = (res, msg) => res.redirect(`/#sso_error=${encodeURIComponent(msg)}`);

  // ── Signing keys (cached; refetched when Microsoft rotates to an unknown kid) ──
  let jwks = { keys: [], at: 0 };
  async function signingKey(kid) {
    const fresh = Date.now() - jwks.at < 12 * 3600000;
    let k = fresh && jwks.keys.find(x => x.kid === kid);
    if (!k) {
      const r = await fetch(`${authority}/discovery/v2.0/keys`);
      if (!r.ok) throw new Error(`Could not fetch Microsoft signing keys (HTTP ${r.status})`);
      jwks = { keys: (await r.json()).keys || [], at: Date.now() };
      k = jwks.keys.find(x => x.kid === kid);
    }
    if (!k) throw new Error("ID token signed with an unknown key");
    return crypto.createPublicKey({ key: { kty: k.kty, n: k.n, e: k.e }, format: "jwk" });
  }

  async function verifyIdToken(idToken, nonce) {
    const parts = String(idToken || "").split(".");
    if (parts.length !== 3) throw new Error("Malformed ID token");
    const header = JSON.parse(fromB64url(parts[0]).toString("utf8"));
    const claims = JSON.parse(fromB64url(parts[1]).toString("utf8"));
    if (header.alg !== "RS256") throw new Error(`Unexpected token algorithm ${header.alg}`);
    const ok = crypto.verify("RSA-SHA256", Buffer.from(`${parts[0]}.${parts[1]}`), await signingKey(header.kid), fromB64url(parts[2]));
    if (!ok) throw new Error("ID token signature is invalid");
    const now = Math.floor(Date.now() / 1000), skew = 300;
    if (claims.iss !== issuer) throw new Error("ID token is from a different tenant");
    if (claims.aud !== clientId) throw new Error("ID token was issued for a different application");
    if (claims.tid && claims.tid !== tenant) throw new Error("ID token is from a different tenant");
    if (typeof claims.exp !== "number" || claims.exp < now - skew) throw new Error("ID token has expired");
    if (typeof claims.nbf === "number" && claims.nbf > now + skew) throw new Error("ID token is not yet valid");
    if (claims.nonce !== nonce) throw new Error("Sign-in response did not match this request — please try again");
    return claims;
  }

  function roleFrom(claims) {
    const roles = (Array.isArray(claims.roles) ? claims.roles : []).map(r => String(r).toLowerCase()).filter(r => ROLE_RANK[r]);
    return roles.sort((a, b) => ROLE_RANK[b] - ROLE_RANK[a])[0] || null;
  }

  // ── Routes ──
  app.get("/auth/config", (req, res) => res.json({ m365: enabled, password: passwordLogin, appName }));

  app.get("/auth/m365/login", (req, res) => {
    if (!enabled) return fail(res, "Microsoft sign-in is not configured for this app.");
    const state = b64url(crypto.randomBytes(24));
    const nonce = b64url(crypto.randomBytes(24));
    const verifier = b64url(crypto.randomBytes(48));
    const challenge = b64url(crypto.createHash("sha256").update(verifier).digest());
    pending.set(state, { nonce, verifier, at: Date.now() });
    const q = new URLSearchParams({
      client_id: clientId, response_type: "code", redirect_uri: redirectUri(req), response_mode: "query",
      scope: "openid profile email", state, nonce, code_challenge: challenge, code_challenge_method: "S256",
      prompt: "select_account",
    });
    res.redirect(`${authority}/oauth2/v2.0/authorize?${q}`);
  });

  app.get("/auth/m365/callback", async (req, res) => {
    try {
      const { code, state, error, error_description } = req.query;
      if (error) {
        console.warn(`[m365] sign-in error: ${error} ${error_description || ""}`);
        // AADSTS50105: user is not assigned to the application.
        if (/AADSTS50105/.test(error_description || "")) return fail(res, `Your Microsoft account has not been given access to ${appName}. Ask an administrator to assign you a role.`);
        return fail(res, "Microsoft sign-in was cancelled or failed. Please try again.");
      }
      const p = pending.get(state);
      pending.delete(state);
      if (!p || !code) return fail(res, "Sign-in expired — please try again.");

      const body = new URLSearchParams({
        client_id: clientId, client_secret: clientSecret, grant_type: "authorization_code",
        code, redirect_uri: redirectUri(req), code_verifier: p.verifier, scope: "openid profile email",
      });
      const r = await fetch(`${authority}/oauth2/v2.0/token`, { method: "POST", headers: { "Content-Type": "application/x-www-form-urlencoded" }, body });
      const tok = await r.json().catch(() => ({}));
      if (!r.ok || !tok.id_token) {
        console.error("[m365] token exchange failed:", r.status, tok.error, (tok.error_description || "").split("\n")[0]);
        if (/AADSTS7000215|AADSTS7000222/.test(tok.error_description || "")) return fail(res, "Microsoft sign-in is misconfigured (client secret invalid or expired). Contact your administrator.");
        return fail(res, "Microsoft sign-in could not be completed. Please try again.");
      }
      const claims = await verifyIdToken(tok.id_token, p.nonce);
      const username = String(claims.preferred_username || claims.email || claims.upn || claims.oid || "").toLowerCase();
      const role = roleFrom(claims);
      if (!role) {
        console.warn(`[m365] ${username} signed in but has no ${appName} role assigned`);
        return fail(res, `Signed in as ${username}, but you have not been given a role in ${appName}. Ask an administrator to assign you Admin, Editor or Viewer.`);
      }
      const email = String(claims.email || claims.preferred_username || "").toLowerCase();
      const token = await issueSession({ username, name: claims.name || username, role, via: "m365", email, oid: claims.oid || "" });
      const handoverCode = b64url(crypto.randomBytes(24));
      handover.set(handoverCode, { token, username, role, at: Date.now() });
      console.log(`[m365] ${username} signed in to ${appName} as ${role}`);
      // Fragment, not query: it never reaches server logs or Referer headers.
      res.redirect(`/#sso=${handoverCode}`);
    } catch (e) {
      console.error("[m365] callback error:", e.message);
      fail(res, e.message || "Microsoft sign-in failed.");
    }
  });

  app.post("/auth/m365/exchange", (req, res) => {
    const code = String((req.body || {}).code || "");
    const h = handover.get(code);
    handover.delete(code);
    if (!h || Date.now() - h.at > 2 * 60000) return res.status(401).json({ error: "Sign-in link expired — please sign in again." });
    res.json({ token: h.token, username: h.username, role: h.role });
  });

  return { enabled, passwordLogin };
};
