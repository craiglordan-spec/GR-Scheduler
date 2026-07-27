/*
 * GR Project Control — Scheduler & Timeline
 * Backend: role-based auth, JSON storage (activities/equipment/bookings/crew),
 * and a server-to-server read of InvoiceDesk (projects/invoices/POs).
 */
const express = require("express");
const path = require("path");
const fs = require("fs");
const crypto = require("crypto");
const invoicedesk = require("./invoicedesk");

const app = express();
app.use(express.json({ limit: "2mb" }));

// ─── Storage ──────────────────────────────────────────────────────────────────
const DATA_DIR = process.env.DATA_DIR || path.join(__dirname, "data");
if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR, { recursive: true });
const FILES = {
  activities: path.join(DATA_DIR, "activities.json"),
  equipment: path.join(DATA_DIR, "equipment.json"),
  bookings: path.join(DATA_DIR, "bookings.json"),
  crew: path.join(DATA_DIR, "crew.json")
};
const SEED_DIR = path.join(__dirname, "seed");
function readJSON(f, fallback = []) { try { return JSON.parse(fs.readFileSync(f, "utf8")); } catch { return fallback; } }
function writeJSON(f, d) { fs.writeFileSync(f, JSON.stringify(d, null, 2)); }
// Seed empty stores on first boot
for (const [k, f] of Object.entries(FILES)) {
  if (!fs.existsSync(f)) {
    const seed = path.join(SEED_DIR, `${k}.json`);
    writeJSON(f, fs.existsSync(seed) ? readJSON(seed) : []);
  }
}
const uid = (p) => `${p}_${crypto.randomBytes(4).toString("hex")}`;

// ─── Auth (role-based) ──────────────────────────────────────────────────────
function parseUsers() {
  const raw = process.env.USERS || "admin:admin:admin";
  return raw.split(",").map(s => s.trim()).filter(Boolean).map(s => {
    const [username, password, role = "viewer"] = s.split(":");
    return { username, password, role };
  });
}
const USERS = parseUsers();
if (!process.env.USERS) console.warn("[auth] USERS not set — using default admin/admin. Set USERS in production.");
const tokens = new Map(); // token -> { username, role, at }

app.post("/auth/login", (req, res) => {
  const { username, password } = req.body || {};
  const u = USERS.find(u => u.username === username && u.password === password);
  if (!u) return res.status(401).json({ error: "Invalid username or password" });
  const token = crypto.randomBytes(24).toString("hex");
  tokens.set(token, { username: u.username, role: u.role, at: Date.now() });
  res.json({ token, username: u.username, role: u.role });
});
app.post("/auth/logout", (req, res) => { const t = bearer(req); if (t) tokens.delete(t); res.json({ ok: true }); });

function bearer(req) { const h = req.headers.authorization || ""; return h.startsWith("Bearer ") ? h.slice(7) : null; }
function auth(req, res, next) {
  const t = bearer(req); const s = t && tokens.get(t);
  if (!s) return res.status(401).json({ error: "Not authenticated" });
  req.user = s; next();
}
function requireRole(...roles) {
  return (req, res, next) => roles.includes(req.user.role) ? next()
    : res.status(403).json({ error: `Requires role: ${roles.join(" or ")}` });
}
const canWrite = requireRole("admin", "scheduler");

app.get("/api/me", auth, (req, res) => res.json({ username: req.user.username, role: req.user.role, invoicedesk: invoicedesk.configured() }));

// ─── Generic CRUD factory for a JSON store ────────────────────────────────────
function crud(name, prefix) {
  const file = FILES[name];
  app.get(`/api/${name}`, auth, (_, res) => res.json(readJSON(file)));
  app.post(`/api/${name}`, auth, canWrite, (req, res) => {
    const list = readJSON(file);
    const item = { ...req.body, id: req.body.id || uid(prefix) };
    list.push(item); writeJSON(file, list); res.json({ ok: true, item });
  });
  app.put(`/api/${name}/:id`, auth, canWrite, (req, res) => {
    const list = readJSON(file); const i = list.findIndex(x => x.id === req.params.id);
    if (i === -1) return res.status(404).json({ error: "Not found" });
    list[i] = { ...list[i], ...req.body, id: req.params.id }; writeJSON(file, list); res.json({ ok: true, item: list[i] });
  });
  app.delete(`/api/${name}/:id`, auth, canWrite, (req, res) => {
    writeJSON(file, readJSON(file).filter(x => x.id !== req.params.id)); res.json({ ok: true });
  });
}
crud("activities", "act");
crud("equipment", "eq");
crud("bookings", "bk");
crud("crew", "cr");

// ─── InvoiceDesk read proxy (cached, server-to-server) ────────────────────────
const proxy = (fn) => async (req, res) => { try { const r = await fn(); res.json({ source: r.source, data: r.data, error: r.error || null }); } catch (e) { res.status(502).json({ error: e.message }); } };
app.get("/api/invoicedesk/projects", auth, proxy(invoicedesk.projects));
app.get("/api/invoicedesk/ar", auth, proxy(invoicedesk.ar));
app.get("/api/invoicedesk/ap", auth, proxy(invoicedesk.ap));
app.get("/api/invoicedesk/po", auth, proxy(invoicedesk.po));

// Seed equipment items from InvoiceDesk POs (dedupe by poId) --------------------
app.post("/api/equipment/import-pos", auth, canWrite, async (req, res) => {
  const { data: pos } = await invoicedesk.po();
  const list = readJSON(FILES.equipment);
  const existing = new Set(list.filter(e => e.poId).map(e => e.poId));
  let added = 0;
  for (const po of pos) {
    if (existing.has(po.id)) continue;
    const desc = (po.lines && po.lines[0] && po.lines[0].desc) || po.supplier;
    list.push({
      id: uid("eq"), projectId: po.projectId, name: desc, supplier: po.supplier,
      orderDate: po.issued || "", eta: po.expiry || "", leadTimeWeeks: weeksBetween(po.issued, po.expiry),
      status: po.status === "Closed" ? "delivered" : "ordered", source: "po", poId: po.id, blocksActivityId: null
    });
    added++;
  }
  writeJSON(FILES.equipment, list);
  res.json({ ok: true, added, total: list.length });
});
function weeksBetween(a, b) { if (!a || !b) return null; const d = (new Date(b) - new Date(a)) / 604800000; return d > 0 ? Math.round(d) : null; }

// ─── Static + health ──────────────────────────────────────────────────────────
app.get("/health", (_, res) => res.json({ ok: true, invoicedesk: invoicedesk.configured(), ts: new Date().toISOString() }));
app.use(express.static(path.join(__dirname, "public")));
app.get("*", (_, res) => res.sendFile(path.join(__dirname, "public", "index.html")));

const PORT = process.env.PORT || 4100;
app.listen(PORT, () => console.log(`GR Scheduler on :${PORT} — InvoiceDesk ${invoicedesk.configured() ? "linked" : "SAMPLE mode"}`));
