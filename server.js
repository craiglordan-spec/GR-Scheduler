/*
 * GR Project Control — Scheduler & Timeline
 * Backend: role-based auth, JSON storage (activities/equipment/bookings/crew),
 * and a server-to-server read of InvoiceDesk (projects/invoices/POs).
 */
const express = require("express");
const path = require("path");
const fs = require("fs");
const crypto = require("crypto");
const JSZip = require("jszip");
const Papa = require("papaparse");
const invoicedesk = require("./invoicedesk");

const app = express();
app.use(express.json({ limit: "2mb" }));

// ─── Storage ──────────────────────────────────────────────────────────────────
// Prefer an explicit DATA_DIR, else the Railway volume mount (auto-set when a
// volume is attached), else the (ephemeral) local folder. PERSISTENT is false
// only when we fall back to local disk — surfaced in the UI as a warning.
const VOL = process.env.RAILWAY_VOLUME_MOUNT_PATH || "";
const DATA_DIR = process.env.DATA_DIR || VOL || path.join(__dirname, "data");
// Monthly off-site backup: key-protected export of the data volume (see backup-export.js).
require("./backup-export")(app, DATA_DIR, "GR Scheduler");
const PERSISTENT = Boolean(process.env.DATA_DIR || VOL);
if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR, { recursive: true });
console.log(`[storage] DATA_DIR=${DATA_DIR} persistent=${PERSISTENT}${VOL ? ` (volume ${VOL})` : ""}`);
const FILES = {
  activities: path.join(DATA_DIR, "activities.json"),
  equipment: path.join(DATA_DIR, "equipment.json"),
  bookings: path.join(DATA_DIR, "bookings.json"),
  crew: path.join(DATA_DIR, "crew.json"),
  assets: path.join(DATA_DIR, "assets.json")
};
const SETTINGS_F = path.join(DATA_DIR, "settings.json");
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
const isAdmin = requireRole("admin");

app.get("/api/me", auth, (req, res) => res.json({ username: req.user.username, role: req.user.role, invoicedesk: invoicedesk.configured(), persistent: PERSISTENT }));

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
crud("assets", "as"); // company asset register (test equipment, routers, rigging, lifting gear)

// ─── Settings (singleton: scheduling scope, etc.) ─────────────────────────────
app.get("/api/settings", auth, (_, res) => res.json(readJSON(SETTINGS_F, { scope: [] })));
app.put("/api/settings", auth, canWrite, (req, res) => {
  const s = { ...readJSON(SETTINGS_F, { scope: [] }), ...req.body };
  writeJSON(SETTINGS_F, s); res.json({ ok: true, settings: s });
});

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

// ─── Backup & restore (admin-only) ────────────────────────────────────────────
// One CSV per record type, bundled into a single .zip download. Nested list
// fields (activities.deps, settings.scope) are encoded as pipe-joined cells and
// decoded again on restore. Numbers/booleans are coerced back by a small schema.
const ENTITIES = ["activities", "equipment", "bookings", "crew", "assets"];
const BACKUP_FILES = { activities: "activities.csv", equipment: "equipment.csv", bookings: "bookings.csv", crew: "crew.csv", assets: "assets.csv", settings: "settings.csv" };
// Preferred column order + type hints. Extra keys found in the data are appended.
const SCHEMA = {
  activities: { cols: ["id", "projectId", "name", "category", "start", "end", "percentComplete", "deps", "order", "critical", "notes"], arrays: ["deps"], numbers: ["percentComplete", "order", "leadTimeWeeks"], booleans: ["critical"] },
  equipment:  { cols: ["id", "projectId", "name", "supplier", "orderDate", "eta", "leadTimeWeeks", "status", "source", "poId", "blocksActivityId", "order"], arrays: [], numbers: ["leadTimeWeeks", "order"], booleans: [] },
  bookings:   { cols: ["id", "projectId", "crewId", "type", "label", "start", "end", "status", "blocksActivityId", "order"], arrays: [], numbers: ["order"], booleans: [] },
  crew:       { cols: ["id", "name", "role", "type", "size", "ticketExpiry", "notes", "order"], arrays: [], numbers: ["size", "order"], booleans: [] },
  assets:     { cols: ["id", "name", "category", "makeModel", "serial", "status", "holder", "purchaseDate", "purchaseValue", "wll", "calibrationDue", "inspectionDue", "notes", "order"], arrays: [], numbers: ["purchaseValue", "order"], booleans: [] },
  settings:   { cols: ["scope"], arrays: ["scope"], numbers: [], booleans: [] }
};
const ARRAY_DELIM = "|";

function columnsFor(name, rows) {
  const cols = [...SCHEMA[name].cols];
  for (const r of rows) for (const k of Object.keys(r || {})) if (!cols.includes(k)) cols.push(k);
  return cols;
}
// Encode one record → flat object of string cells, ready for CSV.
function encodeRow(name, rec, cols) {
  const arrays = SCHEMA[name].arrays;
  const out = {};
  for (const c of cols) {
    const v = rec[c];
    if (arrays.includes(c)) out[c] = Array.isArray(v) ? v.join(ARRAY_DELIM) : (v == null ? "" : String(v));
    else if (v == null) out[c] = "";
    else if (typeof v === "object") out[c] = JSON.stringify(v); // defensive: unexpected nested object
    else out[c] = String(v);
  }
  return out;
}
// Decode one CSV row-object → typed record.
function decodeRow(name, row) {
  const s = SCHEMA[name];
  const rec = {};
  for (const [k, raw] of Object.entries(row)) {
    const cell = raw == null ? "" : String(raw);
    if (s.arrays.includes(k)) { rec[k] = cell === "" ? [] : cell.split(ARRAY_DELIM).map(x => x.trim()).filter(Boolean); continue; }
    if (cell === "") continue; // preserve "field absent" rather than inventing ""
    if (s.numbers.includes(k) && cell !== "" && !isNaN(Number(cell))) { rec[k] = Number(cell); continue; }
    if (s.booleans.includes(k) && (cell === "true" || cell === "false")) { rec[k] = cell === "true"; continue; }
    rec[k] = cell;
  }
  return rec;
}
function entityToCsv(name, rows) {
  const cols = columnsFor(name, rows);
  const data = rows.map(r => encodeRow(name, r, cols));
  return Papa.unparse({ fields: cols, data }, { quotes: true, newline: "\r\n" });
}
function csvToEntity(name, text) {
  const parsed = Papa.parse((text || "").trim(), { header: true, skipEmptyLines: true });
  return parsed.data.map(r => decodeRow(name, r));
}

app.get("/api/backup", auth, isAdmin, async (req, res) => {
  try {
    const stamp = new Date().toISOString();
    const zip = new JSZip();
    const counts = {};
    for (const name of ENTITIES) {
      const rows = readJSON(FILES[name]);
      counts[name] = rows.length;
      zip.file(BACKUP_FILES[name], entityToCsv(name, rows));
    }
    const settings = readJSON(SETTINGS_F, { scope: [] });
    zip.file(BACKUP_FILES.settings, entityToCsv("settings", [settings]));
    const manifest = { app: "GR-Scheduler", format: "csv-zip", version: 1, exportedAt: stamp, counts, arrayDelimiter: ARRAY_DELIM };
    zip.file("manifest.json", JSON.stringify(manifest, null, 2));
    zip.file("README.txt",
      "GR Scheduler backup\n" +
      "===================\n" +
      `Exported: ${stamp}\n\n` +
      "One CSV per record type: activities, equipment, bookings, crew, settings.\n" +
      `List fields (activities 'deps', settings 'scope') are encoded in a single cell, values separated by '${ARRAY_DELIM}'.\n` +
      "Empty cell means the field is not set for that row.\n\n" +
      "To restore: sign in as an admin, open the app header, choose 'Restore', and select this .zip file.\n" +
      "Restore REPLACES all scheduler data. The server saves a safety snapshot of the current data first.\n" +
      "You may edit the CSVs in Excel before restoring, but keep the column headers and the id column intact.\n");
    const buf = await zip.generateAsync({ type: "nodebuffer", compression: "DEFLATE" });
    const fname = `gr-scheduler-backup-${stamp.slice(0, 10)}.zip`;
    res.setHeader("Content-Type", "application/zip");
    res.setHeader("Content-Disposition", `attachment; filename="${fname}"`);
    res.send(buf);
  } catch (e) {
    console.error("[backup] failed", e);
    res.status(500).json({ error: "Backup failed: " + e.message });
  }
});

app.post("/api/restore", auth, isAdmin, express.raw({ type: ["application/zip", "application/octet-stream"], limit: "50mb" }), async (req, res) => {
  try {
    if (!req.body || !req.body.length) return res.status(400).json({ error: "No file received" });
    let zip;
    try { zip = await JSZip.loadAsync(req.body); } catch { return res.status(400).json({ error: "Not a valid .zip file" }); }
    // Require every CSV so a partial/foreign zip can't silently wipe a store.
    const missing = Object.values(BACKUP_FILES).filter(f => !zip.file(f));
    if (missing.length) return res.status(400).json({ error: `Backup is missing: ${missing.join(", ")}. Use a full GR Scheduler backup .zip.` });

    // Parse + validate everything BEFORE touching disk.
    const parsed = {};
    for (const name of ENTITIES) {
      const rows = csvToEntity(name, await zip.file(BACKUP_FILES[name]).async("string"));
      const bad = rows.findIndex(r => !r.id);
      if (bad !== -1) return res.status(400).json({ error: `${BACKUP_FILES[name]} row ${bad + 2} has no id — restore aborted.` });
      parsed[name] = rows;
    }
    const settingsRows = csvToEntity("settings", await zip.file(BACKUP_FILES.settings).async("string"));
    const settings = settingsRows[0] || { scope: [] };
    if (!Array.isArray(settings.scope)) settings.scope = [];

    // Safety snapshot of current data, then write the restore.
    const snap = { ts: new Date().toISOString() };
    for (const name of ENTITIES) snap[name] = readJSON(FILES[name]);
    snap.settings = readJSON(SETTINGS_F, { scope: [] });
    const snapFile = path.join(DATA_DIR, `_pre-restore-${snap.ts.replace(/[:.]/g, "-")}.json`);
    try { writeJSON(snapFile, snap); } catch (e) { console.warn("[restore] snapshot failed:", e.message); }

    const counts = {};
    for (const name of ENTITIES) { writeJSON(FILES[name], parsed[name]); counts[name] = parsed[name].length; }
    writeJSON(SETTINGS_F, settings);
    console.log(`[restore] by ${req.user.username}:`, counts, "snapshot", path.basename(snapFile));
    res.json({ ok: true, counts, snapshot: path.basename(snapFile) });
  } catch (e) {
    console.error("[restore] failed", e);
    res.status(500).json({ error: "Restore failed: " + e.message });
  }
});

// ─── Static + health ──────────────────────────────────────────────────────────
app.get("/health", (_, res) => res.json({ ok: true, invoicedesk: invoicedesk.configured(), persistent: PERSISTENT, dataDir: DATA_DIR, ts: new Date().toISOString() }));
app.use(express.static(path.join(__dirname, "public")));
app.get("*", (_, res) => res.sendFile(path.join(__dirname, "public", "index.html")));

const PORT = process.env.PORT || 4100;
app.listen(PORT, () => console.log(`GR Scheduler on :${PORT} — InvoiceDesk ${invoicedesk.configured() ? "linked" : "SAMPLE mode"}`));
