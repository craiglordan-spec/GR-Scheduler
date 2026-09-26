/**
 * backup-export.js — shared by InvoiceDesk, ExpenseDesk, GR Pipeline and GR Scheduler.
 *
 * Lets the monthly backup script on Craig's PC copy every data file off this
 * app's Railway volume. It uses no packages beyond Node's own.
 *
 *   GET /backup-export/manifest        → { app, createdAt, files: [{ path, size, mtime }] }
 *   GET /backup-export/file?path=<rel> → the raw file (streamed)
 *
 * Both routes need the header  x-backup-key: <BACKUP_KEY>. The key is compared
 * in constant time. If BACKUP_KEY is not set, both routes return 404, so the
 * feature is off by default. Mount this before the app's own auth middleware:
 *
 *   require("./backup-export")(app, DATA_DIR, "InvoiceDesk");
 *
 * Secrets and noise are never exported: Xero token files, login sessions,
 * temporary files, the app's own rolling CSV backups and pre-restore
 * snapshots.
 */
"use strict";
const fs = require("fs");
const path = require("path");
const crypto = require("crypto");

const EXCLUDE = [
  /(^|\/)\.xero_tokens/i,          // OAuth tokens: secrets, and they expire anyway
  /(^|\/)sessions\.json$/i,        // login sessions
  /\.tmp$/i,
  /(^|\/)node_modules\//,
  /^backups\//,                    // the app's own rolling CSV backups
  /(^|\/)_pre-restore/i,           // restore safety snapshots
  /^lost\+found(\/|$)/,
];
const excluded = rel => EXCLUDE.some(rx => rx.test(rel));

function listFiles(root) {
  const out = [];
  (function walk(dir) {
    let entries = [];
    try { entries = fs.readdirSync(dir, { withFileTypes: true }); } catch { return; }
    for (const e of entries) {
      const abs = path.join(dir, e.name);
      const rel = path.relative(root, abs).split(path.sep).join("/");
      if (excluded(rel + (e.isDirectory() ? "/" : ""))) continue;
      if (e.isDirectory()) walk(abs);
      else if (e.isFile()) {
        try { const st = fs.statSync(abs); out.push({ path: rel, size: st.size, mtime: st.mtime.toISOString() }); } catch {}
      }
    }
  })(root);
  return out.sort((a, b) => a.path.localeCompare(b.path));
}

module.exports = function mountBackupExport(app, dataDir, appName) {
  const root = path.resolve(dataDir);
  const failures = new Map();   // ip -> { n, until }

  function guard(req, res, next) {
    const key = process.env.BACKUP_KEY || "";
    if (key.length < 20) return res.status(404).end();              // feature off
    const ip = req.ip || "";
    const f = failures.get(ip);
    if (f && f.n >= 10 && Date.now() < f.until) return res.status(429).json({ error: "Too many attempts" });
    const given = Buffer.from(String(req.get("x-backup-key") || ""));
    const want = Buffer.from(key);
    if (given.length !== want.length || !crypto.timingSafeEqual(given, want)) {
      failures.set(ip, { n: (f ? f.n : 0) + 1, until: Date.now() + 15 * 60000 });
      return res.status(401).json({ error: "Invalid backup key" });
    }
    failures.delete(ip);
    res.set("Cache-Control", "no-store");
    next();
  }

  app.get("/backup-export/manifest", guard, (req, res) => {
    const files = listFiles(root);
    console.log(`[backup-export] manifest requested: ${files.length} files`);
    res.json({ app: appName, createdAt: new Date().toISOString(), files });
  });

  app.get("/backup-export/file", guard, (req, res) => {
    const rel = String(req.query.path || "").replace(/\\/g, "/");
    const abs = path.resolve(root, rel);
    if (!rel || rel.includes("\0") || !abs.startsWith(root + path.sep) || excluded(rel))
      return res.status(400).json({ error: "Invalid path" });
    fs.stat(abs, (err, st) => {
      if (err || !st.isFile()) return res.status(404).json({ error: "Not found" });
      res.set({ "Content-Type": "application/octet-stream", "Content-Length": String(st.size) });
      fs.createReadStream(abs).on("error", () => res.destroy()).pipe(res);
    });
  });
};
