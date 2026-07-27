// ─── InvoiceDesk client (server-to-server, read-only, cached) ─────────────────
// Reads projects / AR / AP / PO from a running InvoiceDesk instance using a
// read-only API key. Falls back to bundled sample data when not configured, so
// the Scheduler runs out-of-the-box for review.

const URL = (process.env.INVOICEDESK_URL || "").replace(/\/$/, "");
const KEY = process.env.INVOICEDESK_API_KEY || "";
const TTL = (Number(process.env.INVOICEDESK_CACHE_TTL) || 60) * 1000;

const cache = {}; // path -> { at, data }

// Sample fallback (mirrors the prototype) ---------------------------------------
const SAMPLE = {
  projects: [
    { id: "BNE-006", name: "Substation Protection Upgrade", client: "Energex Ltd", type: "AUS Services", status: "Active", value: 485000, currency: "AUD", pm: "Craig Lordan", customerRef: "ENX-2025-114" },
    { id: "PNG-012", name: "Ramu Grid Telecom Link", client: "PNG Power Ltd", type: "PNG Services", status: "Active", value: 1240000, currency: "AUD", pm: "Craig Lordan", customerRef: "PP-RAMU-22" },
    { id: "BNE-008", name: "Ferny Grove RF Corridor Survey", client: "Queensland Rail", type: "AUS Consulting", status: "Active", value: 96000, currency: "AUD", pm: "Craig Lordan", customerRef: "QR-2026-337" }
  ],
  ar: [
    { id: "614601", projectId: "BNE-006", client: "Energex Ltd", status: "Paid", issued: "2026-08-30", due: "2026-09-29", lines: [{ desc: "Design milestone", qty: 1, rate: 85000, gst: true }] },
    { id: "614602", projectId: "BNE-006", client: "Energex Ltd", status: "Approved", issued: "2026-10-31", due: "2026-11-30", lines: [{ desc: "Procurement milestone", qty: 1, rate: 120000, gst: true }] },
    { id: "614603", projectId: "BNE-006", client: "Energex Ltd", status: "Submitted", issued: "2026-12-20", due: "2027-01-19", lines: [{ desc: "Install milestone", qty: 1, rate: 140000, gst: true }] },
    { id: "614604", projectId: "PNG-012", client: "PNG Power Ltd", status: "Paid", issued: "2026-09-15", due: "2026-10-15", lines: [{ desc: "Design", qty: 1, rate: 180000, gst: true }] },
    { id: "614605", projectId: "PNG-012", client: "PNG Power Ltd", status: "Overdue", issued: "2026-11-30", due: "2026-12-30", lines: [{ desc: "Equipment progress claim", qty: 1, rate: 220000, gst: true }] },
    { id: "614607", projectId: "BNE-008", client: "Queensland Rail", status: "Submitted", issued: "2026-09-26", due: "2026-10-26", lines: [{ desc: "Survey & report", qty: 1, rate: 96000, gst: true }] }
  ],
  ap: [
    { id: "AP-001", projectId: "PNG-012", subcontractor: "Highlands Rigging", amount: 48000, currency: "AUD", gstInclusive: true, received: "2026-11-05", due: "2026-12-05", status: "Approved" }
  ],
  po: [
    { id: "PO-1007", projectId: "BNE-006", supplier: "Schweitzer (SEL)", status: "Issued", issued: "2026-08-01", expiry: "2026-11-20", lines: [{ desc: "SEL-411L protection relays x6", qty: 6, rate: 9800, gst: true }] },
    { id: "PO-1008", projectId: "BNE-006", supplier: "NHP", status: "Issued", issued: "2026-08-15", expiry: "2026-10-24", lines: [{ desc: "Marshalling panels", qty: 3, rate: 6400, gst: true }] },
    { id: "PO-1011", projectId: "PNG-012", supplier: "Aviat Networks", status: "Issued", issued: "2026-08-10", expiry: "2026-12-04", lines: [{ desc: "WTM 4200 radios + antennas", qty: 4, rate: 41000, gst: true }] },
    { id: "PO-1012", projectId: "PNG-012", supplier: "AFL", status: "Issued", issued: "2026-09-01", expiry: "2026-10-15", lines: [{ desc: "Fibre splice + OTDR kit", qty: 1, rate: 22000, gst: true }] }
  ]
};

async function fetchPath(path) {
  if (!URL || !KEY) return { data: SAMPLE[path.replace("/api/", "")] || [], source: "sample" };
  const hit = cache[path];
  if (hit && Date.now() - hit.at < TTL) return { data: hit.data, source: "cache" };
  try {
    const ctrl = new AbortController();
    const timer = setTimeout(() => ctrl.abort(), 8000);
    let res;
    try { res = await fetch(`${URL}${path}`, { headers: { "x-api-key": KEY }, signal: ctrl.signal }); }
    finally { clearTimeout(timer); }
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    const data = await res.json();
    if (!Array.isArray(data)) throw new Error("unexpected response shape (not an array)");
    cache[path] = { at: Date.now(), data };
    return { data, source: "live" };
  } catch (e) {
    const reason = e.name === "AbortError" ? "timeout" : e.message;
    console.error("[invoicedesk]", path, "read failed:", reason, "— serving", hit ? "stale cache" : "sample");
    return { data: hit ? hit.data : SAMPLE[path.replace("/api/", "")] || [], source: hit ? "stale" : "sample", error: reason };
  }
}

module.exports = {
  configured: () => Boolean(URL && KEY),
  projects: () => fetchPath("/api/projects"),
  ar: () => fetchPath("/api/ar"),
  ap: () => fetchPath("/api/ap"),
  po: () => fetchPath("/api/po")
};
