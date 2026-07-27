# GR Project Control — Scheduler & Timeline

Programme scheduling for Gravel Road's engineering projects (AUS & PNG). Companion to **InvoiceDesk**: it reads projects, invoices and purchase orders from InvoiceDesk (server-to-server, read-only) and adds the *time* dimension — activities, dependencies, equipment lead times and crew bookings — with a visual Gantt and a per-project invoice roll-up.

## Run locally
```bash
npm install
cp .env.example .env      # edit values
npm start                 # http://localhost:4100
```
With no `INVOICEDESK_API_KEY` set, it runs on **bundled sample data** so you can click around immediately. Default login (if `USERS` unset): `admin` / `admin`.

## Deploy on Railway
1. Push this repo to GitHub, create a Railway service from it.
2. Set variables (see `.env.example`): `USERS`, `SESSION_SECRET`, `INVOICEDESK_URL`, `INVOICEDESK_API_KEY`.
3. Add a persistent volume mounted at `/data` and set `DATA_DIR=/data` so scheduling data survives redeploys.

## Users & roles
`USERS` is `username:password:role` comma-separated. Roles:
- **admin** — everything;
- **scheduler** — create/edit activities, equipment, bookings, crew;
- **viewer** — read-only (good for clients/partners).

## Link to InvoiceDesk
The Scheduler calls InvoiceDesk with a read-only API key (`x-api-key`). On the InvoiceDesk side, set `INVOICEDESK_READ_KEY` and the small middleware that lets `GET /api/*` through with that header. Endpoints consumed: `/api/projects`, `/api/ar`, `/api/ap`, `/api/po`. Results are cached (`INVOICEDESK_CACHE_TTL`).

## Data model (stored here)
`crew`, `activities`, `equipment`, `bookings` — see `seed/*.json` for shapes. Projects and invoices are **never** stored here; they come from InvoiceDesk. Shared key = project id (e.g. `PNG-012`).

## Notes
- Equipment can be **imported from InvoiceDesk POs** ("Import from POs") or added manually.
- The **critical path** is computed from activity dependencies plus equipment ETAs and booking completion, and drawn in red.
