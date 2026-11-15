# GR Scheduler — Microsoft 365 sign-in setup

GR Scheduler signs users in with their Gravelroad Microsoft 365 account (Entra ID), exactly as
InvoiceDesk does: multi-factor comes from Microsoft 365, and who may use GR Scheduler — and at what
level — is set in Entra. Removing someone's Microsoft 365 access removes their GR Scheduler access.

Nothing changes until the Railway variables in step 3 are set. Password sign-in keeps working
alongside until you switch it off in step 5. The code is `m365-auth.js` (shared with InvoiceDesk).

## 1. Register the app in Entra (about 15 minutes)

entra.microsoft.com → **Applications → App registrations → + New registration**
- Name: `GR Scheduler` · **Single tenant** · Redirect URI, platform **Web**:
  `https://gr-scheduler-production.up.railway.app/auth/m365/callback` → **Register**.
- Overview: copy **Application (client) ID** → `M365_CLIENT_ID`. (Directory (tenant) ID is the same
  tenant GUID InvoiceDesk uses.)
- **Certificates & secrets → + New client secret**, 24 months. Copy the **Value** (not the Secret ID)
  → `M365_CLIENT_SECRET`. Diary a reminder before it expires.
- **App roles → + Create app role**, three times (Value must be exactly as shown; tick *enable*):

| Display name | Allowed member types | Value | Meaning in GR Scheduler |
|---|---|---|---|
| Admin | Users/Groups | `admin` | Full access, incl. backup/restore |
| Editor | Users/Groups | `editor` | Scheduler — edit the programme |
| Viewer | Users/Groups | `viewer` | Read-only |

- **API permissions:** leave `User.Read`; click **Grant admin consent for Gravelroad**.

## 2. Decide who gets in

**Enterprise applications → GR Scheduler** → **Properties → Assignment required? → Yes → Save**.
**Users and groups → + Add user/group** → user → role → **Assign**. Assign individuals (groups need
Entra ID P1, and most staff are on Business Basic).

## 3. Railway variables

Railway → project **gracious-expression** → service **GR-Scheduler** → **Variables**:

| Variable | Value |
|---|---|
| `M365_TENANT_ID` | Tenant GUID  |
| `M365_CLIENT_ID` | Application (client) ID |
| `M365_CLIENT_SECRET` | Secret **Value** |
| `APP_BASE_URL` | `https://gr-scheduler-production.up.railway.app`  |

Click **Deploy** on the staged-changes banner. The deploy log should show
`[m365] Microsoft 365 sign-in enabled for GR Scheduler; password login ON`.

## 4. Test

Sign in with Microsoft; check your name and role. Have a Viewer and an Editor try it. An account
that isn't assigned should be refused with a clear message.

## 5. Switch off passwords

Once everyone uses Microsoft: `PASSWORD_LOGIN` = `off`, deploy. **Break-glass:** set it back to `on`
(or delete it) and deploy. Keep at least one strong admin password for this: `USERS` (unchanged) = `username:password:role`, roles admin / scheduler / viewer.

## What else changed

- The Entra **Editor** role is the Scheduler's **scheduler** role (same three role values across all GR apps).
- Sessions now end after 8 h idle / 12 h maximum (were unlimited until redeploy).
- The `admin`/`admin` default account now applies only when neither `USERS` nor Microsoft sign-in is configured.
- `SESSION_SECRET` was never used by the code; it can be left or removed.
- Same security headers as InvoiceDesk. Password sign-in: 5 wrong attempts per user (20 per address) → 15-minute lock.
- `/backup-export/*` (monthly off-site backup, `BACKUP_KEY`) and the InvoiceDesk keys are unaffected.

## Troubleshooting

| Message | Cause |
|---|---|
| "has not been given access to GR Scheduler" | Not assigned in Enterprise applications. |
| "you have not been given a role" | Assigned with no role, or role Value not `admin`/`editor`/`viewer`. |
| "client secret invalid or expired" | Secret ID pasted instead of Value, or expired. |
| AADSTS50011 reply URL mismatch | Redirect URI ≠ `https://gr-scheduler-production.up.railway.app/auth/m365/callback`. |
| No Microsoft button | A variable is missing — check the deploy log for `[m365]`. |
