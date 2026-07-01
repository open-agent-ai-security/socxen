# Enrichment playbook — context tables that tip FP vs TP

Baselining with `search_events` tells you *what happened*. Context tables tell you *who/what it happened
to* — and that's usually what turns "I found nothing suspicious" into a **positive** benign or malicious
explanation. Per the close rule, you can't close an alert FP without a positive benign explanation;
enrichment is where most of those come from (a documented service account, an approved admin, an expected
travel pattern) — and where a benign-looking event becomes malicious (an unmanaged host, an
unknown-to-HR account, a threat-intel IP).

## The two tools

- `exabeam_context_table_list` — **no args** (call with `{}`). Returns every context table with its
  `id`, `name`, and `attributes` (each attribute has `displayName`, `id`, `isKey`).
- `exabeam_get_context_table_records` — `arg0: {` **`tableId`** `, limit, offset }`. Returns rows.

Table names are **tenant-specific** (a real tenant had 114 tables, many with generated names like
`Entra-ID-User-4893…` or `Okta-Context-User-8743…`). **Don't hardcode names — discover at runtime:**
list the tables, pick the ones whose `attributes` match the category you need (below), then read records
or reference the table by `IN` in a search.

## The categories that tip triage (confirmed on a live New-Scale tenant)

### 1. Identity / HR — the highest-value enrichment
Sourced from the IdP/directory — **Entra ID**, **Okta**, **Azure AD** context tables. Real attributes
seen: `Primary Login (Email Format)`, `Display Name`, **`Title`**, **`Department`**, **`Employee Type`**,
`Manager`, `City`/`Country`, and MFA fields (`isMfaRegistered`, `isMfaCapable`, `methodsRegistered`).

What each answers, and which way it tips:

| Attribute | Question | Tips toward… |
|---|---|---|
| `Title` / `Department` | Is this a VIP / exec / finance / privileged role? | **Raise the stakes.** A finance VP or C-level with an anomaly is escalate-first; the same event for a rank-and-file dev may be routine. |
| `Employee Type` | Employee vs **contractor / service / vendor**? | **Disambiguates.** Machine-like odd-hours/geo activity for a *service* account is often automation (benign); the same for a *human* employee is suspicious. A service account doing *interactive/new* behavior flips to TP. |
| `isMfaRegistered` / `methodsRegistered` | Was MFA available/satisfied? | An "impossible-travel" sign-in where **MFA is registered and satisfied** leans benign (token/VPN reuse). A privileged account with **no MFA registered** is a standing gap and raises TP weight. |
| `Manager` / `Department` | Peer-group baseline; who owns the response? | Baseline against the team; route escalation to the manager. |
| `City` / `Country` | Home location baseline | Compare to the alert's geo (`geo_src_ip.country`); a first-ever country against a stable home is signal. |

### 2. Host / asset — is this a known machine?
Table like **`AD Host IP`** — attributes `Hostname`, `IP Addresses (v4/v6)`, `Operating System`.
- **Known corporate asset?** An unmanaged/unknown host in the chain raises suspicion.
- **Server vs workstation** (from OS) changes the story — a service running on a server ≠ a workstation
  suddenly acting like a server.
- **IP ↔ hostname resolution** for pivots when an event only has one side.

### 3. Identity mapping — resolve raw identifiers
Tables like **`User SID`** (`Object Sid` → `Primary User Name`) and **`UID User`** (`ID` → `Primary
User Name`). When a Windows/endpoint event carries only a `S-1-5-…` SID or a numeric UID, map it to a
real user before you pivot — otherwise the timeline is full of unresolved identifiers.

### 4. Watchlists / custom tables — positive evidence, both directions
Custom tables (admin allowlists, approved-automation accounts, threat-intel IPs/domains, known-good OAuth
apps). These are the cleanest positive explanations:
- A `src_ip` **in** a threat-intel table → strong **TP** signal.
- A user **in** an "approved admins" table performing admin actions → the **positive benign explanation**
  that justifies an FP close.
- An OAuth app **in** a known-good table → benign consent.

## Using them

**Membership test inside a search** (cheapest — no need to hand-list values; the column qualifier is
required, see `search-cookbook.md`):
```jsonc
{"arg0": {"filter": "src_ip IN \"Threat Intel IPs\".\"IP Address\"",
  "fields": ["time","user","src_ip","dest_host","action"],
  "orderBy": ["time DESC"], "startTime": "<t-24h>", "endTime": "<t>", "limit": 100}}
```

**Direct lookup** — read a table's rows to enrich an entity:
```jsonc
// 1) find the identity table
{}                                   // → exabeam_context_table_list, pick the Entra/Okta table id
// 2) read it
{"arg0": {"tableId": "<id-from-list>", "limit": 50}}   // → exabeam_get_context_table_records
```

## The discipline

- Enrichment supplies the **positive** explanation the close rule demands — "user is in the approved-admin
  table and this is expected admin behavior" is a valid FP close; "I didn't see anything else" is not.
- The mirror holds for TP: an unmanaged host, an account unknown to the IdP table, or a threat-intel IP
  hit is positive malicious evidence — enough to raise, not to *confirm* alone (calibrate to what you
  gathered).
- **Cite the table** in the report like any other evidence (which table, which record) — an enrichment
  claim with no source doesn't belong in the writeup (`report-template.md`).
