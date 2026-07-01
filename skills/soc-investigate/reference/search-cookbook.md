# Search cookbook — `exabeam_search_events`

`search_events` is the evidence workhorse, and it is only as good as the query you hand it. This file
is the query craft the skill leans on: the request shape, the filter grammar, the **real field names**
an analyst pivots on, and copy-paste recipes for each step of the investigation loop.

Everything here is grounded in the **live** Exabeam New-Scale API — the `/search/v2/events` request
schema and its own worked examples — and the **Common Information Model** field catalogue
([`ExabeamLabs/CIMLibrary` → `Fields_Descriptions.md`](https://github.com/ExabeamLabs/CIMLibrary/blob/main/Fields_Descriptions.md)),
which is the authoritative list of field names for building searches and correlation rules. Use the
exact field names below; **do not invent fields** — if you need one that isn't here, discover it with a
Field Summary query (last section) rather than guessing.

> Names, not shapes, are what break first. If a call fails schema validation, it's almost always the
> `arg0`/`arg1` wrapper (see `tool-map.md`), not the filter — fix the wrapper first.

## The request shape (`SearchDetails`)

`exabeam_search_events` wraps its argument under **`arg0`**. The object is the API's `SearchDetails`:

| Field | Required | What it does |
|---|---|---|
| `filter` | ✅ | The query string (grammar below). May be empty `""` to match everything in the window. |
| `fields` | ✅ | Columns to return. `["*"]` = all applicable fields. Name specific fields to keep results skimmable. |
| `startTime` | ✅ | ISO-8601, e.g. `2024-04-01T00:00:00Z`. |
| `endTime` | ✅ | ISO-8601. Keep windows tight — search spans years; a wide window is slow and noisy. |
| `limit` | | Max rows. **Default 3000.** Set it low (25–100) while pivoting, high only when counting. |
| `groupBy` | | Fields to GROUP BY (aggregation). |
| `orderBy` | | e.g. `["time DESC"]`, `["riskScore DESC"]`, `["app ASC"]`. |
| `distinct` | | `true` → DISTINCT on the selected fields. |

Minimal call:

```json
{"arg0": {
  "filter": "user:\"jsmith\"",
  "fields": ["time","activity_type","src_host","dest_host","src_ip","result"],
  "startTime": "2024-04-01T00:00:00Z",
  "endTime":   "2024-04-08T00:00:00Z",
  "orderBy":   ["time DESC"],
  "limit": 100
}}
```

Response is `{ rows: [...], totalRows, timeStartedMillis, timeCompletedMillis }`. **`totalRows` is
itself evidence** — "how many times did this happen?" is often the whole triage question.

## Filter grammar (EQL)

The query language is **Exabeam Query Language (EQL)** — the same language the Search UI parses. The
grammar below is confirmed from the [official EQL
docs](https://docs.exabeam.com/en/exa-search/all/search-guide/performing-searches/advanced-search/query-syntax.html)
and from the live `/search/v2/events` examples; a few forms are additionally shown as they appear in
real in-product queries.

- **Field match:** `field:"value"` — quote the value. `:` and `=` are **interchangeable**
  (`vendor:"Exabeam"` ≡ `vendor="Exabeam"`); Exabeam recommends `=`. Match modes:
  - loose keyword `product:"web application"` (words matched independently),
  - exact keyword `` product="`web application`" `` (backticks),
  - exact full `product=="web application"` (double `==`).
- **Boolean:** `AND`, `OR`, `NOT`, `TO` — upper- or lower-case (uppercase recommended). **Parentheses
  group:** `((subject:"user" OR subject:"app") AND product:"Windows")`.
- **Value sets** (match any of a list — cleaner than chained `OR`): `field:("a","b","c")`. Real example:
  `activity_type:("app-login","authentication-successful","vpn-login","remote-logon")`.
- **Comparisons / ranges** (numeric & date): `>`, `<`, `>=`, `<=`, and inclusive `TO` ranges —
  `num_pages:>50`, `logon_date:[2018-10-31 TO 2018-12-31]`.
- **Wildcards:** `*` (multi-char) and `?` (single) *inside* a value — `subject:"W*b"`. `*` can't stand
  alone; for keyword wildcard matching use `WLD("MiCrO*")` (case-sensitive) / `WLDi("micro*")` (insensitive).
- **Regex:** `field = RGX("<regex>")`. Powerful for threat hunts — e.g.
  `dns_query = RGX(".*katz-stealer\.com.*")`, `file_path = RGX("\\\.library\\-ms$")`.
- **Null / exists:** `field:null` (or `= NULL`); exists = `NOT field:null`. `caseId:null` = "not yet
  triaged into a case" (see Queue sweep).
- **Context-table membership:** `field IN "<Table>"."<Column>"` — the **column qualifier is required**:
  `src_ip IN "Admin Users"."IP Address"`, `category IN "AI/LLM Proxy Categories"."Key"`. Combine with
  `AND` to intersect tables.
- **Entity-attribute accessor:** `user(<attr>, "<value>")` pins an identity by a specific attribute
  rather than the loose `user:"…"` — `user(username, "gary.hardin")`,
  `user(email, "gary.hardin@ktenergy.com")`. Nested/derived fields use dotted paths:
  `geo_src_ip.country:("ru","kp","ir")`.
- **Aggregation:** `COUNT`/`SUM`/`AVG`/`MIN`/`MAX`, aliased with `AS`. In SQL-style filters the clause
  keywords are **hyphenated**: `GROUP-BY`, `ORDER-BY` (… `ASC`/`DESC`). `COUNT` counts non-null on any
  field; `SUM`/`AVG` need numeric.
- **SQL-style filter** (put the whole query in `filter`; clause order
  `[SELECT] [WHERE] [GROUP-BY] [ORDER-BY] [LIMIT]`):
  `SELECT app, COUNT(*) AS app_count WHERE product:"Audit Log" GROUP-BY app ORDER-BY app_count DESC`.
- **Pipe** `|` chains statements, feeding results forward (**max 5 pipes / 6 statements**):
  `SELECT product, AVG(raw_log_size) AS avgLogSize GROUP-BY product ORDER-BY avgLogSize DESC | avgLogSize > 2000`.
  The API's own examples also show a table-materialize form
  (`SELECT * WHERE … as rt_table | from rt_table WHERE NOT rawLogIds:null`); it appears in the
  `/search/v2/events` examples but not the general EQL UI docs, so treat `from <table>` as
  API-example-sourced rather than broadly documented.

> **Object form vs. SQL form.** Simple filters go in `filter` with `fields`/`groupBy`/`orderBy` as
> object keys (below). Complex analytics can instead be written entirely inside `filter` as one
> `SELECT … WHERE … GROUP-BY …` string. Both hit the same engine — use whichever is clearer.

## Field vocabulary (what to pivot on)

Canonical CIM names. These are the ones triage actually turns on — filter and `fields` both use them.

**Identity / user**
`user` (the actor) · `src_user` (initiator) · `dest_user` (target) · `account`, `account_name`
(the account operated on) · `domain`, `src_domain`, `dest_domain` · `email_address` · `sender`,
`recipient` (mail).

**Host / network**
`host` (machine that logged it — hostname *or* IP) · `src_host`, `dest_host` · `src_ip`, `dest_ip` ·
`src_port`, `dest_port` · `url` · `user_agent` · `country`, `city`, `src_location` (geo).

**Process / endpoint**
`process` (path) · `process_name` · `process_id` (PID) · `parent_process` · `command` · `file_hash`.

**Auth / outcome**
`auth_method` · `logon_type` · `mfa` · `action` (allowed/blocked/quarantined…) · `result`
(succeeded/failed as parsed) · `outcome`.

**Event classification**
`activity_type` · `activity` · `app` · `product` · `vendor` · `platform` · `time`.

**Analytics (Exabeam AA rule-trigger events)** — how you see *why* a risk score moved:
`rule`, `rule_reason`, `original_risk_score`, `rawLogIds` (the raw logs behind the trigger).

## Recipes — mapped to the investigation loop

### Step 2 — baseline: "is this normal for this entity?"
There is no entity-lookup tool; you baseline with search. Pull the entity's recent behavior and eyeball
what's routine before you judge the triggering event.

```jsonc
// What does jsmith normally do? (activity mix over the last week)
{"arg0": {"filter": "user:\"jsmith\"",
  "fields": ["activity_type","count(activity_type) as n"],
  "groupBy": ["activity_type"], "orderBy": ["n DESC"],
  "startTime": "<t-7d>", "endTime": "<t>", "limit": 100}}

// Where does jsmith normally sign in from? (baseline geo/IP)
{"arg0": {"filter": "user:\"jsmith\" AND activity_type:\"authentication\"",
  "fields": ["src_ip","country","city","count(*) as n"],
  "groupBy": ["src_ip","country","city"], "orderBy": ["n DESC"],
  "startTime": "<t-30d>", "endTime": "<t>", "limit": 200}}
```

A country/IP that appears for the first time in the alert window, against a 30-day baseline that never
shows it, is a real signal. A country the user hits weekly is not.

### Step 3 — pivot the entity chain (user → host → IP → process)
Each answer feeds the next filter.

```jsonc
// User's activity in the alert window — the spine of the timeline
{"arg0": {"filter": "user:\"jsmith\"",
  "fields": ["time","activity_type","src_host","dest_host","src_ip","dest_ip","result"],
  "orderBy": ["time DESC"], "startTime": "<alert-start>", "endTime": "<alert-end>", "limit": 200}}

// Everything on the host the alert named (who else touched it?)
{"arg0": {"filter": "(src_host:\"FIN-LT-014\" OR dest_host:\"FIN-LT-014\")",
  "fields": ["time","user","activity_type","process_name","dest_ip"],
  "orderBy": ["time DESC"], "startTime": "<t-24h>", "endTime": "<t>", "limit": 200}}

// What ran on the host (process/endpoint view)
{"arg0": {"filter": "host:\"FIN-LT-014\" AND NOT process_name:null",
  "fields": ["time","user","process_name","parent_process","command","file_hash"],
  "orderBy": ["time DESC"], "startTime": "<t-24h>", "endTime": "<t>", "limit": 200}}

// Fan-out from an IP (who else, what destinations)
{"arg0": {"filter": "src_ip:\"203.0.113.7\"",
  "fields": ["time","user","dest_host","dest_ip","dest_port","action"],
  "orderBy": ["time DESC"], "startTime": "<t-24h>", "endTime": "<t>", "limit": 200}}
```

### Step 3 — see *why* a rule/model fired (the fastest FP/TP tell)
For Exabeam Advanced Analytics risk, go straight to the rule-trigger events and their raw logs — it
often decides the verdict before any correlation-rule reading.

```jsonc
{"arg0": {"filter": "activity_type:\"rule-trigger\" AND platform:\"Exabeam AA\" AND user:\"jsmith\"",
  "fields": ["time","rule","rule_reason","original_risk_score","rawLogIds"],
  "orderBy": ["original_risk_score DESC"],
  "startTime": "<alert-start>", "endTime": "<alert-end>", "limit": 50}}
```

`rule_reason` is the model's own explanation; `rawLogIds` links to the underlying logs to corroborate
(or debunk) it. A high score built entirely on one noisy rule is an FP hypothesis, not a verdict.

### Auth-failure / brute-force shape
```jsonc
{"arg0": {"filter": "dest_user:\"jsmith\" AND activity_type:\"authentication\" AND result:\"failed\"",
  "fields": ["time","src_ip","auth_method","logon_type","result"],
  "orderBy": ["time DESC"], "startTime": "<t-6h>", "endTime": "<t>", "limit": 500}}
```
Then count sources to tell spray from a single fat-fingered client:
```jsonc
{"arg0": {"filter": "dest_user:\"jsmith\" AND result:\"failed\"",
  "fields": ["src_ip","count(*) as attempts"], "groupBy": ["src_ip"],
  "orderBy": ["attempts DESC"], "startTime": "<t-6h>", "endTime": "<t>", "limit": 100}}
```

### Watchlist / allowlist test (context tables)
```jsonc
// Is the source IP catalogued in a watchlist context table? (column qualifier is required)
{"arg0": {"filter": "src_ip IN \"Threat Intel IPs\".\"IP Address\"",
  "fields": ["time","user","src_ip","dest_host","action"],
  "orderBy": ["time DESC"], "startTime": "<t-24h>", "endTime": "<t>", "limit": 100}}
```
Use `exabeam_context_table_list` to find the exact table **and column** names; membership via `IN`
beats hand-listing values and keeps the query honest as the table changes.

### Threat hunting (regex, geo, value-sets)
When you're hunting a known TTP rather than triaging one alert, EQL's `RGX()`, dotted geo fields, and
value-sets do the heavy lifting (patterns below are real in-product query shapes):

```jsonc
// Malicious-domain beaconing across all DNS (regex over dns_query)
{"arg0": {"filter": "(dns_query = RGX(\".*katz-stealer\\.com.*\") OR dns_query = RGX(\".*twist2katz\\.com.*\"))",
  "fields": ["time","user","src_host","dns_query"],
  "orderBy": ["time DESC"], "startTime": "<t-30d>", "endTime": "<t>", "limit": 500}}

// Logins from sanctioned/high-risk geographies (dotted geo field + value-set + activity value-set)
{"arg0": {"filter": "geo_src_ip.country:(\"ru\",\"kp\",\"ir\",\"sy\",\"cu\") AND activity_type:(\"app-login\",\"authentication-successful\",\"vpn-login\",\"remote-logon\")",
  "fields": ["time","user","src_ip","geo_src_ip.country","activity_type","result"],
  "orderBy": ["time DESC"], "startTime": "<t-30d>", "endTime": "<t>", "limit": 500}}

// Rare-process hunt (regex on process_name)
{"arg0": {"filter": "process_name = RGX(\".*(mimikatz|psexec|rundll32).*\")",
  "fields": ["time","user","host","process_name","parent_process","command"],
  "orderBy": ["time DESC"], "startTime": "<t-30d>", "endTime": "<t>", "limit": 200}}
```
> **Regex escaping:** the `RGX("…")` argument is a regex; when it rides inside the JSON `filter`
> string, every backslash must be JSON-escaped (`\.` → `\\.`). For Windows-path patterns
> (`\\host\share`, `.library-ms`) the backslashes stack up fast — build and test the pattern in the
> Search UI first, then escape it for the API call.

## Queue sweep & reporting (aggregation)

**Untriaged alerts** — this is an *alert* search, not events, but it's the queue-sweep entry point
(`exabeam_search_alerts`, same `SearchDetails` shape; real alert fields:
`alertId, alertName, caseId, caseNumber, creationTimestamp, mitres, priority, product, riskScore,
rules, tags, useCases, user, vendor`):

```jsonc
{"arg0": {"filter": "caseId:null",
  "fields": ["alertId","alertName","priority","riskScore","user","mitres","rules","creationTimestamp"],
  "orderBy": ["riskScore DESC"], "startTime": "<t-24h>", "endTime": "<t>", "limit": 500}}
```
`caseId:null` = alerts not yet pulled into a case. Order by `riskScore DESC`, cluster by `user`/`rules`,
and prioritize — remember (per SKILL Modes) a sweep *prioritizes*, it does not *conclude*.

**Field Summary / "what's in this data?"** — orient before you filter:
```jsonc
{"arg0": {"filter": "",
  "fields": ["product","COUNT(product) as product_count"],
  "groupBy": ["product"], "orderBy": ["COUNT(product) DESC"],
  "startTime": "<t-24h>", "endTime": "<t>", "limit": 100}}
```
Swap `product` for any field to discover its real values (and confirm a field name exists) instead of
guessing. This is the honest way to find a field you're unsure of.

**Reporting caution** (per SKILL Modes): aggregation *amplifies* data-quality artifacts. A count that
alarms mainly by its size is a noise hypothesis before it's a scale story — verify the underlying rows
before a number goes in a brief.

## Quality bar for a query

- **Tight window.** Start narrow (the alert window ± hours); widen only with a reason.
- **Named fields over `*`** once you know what you're after — skimmable evidence, cheaper calls.
- **Count before you conclude.** `totalRows` and `groupBy` counts turn "I saw some" into a number.
- **Cite it.** Every row that lands in the report names the query/tool that produced it (report-template).
