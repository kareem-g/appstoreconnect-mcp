# appstoreconnect-mcp

A standalone MCP server for the [App Store Connect API](https://developer.apple.com/documentation/appstoreconnectapi).
It speaks MCP Streamable HTTP, signs its own ES256 JWTs from your App Store
Connect API key, and covers apps, versions, builds, TestFlight, App Review
submissions, localizations, screenshots, pricing, users, and sales reports —
including submitting apps for review. No browser, no third-party CLI, no
account-specific values in the code: everything is configured by environment
variables.

## Safety rule

Reads are unrestricted. **Every write, submit, or publish tool requires an
explicit `"confirm": true` argument.** Without it the tool refuses and
describes exactly what it *would* do — it never calls Apple. Nothing in this
server auto-submits, auto-publishes, or auto-changes anything. Write tools
are marked `(WRITE - requires confirm:true)` in their descriptions.

## Setup

### 1. Create an App Store Connect API key

In App Store Connect, go to **Users and Access → Keys** (under
Integrations) and create a key. Give it the role your work needs (Admin for
writes; Finance, Sales, or Admin for sales reports). Download the `.p8`
private key file — Apple shows it only once. Note the **Issuer ID** and the
**Key ID** (the Key ID is also the part after `AuthKey_` in the `.p8`
filename).

### 2. Configure

```sh
cp .env.example .env
```

Edit `.env` with your own values:

```text
ASC_ISSUER_ID=xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
ASC_KEY_ID=XXXXXXXXXX
ASC_PRIVATE_KEY_PATH=/path/to/AuthKey_XXXXXXXXXX.p8
ASC_BIND=127.0.0.1:3001
# ASC_VENDOR_NUMBER=12345678   # only needed for sales reports
```

`.env` is gitignored. Never commit it, and never put a key, issuer ID, or
`.p8` file in this repo.

### 3. Run

Requires Python 3.9+ and PyJWT:

```sh
pip install 'PyJWT[crypto]'
export $(cat .env | xargs)   # or use your preferred env loader
python3 server.py
```

The server listens on `ASC_BIND` (default `127.0.0.1:3001`) and serves:

- `GET /healthz` — `{"status": "ok", "credentials_configured": true/false, ...}`
- `POST /mcp` — MCP Streamable HTTP (`initialize`, `ping`, `tools/list`, `tools/call`)

If credentials are missing, the server still starts; `/healthz` reports
`credentials_configured: false` and tool calls fail with a clear
"credentials not configured" error naming the missing variable.

### 4. Call it

`asc-call.py` is a stdlib-only client:

```sh
# Point it at the server (default http://127.0.0.1:3001/mcp)
export ASC_MCP_URL=http://127.0.0.1:3001/mcp

python3 asc-call.py health
python3 asc-call.py list-tools
python3 asc-call.py asc_list_apps '{}'
python3 asc-call.py asc_list_builds '{"app_id": "YOUR_APP_ID", "limit": 5}'
```

Exit codes: 0 success, 1 tool/API error, 2 usage/config error.

## Deploying as a systemd service (Linux server)

An example unit is in `systemd/appstoreconnect-mcp.service`. Adapt the
paths, put your credentials in `/opt/appstoreconnect/.env` (mode 600), and:

```sh
sudo cp systemd/appstoreconnect-mcp.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now appstoreconnect-mcp
curl http://127.0.0.1:3001/healthz
```

Bind to a private interface only (e.g. a Tailscale IP) if the server should
not be reachable from the public internet. There is no auth on the MCP
endpoint itself — treat it like any other internal service and keep it off
public interfaces.

## Tool list

IDs come from earlier reads: `asc_list_apps` gives app IDs,
`asc_list_builds` gives build IDs, `asc_list_app_store_versions` gives
version IDs.

### Reads

| Tool | What it does |
| --- | --- |
| `asc_list_apps` | List apps on the team (ID, name, bundle ID) |
| `asc_get_app` | Get one app |
| `asc_list_app_store_versions` | List an app's App Store versions |
| `asc_get_app_store_version` | Get one App Store version |
| `asc_list_builds` | List an app's builds, newest first |
| `asc_get_build` | Get one build (processing state, expiration) |
| `asc_list_beta_testers` | List beta testers |
| `asc_list_beta_groups` | List an app's TestFlight beta groups |
| `asc_get_beta_group` | Get one beta group |
| `asc_list_beta_app_review_submissions` | List beta app review submissions |
| `asc_get_beta_app_review_submission` | Get one (state: WAITING_FOR_REVIEW, IN_REVIEW, REJECTED, APPROVED) |
| `asc_get_beta_app_review_detail` | Get an app's beta review contact/demo details |
| `asc_list_beta_build_localizations` | List a build's What to Test notes |
| `asc_list_review_submissions` | List App Review submissions |
| `asc_get_review_submission` | Get one (state: READY_FOR_REVIEW … COMPLETE) |
| `asc_get_app_info` | Get an app's app info |
| `asc_list_app_info_localizations` | List an app info's localizations |
| `asc_list_app_store_version_localizations` | List a version's localizations |
| `asc_get_app_store_version_localization` | Get one version localization |
| `asc_list_app_screenshot_sets` | List a localization's screenshot sets |
| `asc_list_app_screenshots` | List a screenshot set's screenshots |
| `asc_list_app_price_points` | List App Store price points (optional territory filter) |
| `asc_list_app_prices` | List an app's prices |
| `asc_list_users` | List users on the team |
| `asc_get_user` | Get one user |
| `asc_sales_report` | Download a sales report (gzipped TSV, returned as text) |

### Writes — all require `"confirm": true`

| Tool | What it does |
| --- | --- |
| `asc_create_app_store_version` | Create a new editable App Store version |
| `asc_update_app_store_version` | Update version metadata and/or attach a build |
| `asc_create_review_submission` | Step 1 of App Review: create the submission container |
| `asc_add_review_submission_item` | Step 2: attach a version to the submission |
| `asc_submit_review_submission` | Step 3: **submit to App Review** (the step that sends it) |
| `asc_cancel_review_submission` | Cancel a review submission |
| `asc_create_beta_app_review_submission` | Submit a build for TestFlight beta review |
| `asc_create_beta_build_localization` | Set a build's What to Test notes |
| `asc_update_beta_app_review_detail` | Update beta review contact/demo details |
| `asc_create_beta_tester` | Create a beta tester (invitation email is sent) |
| `asc_add_beta_tester_to_group` | Add a tester to a beta group |

## Submitting an app for review (the modern flow)

Apple deprecated `POST /v1/appStoreVersionSubmissions`. The current flow is
three steps, and only step 3 sends anything to App Review:

```sh
# 1. Create the submission container
python3 asc-call.py asc_create_review_submission '{"app_id": "YOUR_APP_ID", "platform": "IOS", "confirm": true}'
# 2. Attach the version (use the submission ID from step 1)
python3 asc-call.py asc_add_review_submission_item '{"submission_id": "SUBMISSION_ID", "version_id": "VERSION_ID", "confirm": true}'
# 3. Submit it
python3 asc-call.py asc_submit_review_submission '{"submission_id": "SUBMISSION_ID", "confirm": true}'
```

Only one open (non-COMPLETE) review submission may exist per app + platform.
Check state any time with `asc_get_review_submission`.

For TestFlight, submit a build with `asc_create_beta_app_review_submission`
after it reaches processing state `VALID` — and set What to Test notes first
with `asc_create_beta_build_localization`.

## Sales reports

```sh
python3 asc-call.py asc_sales_report '{"vendor_number": "YOUR_VENDOR_NUMBER", "frequency": "DAILY", "report_date": "2026-11-21", "report_type": "SALES", "report_sub_type": "SUMMARY"}'
```

Omit `report_date` on `DAILY` to get the latest available day. The vendor
number is shown in App Store Connect under Payments and Financial Reports.
The key needs the Finance, Sales, or Admin role; otherwise Apple returns a
403, which the server passes through as a clean error.

## Scope notes

Covered: apps, App Store versions, builds, TestFlight (groups, testers, beta
review), review submissions, app info and version localizations, screenshot
sets, pricing, users, sales reports. Not covered (yet): in-app purchases and
subscriptions, customer reviews, and analytics report requests — contributions
welcome.

## License

MIT — see [LICENSE](LICENSE).
