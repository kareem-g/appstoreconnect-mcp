#!/usr/bin/env python3
"""App Store Connect MCP server.

A standalone MCP server (Streamable HTTP) that talks to the App Store
Connect API (https://api.appstoreconnect.apple.com) with a short-lived
ES256 JWT signed by your own App Store Connect API key.

Configuration is environment only. There are no secrets, account IDs,
team IDs, app IDs, or hostnames in this file:

    ASC_ISSUER_ID         Issuer ID of the API key (App Store Connect >
                          Users and Access > Keys)
    ASC_KEY_ID            Key ID of the API key (the part after "AuthKey_"
                          in the .p8 filename)
    ASC_PRIVATE_KEY_PATH  Path to the .p8 private key file
    ASC_BIND              Bind address, host:port (default 127.0.0.1:3001)
    ASC_VENDOR_NUMBER     Optional default vendor number for sales reports

Safety rule: every write/submit/publish tool requires an explicit
"confirm": true argument. Without it the tool refuses and describes
exactly what it would do. Reads never require confirmation, and this
server never submits, publishes, or changes anything on its own.

Endpoints:
    GET  /healthz   {"status": "ok", "credentials_configured": bool, ...}
                    (never returns any secret or credential value)
    POST /mcp       MCP Streamable HTTP (JSON-RPC 2.0):
                    initialize, ping, tools/list, tools/call

Dependencies: Python 3.9+ standard library + PyJWT (ES256).
"""

import gzip
import json
import os
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

try:
    import jwt
except ImportError:  # pragma: no cover - exercised by the error path
    jwt = None

VERSION = "0.1.0"
SERVER_NAME = "appstoreconnect-mcp"
APPLE_BASE = "https://api.appstoreconnect.apple.com"
MAX_REPORT_CHARS = 100000


def _env(name, default=""):
    return os.environ.get(name, default).strip()


class Config:
    """All configuration comes from the environment; nothing is hardcoded."""

    def __init__(self):
        self.issuer_id = _env("ASC_ISSUER_ID")
        self.key_id = _env("ASC_KEY_ID")
        self.private_key_path = _env("ASC_PRIVATE_KEY_PATH")
        self.vendor_number = _env("ASC_VENDOR_NUMBER")
        bind = _env("ASC_BIND", "127.0.0.1:3001")
        if ":" in bind:
            host, _, port = bind.rpartition(":")
            self.host = host or "127.0.0.1"
            try:
                self.port = int(port)
            except ValueError:
                self.port = 3001
        else:
            self.host, self.port = bind, 3001
        self._key = None
        self._key_error = None

    def _load_key(self):
        if self._key is not None:
            return self._key
        if self._key_error is not None:
            return None
        try:
            with open(self.private_key_path, "r") as f:
                self._key = f.read()
        except OSError as exc:
            self._key_error = str(exc)
            return None
        return self._key

    @property
    def configured(self):
        """True only when every credential piece is present and readable.

        Never returns, logs, or exposes any credential value.
        """
        if not (self.issuer_id and self.key_id and self.private_key_path):
            return False
        return self._load_key() is not None

    @property
    def missing(self):
        out = []
        if not self.issuer_id:
            out.append("ASC_ISSUER_ID")
        if not self.key_id:
            out.append("ASC_KEY_ID")
        if not self.private_key_path:
            out.append("ASC_PRIVATE_KEY_PATH")
        elif self._load_key() is None:
            out.append("ASC_PRIVATE_KEY_PATH (file unreadable)")
        return out


class AppleError(Exception):
    """An error talking to Apple (or a missing-credential error).

    `status` is the HTTP status from Apple, or 0 for a local error.
    The message never contains a token or any credential value.
    """

    def __init__(self, status, message):
        super().__init__(message)
        self.status = status
        self.message = message


def mint_token(cfg):
    """Mint a fresh ES256 JWT for one App Store Connect API request."""
    if jwt is None:
        raise AppleError(0, "PyJWT is not installed; install it with: pip install 'PyJWT[crypto]'")
    key = cfg._load_key()
    if not key:
        raise AppleError(0, "credentials not configured: private key file is missing or unreadable")
    now = int(time.time())
    headers = {"alg": "ES256", "kid": cfg.key_id, "typ": "JWT"}
    payload = {"iss": cfg.issuer_id, "iat": now, "exp": now + 20 * 60, "aud": "appstoreconnect-v1"}
    return jwt.encode(payload, key, algorithm="ES256", headers=headers)


def _apple_error_text(status, raw):
    try:
        data = json.loads(raw)
        errors = data.get("errors") or []
        parts = []
        for err in errors:
            title = err.get("title", "")
            detail = err.get("detail", "")
            code = err.get("code", "")
            piece = title
            if detail:
                piece += " - " + detail
            if code:
                piece += " (code: %s)" % code
            parts.append(piece)
        if parts:
            return "Apple API error %d: %s" % (status, "; ".join(parts))
    except (ValueError, UnicodeDecodeError, AttributeError):
        pass
    text = raw.decode("utf-8", "replace").strip()
    return "Apple API error %d: %s" % (status, text[:500] or "no detail")


def apple_request(cfg, method, path, query=None, body=None, accept="application/json"):
    """One authenticated request to the App Store Connect API.

    Returns (status, raw_bytes). Raises AppleError on any failure.
    The JWT is never logged or returned.
    """
    if not cfg.issuer_id or not cfg.key_id or not cfg.private_key_path:
        raise AppleError(
            0,
            "credentials not configured: set ASC_ISSUER_ID, ASC_KEY_ID and "
            "ASC_PRIVATE_KEY_PATH (missing: %s)" % ", ".join(cfg.missing),
        )
    token = mint_token(cfg)
    url = APPLE_BASE + path
    if query:
        url += "?" + urllib.parse.urlencode(query, doseq=True)
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(
        url,
        data=data,
        method=method,
        headers={
            "Authorization": "Bearer " + token,
            "Accept": accept,
            "Content-Type": "application/json",
        },
    )
    try:
        with urllib.request.urlopen(req, timeout=60) as resp:
            return resp.status, resp.read()
    except urllib.error.HTTPError as exc:
        raise AppleError(exc.code, _apple_error_text(exc.code, exc.read()))
    except urllib.error.URLError as exc:
        raise AppleError(0, "could not reach api.appstoreconnect.apple.com: %s" % exc.reason)


def _pretty(raw):
    try:
        return json.dumps(json.loads(raw), indent=2)
    except (ValueError, UnicodeDecodeError):
        return raw.decode("utf-8", "replace")


def _get(cfg, path, query=None):
    _status, raw = apple_request(cfg, "GET", path, query=query)
    return _pretty(raw)


def _send(cfg, method, path, body):
    _status, raw = apple_request(cfg, method, path, body=body)
    return _pretty(raw)


def _limit(args, default=20):
    try:
        return str(max(1, min(200, int(args.get("limit", default)))))
    except (TypeError, ValueError):
        return str(default)


def _filters(args, names):
    """Pass through Apple filter[...] query params the caller supplied."""
    out = {}
    for name in names:
        value = args.get(name)
        if value:
            out["filter[%s]" % name] = str(value)
    return out

# ---------------------------------------------------------------------------
# Tool handlers. Each takes (cfg, args) and returns a text result.
# IDs are always caller-supplied arguments; nothing is hardcoded here.
# ---------------------------------------------------------------------------

# --- Reads: apps, versions, builds -----------------------------------------

def list_apps(cfg, args):
    query = {"limit": _limit(args)}
    query.update(_filters(args, ["bundleId"]))
    return _get(cfg, "/v1/apps", query)


def get_app(cfg, args):
    return _get(cfg, "/v1/apps/%s" % args["app_id"])


def list_app_store_versions(cfg, args):
    query = {"limit": _limit(args)}
    query.update(_filters(args, ["platform", "appStoreState"]))
    if args.get("sort"):
        query["sort"] = str(args["sort"])
    return _get(cfg, "/v1/apps/%s/appStoreVersions" % args["app_id"], query)


def get_app_store_version(cfg, args):
    return _get(cfg, "/v1/appStoreVersions/%s" % args["version_id"])


def list_builds(cfg, args):
    query = {"limit": _limit(args)}
    query.update(_filters(args, ["processingState", "version", "preReleaseVersion"]))
    query["sort"] = str(args.get("sort", "-uploadedDate"))
    return _get(cfg, "/v1/apps/%s/builds" % args["app_id"], query)


def get_build(cfg, args):
    return _get(cfg, "/v1/builds/%s" % args["build_id"])


# --- Reads: TestFlight ------------------------------------------------------

def list_beta_testers(cfg, args):
    query = {"limit": _limit(args)}
    query.update(_filters(args, ["email", "firstName", "lastName", "inviteType"]))
    return _get(cfg, "/v1/betaTesters", query)


def list_beta_groups(cfg, args):
    return _get(cfg, "/v1/apps/%s/betaGroups" % args["app_id"], {"limit": _limit(args)})


def get_beta_group(cfg, args):
    return _get(cfg, "/v1/betaGroups/%s" % args["group_id"])


def list_beta_app_review_submissions(cfg, args):
    query = {"limit": _limit(args)}
    query.update(_filters(args, ["build"]))
    return _get(cfg, "/v1/betaAppReviewSubmissions", query)


def get_beta_app_review_submission(cfg, args):
    return _get(cfg, "/v1/betaAppReviewSubmissions/%s" % args["submission_id"])


def get_beta_app_review_detail(cfg, args):
    return _get(cfg, "/v1/apps/%s/betaAppReviewDetail" % args["app_id"])


def list_beta_build_localizations(cfg, args):
    return _get(cfg, "/v1/builds/%s/betaBuildLocalizations" % args["build_id"],
                {"limit": _limit(args)})


# --- Reads: review submissions ----------------------------------------------

def list_review_submissions(cfg, args):
    query = {"limit": _limit(args)}
    query.update(_filters(args, ["app", "platform"]))
    return _get(cfg, "/v1/reviewSubmissions", query)


def get_review_submission(cfg, args):
    return _get(cfg, "/v1/reviewSubmissions/%s" % args["submission_id"])


# --- Reads: app info, localizations, screenshots ----------------------------

def get_app_info(cfg, args):
    return _get(cfg, "/v1/apps/%s/appInfo" % args["app_id"])


def list_app_info_localizations(cfg, args):
    return _get(cfg, "/v1/appInfos/%s/appInfoLocalizations" % args["app_info_id"],
                {"limit": _limit(args)})


def list_app_store_version_localizations(cfg, args):
    return _get(cfg, "/v1/appStoreVersions/%s/appStoreVersionLocalizations" % args["version_id"],
                {"limit": _limit(args)})


def get_app_store_version_localization(cfg, args):
    return _get(cfg, "/v1/appStoreVersionLocalizations/%s" % args["localization_id"])


def list_app_screenshot_sets(cfg, args):
    return _get(cfg, "/v1/appStoreVersionLocalizations/%s/appScreenshotSets" % args["localization_id"],
                {"limit": _limit(args)})


def list_app_screenshots(cfg, args):
    return _get(cfg, "/v1/appScreenshotSets/%s/appScreenshots" % args["screenshot_set_id"],
                {"limit": _limit(args)})


# --- Reads: pricing, users, sales reports -----------------------------------

def list_app_price_points(cfg, args):
    query = {"limit": _limit(args)}
    query.update(_filters(args, ["territory"]))
    return _get(cfg, "/v1/appPricePoints", query)


def list_app_prices(cfg, args):
    return _get(cfg, "/v1/apps/%s/appPrices" % args["app_id"], {"limit": _limit(args)})


def list_users(cfg, args):
    return _get(cfg, "/v1/users", {"limit": _limit(args)})


def get_user(cfg, args):
    return _get(cfg, "/v1/users/%s" % args["user_id"])


def sales_report(cfg, args):
    """Download a sales report. Apple returns a gzipped TSV file.

    Needs a vendor number (argument, or ASC_VENDOR_NUMBER) and a key with
    the Finance, Sales, or Admin role; Apple returns a clean 403 otherwise.
    """
    vendor = args.get("vendor_number") or cfg.vendor_number
    if not vendor:
        raise AppleError(0, "sales report needs a vendor number: pass vendor_number "
                            "or set ASC_VENDOR_NUMBER (find it in App Store Connect > "
                            "Payments and Financial Reports)")
    query = {
        "filter[frequency]": str(args.get("frequency", "DAILY")),
        "filter[reportType]": str(args.get("report_type", "SALES")),
        "filter[reportSubType]": str(args.get("report_sub_type", "SUMMARY")),
        "filter[vendorNumber]": str(vendor),
        "filter[version]": str(args.get("version", "1_0")),
    }
    if args.get("report_date"):
        query["filter[reportDate]"] = str(args["report_date"])
    _status, raw = apple_request(cfg, "GET", "/v1/salesReports", query=query,
                                 accept="application/a-gzip")
    data = gzip.decompress(raw) if raw[:2] == b"\x1f\x8b" else raw
    text = data.decode("utf-8", "replace")
    if len(text) > MAX_REPORT_CHARS:
        text = text[:MAX_REPORT_CHARS] + "\n... [truncated, %d chars total]" % len(text)
    return text


# --- Writes: versions --------------------------------------------------------
# Every write handler has a matching plan_* that describes the exact call
# it would make, so the confirm gate can refuse safely without calling Apple.

def create_app_store_version(cfg, args):
    body = {"data": {"type": "appStoreVersions",
                     "attributes": {"platform": args.get("platform", "IOS"),
                                    "versionString": args["version_string"]},
                     "relationships": {"app": {"data": {"type": "apps", "id": args["app_id"]}}}}}
    if args.get("copyright"):
        body["data"]["attributes"]["copyright"] = args["copyright"]
    return _send(cfg, "POST", "/v1/appStoreVersions", body)


def plan_create_app_store_version(args):
    return ("POST /v1/appStoreVersions: create version %s (%s) for app %s. "
            "This creates a new editable App Store version; it does not "
            "submit anything for review."
            % (args.get("version_string"), args.get("platform", "IOS"), args.get("app_id")))


def update_app_store_version(cfg, args):
    attributes = {}
    for key in ("versionString", "copyright", "releaseType", "earliestReleaseDate",
                "downloadable"):
        if key in args:
            attributes[key] = args[key]
    if args.get("version_string") and "versionString" not in attributes:
        attributes["versionString"] = args["version_string"]
    data = {"type": "appStoreVersions", "id": args["version_id"]}
    if attributes:
        data["attributes"] = attributes
    if args.get("build_id"):
        data["relationships"] = {"build": {"data": {"type": "builds", "id": args["build_id"]}}}
    if not attributes and not args.get("build_id"):
        raise AppleError(0, "nothing to update: pass at least one of version_string, "
                            "copyright, releaseType, earliestReleaseDate, downloadable, "
                            "or build_id")
    return _send(cfg, "PATCH", "/v1/appStoreVersions/%s" % args["version_id"], {"data": data})


def plan_update_app_store_version(args):
    changes = []
    for key in ("version_string", "copyright", "releaseType", "earliestReleaseDate",
                "downloadable"):
        if key in args:
            changes.append("%s=%s" % (key, args[key]))
    if args.get("build_id"):
        changes.append("build=%s" % args["build_id"])
    return ("PATCH /v1/appStoreVersions/%s: update version %s (%s). "
            "Setting a build only attaches it to the version; it does not "
            "submit anything for review."
            % (args.get("version_id"), args.get("version_id"), ", ".join(changes) or "no changes"))


# --- Writes: review submissions ----------------------------------------------
# The modern flow (the old /v1/appStoreVersionSubmissions is deprecated):
#   1. asc_create_review_submission   -> POST /v1/reviewSubmissions
#   2. asc_add_review_submission_item -> POST /v1/reviewSubmissionItems
#   3. asc_submit_review_submission   -> PATCH submitted=true
# Only step 3 sends anything to App Review. Only one open (non-COMPLETE)
# review submission may exist per app + platform.

def create_review_submission(cfg, args):
    body = {"data": {"type": "reviewSubmissions",
                     "attributes": {"platform": args.get("platform", "IOS")},
                     "relationships": {"app": {"data": {"type": "apps", "id": args["app_id"]}}}}}
    return _send(cfg, "POST", "/v1/reviewSubmissions", body)


def plan_create_review_submission(args):
    return ("POST /v1/reviewSubmissions: create a review-submission container "
            "for app %s (%s). This only creates the container; nothing is "
            "sent to App Review until asc_submit_review_submission runs."
            % (args.get("app_id"), args.get("platform", "IOS")))


def add_review_submission_item(cfg, args):
    body = {"data": {"type": "reviewSubmissionItems",
                     "relationships": {
                         "reviewSubmission": {"data": {"type": "reviewSubmissions",
                                                       "id": args["submission_id"]}},
                         "appStoreVersion": {"data": {"type": "appStoreVersions",
                                                      "id": args["version_id"]}}}}}
    return _send(cfg, "POST", "/v1/reviewSubmissionItems", body)


def plan_add_review_submission_item(args):
    return ("POST /v1/reviewSubmissionItems: attach App Store version %s to "
            "review submission %s. This only attaches the version; nothing "
            "is sent to App Review yet."
            % (args.get("version_id"), args.get("submission_id")))


def submit_review_submission(cfg, args):
    body = {"data": {"type": "reviewSubmissions", "id": args["submission_id"],
                     "attributes": {"submitted": True}}}
    return _send(cfg, "PATCH", "/v1/reviewSubmissions/%s" % args["submission_id"], body)


def plan_submit_review_submission(args):
    return ("PATCH /v1/reviewSubmissions/%s (submitted=true): SUBMIT the review "
            "submission to App Review. Apple will start reviewing the attached "
            "version(s). This is the step that actually sends the app for review."
            % args.get("submission_id"))


def cancel_review_submission(cfg, args):
    body = {"data": {"type": "reviewSubmissions", "id": args["submission_id"],
                     "attributes": {"canceled": True}}}
    return _send(cfg, "PATCH", "/v1/reviewSubmissions/%s" % args["submission_id"], body)


def plan_cancel_review_submission(args):
    return ("PATCH /v1/reviewSubmissions/%s (canceled=true): CANCEL the review "
            "submission before review finishes."
            % args.get("submission_id"))


# --- Writes: TestFlight -------------------------------------------------------

def create_beta_app_review_submission(cfg, args):
    body = {"data": {"type": "betaAppReviewSubmissions",
                     "relationships": {"build": {"data": {"type": "builds",
                                                          "id": args["build_id"]}}}}}
    return _send(cfg, "POST", "/v1/betaAppReviewSubmissions", body)


def plan_create_beta_app_review_submission(args):
    return ("POST /v1/betaAppReviewSubmissions: submit build %s for TestFlight "
            "beta review. External testers cannot install the build until "
            "Apple approves it." % args.get("build_id"))


def create_beta_build_localization(cfg, args):
    body = {"data": {"type": "betaBuildLocalizations",
                     "attributes": {"locale": args["locale"], "whatsNew": args["whats_new"]},
                     "relationships": {"build": {"data": {"type": "builds",
                                                          "id": args["build_id"]}}}}}
    return _send(cfg, "POST", "/v1/betaBuildLocalizations", body)


def plan_create_beta_build_localization(args):
    return ("POST /v1/betaBuildLocalizations: set TestFlight 'What to Test' "
            "notes (%s) for build %s. Testers see these notes when the build "
            "is available." % (args.get("locale"), args.get("build_id")))


def update_beta_app_review_detail(cfg, args):
    attributes = {}
    for key in ("contactFirstName", "contactLastName", "contactEmail", "contactPhone",
                "demoAccountName", "demoAccountPassword", "demoAccountRequired", "notes"):
        if key in args:
            attributes[key] = args[key]
    if not attributes:
        raise AppleError(0, "nothing to update: pass at least one contact/demo field")
    body = {"data": {"type": "betaAppReviewDetails", "id": args["detail_id"],
                     "attributes": attributes}}
    return _send(cfg, "PATCH", "/v1/betaAppReviewDetails/%s" % args["detail_id"], body)


def plan_update_beta_app_review_detail(args):
    return ("PATCH /v1/betaAppReviewDetails/%s: update the beta review contact "
            "and demo-account details Apple uses during TestFlight beta review."
            % args.get("detail_id"))


def create_beta_tester(cfg, args):
    data = {"type": "betaTesters",
            "attributes": {"firstName": args["first_name"],
                           "lastName": args["last_name"],
                           "email": args["email"]}}
    group_ids = args.get("beta_group_ids") or []
    if group_ids:
        data["relationships"] = {"betaGroups": {"data": [{"type": "betaGroups", "id": gid}
                                                         for gid in group_ids]}}
    return _send(cfg, "POST", "/v1/betaTesters", {"data": data})


def plan_create_beta_tester(args):
    groups = ", ".join(args.get("beta_group_ids") or []) or "no group"
    return ("POST /v1/betaTesters: create beta tester %s %s <%s> and add them "
            "to %s. Apple sends the tester a TestFlight invitation email."
            % (args.get("first_name"), args.get("last_name"), args.get("email"), groups))


def add_beta_tester_to_group(cfg, args):
    body = {"data": [{"type": "betaTesters", "id": args["tester_id"]}]}
    return _send(cfg, "POST", "/v1/betaGroups/%s/relationships/betaTesters" % args["group_id"], body)


def plan_add_beta_tester_to_group(args):
    return ("POST /v1/betaGroups/%s/relationships/betaTesters: add beta tester "
            "%s to the group. The tester gains access to the group's builds."
            % (args.get("group_id"), args.get("tester_id")))

# ---------------------------------------------------------------------------
# Tool registry. Reads are unrestricted; every write is marked and gated.
# ---------------------------------------------------------------------------

WRITE_NOTE = " (WRITE - requires confirm:true)"


def _schema(properties, required):
    return {"type": "object", "properties": properties, "required": required,
            "additionalProperties": False}


def _str(desc):
    return {"type": "string", "description": desc}


def _id(desc):
    return {"type": "string", "description": desc + " (Apple resource ID)"}


_OPT_LIMIT = {"limit": {"type": "integer", "description": "Max results (1-200, default 20)"}}


def _tool(name, description, schema, handler, write=False, plan=None):
    return {"name": name, "description": description, "inputSchema": schema,
            "handler": handler, "write": write, "plan": plan}


TOOLS = [
    # Reads: apps, versions, builds
    _tool("asc_list_apps", "List apps on the team. Returns each app's ID, name and bundle ID - use the ID for every other tool.",
          _schema({**_OPT_LIMIT, "bundleId": _str("Filter by bundle ID, e.g. com.example.app")}, []), list_apps),
    _tool("asc_get_app", "Get one app by ID.",
          _schema({"app_id": _id("App ID from asc_list_apps")}, ["app_id"]), get_app),
    _tool("asc_list_app_store_versions", "List an app's App Store versions (state, platform, build).",
          _schema({"app_id": _id("App ID"), **_OPT_LIMIT,
                   "platform": _str("Filter: IOS, MAC_OS, TV_OS, VISION_OS"),
                   "appStoreState": _str("Filter, e.g. READY_FOR_REVIEW, READY_FOR_DISTRIBUTION"),
                   "sort": _str("Sort, e.g. -versionString")}, ["app_id"]), list_app_store_versions),
    _tool("asc_get_app_store_version", "Get one App Store version by ID.",
          _schema({"version_id": _id("App Store version ID")}, ["version_id"]), get_app_store_version),
    _tool("asc_list_builds", "List an app's builds, newest first.",
          _schema({"app_id": _id("App ID"), **_OPT_LIMIT,
                   "processingState": _str("Filter: PROCESSING, FAILED, INVALID, VALID"),
                   "version": _str("Filter by build version, e.g. 1.0.2"),
                   "preReleaseVersion": _str("Filter by pre-release version"),
                   "sort": _str("Sort (default -uploadedDate)")}, ["app_id"]), list_builds),
    _tool("asc_get_build", "Get one build by ID (processing state, version, expiration).",
          _schema({"build_id": _id("Build ID")}, ["build_id"]), get_build),
    # Reads: TestFlight
    _tool("asc_list_beta_testers", "List beta testers on the team.",
          _schema({**_OPT_LIMIT, "email": _str("Filter by tester email"),
                   "firstName": _str("Filter by first name"), "lastName": _str("Filter by last name"),
                   "inviteType": _str("Filter: EMAIL, PUBLIC_LINK")}, []), list_beta_testers),
    _tool("asc_list_beta_groups", "List an app's TestFlight beta groups.",
          _schema({"app_id": _id("App ID"), **_OPT_LIMIT}, ["app_id"]), list_beta_groups),
    _tool("asc_get_beta_group", "Get one beta group by ID.",
          _schema({"group_id": _id("Beta group ID")}, ["group_id"]), get_beta_group),
    _tool("asc_list_beta_app_review_submissions", "List beta app review submissions, optionally for one build.",
          _schema({**_OPT_LIMIT, "build": _str("Filter by build ID")}, []), list_beta_app_review_submissions),
    _tool("asc_get_beta_app_review_submission", "Get one beta app review submission by ID (betaReviewState: WAITING_FOR_REVIEW, IN_REVIEW, REJECTED, APPROVED).",
          _schema({"submission_id": _id("Beta app review submission ID")}, ["submission_id"]), get_beta_app_review_submission),
    _tool("asc_get_beta_app_review_detail", "Get an app's beta app review detail (contact + demo account Apple uses for TestFlight review).",
          _schema({"app_id": _id("App ID")}, ["app_id"]), get_beta_app_review_detail),
    _tool("asc_list_beta_build_localizations", "List a build's TestFlight localizations (What to Test notes per locale).",
          _schema({"build_id": _id("Build ID"), **_OPT_LIMIT}, ["build_id"]), list_beta_build_localizations),
    # Reads: review submissions
    _tool("asc_list_review_submissions", "List App Review submissions, optionally for one app.",
          _schema({**_OPT_LIMIT, "app": _str("Filter by app ID"), "platform": _str("Filter: IOS, MAC_OS, TV_OS, VISION_OS")}, []), list_review_submissions),
    _tool("asc_get_review_submission", "Get one review submission by ID (state: READY_FOR_REVIEW, WAITING_FOR_REVIEW, IN_REVIEW, UNRESOLVED_ISSUES, CANCELING, COMPLETING, COMPLETE).",
          _schema({"submission_id": _id("Review submission ID")}, ["submission_id"]), get_review_submission),
    # Reads: app info, localizations, screenshots
    _tool("asc_get_app_info", "Get an app's app info (categories, etc.).",
          _schema({"app_id": _id("App ID")}, ["app_id"]), get_app_info),
    _tool("asc_list_app_info_localizations", "List an app info's localizations.",
          _schema({"app_info_id": _id("App info ID from asc_get_app_info"), **_OPT_LIMIT}, ["app_info_id"]), list_app_info_localizations),
    _tool("asc_list_app_store_version_localizations", "List an App Store version's localizations (description, keywords, subtitle per locale).",
          _schema({"version_id": _id("App Store version ID"), **_OPT_LIMIT}, ["version_id"]), list_app_store_version_localizations),
    _tool("asc_get_app_store_version_localization", "Get one App Store version localization by ID.",
          _schema({"localization_id": _id("Version localization ID")}, ["localization_id"]), get_app_store_version_localization),
    _tool("asc_list_app_screenshot_sets", "List a version localization's screenshot sets (display types).",
          _schema({"localization_id": _id("Version localization ID"), **_OPT_LIMIT}, ["localization_id"]), list_app_screenshot_sets),
    _tool("asc_list_app_screenshots", "List a screenshot set's screenshots.",
          _schema({"screenshot_set_id": _id("Screenshot set ID"), **_OPT_LIMIT}, ["screenshot_set_id"]), list_app_screenshots),
    # Reads: pricing, users, sales reports
    _tool("asc_list_app_price_points", "List App Store price points, optionally for one territory (e.g. USA).",
          _schema({**_OPT_LIMIT, "territory": _str("Filter by territory code, e.g. USA")}, []), list_app_price_points),
    _tool("asc_list_app_prices", "List an app's prices.",
          _schema({"app_id": _id("App ID"), **_OPT_LIMIT}, ["app_id"]), list_app_prices),
    _tool("asc_list_users", "List users on the team.",
          _schema(_OPT_LIMIT, []), list_users),
    _tool("asc_get_user", "Get one user by ID.",
          _schema({"user_id": _id("User ID")}, ["user_id"]), get_user),
    _tool("asc_sales_report", "Download a sales report (gzipped TSV from Apple, returned as text). Needs a vendor number and a key with the Finance, Sales, or Admin role; Apple returns a clean 403 otherwise.",
          _schema({"vendor_number": _str("Vendor number (or set ASC_VENDOR_NUMBER). Find it in App Store Connect > Payments and Financial Reports"),
                   "frequency": _str("DAILY, WEEKLY, MONTHLY, YEARLY (default DAILY)"),
                   "report_date": _str("Date, e.g. 2026-11-21 (omit for the latest day on DAILY)"),
                   "report_type": _str("SALES, INSTALLS, SUBSCRIPTION_EVENT, PRE_ORDER (default SALES)"),
                   "report_sub_type": _str("SUMMARY or DETAILED (default SUMMARY)"),
                   "version": _str("Report version (default 1_0)")}, []), sales_report),
    # Writes: versions
    _tool("asc_create_app_store_version",
          "Create a new editable App Store version for an app.",
          _schema({"app_id": _id("App ID"), "version_string": _str("Version string, e.g. 1.0.3"),
                   "platform": _str("Platform (default IOS)"), "copyright": _str("Copyright text (optional)"),
                   "confirm": {"type": "boolean", "description": "Must be true to run this write"}}, ["app_id", "version_string"]),
          create_app_store_version, write=True, plan=plan_create_app_store_version),
    _tool("asc_update_app_store_version",
          "Update an App Store version (metadata and/or attach a build).",
          _schema({"version_id": _id("App Store version ID"),
                   "version_string": _str("New version string (optional)"),
                   "copyright": _str("Copyright text (optional)"),
                   "releaseType": _str("MANUAL, AFTER_APPROVAL, SCHEDULED (optional)"),
                   "earliestReleaseDate": _str("ISO date, e.g. 2026-12-01 (optional)"),
                   "downloadable": {"type": "boolean", "description": "Whether the version is downloadable (optional)"},
                   "build_id": _str("Build ID to attach to the version (optional)"),
                   "confirm": {"type": "boolean", "description": "Must be true to run this write"}}, ["version_id"]),
          update_app_store_version, write=True, plan=plan_update_app_store_version),
    # Writes: review submissions (the modern 3-step flow)
    _tool("asc_create_review_submission",
          "Step 1 of App Review: create a review-submission container for an app. Sends nothing to review by itself.",
          _schema({"app_id": _id("App ID"), "platform": _str("Platform (default IOS)"),
                   "confirm": {"type": "boolean", "description": "Must be true to run this write"}}, ["app_id"]),
          create_review_submission, write=True, plan=plan_create_review_submission),
    _tool("asc_add_review_submission_item",
          "Step 2 of App Review: attach an App Store version to a review submission. Sends nothing to review by itself.",
          _schema({"submission_id": _id("Review submission ID"), "version_id": _id("App Store version ID"),
                   "confirm": {"type": "boolean", "description": "Must be true to run this write"}}, ["submission_id", "version_id"]),
          add_review_submission_item, write=True, plan=plan_add_review_submission_item),
    _tool("asc_submit_review_submission",
          "Step 3 of App Review: SUBMIT a review submission to App Review. This is the step that actually sends the app for review.",
          _schema({"submission_id": _id("Review submission ID"),
                   "confirm": {"type": "boolean", "description": "Must be true to run this write"}}, ["submission_id"]),
          submit_review_submission, write=True, plan=plan_submit_review_submission),
    _tool("asc_cancel_review_submission",
          "Cancel a review submission before review finishes.",
          _schema({"submission_id": _id("Review submission ID"),
                   "confirm": {"type": "boolean", "description": "Must be true to run this write"}}, ["submission_id"]),
          cancel_review_submission, write=True, plan=plan_cancel_review_submission),
    # Writes: TestFlight
    _tool("asc_create_beta_app_review_submission",
          "Submit a build for TestFlight beta review. External testers cannot install it until Apple approves.",
          _schema({"build_id": _id("Build ID"),
                   "confirm": {"type": "boolean", "description": "Must be true to run this write"}}, ["build_id"]),
          create_beta_app_review_submission, write=True, plan=plan_create_beta_app_review_submission),
    _tool("asc_create_beta_build_localization",
          "Set a build's TestFlight 'What to Test' notes for one locale.",
          _schema({"build_id": _id("Build ID"), "locale": _str("Locale, e.g. en-US"), "whats_new": _str("What to Test notes"),
                   "confirm": {"type": "boolean", "description": "Must be true to run this write"}}, ["build_id", "locale", "whats_new"]),
          create_beta_build_localization, write=True, plan=plan_create_beta_build_localization),
    _tool("asc_update_beta_app_review_detail",
          "Update the beta review contact and demo-account details Apple uses during TestFlight beta review.",
          _schema({"detail_id": _id("Beta app review detail ID from asc_get_beta_app_review_detail"),
                   "contactFirstName": _str("Contact first name (optional)"), "contactLastName": _str("Contact last name (optional)"),
                   "contactEmail": _str("Contact email (optional)"), "contactPhone": _str("Contact phone (optional)"),
                   "demoAccountName": _str("Demo account name (optional)"), "demoAccountPassword": _str("Demo account password (optional)"),
                   "demoAccountRequired": {"type": "boolean", "description": "Whether a demo account is required (optional)"},
                   "notes": _str("Notes for the reviewer (optional)"),
                   "confirm": {"type": "boolean", "description": "Must be true to run this write"}}, ["detail_id"]),
          update_beta_app_review_detail, write=True, plan=plan_update_beta_app_review_detail),
    _tool("asc_create_beta_tester",
          "Create a beta tester and optionally add them to beta groups. Apple sends the tester a TestFlight invitation email.",
          _schema({"first_name": _str("Tester first name"), "last_name": _str("Tester last name"),
                   "email": _str("Tester email"),
                   "beta_group_ids": {"type": "array", "items": {"type": "string"}, "description": "Beta group IDs to add the tester to (optional)"},
                   "confirm": {"type": "boolean", "description": "Must be true to run this write"}}, ["first_name", "last_name", "email"]),
          create_beta_tester, write=True, plan=plan_create_beta_tester),
    _tool("asc_add_beta_tester_to_group",
          "Add an existing beta tester to a beta group.",
          _schema({"group_id": _id("Beta group ID"), "tester_id": _id("Beta tester ID"),
                   "confirm": {"type": "boolean", "description": "Must be true to run this write"}}, ["group_id", "tester_id"]),
          add_beta_tester_to_group, write=True, plan=plan_add_beta_tester_to_group),
]

TOOL_MAP = {t["name"]: t for t in TOOLS}


def public_tools():
    """Tool list as MCP clients see it (handler/plan stripped out).

    Write tools carry the "(WRITE - requires confirm:true)" marker in
    their description, so a client can tell at a glance what is gated.
    """
    out = []
    for t in TOOLS:
        desc = t["description"]
        if t["write"]:
            desc += WRITE_NOTE
        out.append({"name": t["name"], "description": desc,
                    "inputSchema": t["inputSchema"]})
    return out


# ---------------------------------------------------------------------------
# MCP over Streamable HTTP (JSON-RPC 2.0)
# ---------------------------------------------------------------------------

CFG = Config()


def call_tool(name, args):
    """Run one tool. Returns (text, is_error). Never raises."""
    tool = TOOL_MAP.get(name)
    if tool is None:
        return "unknown tool: %s (run tools/list for the full list)" % name, True
    if not isinstance(args, dict):
        return "tool arguments must be a JSON object", True
    missing = [r for r in tool["inputSchema"].get("required", []) if r not in args]
    if missing:
        return "missing required argument(s): %s" % ", ".join(missing), True
    if tool["write"] and args.get("confirm") is not True:
        plan = tool["plan"](args) if tool["plan"] else tool["description"]
        return ("REFUSED - this is a write and confirm was not given.\n"
                "It would do: %s\n"
                "To proceed, call again with \"confirm\": true." % plan), True
    try:
        return tool["handler"](CFG, args), False
    except AppleError as exc:
        return exc.message, True
    except Exception as exc:  # never leak a stack trace or paths
        return "internal error: %s" % type(exc).__name__, True


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, fmt, *args):
        # Minimal access log: method and path only. No bodies, no tokens.
        sys.stderr.write("%s - %s\n" % (self.address_string(), fmt % args))

    def _send(self, status, body, content_type="application/json"):
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def _rpc_result(self, req_id, result):
        self._send(200, json.dumps({"jsonrpc": "2.0", "id": req_id, "result": result}).encode())

    def _rpc_error(self, req_id, code, message):
        self._send(200, json.dumps({"jsonrpc": "2.0", "id": req_id,
                                    "error": {"code": code, "message": message}}).encode())

    def do_GET(self):
        if self.path == "/healthz":
            body = json.dumps({"status": "ok", "credentials_configured": CFG.configured,
                               "tools": len(TOOLS), "version": VERSION}).encode()
            self._send(200, body)
        else:
            self._send(404, b'{"error":"not found"}')

    def do_POST(self):
        if self.path != "/mcp":
            self._send(404, b'{"error":"not found"}')
            return
        try:
            length = int(self.headers.get("Content-Length") or 0)
        except ValueError:
            length = 0
        raw = self.rfile.read(length) if length else b""
        try:
            req = json.loads(raw)
        except ValueError:
            self._rpc_error(None, -32700, "parse error")
            return
        if not isinstance(req, dict):
            self._rpc_error(None, -32600, "invalid request: expected a JSON object")
            return
        if "id" not in req:
            # Notification (e.g. notifications/initialized): no response.
            self._send(202, b"")
            return
        req_id = req.get("id")
        method = req.get("method", "")
        params = req.get("params") or {}
        if method == "initialize":
            self._rpc_result(req_id, {
                "protocolVersion": params.get("protocolVersion", "2025-03-26"),
                "capabilities": {"tools": {}},
                "serverInfo": {"name": SERVER_NAME, "version": VERSION},
            })
        elif method == "ping":
            self._rpc_result(req_id, {})
        elif method == "tools/list":
            self._rpc_result(req_id, {"tools": public_tools()})
        elif method == "tools/call":
            name = params.get("name", "")
            args = params.get("arguments") or {}
            text, is_error = call_tool(name, args)
            self._rpc_result(req_id, {"content": [{"type": "text", "text": text}],
                                      "isError": is_error})
        else:
            self._rpc_error(req_id, -32601, "method not found: %s" % method)


def main():
    if not CFG.configured:
        sys.stderr.write("appstoreconnect-mcp: starting WITHOUT credentials "
                         "(missing: %s). /healthz will report "
                         "credentials_configured=false and tool calls will fail "
                         "cleanly until ASC_ISSUER_ID, ASC_KEY_ID and "
                         "ASC_PRIVATE_KEY_PATH are set.\n" % ", ".join(CFG.missing))
    server = ThreadingHTTPServer((CFG.host, CFG.port), Handler)
    sys.stderr.write("appstoreconnect-mcp %s listening on %s:%d (%d tools)\n"
                     % (VERSION, CFG.host, CFG.port, len(TOOLS)))
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
