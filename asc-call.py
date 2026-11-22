#!/usr/bin/env python3
"""Call the App Store Connect MCP server over Streamable HTTP (stdlib only).

Usage:
    asc-call.py health
    asc-call.py list-tools
    asc-call.py <tool> '<json-args>'

The server URL comes from ASC_MCP_URL (default http://127.0.0.1:3001/mcp).
When the server runs on another host, point ASC_MCP_URL at it, e.g.
ASC_MCP_URL=http://192.0.2.10:3001/mcp.

Exit codes: 0 success, 1 tool/API error, 2 usage/config error.
The tool result is printed as JSON (or as plain text when it is not JSON).
"""
import json
import os
import sys
import urllib.error
import urllib.request

MCP_URL = os.environ.get("ASC_MCP_URL", "http://127.0.0.1:3001/mcp")


def rpc(method, params=None):
    payload = {"jsonrpc": "2.0", "id": 1, "method": method}
    if params is not None:
        payload["params"] = params
    req = urllib.request.Request(
        MCP_URL, data=json.dumps(payload).encode(), method="POST",
        headers={"Content-Type": "application/json",
                 "Accept": "application/json, text/event-stream"})
    try:
        with urllib.request.urlopen(req, timeout=60) as r:
            return json.load(r)
    except urllib.error.HTTPError as e:
        print("HTTP %d: %s" % (e.code, e.read().decode(errors="replace")[:500]),
              file=sys.stderr)
        sys.exit(1)
    except OSError as e:
        print("cannot reach MCP server at %s: %s" % (MCP_URL, e), file=sys.stderr)
        sys.exit(2)


def health():
    base = MCP_URL.rsplit("/mcp", 1)[0]
    try:
        with urllib.request.urlopen(base + "/healthz", timeout=10) as r:
            print(json.dumps(json.load(r), indent=2))
    except OSError as e:
        print("cannot reach MCP server at %s/healthz: %s" % (base, e), file=sys.stderr)
        return 2
    return 0


def list_tools():
    resp = rpc("tools/list")
    if "error" in resp:
        print(json.dumps(resp["error"], indent=2), file=sys.stderr)
        return 1
    print(json.dumps(resp["result"]["tools"], indent=2))
    return 0


def call_tool(name, args_json):
    try:
        args = json.loads(args_json)
    except ValueError:
        print("second argument must be valid JSON", file=sys.stderr)
        return 2
    if not isinstance(args, dict):
        print("arguments must be a JSON object", file=sys.stderr)
        return 2
    resp = rpc("tools/call", {"name": name, "arguments": args})
    if "error" in resp:
        print(json.dumps(resp["error"], indent=2), file=sys.stderr)
        return 1
    result = resp["result"]
    for item in result.get("content", []):
        text = item.get("text", "")
        try:
            print(json.dumps(json.loads(text), indent=2))
        except ValueError:
            print(text)
    return 1 if result.get("isError") else 0


def main():
    a = sys.argv[1:]
    if not a:
        print(__doc__)
        return 2
    if a[0] == "health":
        return health()
    if a[0] == "list-tools":
        return list_tools()
    if len(a) == 2:
        return call_tool(a[0], a[1])
    print(__doc__)
    return 2


if __name__ == "__main__":
    sys.exit(main())
