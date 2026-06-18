#!/usr/bin/env python3
"""
hw_ecs_discover.py
──────────────────
SDK-based ECS discovery for Alpha Edge (private Huawei Cloud deployment).

WHY THIS EXISTS
  hcloud (KooCLI) resolves endpoints from its own internal metadata catalogue,
  which only knows public Huawei Cloud regions (*.myhuaweicloud.com). It has no
  awareness of private endpoints like ecs.my-kualalumpur-1.alphaedge.tmone.com.my,
  so `hcloud ECS ListServersDetails` silently queried the wrong region and
  returned an empty list. This script uses the official Python SDK instead,
  which signs each request locally with AK/SK (HMAC-SHA256) and is pointed
  explicitly at the private endpoint. Confirmed working end-to-end from both
  a local Windows machine and GitHub Actions hosted runners.

USAGE
  Required env vars:
    HUAWEICLOUD_ACCESS_KEY   IAM Access Key (AK)
    HUAWEICLOUD_SECRET_KEY   IAM Secret Key (SK)
    HW_PROJECT_ID            IAM Project ID (Console → My Credentials → Projects)
    HW_ECS_ENDPOINT          Full private ECS endpoint URL
                             e.g. https://ecs.my-kualalumpur-1.alphaedge.tmone.com.my

  Optional env vars:
    HW_ECS_TAG_KEY           Tag key to filter instances (e.g. "Environment")
    HW_ECS_TAG_VAL           Tag value to match (e.g. "Prod")
                             Both must be set for tag filtering to apply.

OUTPUT
  JSON to stdout — same shape as the Huawei Cloud ECS API response:
    { "servers": [ { "id", "name", "status", "metadata", "addresses",
                     "image", "tags", ... }, ... ] }

  Empty stdout + error on stderr on any failure.
  Exit code 0 on success, non-zero on failure.

  The bash discovery block in multi_os_benchmark.sh reads stdout and
  checks `if [ -z "$HW_RAW" ]` to detect failures — so stdout must be
  either valid JSON or completely empty (never partial).

DEPENDENCIES
  pip install huaweicloudsdkcore huaweicloudsdkecs
"""

import json
import os
import sys


def main():
    # ── Validate required env vars ────────────────────────────────────────
    required = {
        "HUAWEICLOUD_ACCESS_KEY": os.environ.get("HUAWEICLOUD_ACCESS_KEY", ""),
        "HUAWEICLOUD_SECRET_KEY": os.environ.get("HUAWEICLOUD_SECRET_KEY", ""),
        "HW_PROJECT_ID":          os.environ.get("HW_PROJECT_ID", ""),
        "HW_ECS_ENDPOINT":        os.environ.get("HW_ECS_ENDPOINT", ""),
    }
    missing = [k for k, v in required.items() if not v]
    if missing:
        print(
            f"[hw_ecs_discover] ❌ Missing required env vars: {', '.join(missing)}",
            file=sys.stderr,
        )
        sys.exit(1)

    ak         = required["HUAWEICLOUD_ACCESS_KEY"]
    sk         = required["HUAWEICLOUD_SECRET_KEY"]
    project_id = required["HW_PROJECT_ID"]
    endpoint   = required["HW_ECS_ENDPOINT"]
    tag_key    = os.environ.get("HW_ECS_TAG_KEY", "").strip()
    tag_val    = os.environ.get("HW_ECS_TAG_VAL", "").strip()

    # ── Import SDK (gives a clear error if not installed) ─────────────────
    try:
        from huaweicloudsdkcore.auth.credentials import BasicCredentials
        from huaweicloudsdkcore.exceptions import exceptions
        from huaweicloudsdkecs.v2 import EcsClient, ListServersDetailsRequest
    except ImportError:
        print(
            "[hw_ecs_discover] ❌ SDK not installed. Run: "
            "pip install huaweicloudsdkcore huaweicloudsdkecs",
            file=sys.stderr,
        )
        sys.exit(1)

    # ── Build SDK client ──────────────────────────────────────────────────
    try:
        client = (
            EcsClient.new_builder()
            .with_credentials(BasicCredentials(ak, sk, project_id))
            .with_endpoint(endpoint)
            .build()
        )
    except Exception as e:
        print(f"[hw_ecs_discover] ❌ Failed to build SDK client: {e}", file=sys.stderr)
        sys.exit(1)

    # ── Paginated fetch (ECS API defaults to 25 servers per page) ─────────
    all_servers = []
    offset = 1          # ECS ListServersDetails uses 1-based page offset

    while True:
        try:
            req = ListServersDetailsRequest()
            req.offset = offset
            req.limit  = 100      # max allowed per page
            resp = client.list_servers_details(req)
        except exceptions.ClientRequestException as e:
            # Distinguish auth failures from other API errors for clear diagnosis
            if e.status_code == 401:
                print(
                    f"[hw_ecs_discover] ❌ 401 Unauthorized — AK/SK invalid or expired. "
                    f"error_code={e.error_code}",
                    file=sys.stderr,
                )
            elif e.status_code == 403:
                print(
                    f"[hw_ecs_discover] ❌ 403 Forbidden — AK/SK valid but IAM user "
                    f"has no ECS:ListServersDetails permission on project {project_id}. "
                    f"error_code={e.error_code}",
                    file=sys.stderr,
                )
            else:
                print(
                    f"[hw_ecs_discover] ❌ API error {e.status_code}: "
                    f"{e.error_code} — {e.error_msg}",
                    file=sys.stderr,
                )
            sys.exit(1)
        except Exception as e:
            # Network / DNS / TLS failures land here
            msg = str(e)
            if "Name or service not known" in msg or "getaddrinfo" in msg:
                print(
                    f"[hw_ecs_discover] ❌ DNS resolution failed for endpoint: {endpoint}\n"
                    f"   The endpoint is not reachable from this network/runner.",
                    file=sys.stderr,
                )
            elif "Connection refused" in msg or "timed out" in msg.lower():
                print(
                    f"[hw_ecs_discover] ❌ Connection failed to {endpoint}\n"
                    f"   Check network path / firewall rules.",
                    file=sys.stderr,
                )
            else:
                print(f"[hw_ecs_discover] ❌ Unexpected error: {e}", file=sys.stderr)
            sys.exit(1)

        page_servers = resp.servers or []
        all_servers.extend(page_servers)

        # Stop when a page comes back with fewer items than requested
        if len(page_servers) < 100:
            break
        offset += 1

    # ── Optional tag filter ───────────────────────────────────────────────
    if tag_key and tag_val:
        filtered = []
        for s in all_servers:
            raw_tags = s.tags or []
            # SDK returns tag objects; normalise to dict regardless of shape
            tag_dict = {}
            for t in raw_tags:
                if hasattr(t, "key"):
                    tag_dict[t.key] = t.value
                elif isinstance(t, dict):
                    tag_dict[t.get("key", "")] = t.get("value", "")
            if tag_dict.get(tag_key) == tag_val:
                filtered.append(s)
        all_servers = filtered

    # ── Serialise to JSON (to_json_object gives a plain dict) ────────────
    # The bash parser in multi_os_benchmark.sh expects the standard ECS
    # response shape: { "servers": [ { "id", "name", "status", "metadata",
    #                                   "addresses", "image", "tags" } ] }
    try:
        servers_json = [s.to_json_object() for s in all_servers]
    except Exception as e:
        print(
            f"[hw_ecs_discover] ❌ Failed to serialise server objects: {e}",
            file=sys.stderr,
        )
        sys.exit(1)

    count = len(servers_json)
    print(
        f"[hw_ecs_discover] ✅ {count} server(s) returned from {endpoint}",
        file=sys.stderr,
    )

    # stdout = clean JSON only — bash checks `if [ -z "$HW_RAW" ]`
    print(json.dumps({"servers": servers_json}))


if __name__ == "__main__":
    main()
