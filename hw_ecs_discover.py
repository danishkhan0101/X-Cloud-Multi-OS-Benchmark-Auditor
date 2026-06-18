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
    HW_ECS_TAG_KEY           Tag key to filter instances  (e.g. "Environment")
    HW_ECS_TAG_VAL           Tag value to match           (e.g. "Prod")
                             Both must be set for tag filtering to apply.

OUTPUT MODES
  Default (no flag):
    JSON to stdout — standard ECS API response shape:
      { "servers": [ { "id", "name", "status", "metadata", "addresses",
                       "image", "tags", ... } ] }
    Used by: multi_os_benchmark.sh (huaweicloud discovery block)

  --tsv flag:
    TSV to stdout — one line per ACTIVE server with a public (floating) IP:
      os_type  image_name  vm_name  public_ip  server_id
    Used by: fleet_commander.yml (discover-vms step)
    Eliminates the need for any inline Python inside the YAML workflow.

  In both modes:
    - All diagnostic messages go to stderr only
    - stdout is either valid output or completely empty (never partial)
    - Exit code 0 on success, non-zero on any failure

DEPENDENCIES
  pip install huaweicloudsdkcore huaweicloudsdkecs
"""

import json
import os
import sys


# ── Helpers ───────────────────────────────────────────────────────────────────

def log(msg):
    """Write a diagnostic line to stderr (never contaminates stdout)."""
    print(f"[hw_ecs_discover] {msg}", file=sys.stderr)


def serialize(obj):
    """
    Recursively convert Huawei Cloud SDK objects into plain Python types.
    This bypasses an SDK bug where `.to_dict()` is shallow and leaves
    nested ServerAddress/Tag objects inside list/dict values.
    """
    if hasattr(obj, "to_dict"):
        try:
            obj = obj.to_dict()
        except Exception:
            pass
            
    if isinstance(obj, list):
        return [serialize(i) for i in obj]
    elif isinstance(obj, dict):
        return {k: serialize(v) for k, v in obj.items()}
    else:
        return obj


def get_public_ip(server):
    """Return the first floating IP found in the server's addresses dict, or ''."""
    for addrs in (server.get("addresses") or {}).values():
        for a in addrs:
            if not isinstance(a, dict):
                continue
            
            # Look for both the API JSON key AND the python snake_case attribute name
            # just in case the SDK's to_dict map translated the key.
            ip_type = a.get("OS-EXT-IPS:type") or a.get("os_ext_ips_type")
            
            if ip_type == "floating":
                ip = a.get("addr", "")
                if ip:
                    return ip
    return ""


def tag_matches(server, tag_key, tag_val):
    """Return True if tag filtering is disabled OR the server has the matching tag."""
    if not tag_key or not tag_val:
        return True
    
    raw_tags = server.get("tags") or []
    for t in raw_tags:
        if isinstance(t, dict):
            if t.get("key") == tag_key and t.get("value") == tag_val:
                return True
    return False


# ── Main ──────────────────────────────────────────────────────────────────────

def main():
    tsv_mode = "--tsv" in sys.argv

    # ── Validate required env vars ────────────────────────────────────────
    required = {
        "HUAWEICLOUD_ACCESS_KEY": os.environ.get("HUAWEICLOUD_ACCESS_KEY", ""),
        "HUAWEICLOUD_SECRET_KEY": os.environ.get("HUAWEICLOUD_SECRET_KEY", ""),
        "HW_PROJECT_ID":          os.environ.get("HW_PROJECT_ID", ""),
        "HW_ECS_ENDPOINT":        os.environ.get("HW_ECS_ENDPOINT", ""),
    }
    missing = [k for k, v in required.items() if not v]
    if missing:
        log(f"❌ Missing required env vars: {', '.join(missing)}")
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
        log("❌ SDK not installed. Run: pip install huaweicloudsdkcore huaweicloudsdkecs")
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
        log(f"❌ Failed to build SDK client: {e}")
        sys.exit(1)

    # ── Paginated fetch (ECS API defaults to 25 servers per page) ─────────
    all_servers_raw = []
    offset = 1  # ECS ListServersDetails uses 1-based page offset

    while True:
        try:
            req        = ListServersDetailsRequest()
            req.offset = offset
            req.limit  = 100   # max allowed per page
            resp       = client.list_servers_details(req)
        except exceptions.ClientRequestException as e:
            if e.status_code == 401:
                log(
                    f"❌ 401 Unauthorized — AK/SK invalid or expired. "
                    f"error_code={e.error_code}"
                )
            elif e.status_code == 403:
                log(
                    f"❌ 403 Forbidden — AK/SK valid but IAM user has no "
                    f"ECS:ListServersDetails permission on project {project_id}. "
                    f"error_code={e.error_code}"
                )
            else:
                log(f"❌ API error {e.status_code}: {e.error_code} — {e.error_msg}")
            sys.exit(1)
        except Exception as e:
            msg = str(e)
            if "Name or service not known" in msg or "getaddrinfo" in msg:
                log(
                    f"❌ DNS resolution failed for endpoint: {endpoint}\n"
                    f"   The endpoint is not reachable from this network/runner."
                )
            elif "Connection refused" in msg or "timed out" in msg.lower():
                log(f"❌ Connection failed to {endpoint} — check network/firewall.")
            else:
                log(f"❌ Unexpected error: {e}")
            sys.exit(1)

        page = resp.servers or []
        all_servers_raw.extend(page)

        if len(page) < 100:   # partial page = last page
            break
        offset += 1

    # ── Serialise SDK objects → plain dicts ───────────────────────────────
    try:
        # We process the raw response through our recursive serializer so 
        # that nested objects like ServerAddress are fully flattened into dicts.
        all_servers = [serialize(s) for s in all_servers_raw]
    except Exception as e:
        log(f"❌ Failed to serialise server objects: {e}")
        sys.exit(1)

    # ── TSV output mode ───────────────────────────────────────────────────
    if tsv_mode:
        emitted = 0
        for s in all_servers:
            if s.get("status") != "ACTIVE":
                continue
            
            if not tag_matches(s, tag_key, tag_val):
                continue
            
            public_ip = get_public_ip(s)
            if not public_ip:
                continue
            
            name      = s.get("name", "")
            srv_id    = s.get("id", "")
            meta      = s.get("metadata") or {}
            os_type   = meta.get("os_type", "Linux")
            img_name  = (s.get("image") or {}).get("name", "").lower()
            
            # Tab-separated: matches what classify_vm in fleet_commander.yml expects
            print(f"{os_type}\t{img_name}\t{name}\t{public_ip}\t{srv_id}")
            emitted += 1
            
        log(f"✅ {emitted} ACTIVE server(s) with public IP emitted as TSV (endpoint: {endpoint})")
        return

    # ── JSON output mode (default) ────────────────────────────────────────
    if tag_key and tag_val:
        all_servers = [s for s in all_servers if tag_matches(s, tag_key, tag_val)]

    log(f"✅ {len(all_servers)} server(s) returned from {endpoint}")
    print(json.dumps({"servers": all_servers}))

if __name__ == "__main__":
    main()
