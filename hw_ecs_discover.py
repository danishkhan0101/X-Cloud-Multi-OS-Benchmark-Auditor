#!/usr/bin/env python3
"""
hw_ecs_discover.py
──────────────────
SDK-based ECS discovery for Alpha Edge (private Huawei Cloud deployment).
"""

import json
import os
import sys
import ipaddress


# ── Helpers ───────────────────────────────────────────────────────────────────

def log(msg):
    """Write a diagnostic line to stderr (never contaminates stdout)."""
    print(f"[hw_ecs_discover] {msg}", file=sys.stderr)


def serialize(obj):
    """
    Recursively convert Huawei Cloud SDK objects into plain Python types.
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


def get_target_ip(server):
    """Scrape all IPs from the server, preferring Public EIPs over Private IPs."""
    addresses_block = server.get("addresses") or {}
    all_ips = []
    
    for network_name, addrs in addresses_block.items():
        if isinstance(addrs, list):
            for a in addrs:
                if isinstance(a, dict) and a.get("addr"):
                    all_ips.append(a.get("addr"))
                elif isinstance(a, str):
                    all_ips.append(a)
                    
    if not all_ips:
        return ""
        
    for ip in all_ips:
        try:
            if not ipaddress.ip_address(ip).is_private:
                return ip
        except ValueError:
            pass
            
    return all_ips[0]


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
    eps_id     = os.environ.get("HW_EPS_ID", "").strip()

    # ── Import SDK ────────────────────────────────────────────────────────
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

    # ── Paginated fetch ───────────────────────────────────────────────────
    all_servers_raw = []
    offset = 1  

    while True:
        try:
            req        = ListServersDetailsRequest()
            req.offset = offset
            req.limit  = 100   
            
            # Add the Enterprise Project ID filter if provided
            if eps_id:
                req.enterprise_project_id = eps_id
                
            resp       = client.list_servers_details(req)
        except exceptions.ClientRequestException as e:
            if e.status_code == 401:
                log(f"❌ 401 Unauthorized — error_code={e.error_code}")
            elif e.status_code == 403:
                log(f"❌ 403 Forbidden — error_code={e.error_code}")
            else:
                log(f"❌ API error {e.status_code}: {e.error_code} — {e.error_msg}")
            sys.exit(1)
        except Exception as e:
            log(f"❌ Unexpected error: {e}")
            sys.exit(1)

        page = resp.servers or []
        all_servers_raw.extend(page)

        if len(page) < 100:   
            break
        offset += len(page)

    # ── Serialise SDK objects → plain dicts ───────────────────────────────
    try:
        all_servers = [serialize(s) for s in all_servers_raw]
    except Exception as e:
        log(f"❌ Failed to serialise server objects: {e}")
        sys.exit(1)

    # ── TSV output mode ───────────────────────────────────────────────────
    if tsv_mode:
        emitted = 0
        for s in all_servers:
            # FIX: Force every variable to have a fallback string so Bash columns never collapse
            name = s.get("name") or "unknown_name"
            status = str(s.get("status", "")).upper()
            
            if status not in ("ACTIVE", "RUNNING"):
                continue
            
            if not tag_matches(s, tag_key, tag_val):
                continue
            
            target_ip = get_target_ip(s)
            if not target_ip:
                continue
            
            srv_id    = s.get("id") or "unknown_id"
            meta      = s.get("metadata") or {}
            os_type   = meta.get("os_type") or "Linux"
            img_name  = (s.get("image") or {}).get("name") or "unknown_image"
            
            # Ensure no tabs or newlines inside the variables
            img_name = img_name.replace('\t', ' ').replace('\n', ' ')
            name = name.replace('\t', ' ').replace('\n', ' ')
            
            print(f"{os_type}\t{img_name}\t{name}\t{target_ip}\t{srv_id}")
            emitted += 1
            
        log(f"✅ {emitted} ACTIVE server(s) emitted as TSV (endpoint: {endpoint})")
        return

    # ── JSON output mode (default) ────────────────────────────────────────
    if tag_key and tag_val:
        all_servers = [s for s in all_servers if tag_matches(s, tag_key, tag_val)]

    log(f"✅ {len(all_servers)} server(s) returned from {endpoint}")
    print(json.dumps({"servers": all_servers}))

if __name__ == "__main__":
    main()
