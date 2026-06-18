#!/usr/bin/env python3
"""
Standalone test: does AK/SK auth work against the private Alpha Edge ECS endpoint?

Usage:
    export HW_ACCESS_KEY=...
    export HW_SECRET_KEY=...
    export HW_PROJECT_ID=b60279cbf502494396b7c363e74e6654   # from earlier console discovery
    python3 test_aksk_auth.py

This does NOT touch the console UI, cookies, or /v3/auth/tokens at all.
The SDK signs each ECS request locally with your AK/SK (HMAC-SHA256) and
sends it straight to the ecs.* endpoint. No IAM token exchange needed
when project_id is supplied explicitly.
"""

import os
import sys

from huaweicloudsdkcore.auth.credentials import BasicCredentials
from huaweicloudsdkcore.exceptions import exceptions
from huaweicloudsdkecs.v2 import EcsClient, ListServersDetailsRequest

ECS_ENDPOINT = "https://ecs.my-kualalumpur-1.alphaedge.tmone.com.my"


def main():
    ak = os.environ.get("HW_ACCESS_KEY")
    sk = os.environ.get("HW_SECRET_KEY")
    project_id = os.environ.get("HW_PROJECT_ID")

    missing = [name for name, val in [
        ("HW_ACCESS_KEY", ak), ("HW_SECRET_KEY", sk), ("HW_PROJECT_ID", project_id)
    ] if not val]
    if missing:
        print(f"❌ Missing required env vars: {', '.join(missing)}")
        sys.exit(1)

    print("========================================")
    print("AK/SK -> Private ECS Endpoint Auth Test")
    print("========================================")
    print(f"Endpoint:   {ECS_ENDPOINT}")
    print(f"Project ID: {project_id}")
    print(f"AK:         {ak[:6]}{'*' * max(len(ak) - 6, 0)}")
    print()

    credentials = BasicCredentials(ak, sk, project_id)

    client = (
        EcsClient.new_builder()
        .with_credentials(credentials)
        .with_endpoint(ECS_ENDPOINT)
        .build()
    )

    request = ListServersDetailsRequest(limit=5)

    try:
        response = client.list_servers_details(request)
        print("✅ SUCCESS — AK/SK signing accepted by the private endpoint.")
        print()
        servers = response.servers or []
        print(f"Server count returned: {len(servers)}")
        for s in servers[:5]:
            print(f"  - {s.id}  {s.name}  status={s.status}")
        sys.exit(0)

    except exceptions.ClientRequestException as e:
        print("❌ FAILED — request was rejected.")
        print(f"HTTP status:   {e.status_code}")
        print(f"error_code:    {e.error_code}")
        print(f"error_msg:     {e.error_msg}")
        print(f"request_id:    {e.request_id}")
        print()
        diagnose(e.status_code, e.error_code, e.error_msg)
        sys.exit(1)

    except Exception as e:
        print("❌ FAILED — connection or unexpected error (not an API rejection).")
        print(f"{type(e).__name__}: {e}")
        print()
        print("This usually means: DNS doesn't resolve, TLS handshake failed, or")
        print("the endpoint isn't reachable from this network at all. Check:")
        print("  - Is this private endpoint resolvable from where you're running this?")
        print("    (it may only resolve inside TM ONE's network / VPN, not the public internet")
        print("     or GitHub Actions runners)")
        sys.exit(2)


def diagnose(status_code, error_code, error_msg):
    print("---- Diagnosis ----")
    if error_msg and "not in allowlist" in error_msg.lower():
        print("This isn't an IAM/auth failure at all — it's a network egress block.")
        print("Whatever machine is running this script can't reach the ECS endpoint")
        print("hostname at the network level (firewall/proxy/allowlist), so the")
        print("request never reached Alpha Edge. Run this from a network that has")
        print("a route to console.alphaedge.tmone.com.my / *.alphaedge.tmone.com.my")
        print("(e.g. the VM itself, or wherever the console UI is reachable from).")
    elif status_code == 401:
        print("401 = authentication failed. Likely causes:")
        print("  - AK/SK is invalid, disabled, or deleted")
        print("  - AK/SK belongs to a different domain/account than this project")
        print("  - Clock skew: signature includes a timestamp; if this machine's")
        print("    clock is off by more than ~15 min, signing will fail. Run `date -u`")
        print("    and compare against real UTC time.")
    elif status_code == 403:
        print("403 = authenticated, but not authorized. Likely causes:")
        print("  - The IAM user behind this AK/SK has no policy granting ECS read access")
        print("  - The project_id doesn't match a project this user has permissions in")
        print("  -> Check IAM console: does this user/user-group have an ECS policy")
        print("     (e.g. ECS ReadOnlyAccess) assigned in the my-kualalumpur-1 project?")
    elif status_code == 404:
        print("404 = endpoint or path not found. Likely causes:")
        print("  - The private endpoint hostname doesn't actually exist / isn't routed")
        print("  - Wrong API version path mismatch (unlikely, SDK handles this)")
    else:
        print(f"Unhandled status {status_code} — read error_msg above for specifics.")
    print("--------------------")


if __name__ == "__main__":
    main()
