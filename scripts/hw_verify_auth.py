#!/usr/bin/env python3
"""
scripts/hw_verify_auth.py

Single source of truth for "can we auth against Huawei Cloud ECS
right now". Called from both the prepare-queue and run-audit jobs
in the workflow so the auth-check logic only exists in one place.

Required env vars:
    HUAWEICLOUD_ACCESS_KEY
    HUAWEICLOUD_SECRET_KEY
    HW_PROJECT_ID
    HW_ECS_ENDPOINT

Exit code 0 + prints instance count on success.
Exit code 1 + prints error to stderr on failure.
"""
import os
import sys

from huaweicloudsdkcore.auth.credentials import BasicCredentials
from huaweicloudsdkcore.exceptions import exceptions
from huaweicloudsdkecs.v2 import EcsClient, ListServersDetailsRequest

REQUIRED_VARS = (
    "HUAWEICLOUD_ACCESS_KEY",
    "HUAWEICLOUD_SECRET_KEY",
    "HW_PROJECT_ID",
    "HW_ECS_ENDPOINT",
)


def main() -> int:
    missing = [v for v in REQUIRED_VARS if not os.environ.get(v)]
    if missing:
        print(f"Missing required environment variable(s): {', '.join(missing)}", file=sys.stderr)
        return 1

    ak = os.environ["HUAWEICLOUD_ACCESS_KEY"]
    sk = os.environ["HUAWEICLOUD_SECRET_KEY"]
    project_id = os.environ["HW_PROJECT_ID"]
    endpoint = os.environ["HW_ECS_ENDPOINT"]

    try:
        client = (
            EcsClient.new_builder()
            .with_credentials(BasicCredentials(ak, sk, project_id))
            .with_endpoint(endpoint)
            .build()
        )
        resp = client.list_servers_details(ListServersDetailsRequest())
        count = len(resp.servers) if resp.servers else 0
        print(f"SDK auth OK - {count} ECS instance(s) visible")
        print(f"endpoint: {endpoint}")
        return 0
    except exceptions.ClientRequestException as e:
        print(f"SDK auth failed: {e.status_code} {e.error_code} {e.error_msg}", file=sys.stderr)
        return 1
    except Exception as e:  # noqa: BLE001 - want a single catch-all exit path here
        print(f"Unexpected error: {e}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
