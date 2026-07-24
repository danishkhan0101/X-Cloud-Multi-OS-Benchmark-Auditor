#!/usr/bin/env python3
"""
hw_sg_rule_manage.py
─────────────────────
Idempotent security-group ingress rule refresh for Alpha Edge (private HW Cloud).
Deletes any existing ingress rule matching (security_group_id, port) that does
NOT already match the target (protocol, remote_ip), then creates a fresh one
scoped to the given remote IP. If a rule already matches exactly, this is a
no-op — nothing is deleted or recreated.

Usage:
  python3 hw_sg_rule_manage.py --sg-id <SG_ID> --port <PORT> --remote-ip <IP>

Required env vars:
  HUAWEICLOUD_ACCESS_KEY, HUAWEICLOUD_SECRET_KEY, HW_PROJECT_ID, HW_VPC_ENDPOINT
"""

import argparse
import os
import sys


def log(msg):
    print(f"[hw_sg_rule_manage] {msg}", file=sys.stderr)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--sg-id", required=True)
    parser.add_argument("--port", required=True, type=int)
    parser.add_argument("--remote-ip", required=True)
    parser.add_argument("--protocol", default="tcp")
    args = parser.parse_args()

    ak         = os.environ.get("HUAWEICLOUD_ACCESS_KEY", "")
    sk         = os.environ.get("HUAWEICLOUD_SECRET_KEY", "")
    project_id = os.environ.get("HW_PROJECT_ID", "")
    endpoint   = os.environ.get("HW_VPC_ENDPOINT", "")

    missing = [k for k, v in {
        "HUAWEICLOUD_ACCESS_KEY": ak, "HUAWEICLOUD_SECRET_KEY": sk,
        "HW_PROJECT_ID": project_id, "HW_VPC_ENDPOINT": endpoint,
    }.items() if not v]
    if missing:
        log(f"❌ Missing required env vars: {', '.join(missing)}")
        sys.exit(1)

    try:
        from huaweicloudsdkcore.auth.credentials import BasicCredentials
        from huaweicloudsdkcore.exceptions import exceptions
        from huaweicloudsdkvpc.v2 import (
            VpcClient,
            ListSecurityGroupRulesRequest,
            DeleteSecurityGroupRuleRequest,
            CreateSecurityGroupRuleRequest,
            CreateSecurityGroupRuleRequestBody,
            CreateSecurityGroupRuleOption,
        )
    except ImportError as e:
        log(f"❌ SDK import failed: {e}")
        sys.exit(1)

    client = (
        VpcClient.new_builder()
        .with_credentials(BasicCredentials(ak, sk, project_id))
        .with_endpoint(endpoint)
        .build()
    )

    # ── Step 1: list existing rules for this SG ──────────────────────────
    try:
        list_req = ListSecurityGroupRulesRequest()
        list_req.security_group_id = args.sg_id
        resp = client.list_security_group_rules(list_req)
        rules = resp.security_group_rules or []
    except exceptions.ClientRequestException as e:
        log(f"❌ list_security_group_rules failed: {e.status_code} {e.error_code} {e.error_msg}")
        sys.exit(1)

    # ── Step 2: delete stale ingress rules for this port, skip if a
    #            matching rule already exists (idempotent no-op) ────────
    target_prefix = f"{args.remote_ip}/32"
    already_correct = False

    for r in rules:
        d = r.to_dict() if hasattr(r, "to_dict") else {}
        if (
            d.get("direction") == "ingress"
            and str(d.get("port_range_min")) == str(args.port)
            and str(d.get("port_range_max")) == str(args.port)
            and str(d.get("protocol")) == str(args.protocol)
        ):
            if d.get("remote_ip_prefix") == target_prefix:
                # Exactly the rule we want already exists — don't touch it.
                already_correct = True
                log(f"✅ Rule already correct: {args.protocol}/{args.port} ← {target_prefix} on SG {args.sg_id} (no-op)")
                continue

            rule_id = d.get("id")
            log(f"🗑️  Deleting stale rule {rule_id} (port {args.port}, was {d.get('remote_ip_prefix')})")
            try:
                del_req = DeleteSecurityGroupRuleRequest()
                del_req.security_group_rule_id = rule_id
                client.delete_security_group_rule(del_req)
            except exceptions.ClientRequestException as e:
                log(f"⚠️  delete failed (continuing): {e.status_code} {e.error_code} {e.error_msg}")

    if already_correct:
        sys.exit(0)

    # ── Step 3: create fresh rule scoped to current runner IP ────────────
    try:
        option = CreateSecurityGroupRuleOption(
            security_group_id=args.sg_id,
            direction="ingress",
            ethertype="IPv4",
            protocol=args.protocol,
            port_range_min=args.port,
            port_range_max=args.port,
            remote_ip_prefix=target_prefix,
        )
        body = CreateSecurityGroupRuleRequestBody(security_group_rule=option)
        create_req = CreateSecurityGroupRuleRequest(body=body)
        client.create_security_group_rule(create_req)
        log(f"✅ Rule created: {args.protocol}/{args.port} ← {target_prefix} on SG {args.sg_id}")
    except exceptions.ClientRequestException as e:
        log(f"❌ create_security_group_rule failed: {e.status_code} {e.error_code} {e.error_msg}")
        sys.exit(1)


if __name__ == "__main__":
    main()
