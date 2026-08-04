#!/usr/bin/env python3
"""
hw_sg_rule_manage.py
─────────────────────
Idempotent, concurrency-safe security-group ingress rule refresh for Alpha
Edge (private HW Cloud).

Each rule this script creates is tagged in its `description` field with an
owner id (defaults to --remote-ip, i.e. the runner's own IP, but can be
overridden with --owner-tag for a stable per-runner identity across IP
changes). On each run, the script:
  1. Skips silently if a rule already matches (protocol, port, remote_ip)
     exactly — true no-op.
  2. Deletes ONLY prior rules that carry this runner's own owner tag but
     have a stale IP (e.g. runner's IP changed between runs).
  3. NEVER deletes or touches rules belonging to a different owner tag —
     this is what previously caused parallel runners to delete each
     other's freshly-created rules for the same port.
  4. Creates the fresh rule, tagged with the owner id.

Usage:
  python3 hw_sg_rule_manage.py --sg-id <SG_ID> --port <PORT> --remote-ip <IP> \
      [--owner-tag <STABLE_ID>] [--protocol tcp]

Required env vars:
  HUAWEICLOUD_ACCESS_KEY, HUAWEICLOUD_SECRET_KEY, HW_PROJECT_ID, HW_VPC_ENDPOINT
"""

import argparse
import os
import sys

TAG_PREFIX = "sgmgr-owner"


def log(msg):
    print(f"[hw_sg_rule_manage] {msg}", file=sys.stderr)


def owner_tag_string(owner_id: str) -> str:
    return f"{TAG_PREFIX}:{owner_id}"


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--sg-id", required=True)
    parser.add_argument("--port", required=True, type=int)
    parser.add_argument("--remote-ip", required=True)
    parser.add_argument("--protocol", default="tcp")
    parser.add_argument(
        "--owner-tag",
        default=None,
        help=(
            "Stable identifier for this runner/VM, used to scope which rules "
            "this invocation is allowed to delete. Defaults to --remote-ip if "
            "not given — but pass a stable value (e.g. VM name/hostname) if "
            "the runner's IP can change between runs, so old-IP rules from "
            "the SAME runner still get cleaned up correctly."
        ),
    )
    parser.add_argument(
        "--action",
        choices=["ensure", "delete"],
        default="ensure",
        help="ensure (default): create/refresh the rule. delete: remove this "
             "owner's rule for this port and exit — no create.",
    )
    args = parser.parse_args()
    owner_id = args.owner_tag or args.remote_ip
    tag = owner_tag_string(owner_id)

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

    if args.action == "delete":
        deleted_any = False
        for r in rules:
            d = r.to_dict() if hasattr(r, "to_dict") else {}
            if not (
                d.get("direction") == "ingress"
                and str(d.get("port_range_min")) == str(args.port)
                and str(d.get("port_range_max")) == str(args.port)
                and str(d.get("protocol")) == str(args.protocol)
            ):
                continue
            description = d.get("description") or ""
            if tag not in description:
                continue  # not ours — leave it alone

            rule_id = d.get("id")
            log(f"🗑️  Deleting rule {rule_id} ({args.protocol}/{args.port}, owner={owner_id})")
            try:
                del_req = DeleteSecurityGroupRuleRequest()
                del_req.security_group_rule_id = rule_id
                client.delete_security_group_rule(del_req)
                deleted_any = True
            except exceptions.ClientRequestException as e:
                log(f"⚠️  delete failed (continuing): {e.status_code} {e.error_code} {e.error_msg}")

        if not deleted_any:
            log(f"ℹ️  No matching owned rule found to delete — no-op")
        sys.exit(0)
    # ── Step 2: check for exact match (true no-op), and separately find
    #            ONLY this owner's stale rules to delete. Rules belonging
    #            to other owners on the same port are left completely
    #            untouched — this is the fix for the parallel-runner
    #            deletion race. ─────────────────────────────────────────
    target_prefix = f"{args.remote_ip}/32"
    already_correct = False
    own_stale_rule_ids = []

    for r in rules:
        d = r.to_dict() if hasattr(r, "to_dict") else {}
        if not (
            d.get("direction") == "ingress"
            and str(d.get("port_range_min")) == str(args.port)
            and str(d.get("port_range_max")) == str(args.port)
            and str(d.get("protocol")) == str(args.protocol)
        ):
            continue

        description = d.get("description") or ""

        if d.get("remote_ip_prefix") == target_prefix and tag in description:
            # Exactly the rule we want, owned by us — no-op.
            already_correct = True
            log(f"✅ Rule already correct: {args.protocol}/{args.port} ← {target_prefix} "
                f"(owner={owner_id}) on SG {args.sg_id} (no-op)")
            continue

        if tag in description:
            # Stale rule, but it's OURS (same owner tag, different/old IP).
            # Safe to delete — no other runner can own a rule with our tag.
            own_stale_rule_ids.append((d.get("id"), d.get("remote_ip_prefix")))
        # else: belongs to a different owner (or untagged legacy rule) —
        # deliberately left alone.

    if already_correct:
        sys.exit(0)

    for rule_id, old_ip in own_stale_rule_ids:
        log(f"🗑️  Deleting own stale rule {rule_id} (port {args.port}, owner={owner_id}, was {old_ip})")
        try:
            del_req = DeleteSecurityGroupRuleRequest()
            del_req.security_group_rule_id = rule_id
            client.delete_security_group_rule(del_req)
        except exceptions.ClientRequestException as e:
            log(f"⚠️  delete failed (continuing): {e.status_code} {e.error_code} {e.error_msg}")

    # ── Step 3: create fresh rule, tagged with this owner's id ───────────
    try:
        option = CreateSecurityGroupRuleOption(
            security_group_id=args.sg_id,
            direction="ingress",
            ethertype="IPv4",
            protocol=args.protocol,
            port_range_min=args.port,
            port_range_max=args.port,
            remote_ip_prefix=target_prefix,
            description=tag,
        )
        body = CreateSecurityGroupRuleRequestBody(security_group_rule=option)
        create_req = CreateSecurityGroupRuleRequest(body=body)
        client.create_security_group_rule(create_req)
        log(f"✅ Rule created: {args.protocol}/{args.port} ← {target_prefix} "
            f"(owner={owner_id}) on SG {args.sg_id}")
    except exceptions.ClientRequestException as e:
        log(f"❌ create_security_group_rule failed: {e.status_code} {e.error_code} {e.error_msg}")
        sys.exit(1)


if __name__ == "__main__":
    main()
