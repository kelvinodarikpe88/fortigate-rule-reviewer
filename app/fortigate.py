"""FortiGate policy review with Tufin-shaped output: owner, expiry, change request.

The checks are deterministic and the config is parsed as data. The model only
turns a finding into the sentence a customer reads, and every change request it
writes must point at a rule that exists in the input.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field

ANY = {"all", "any"}
MGMT_PORTS = {"HTTP", "HTTPS", "SSH", "TELNET", "FORTIGATE-MGMT"}
WAN_INTERFACES = {"wan", "wan1", "wan2", "port1", "internet"}
BUILTIN_SERVICES = {
    "ALL", "ANY", "HTTP", "HTTPS", "SSH", "TELNET", "DNS", "SMTP", "SMB",
    "FTP", "ICMP", "PING", "NTP", "LDAP", "LDAPS", "RDP", "SNMP", "SYSLOG",
    "POP3", "IMAP", "IKE", "ESP", "GRE",
}
SEVERITY_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3}

EDIT_RE = re.compile(r"^\s*edit\s+(\S+)\s*$")
NEXT_RE = re.compile(r"^\s*next\s*$")
SET_RE = re.compile(r"^\s*set\s+(\S+)\s+(.*)$")
QUOTED_RE = re.compile(r'"([^"]*)"')


@dataclass
class Rule:
    rule_id: str
    name: str
    srcintf: set[str] = field(default_factory=set)
    dstintf: set[str] = field(default_factory=set)
    srcaddr: set[str] = field(default_factory=set)
    dstaddr: set[str] = field(default_factory=set)
    service: set[str] = field(default_factory=set)
    action: str = "deny"
    logtraffic: str = "all"
    schedule: str = "always"
    comments: str = ""
    status: str = "enable"

    @property
    def accepts(self) -> bool:
        return self.action == "accept" and self.status == "enable"


@dataclass
class Finding:
    rule_id: str
    rule_name: str
    category: str
    severity: str
    evidence: str
    owner: str | None = None
    expires_at: str | None = None

    def as_dict(self) -> dict:
        return {
            "rule_id": self.rule_id,
            "rule_name": self.rule_name,
            "category": self.category,
            "severity": self.severity,
            "evidence": self.evidence,
            "owner": self.owner,
            "expires_at": self.expires_at,
        }


def _values(raw: str) -> set[str]:
    quoted = QUOTED_RE.findall(raw)
    if quoted:
        return {value for value in quoted}
    return set(raw.split())


def _config_block(lines: list[str], header: str) -> list[str]:
    start = None
    for index, line in enumerate(lines):
        if line.strip() == header:
            start = index + 1
            break
    if start is None:
        return []
    depth = 1
    block: list[str] = []
    for line in lines[start:]:
        stripped = line.strip()
        if stripped.startswith("config "):
            depth += 1
        elif stripped == "end":
            depth -= 1
            if depth == 0:
                break
        if depth >= 1:
            block.append(line)
    return block


def parse_policies(text: str) -> list[Rule]:
    lines = text.splitlines()
    block = _config_block(lines, "config firewall policy")

    rules: list[Rule] = []
    current: dict[str, str] | None = None
    current_id = ""
    for line in block:
        edit = EDIT_RE.match(line)
        if edit:
            current = {}
            current_id = edit.group(1).strip('"')
            continue
        if NEXT_RE.match(line):
            if current is not None:
                rules.append(_to_rule(current_id, current))
            current = None
            continue
        setting = SET_RE.match(line)
        if setting and current is not None:
            current[setting.group(1)] = setting.group(2).strip()
    return rules


def _to_rule(rule_id: str, values: dict[str, str]) -> Rule:
    return Rule(
        rule_id=rule_id,
        name=values.get("name", f"rule-{rule_id}").strip('"'),
        srcintf=_values(values.get("srcintf", "any")),
        dstintf=_values(values.get("dstintf", "any")),
        srcaddr=_values(values.get("srcaddr", "all")),
        dstaddr=_values(values.get("dstaddr", "all")),
        service=_values(values.get("service", "ALL")),
        action=values.get("action", "deny").strip('"'),
        logtraffic=values.get("logtraffic", "all").strip('"'),
        schedule=values.get("schedule", "always").strip('"'),
        comments=values.get("comments", "").strip('"'),
        status=values.get("status", "enable").strip('"'),
    )


def parse_object_names(text: str) -> tuple[set[str], set[str]]:
    addresses: set[str] = set()
    services: set[str] = set()
    for header, sink in (
        ("config firewall address", addresses),
        ("config firewall addrgrp", addresses),
        ("config firewall service custom", services),
        ("config firewall service group", services),
    ):
        block = _config_block(text.splitlines(), header)
        for line in block:
            edit = EDIT_RE.match(line)
            if edit:
                sink.add(edit.group(1).strip('"'))
    return addresses, services


def _norm(values: set[str]) -> set[str]:
    return {value.lower() for value in values}


def superset(left: set[str], right: set[str]) -> bool:
    outer, inner = _norm(left), _norm(right)
    if outer & ANY:
        return True
    return inner <= outer


def covers(outer: Rule, inner: Rule) -> bool:
    return (
        outer.accepts
        and superset(outer.srcintf, inner.srcintf)
        and superset(outer.dstintf, inner.dstintf)
        and superset(outer.srcaddr, inner.srcaddr)
        and superset(outer.dstaddr, inner.dstaddr)
        and superset(outer.service, inner.service)
    )


def _rule_key(rule: Rule) -> tuple:
    return (
        frozenset(_norm(rule.srcintf)),
        frozenset(_norm(rule.dstintf)),
        frozenset(_norm(rule.srcaddr)),
        frozenset(_norm(rule.dstaddr)),
        frozenset(_norm(rule.service)),
        rule.action.lower(),
    )


def _is_management(rule: Rule) -> bool:
    """Admin exposure: interactive admin services, or HTTP(S) to a mgmt-named host."""
    services = _norm(rule.service)
    if services & {"ssh", "telnet", "fortigate-mgmt"}:
        return True
    destinations = " ".join(_norm(rule.dstaddr))
    return bool(services & {"http", "https"}) and any(
        token in destinations for token in ("mgmt", "admin", "fortigate", "fw-", "firewall")
    )


def review(text: str) -> dict:
    rules = parse_policies(text)
    addresses, services = parse_object_names(text)
    findings: list[Finding] = []
    seen_keys: dict[tuple, str] = {}

    for index, rule in enumerate(rules):
        if not rule.accepts:
            if rule.status == "enable":
                for earlier in rules[:index]:
                    if covers(earlier, rule):
                        findings.append(
                            Finding(
                                rule.rule_id,
                                rule.name,
                                "dead_deny",
                                "low",
                                f"deny rule unreachable: earlier accept rule {earlier.rule_id} covers it",
                            )
                        )
                        break
            continue

        key = _rule_key(rule)
        if key in seen_keys:
            findings.append(
                Finding(
                    rule.rule_id,
                    rule.name,
                    "duplicate",
                    "low",
                    f"identical to rule {seen_keys[key]}",
                )
            )
            continue
        seen_keys[key] = rule.rule_id

        shadower = None
        for earlier in rules[:index]:
            if covers(earlier, rule):
                shadower = earlier
                break
        if shadower is not None:
            findings.append(
                Finding(
                    rule.rule_id,
                    rule.name,
                    "shadowed",
                    "high",
                    f"fully covered by earlier accept rule {shadower.rule_id}",
                )
            )

        if (
            rule.srcaddr & ANY
            and rule.dstaddr & ANY
            and _norm(rule.service) & ANY
        ):
            findings.append(
                Finding(
                    rule.rule_id,
                    rule.name,
                    "any_any",
                    "critical",
                    "srcaddr all + dstaddr all + service ALL on an accept rule",
                )
            )

        inbound_wan = _norm(rule.srcintf) & WAN_INTERFACES
        if inbound_wan and _is_management(rule):
            findings.append(
                Finding(
                    rule.rule_id,
                    rule.name,
                    "management_exposed",
                    "high",
                    f"management service {sorted(_norm(rule.service) & MGMT_PORTS)} permitted inbound from {sorted(inbound_wan)}",
                )
            )

        if rule.logtraffic.lower() in {"disable", "off"}:
            findings.append(
                Finding(
                    rule.rule_id,
                    rule.name,
                    "no_logging",
                    "medium",
                    "logtraffic is disabled on an accept rule",
                )
            )

        if shadower is None and (rule.dstaddr & ANY) and not (_norm(rule.service) & ANY):
            findings.append(
                Finding(
                    rule.rule_id,
                    rule.name,
                    "broad_destination",
                    "medium",
                    f"service {sorted(_norm(rule.service))} permitted to every destination",
                )
            )

        if re.search(r"\b(temp|tmp|temporary|vendor)\b", f"{rule.name} {rule.comments}", re.I):
            if rule.schedule.lower() in {"always", ""}:
                findings.append(
                    Finding(
                        rule.rule_id,
                        rule.name,
                        "temporary_no_expiry",
                        "medium",
                        "temporary or vendor rule on schedule always, with no expiry recorded",
                    )
                )

        for referenced, known in ((rule.srcaddr, addresses), (rule.dstaddr, addresses), (rule.service, services)):
            missing = {
                name
                for name in referenced
                if name not in known
                and name.upper() not in {"ALL", "ANY"}
                and name.upper() not in BUILTIN_SERVICES
                and name.lower() != "any"
            }
            if missing:
                findings.append(
                    Finding(
                        rule.rule_id,
                        rule.name,
                        "undefined_object",
                        "high",
                        f"references undefined object(s): {', '.join(sorted(missing))}",
                    )
                )

    findings.sort(key=lambda f: (SEVERITY_RANK[f.severity], f.rule_id, f.category))

    counts: dict[str, int] = {}
    for finding in findings:
        counts[finding.category] = counts.get(finding.category, 0) + 1

    return {
        "summary": {
            "rules": len(rules),
            "findings": len(findings),
            "by_category": counts,
            "by_severity": {
                level: sum(1 for f in findings if f.severity == level)
                for level in ("critical", "high", "medium", "low")
            },
        },
        "findings": [f.as_dict() for f in findings],
    }
