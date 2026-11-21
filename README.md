# fortigate-rule-reviewer

Reviews a FortiGate policy export the way a Tufin owner would — every finding gets an owner, an expiry and a change request a customer's network team can act on.

<!-- claims: rules=9 findings=9 critical=1 clean=0 -->

## What it looks for

| Category | Severity | What it means |
|---|---|---|
| `any_any` | critical | accept rule with `all → all`, service `ALL` |
| `management_exposed` | high | SSH/Telnet, or HTTP(S) to a management-named host, permitted inbound from a WAN interface |
| `shadowed` | high | an earlier accept rule already matches everything this rule matches, so it can never fire |
| `undefined_object` | high | rule references an address or service object that no longer exists |
| `no_logging` | medium | accept rule with `logtraffic disable` |
| `broad_destination` | medium | specific service permitted to every destination |
| `temporary_no_expiry` | medium | rule named or commented TEMP/vendor, on schedule `always` |
| `dead_deny` | low | deny rule that an earlier accept rule makes unreachable |
| `duplicate` | low | two rules with identical tuples |

## Why the checks are ordered the way they are

A rule can be several things at once. Reporting all of them produces a list nobody finishes, so the report picks the finding that changes the decision:

- a rule that is a **duplicate** is not also reported as **shadowed** — the duplicate is the actionable one
- a rule that is **shadowed** is not also reported as **broad_destination** — an unreachable rule's breadth is not the problem
- **management_exposed** distinguishes interactive admin (SSH/Telnet) from an ordinary inbound web service, so publishing HTTPS to a web server is not flagged as a firewall fault

That last one is the difference between a tool a network team uses and a tool that gets muted in a week.

## Where the model is, and where it is not

```
config ──► parse policies + object table ──► deterministic checks ──► findings
                                                              │
                                                              ▼
                                                    model drafts the change request
                                                              │
                                                              ▼
                                              rule-id check ──► template fallback
```

- Findings, categories and severities are computed, never generated.
- The model writes the two-sentence change request only.
- Every rule id it mentions must exist in the input. An invented rule id discards the note and the template is used instead.
- Config text is control-stripped and fenced as data, so a rule named `ignore previous instructions` is a rule name, not an instruction.

## Run it

```bash
python -m venv .venv && . .venv/bin/activate
pip install -r requirements-dev.txt

python -m app.cli fixtures/planted.conf

export SECOPS_API_KEYS=dev-key-change-me
uvicorn app.main:app --port 8000
curl -s localhost:8000/v1/review -H "x-api-key: dev-key-change-me" \
  -H 'content-type: application/json' \
  -d "{\"config\": $(python -c 'import json;print(json.dumps(open("fixtures/planted.conf").read()))')}"
```

## What this does not claim

The parser handles the `config firewall policy` block of a standard FortiOS export and the address and service object tables it references. It does not resolve dynamic objects, VIPs, or security profiles, and it does not read hit counts — a rule with zero hits is only provably unused if the export carries `diagnose firewall iprope` output, which a config file does not.

The shadowing test is a conservative set-containment check on interfaces, addresses and services. It will miss coverage that depends on negation, on overlapping subnets inside different address objects, or on routing that makes an interface irrelevant. A miss is a miss; a false positive is what erodes trust, so it prefers to under-report.
