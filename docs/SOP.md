# SOP — Operating the FortiGate policy reviewer

**Service:** `fortigate-rule-reviewer`
**Owner:** security engineering
**Audience:** the consultant running the review, and the service owner who maintains it
**Review cadence:** quarterly

---

## 1. Purpose and scope

This procedure covers how a FortiGate configuration export is taken, sanitised, reviewed, reported and closed out.

**In scope:** export handling, redaction, review, change-request lifecycle, suppression of known-acceptable findings.
**Out of scope:** applying changes to the firewall. This tool produces a change request; a network engineer makes the change under change control.

---

## 2. Roles

| Role | Owns |
|---|---|
| Consultant | takes the export, sanitises it, runs the review, writes the report |
| Service owner | categories, severities, parser changes, releases |
| Customer network owner | the change request, the owner field, the expiry date |

---

## 3. Handling the configuration export — read this first

**A FortiGate configuration contains secrets.** Treat the export as customer-confidential at minimum, and as a credential store in practice: pre-shared keys, admin password hashes, RADIUS and LDAP bind secrets, SNMP communities and API keys all live in the same text file as the policy table you actually need.

### 3.1 Take the export off the device

```bash
# on the device, as an admin, to a USB or TFTP target you control
execute backup config usb review.conf
```

Do not review a live configuration by pasting it into a web form. Do not email the raw file. Keep the raw export inside the customer's environment or your managed case folder, and move only the sanitised copy to the review workstation.

### 3.2 Redact before upload

Every line of the form `set <secret-field> <value>` must be masked. The secret-bearing field names in a standard FortiOS export include:

```
password  passwd  psksecret  key  auth-pwd  secondary-secret  server-key
secret  community  private-key  api-key
```

A safe first pass:

```bash
sed -E 's/(set (password|passwd|psksecret|auth-pwd|secondary-secret|server-key|secret|community|private-key|api-key) )[^ ]+/\1REDACTED/I' \
    review.conf > review.redacted.conf

diff <(sed -E 's/REDACTED//g' review.redacted.conf) review.conf
```

**Read the diff.** The diff should show only the values you intended to remove. If it shows a policy line, your pattern was too wide; fix it and start again.

### 3.3 What to send, what to keep

| Artefact | Where it lives | Retention |
|---|---|---|
| Raw export | customer environment or managed case folder, access-logged | 30 days, then delete |
| Redacted export | review workstation | duration of the engagement |
| Findings JSON | customer report + case folder | 12 months |
| Change requests | the customer's ITSM, not this tool | per customer policy |

If a customer cannot permit even a redacted config to leave their environment, run the container **inside** their estate and give them the findings only. The image is self-contained and needs no outbound network.

---

## 4. Standard run

```bash
export SECOPS_API_KEYS="$(openssl rand -hex 24)"
uvicorn app.main:app --port 8000
```

1. Confirm the export parses: the review must report a non-zero `rules` count. `422` here means the `config firewall policy` block is missing or the file was truncated during copy.
2. Submit:

```bash
curl -s localhost:8000/v1/review -H "x-api-key: $SECOPS_API_KEYS" \
  -H 'content-type: application/json' \
  -d "{\"config\": $(python -c 'import json;print(json.dumps(open("review.redacted.conf").read()))')}"
```

3. Work the findings in severity order. Critical first, always — an `any_any` accept rule invalidates the rest of the review until it is resolved.
4. Spot-check three findings against the config by hand before the report goes out. At least once per engagement, verify the `shadowed` finding: containment logic is the most complex check in the tool and the most damaging when it is wrong.
5. Send the report with the change requests, not as a findings dump.

---

## 5. Reading the findings

| Category | What you tell the customer |
|---|---|
| `any_any` | the rule makes every other restriction advisory; fix or disable it first |
| `management_exposed` | admin services reachable from the WAN; scope to management ranges or the VPN |
| `shadowed` | the rule cannot fire; it is either dead weight or a false sense of control |
| `undefined_object` | a referenced object is gone; confirm what the rule now matches before touching it |
| `broad_destination` | a service is open to every destination; narrow it to the application's real targets |
| `temporary_no_expiry` | the "temporary" rule is permanent in practice; give it an owner and a date |
| `dead_deny` | the intended deny never runs; move it above the accept rule |
| `duplicate` | two rules do the same thing; keep one and say which |

Severity is about blast radius, not effort. A `dead_deny` is low severity and still matters, because the customer believes a block exists that does not.

---

## 6. Suppressions — when a finding is acceptable

Some findings are correct and acceptable: a management rule scoped by an upstream jump host, a temporary rule mid-way through a migration.

**Do not edit the config to make the tool quiet.** Record the suppression instead:

1. Add the rule id and the category to the customer's exception register, with an owner, a justification and an expiry date.
2. Note it in the report as *known and accepted*, with the date.
3. Re-check at the expiry. An exception with no date is an unmanaged risk.

If a finding is a **false positive**, that is different: raise it with the service owner and attach the config fragment. False positives get fixed in the parser, not suppressed per customer.

---

## 7. Change-request lifecycle

Each finding carries `owner` and `expires_at` fields in the output. They start empty on purpose — the tool does not know the customer's organisation.

| Stage | What must be true |
|---|---|
| Raised | finding delivered with the report |
| Owned | a named person in the customer's team accepts it |
| Dated | a change window or an expiry, never "next quarter" |
| Closed | either the config changed (attach the rule before/after) or a dated exception was signed |
| Verified | re-run the review against the **new** export and confirm the finding is gone |

A finding is not closed because a ticket says "done". It is closed when a fresh export no longer produces it.

---

## 8. Failure modes

| Symptom | Likely cause | First response |
|---|---|---|
| `422 no 'config firewall policy' block found` | wrong section of the config, or truncated export | re-export the full configuration |
| `413 config exceeds 2 MB` | whole-estate export including all VDOMs and certificates | review per VDOM |
| findings reference objects that do exist | object defined in a VDOM or table the parser does not read | raise with the service owner; suppress per case until fixed |
| a shadowed finding looks wrong | negation, overlapping subnets, or routing the parser does not model | report as suspected false positive with the fragment; do not present it as fact |
| `change_request_source: template` | no provider configured, or the model named an unknown rule | normal; the template text is complete and safe to send |

---

## 9. Secrets and access

- API keys are per-engagement and destroyed at close-out.
- The service keeps no state between requests: no stored configs, no stored findings. The customer's data exists only for the duration of the call.
- Container runs non-root, read-only root filesystem, all capabilities dropped (§`docker-compose.yml`).
- If you enable the model provider, note that the prompt contains redacted policy lines. Redaction is therefore a precondition for using `use_model: true`, not a nice-to-have.

---

## 10. Known limits

- One policy table at a time; multi-VDOM estates need a review per VDOM, and cross-VDOM references are not resolved.
- No hit counts: the export does not carry `diagnose firewall iprope` output, so "unused" cannot be proven from a config file.
- The shadowing check is conservative set containment. It can miss coverage through negation or overlapping subnets; it is tuned to under-report rather than cry wolf.
- Dynamic objects, VIPs and security profiles are parsed as names only.
- This has not been run against a customer's live estate. First engagement is a supervised, hand-checked run.

---

## 11. Escalation

| Situation | Route |
|---|---|
| Suspected false positive | service owner with the config fragment and the rule id |
| Secret found in a report or case folder | customer security contact same day; rotate the credential; incident record |
| Customer wants the tool to modify the firewall | not in scope — route to change management |
| Parser does not understand a construct | service owner; do not hand-edit the output |
