# Phase 01 - Triage

> **Investigation:** HUNT-08, Second Vector
> **Analyst:** Will-Garlens Pierre, SOC Analyst
> **Environment:** Log(N) Pacific, Microsoft Sentinel / Defender XDR
> **Phase Status:** Complete

## Objective

Establish the entry point of the incident. Identify which identity was compromised, the source of the malicious activity, and whether the organization's identity protection controls recognized the threat or allowed it to persist. This phase answers the first analyst question of any intrusion: *who, from where, and did anything catch it?*

## Scope

- Single tenant: `lognpacific.org`
- Identity-layer telemetry only (sign-ins and Identity Protection risk events)
- Time window aligned to the first observed risk detections against the principal in scope
- No endpoint or mail analysis at this stage, triage is intentionally narrow to confirm the foothold before expanding

## Data Sources

| Source | Role in this phase |
|---|---|
| `AADUserRiskEvents` | Identity Protection risk detections, risk type, and verdict (state) |
| `SigninLogs` | Interactive sign-in records, source IP, client OS, result codes |
| `IdentityInfo` | Account state (enabled/disabled) at time of investigation |

## Findings Table

| Question | Finding | Evidence | Analyst Interpretation |
|---|---|---|---|
| Q01: The Compromised Principal | `m.smith@lognpacific.org` | Principal carrying the cluster of Identity Protection risk detections | This account is the foothold. All downstream activity should be pivoted from this UPN. |
| Q02: The Flagged Source | `103.69.224.136` | Source IP attached to the risk detections and risky sign-ins for the principal | Primary attacker IP. Becomes the master pivot for the entire investigation. |
| Q03: The Client OS | Linux | `DeviceDetail.operatingSystem` on the sign-ins from the flagged IP | The principal is a corporate user, a Linux client from an unmanaged host is an environmental anomaly consistent with attacker tooling, not the user's normal device. |
| Q04: The Stored Detection Type | `anonymizedIPAddress` | `RiskEventType` recorded in `AADUserRiskEvents` | Identity Protection saw the sign-in originate from an anonymizing service (VPN/Tor/proxy). The signal existed; the question is what was done with it. |
| Q05: Audit to Verdict | `dismissed` | Majority `RiskState` across the principal's risk detections | The detections were generated but triaged away. The control fired and was overridden, a process gap, not a visibility gap. |
| Q06: Live Exposure | Account remained **Enabled** | `AccountEnabled = true` in `IdentityInfo` | At the point of triage the compromised identity was still active and usable. The foothold was live, not historical. |

## Key Pivot Values

```
Compromised UPN : m.smith@lognpacific.org
Attacker IP      : 103.69.224.136
Client OS        : Linux
Risk type        : anonymizedIPAddress
Risk verdict     : dismissed
Account state    : Enabled
```

## Analyst Assessment

The compromise of `m.smith@lognpacific.org` was not a failure of detection, it was a failure of response. Identity Protection correctly flagged sign-ins from an anonymized IP (`103.69.224.136`) on an out-of-profile Linux client. The risk detections were generated and then **dismissed**, and the account was left **enabled**.

This is the most important framing for the rest of the investigation: the attacker did not defeat the tooling. The tooling produced the signal, an analyst (or an auto-remediation gap) closed it, and the door stayed open. Everything that follows in Phases 02-08 happened in the window this dismissal created.

## Detection Opportunities

- **Risk-event dismissal monitoring**, alert when an Identity Protection risk detection of type `anonymizedIPAddress` (or any high-confidence type) is dismissed without an associated remediation action (password reset / session revocation) within N minutes.
- **OS-profile anomaly**, baseline each principal's normal client OS from `SigninLogs.DeviceDetail`; alert on first-seen OS for privileged or finance-adjacent users.
- **Anonymized-IP sign-in success**, alert specifically when a sign-in tagged `anonymizedIPAddress` returns `ResultType == 0` (success) rather than treating risk as informational.

## MITRE ATT&CK Mapping

| Technique | ID | Justification |
|---|---|---|
| Valid Accounts: Cloud Accounts | T1078.004 | Authentication using legitimate `m.smith` credentials against the cloud tenant |
| Proxy: Multi-hop Proxy | T1090.003 | Source identified by Identity Protection as an anonymized (VPN/Tor/proxy) address |

## Response Considerations

- The dismissed risk detections should be re-opened and the original triage decision audited, who dismissed them and on what basis.
- `m.smith` should be treated as compromised from the first anonymized sign-in forward, not from the date of this hunt.
- Containment is deferred to Phase 08 by design, but note here: because the account is still enabled and sessions may still be live, **session revocation must precede password reset** (proved out in Q37).
