# Phase 03 - Directory Recon

> **Investigation:** HUNT-08, Second Vector
> **Analyst:** Will-Garlens Pierre, SOC Analyst
> **Environment:** Log(N) Pacific, Microsoft Sentinel / Defender XDR
> **Phase Status:** Complete

## Objective

Document what the attacker did once inside the session. Identify the reconnaissance performed against the directory, specifically the profiling of user MFA posture and the enumeration of groups, and explain the operational purpose behind it. This phase establishes intent: the attacker was not browsing, they were target-selecting.

## Scope

- Directory and Graph activity attributable to the compromised session
- User-level MFA/authentication-method profiling
- Group enumeration
- No mail rule or exfiltration analysis yet, this phase covers the discovery stage only

## Data Sources

| Source | Role in this phase |
|---|---|
| `MicrosoftGraphActivityLogs` | Graph API read requests against `/users`, authentication-method endpoints, and `/groups` |
| `AuditLogs` | Directory read operations recorded by Azure AD where available |

## Findings Table

| Question | Finding | Evidence | Analyst Interpretation |
|---|---|---|---|
| Q12: MFA-Status Profiling | Attacker enumerated the MFA / authentication-method posture of directory users | Graph `GET` requests against user authentication-method endpoints during the compromised session | The attacker was identifying which accounts were weakly protected, the natural precursor to choosing a lateral or escalation target. Profiling MFA status is target qualification. |
| Q13: Group Enumeration | Attacker enumerated directory groups | Graph `GET` requests against `/groups` (and members) during the compromised session | Group enumeration reveals privilege structure, distribution lists, and finance/approval groupings, the map an attacker needs to understand blast radius and pick whom to impersonate. |

## Key Pivot Values

```
Recon type 1 : MFA / authentication-method profiling (per-user)
Recon type 2 : Group enumeration (privilege + distribution mapping)
Objective    : privilege discovery and blast-radius analysis
```

## Analyst Assessment

This phase is where the intrusion stops being opportunistic and becomes targeted. Two distinct reconnaissance behaviors appear in the compromised session: profiling individual users' MFA status, and enumerating groups.

Read together, they answer two attacker questions. MFA profiling answers *"who is easy to take next?"* Group enumeration answers *"who matters, and who can approve money or access?"* The objective is privilege discovery and blast-radius analysis, the attacker is building a target list. The selection that comes out of this recon is what drives Phase 04 (the fraud) and Phase 05 (persistence on the finance recipient). Recon here is the hinge between initial access and the fraud operation.

## Detection Opportunities

- **Bulk directory reads from a single session**, alert on a spike in Graph `GET /users` or `GET /groups` volume from one principal/session within a short window, especially from an anonymized source IP.
- **Authentication-method enumeration**, flag Graph reads against authentication-method / MFA-state endpoints performed by a non-administrative user, which is rarely legitimate.
- **Recon-to-action chaining**, correlate a directory-enumeration burst with a subsequent inbox-rule creation or anomalous mail send from the same session (the Phase 03 → 04/05 pivot).

## MITRE ATT&CK Mapping

| Technique | ID | Justification |
|---|---|---|
| Account Discovery: Cloud Account | T1087.004 | Enumeration and profiling of directory users, including MFA posture |
| Permission Groups Discovery: Cloud Groups | T1069.003 | Enumeration of Azure AD / cloud groups to map privilege and distribution structure |

## Response Considerations

- Treat the enumerated users and groups as a potential secondary target list; prioritize monitoring and protective controls on finance/approval groups surfaced during recon.
- The recon was conducted through legitimate Graph calls on a valid token, another reason session revocation is required to stop the activity at its source.
- Feed the enumerated finance recipient(s) into Phase 05 monitoring for inbox-rule tampering.
