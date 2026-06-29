# Phase 08 - Correlation and Containment

> **Investigation:** HUNT-08, Second Vector
> **Analyst:** Will-Garlens Pierre, SOC Analyst
> **Environment:** Log(N) Pacific, Microsoft Sentinel / Defender XDR
> **Phase Status:** Complete

## Objective

Tie the intrusion together into one actor and one operation, then define the correct containment. Identify the automation's source IP and identity, name the abused service, prove a single actor touched the environment across many telemetry sources, and establish the containment ordering, including the control that should have stopped this and why session revocation must come before password reset.

## Scope

- Automation source-IP and identity attribution
- Service abuse identification (Power Automate)
- Single-actor correlation across in-scope telemetry tables
- Containment sequencing and control-gap analysis

## Data Sources

| Source | Role in this phase |
|---|---|
| `MicrosoftGraphActivityLogs` | Automation source IP and the mail-driving Graph requests |
| `SigninLogs` | App-ID resolution and Conditional Access status |
| `search "<IP>"` (cross-table) | Single-actor correlation across all in-scope tables |

## Findings Table

| Question | Finding | Evidence | Analyst Interpretation |
|---|---|---|---|
| Q30: The Automation Source IP | **`20.150.129.194`** | `MicrosoftGraphActivityLogs` `POST` requests to mail endpoints (forward/sendMail/messages) | The automation ran from a Microsoft/Azure service IP, distinct from the human attacker IP. This is the machine half of the operation, where the planted flow executed. |
| Q31: The Automation Identity | App ID **`7ab7862c-4c57-491e-8a45-d52a7e023983`** | Resolved from `SigninLogs` by `AppId` | The flow ran as a specific application identity. Naming the App ID is what makes targeted removal and tenant-wide hunting possible. |
| Q32: The Abused Service | **Microsoft Power Automate** | App-ID resolution + Flow Portal attribution from Phase 07 | The attacker weaponized a legitimate, sanctioned platform service. The abuse hides inside normal-looking platform telemetry, which is why it survived earlier review. |
| Q33: One Actor, Every Source | Attacker IP `103.69.224.136` appears in **7** in-scope telemetry tables | Cross-table `search` for the IP across the incident window | One source IP threading through seven distinct tables is the correlation proof that this is a single coordinated actor, not unrelated noise. |
| Q34: Containment Ordering | **Revoke sessions** first | Session persistence established in Phase 02 (live refresh token) | The live session is the active foothold. Revoking it first stops ongoing access before any other step. |
| Q35: Where the Flow Is Removed | **Power Platform Admin Center** | Service location for managing/removing Power Automate flows | The malicious flow is not removed from Exchange or Entra, it lives in the Power Platform, so containment must reach into that admin plane. |
| Q36: The Control That Never Fired | Conditional Access **not applied**, so sign-ins succeeded | `ConditionalAccessStatus == notApplied` in `SigninLogs` | The one control positioned to break this chain never evaluated the sign-ins. Its absence is the through-line from Phase 02 to the full compromise. |
| Q37: Why Revoke Before Reset | **Active sessions survive a password reset** | Refresh-token persistence (Phase 02) + automation running on delegated authority | A password reset alone leaves issued refresh tokens valid and the flow running. Revoke sessions first, then reset, order is the difference between containment and a false sense of it. |

## Key Pivot Values

```
Automation IP        : 20.150.129.194
Automation App ID    : 7ab7862c-4c57-491e-8a45-d52a7e023983
Abused service       : Microsoft Power Automate
Actor correlation    : 103.69.224.136 across 7 in-scope tables
Flow removal plane   : Power Platform Admin Center
Containment order    : revoke sessions -> remove flow -> reset password
Control gap          : Conditional Access notApplied
```

## Analyst Assessment

Phase 08 closes the loop on both attribution and response.

**One actor.** The human attacker IP `103.69.224.136` appears across seven distinct in-scope telemetry tables, and the automation runs from `20.150.129.194` under App ID `7ab7862c-4c57-491e-8a45-d52a7e023983`, identified as **Microsoft Power Automate**. The attacker abused a sanctioned platform service to run a flow that drove mail actions automatically, which is why the activity blended into normal platform telemetry and why naming the App ID matters: it converts "something automated did this" into a specific, removable object.

**Correct containment, in order.** The single most important response finding in this investigation is sequencing. Because the foothold is a live refresh token (Phase 02) and a flow running on delegated authority (Phase 07), a password reset performed first would leave both intact, the attacker keeps their session and the flow keeps forwarding mail. The correct order is: **revoke sessions first** to kill the live token, **remove the flow** in the Power Platform Admin Center, then **reset the password** (and rotate the stolen VPN credentials from Phase 06). Conditional Access, the control that should have forced re-authentication and blocked the anonymized source, was `notApplied` throughout, which is the structural gap that allowed the entire chain.

## Detection Opportunities

- **Power Automate mail abuse**, alert on flow/automation app identities performing mail `POST` operations (forward/sendMail) through Graph, particularly on finance mailboxes.
- **Single-IP cross-table correlation**, scheduled analytic that counts the number of distinct tables a risk-flagged IP appears in; a single IP spanning many tables is a strong coordinated-actor signal.
- **CA coverage assurance**, continuous report of successful sign-ins with `ConditionalAccessStatus == notApplied` for sensitive user populations, treated as control failures rather than informational.

## MITRE ATT&CK Mapping

| Technique | ID | Justification |
|---|---|---|
| Serverless Execution | T1648 | Abuse of Microsoft Power Automate to execute mail actions as a flow |
| Valid Accounts: Cloud Accounts | T1078.004 | Operation conducted under the compromised cloud identity and its delegated app authority |
| Use Alternate Authentication Material: Web Session Cookie | T1550.004 | Live refresh-token session that survives password reset, driving the containment order |

## Response Considerations: Containment Runbook

1. **Revoke all sessions** for `m.smith@lognpacific.org` (and any identity tied to the flow) to invalidate live refresh tokens, *do this first*.
2. **Remove the malicious flow** in the **Power Platform Admin Center**; disable/delete the offending Power Automate automation (App ID `7ab7862c-4c57-491e-8a45-d52a7e023983`).
3. **Reset the password** for the compromised identity *after* sessions are revoked.
4. **Remove the inbox rules** on `j.reynolds@lognpacific.org` ("Invoice Processing" + external forward to `merovingian1337@proton.me`).
5. **Rotate the stolen VPN credentials** (`VPN-Access-Credentials.txt`) and secure whatever `yomark.pdf` points to.
6. **Close the control gap**, apply Conditional Access requiring MFA / blocking anonymized sources / enforcing sign-in frequency for this user class.
7. **Block IOCs**, `103.69.224.136`, `185.130.187.4`, `merovingian1337@proton.me`; retro-hunt the automation IP `20.150.129.194` and App ID across the tenant.
8. **Re-open and audit** the originally dismissed risk detections (Phase 01) and review the triage decision.
