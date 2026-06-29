# Phase 07 - The Plant and the Trigger

> **Investigation:** HUNT-08, Second Vector
> **Analyst:** Will-Garlens Pierre, SOC Analyst
> **Environment:** Log(N) Pacific, Microsoft Sentinel / Defender XDR
> **Phase Status:** Complete

## Objective

Disprove the "innocent user" explanation for the malicious mail behavior and prove it was machine-driven. Identify the automation that was planted, the telemetry that explains the forward, and the time-ordered sequence that proves an API call, not a human at a keyboard, triggered the mail event. This phase is where correlation turns suspicion into evidence.

## Scope

- Sign-in evidence used to rule out a legitimate interactive MFA login
- Identification of the automation application behind the activity
- Determination of the telemetry table that explains the forward
- Time-sequence proof linking the Graph call to the mail event

## Data Sources

| Source | Role in this phase |
|---|---|
| `SigninLogs` | Successful-MFA count (used to disprove a human login) and the automation app name |
| `MicrosoftGraphActivityLogs` | The Graph API call that caused the forward, with precise timestamps |
| `search *` (table discovery) | Identifying which table carries the responsible telemetry |

## Findings Table

| Question | Finding | Evidence | Analyst Interpretation |
|---|---|---|---|
| Q26: Disprove the Innocent Explanation | Successful MFA count = **0** | No `SigninLogs` records show a completed MFA at the time of the malicious mail behavior | If no one passed MFA, no human interactively performed the action. The "the user just forwarded an email" explanation is eliminated by the absence of a legitimate authenticated session. |
| Q27: Catch the Plant | **Microsoft Flow Portal** | App attribution in `SigninLogs` for the automation activity | The activity is attributable to an automation application, not the user's mail client. Something was *planted* to act on the attacker's behalf. |
| Q28: The Cause Behind the Forward | **`MicrosoftGraphActivityLogs`** | Table-discovery sweep identifies the table holding the responsible API call | The mail event was driven through Microsoft Graph. The forward's cause lives in Graph activity, not in mailbox-client telemetry, which is why surface-level mail review would miss it. |
| Q29: Prove It With The Sequence | Graph API call occurred **before** the mail event | Time-ordered `MicrosoftGraphActivityLogs` showing the Graph request preceding the resulting mail action | Cause precedes effect. The API call firing immediately before the mail event is the proof that automation triggered the forward, closing the loop on Q26. |

## Key Pivot Values

```
Successful MFA count : 0  (no human login at the time)
Automation app       : Microsoft Flow Portal
Responsible table    : MicrosoftGraphActivityLogs
Sequence proof       : Graph API call -> THEN mail event (cause before effect)
```

## Analyst Assessment

This phase is the analytical hinge of the whole investigation. The obvious story, "a logged-in user forwarded an email", collapses under two facts: there were **zero** successful MFA events at the time, and the activity is attributed to the **Microsoft Flow Portal**, an automation application, rather than to an interactive sign-in.

From there the proof is built on ordering. The responsible telemetry is not in the mailbox client logs; it is in `MicrosoftGraphActivityLogs`, which captures the Graph API call that actually drove the forward. When that table is sorted by time, the Graph request lands *before* the resulting mail event. Cause precedes effect. A human did not do this, a planted automation did, executing through Graph on a token the attacker controlled.

This is the difference between a SOC analyst who reads the mailbox and one who proves the mechanism. The forward looked like a user action; the telemetry shows it was serverless automation firing on an API call.

## Detection Opportunities

- **Mail action without a sign-in**, alert when a mail forward/send occurs for a user with no corresponding successful interactive (MFA-satisfied) sign-in in the surrounding window.
- **Automation-app mail activity**, flag mail operations attributed to automation apps (Microsoft Flow Portal / Power Automate) on user mailboxes, especially finance mailboxes.
- **Graph-to-mail sequence rule**, correlate a Graph `POST` to a mail endpoint immediately followed by a mailbox mail event from the same identity as a high-confidence automated-exfiltration signal.

## MITRE ATT&CK Mapping

| Technique | ID | Justification |
|---|---|---|
| Serverless Execution | T1648 | A planted Power Automate / Flow automation executed mail actions without interactive logon |
| Email Collection: Email Forwarding Rule | T1114.003 | The automation drove forwarding of mail to an attacker-controlled destination |
| Valid Accounts: Cloud Accounts | T1078.004 | Automation executed under the compromised cloud identity's authority |

## Response Considerations

- The forward will keep happening until the automation is removed, disabling the user or resetting the password does not stop a flow running on a service principal's authority. Removal is handled in Phase 08 (Power Platform Admin Center).
- Preserve the `MicrosoftGraphActivityLogs` sequence as the evidentiary core of the case; it is what proves intent and mechanism.
- Treat the Flow Portal attribution as the bridge into Phase 08's automation-identity and app-ID findings.
