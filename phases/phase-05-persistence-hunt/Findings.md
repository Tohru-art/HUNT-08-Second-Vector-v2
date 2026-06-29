# Phase 05 - Persistence Hunt

> **Investigation:** HUNT-08, Second Vector
> **Analyst:** Will-Garlens Pierre, SOC Analyst
> **Environment:** Log(N) Pacific, Microsoft Sentinel / Defender XDR
> **Phase Status:** Complete

## Objective

Find the mechanisms the attacker put in place to keep the fraud alive after the initial send. Identify the mailbox rules used to conceal verification mail and to forward sensitive mail externally, determine what those rules did with the messages, and confirm whose mailbox was targeted. This phase explains how the attacker controlled what the finance contact could and could not see.

## Scope

- Mailbox/inbox rule creation and modification events
- Rule logic: move/conceal vs. external forward
- Targeted mailbox attribution
- No file-download analysis, that is Phase 06

## Data Sources

| Source | Role in this phase |
|---|---|
| `CloudAppEvents` | Inbox-rule create/modify operations (`New-InboxRule`, `Set-InboxRule`, `UpdateInboxRules`) and their parameters |
| `OfficeActivity` | Exchange audit corroboration for rule operations where present |

## Findings Table

| Question | Finding | Evidence | Analyst Interpretation |
|---|---|---|---|
| Q18: The Concealment Rule | Mailbox rule named **"Invoice Processing"** | Inbox-rule create/modify event carrying the rule name and conditions | The benign-sounding name is deliberate camouflage. A rule called "Invoice Processing" hides in plain sight in a finance mailbox while it suppresses verification mail. |
| Q19: Where the Hidden Mail Goes | Messages were **moved to a hidden folder** via a move action, not deleted | Rule action specifies a move to a low-visibility/hidden folder rather than a delete | Moving (not deleting) is quieter, the mail still "exists," so nothing looks lost, but it is routed into a hidden folder out of the inbox where the user would notice it. Concealment over destruction. |
| Q20: The Exfiltration Rule | External forwarding to **`merovingian1337@proton.me`** | Inbox rule with an external `ForwardTo` action targeting the Proton address | A second rule quietly copies sensitive mail to an attacker-controlled external mailbox, live exfiltration of correspondence, independent of the concealment rule. |
| Q21: The Both-Rules Target | **`j.reynolds@lognpacific.org`** | Both rules were created on the `j.reynolds` mailbox | The legitimate finance contact is the target. Concealing his verification mail and forwarding his correspondence externally is precisely what lets the Phase 04 fraud proceed unchallenged. |

## Key Pivot Values

```
Concealment rule  : "Invoice Processing"  (action: move to folder)
Exfil rule        : external ForwardTo -> merovingian1337@proton.me
Targeted mailbox  : j.reynolds@lognpacific.org
Persistence goal  : suppress payment-verification mail + exfiltrate correspondence
```

## Analyst Assessment

The two rules are a matched pair, and together they are the persistence backbone of the fraud.

The "Invoice Processing" rule is concealment: it moves payment-verification and pushback mail out of `j.reynolds`'s inbox so the legitimate finance contact never sees the messages that would expose the banking-detail change as fraudulent. The forwarding rule is exfiltration: it copies his correspondence to `merovingian1337@proton.me`, an attacker-controlled external mailbox. One rule blinds the victim; the other keeps the attacker informed. Critically, the attacker chose to *move* rather than *delete*, quieter, reversible-looking, and less likely to trigger "where did my mail go?" suspicion.

This is also the phase that ties the operation to a specific named victim. By landing both rules on `j.reynolds`, the attacker is controlling the exact information channel the Phase 04 fraud depends on. Persistence here is not about re-entry, it is about keeping the fraud invisible long enough to complete.

## Detection Opportunities

- **New external-forwarding inbox rule**, high-fidelity alert on `New-InboxRule`/`Set-InboxRule` containing a `ForwardTo`/`RedirectTo` to an external domain (Proton, Gmail, etc.). This single detection would have caught the exfil rule immediately.
- **Concealment-pattern rules**, alert on inbox rules that move/mark-as-read mail matching finance keywords ("invoice", "payment", "banking", "verify") into non-default folders.
- **Rule creation from a risky session**, correlate inbox-rule changes with a source IP or session already carrying a risk detection (ties back to `103.69.224.136`).

## MITRE ATT&CK Mapping

| Technique | ID | Justification |
|---|---|---|
| Email Collection: Email Forwarding Rule | T1114.003 | External forwarding rule copying mail to `merovingian1337@proton.me` |
| Hide Artifacts: Email Hiding Rules | T1564.008 | "Invoice Processing" rule moving verification mail out of the visible inbox |
| Account Manipulation | T1098 | Modification of mailbox configuration to maintain attacker control of the mail channel |

## Response Considerations

- Remove both inbox rules from `j.reynolds` and audit the mailbox for any additional rules, delegates, or forwarding configured during the compromise window.
- Block/deny outbound forwarding to `proton.me` (or external domains broadly) for finance mailboxes, and review tenant-wide auto-forwarding policy.
- Recover the moved verification mail from the destination folder for the case record and to confirm what the victim was prevented from seeing.
- Add `merovingian1337@proton.me` to the IOC list for blocking and retro-hunting.
