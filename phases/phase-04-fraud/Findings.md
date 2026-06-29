# Phase 04 - The Fraud

> **Investigation:** HUNT-08, Second Vector
> **Analyst:** Will-Garlens Pierre, SOC Analyst
> **Environment:** Log(N) Pacific, Microsoft Sentinel / Defender XDR
> **Phase Status:** Complete

## Objective

Reconstruct the business email compromise (BEC) at the center of the intrusion. Identify the fraudulent request, the legitimate thread it was built on top of, the target of the fraud, and how the attacker reinforced the deception. This phase establishes the *motive*, financial fraud via a banking-detail change, and the social engineering scaffold that made it credible.

## Scope

- Mail flow involving the "Updated Banking Details" subject family
- Historical payment-thread reconnaissance
- Thread reconstruction and timeline of the impersonated conversation
- Sender IP analysis to separate attacker-originated mail from infrastructure responses
- Second-channel reinforcement through Microsoft Teams
- No persistence-rule or download analysis, those are Phases 05 and 06

## Data Sources

| Source | Role in this phase |
|---|---|
| `EmailEvents` | Sender/recipient, subject, timestamp, and sender IP for the fraud thread |
| `EmailUrlInfo` / `EmailAttachmentInfo` | Supporting detail on payload content where present |
| `CloudAppEvents` | Second-channel reinforcement signals, including Teams/collaboration activity |

## Findings Table

| Question | Finding | Evidence | Analyst Interpretation |
|---|---|---|---|
| Q14: The Fraudulent Request | Email subject **"Updated Banking Details - Pacific IT Monthly"** | `EmailEvents` record for the attacker-sent message | This is the payload of the entire intrusion, a request to change banking/payment details, the classic BEC pivot from access to money. |
| Q15: The Thread They Mimicked | **`Q1 Vendor Payment Schedule - Review Required`** | Historical payment workflow thread reviewed before the fraud message | The attacker did not invent the fraud from nothing. They studied a legitimate vendor payment workflow and reused that business context to make the banking-detail request believable. |
| Q16: The Fraud Target | **`j.reynolds@lognpacific.org`** | Recipient address on the fraudulent message and later persistence target | The target was the finance/payment recipient who could act on a "new bank details" instruction. This is the human the attacker tried to steer toward authorizing fraud. |
| Q17: Second Channel Reinforcement | **Microsoft Teams** | Collaboration activity around the same fraud window | The attacker reinforced the deception outside the email thread. Using Teams added urgency and credibility because the request appeared to come through normal internal collaboration channels. |

## Email Timeline

| Time | Event | Interpretation |
|---|---|---|
| 04:13 | Original message | The "Updated Banking Details" fraud message enters the mail timeline. |
| 12:40 | Reply (`Re:`) | Conversation continuity established on the trusted thread. |
| 12:41 | Forward (`FW:`) | The banking-change instruction is propagated onward. |
| 12:42 | Undeliverable (`Undeliverable: FW...`) | A non-delivery response confirms attempted onward send and exposes routing/recipient detail. |

## Sender IPv4 Values Observed

| IP | Role |
|---|---|
| `103.69.224.136` | Attacker IP, the master pivot from Phase 01, now seen originating fraud mail |
| `185.130.187.4` | Secondary attacker-associated sending infrastructure |
| `20.190.190.224` | Microsoft service range, consistent with platform-generated responses such as the undeliverable/NDR, not attacker-originated |

## Key Pivot Values

```
Fraud subject     : Updated Banking Details - Pacific IT Monthly
Mimicked thread   : Q1 Vendor Payment Schedule - Review Required
Fraud target      : j.reynolds@lognpacific.org
Second channel    : Microsoft Teams
Attacker mail IPs : 103.69.224.136, 185.130.187.4
Platform IP       : 20.190.190.224 (NDR / service infrastructure)
Motive            : banking-detail change fraud (BEC)
```

## Analyst Assessment

This is the operation the access was for. Everything in Phases 01-03 was setup; Phase 04 is the act.

The attacker ran a BEC operation by studying a legitimate vendor payment workflow, `Q1 Vendor Payment Schedule - Review Required`, then issuing `Updated Banking Details - Pacific IT Monthly` to `j.reynolds@lognpacific.org`. Reusing real payment context means the fraudulent banking instruction arrived wrapped in business legitimacy the target already understood.

The sender-IP split is analytically important: `103.69.224.136` and `185.130.187.4` are attacker-originated, while `20.190.190.224` falls in Microsoft's range and corresponds to platform responses such as the undeliverable notice. Keeping those separated prevents misattributing infrastructure noise to the actor.

The Microsoft Teams reinforcement increased the credibility of the fraud. This phase also sets up Phase 05: to make the fraud succeed, the attacker needed `j.reynolds` to miss verification or pushback, which is exactly what the persistence rules in the next phase were designed to accomplish.

## Detection Opportunities

- **Banking-change thread detection**, alert on inbound/outbound mail whose subject matches payment/banking-change language ("updated banking details", "new account number", "remittance change"), especially when correlated to a recently risk-flagged sender.
- **Historical payment-thread replay**, flag users who read or interact with older payment workflow threads shortly before sending new banking-detail changes.
- **Same-thread, new-sender-IP**, flag when a message in an existing thread is sent from an IP never previously associated with that conversation's participants.
- **BEC plus Teams reinforcement**, correlate finance-themed email activity with Teams messages or collaboration activity from the same compromised user.
- **NDR mining**, use `Undeliverable`/NDR events as a signal that an attacker is fanning a forwarded message to additional external recipients.

## MITRE ATT&CK Mapping

| Technique | ID | Justification |
|---|---|---|
| Internal Spearphishing | T1534 | Use of the compromised internal mailbox to push a fraudulent request to an internal target |
| Impersonation | T1656 | Reusing trusted payment workflow context to impersonate a legitimate banking-details conversation |
| Email Collection | T1114 | Reading and reusing existing mail content to build a credible fraud |

## Response Considerations

- Notify `j.reynolds@lognpacific.org` and any payment-processing function immediately; place a hold on any banking-detail change tied to this thread until independently verified out-of-band.
- Preserve the full email and Teams thread evidence for the case record before cleanup.
- Cross-reference `185.130.187.4` against the tenant the same way `103.69.224.136` is treated in Phase 08, it is a second attacker pivot.