# Phase 04 - The Fraud

> **Investigation:** HUNT-08, Second Vector
> **Analyst:** Will-Garlens Pierre, SOC Analyst
> **Environment:** Log(N) Pacific, Microsoft Sentinel / Defender XDR
> **Phase Status:** Complete

## Objective

Reconstruct the business email compromise (BEC) at the center of the intrusion. Identify the fraudulent request, the legitimate thread it was built on top of, the target of the fraud, and how the attacker reinforced the deception. This phase establishes the *motive*, financial fraud via a banking-detail change, and the social engineering scaffold that made it credible.

## Scope

- Mail flow involving the "Updated Banking Details" subject family
- Thread reconstruction and timeline of the impersonated conversation
- Sender IP analysis to separate attacker-originated mail from infrastructure responses
- No persistence-rule or download analysis, those are Phases 05 and 06

## Data Sources

| Source | Role in this phase |
|---|---|
| `EmailEvents` | Sender/recipient, subject, timestamp, and sender IP for the fraud thread |
| `EmailUrlInfo` / `EmailAttachmentInfo` | Supporting detail on payload content where present |
| `CloudAppEvents` | Second-channel reinforcement signals (e.g., chat/collaboration) |

## Findings Table

| Question | Finding | Evidence | Analyst Interpretation |
|---|---|---|---|
| Q14: The Fraudulent Request | Email subject **"Updated Banking Details - Pacific IT Monthly"** | `EmailEvents` record for the attacker-sent message | This is the payload of the entire intrusion, a request to change banking/payment details, the classic BEC pivot from access to money. |
| Q15: The Thread They Mimicked | A legitimate recurring payment conversation, reused as the parent thread | Forwarded chain: `Updated Banking Details` → `Re: Updated Banking Details` → `FW: Updated Banking Details` → `Undeliverable: FW Updated Banking Details` | The attacker did not invent a new thread, they grafted the fraud onto an existing, trusted payment conversation so it inherited legitimacy. Thread mimicry is what defeats recipient suspicion. |
| Q16: The Fraud Target | The finance/payment recipient of the banking-change request _(populate the exact recipient address from your query output)_ | Recipient address on the fraudulent message | The target is whoever processes payments, the person who can act on a "new bank details" instruction. This is the human the attacker is steering toward authorizing fraud. |
| Q17: Second Channel Reinforcement | The deception was reinforced beyond the single email | Forward + reply activity and supporting collaboration signal around the same window | Attackers reinforce BEC across channels/messages to add urgency and credibility. The repeated forward/reply pattern is the reinforcement that pressures the target to act. |

## Email Timeline

| Time | Event | Interpretation |
|---|---|---|
| 04:13 | Original message | The legitimate (or seed) "Updated Banking Details" message, the thread root. |
| 12:40 | Reply (`Re:`) | Conversation continuity established on the trusted thread. |
| 12:41 | Forward (`FW:`) | Attacker propagates the banking-change instruction onward. |
| 12:42 | Undeliverable (`Undeliverable: FW...`) | A non-delivery response, confirming an attempted onward send and exposing routing/recipient detail. |

## Sender IPv4 Values Observed

| IP | Role |
|---|---|
| `103.69.224.136` | Attacker IP, the master pivot from Phase 01, now seen originating fraud mail |
| `185.130.187.4` | Secondary attacker-associated sending infrastructure |
| `20.190.190.224` | Microsoft service range, consistent with platform-generated responses (e.g., the undeliverable/NDR), not attacker-originated |

## Key Pivot Values

```
Fraud subject     : Updated Banking Details - Pacific IT Monthly
Thread family     : Updated Banking Details (Re / FW / Undeliverable)
Attacker mail IPs : 103.69.224.136, 185.130.187.4
Platform IP       : 20.190.190.224 (NDR / service infrastructure)
Motive            : banking-detail change fraud (BEC)
```

## Analyst Assessment

This is the operation the access was for. Everything in Phases 01-03 was setup; Phase 04 is the act.

The attacker ran a textbook BEC: rather than fabricating a cold request, they hijacked an existing, trusted "Updated Banking Details" payment thread and continued it with reply/forward activity. Reusing a real conversation means the fraudulent banking instruction arrives wrapped in legitimacy the target already accepts. The sender-IP split is analytically important, `103.69.224.136` and `185.130.187.4` are attacker-originated, while `20.190.190.224` falls in Microsoft's range and corresponds to platform responses such as the undeliverable notice. Keeping those separated prevents misattributing infrastructure noise to the actor.

The fraud target is the payment processor on the receiving end of the banking change. The reinforcement across the forward/reply chain is the pressure mechanism. This phase also sets up Phase 05: to make the fraud succeed, the attacker needs the legitimate finance contact (`j.reynolds`) to *not* see verification or pushback, which is exactly what the persistence rules in the next phase accomplish.

## Detection Opportunities

- **Banking-change thread detection**, alert on inbound/outbound mail whose subject matches payment/banking-change language ("updated banking details", "new account number", "remittance change"), especially when correlated to a recently risk-flagged sender.
- **Same-thread, new-sender-IP**, flag when a message in an existing thread is sent from an IP never previously associated with that conversation's participants.
- **NDR mining**, use `Undeliverable`/NDR events as a signal that an attacker is fanning a forwarded message to additional external recipients.

## MITRE ATT&CK Mapping

| Technique | ID | Justification |
|---|---|---|
| Internal Spearphishing | T1534 | Use of the compromised internal mailbox to push a fraudulent request to other internal targets |
| Impersonation | T1656 | Hijacking a trusted payment thread to impersonate a legitimate banking-details conversation |
| Email Collection | T1114 | Reading and reusing existing mail content to build a credible fraud |

## Response Considerations

- Notify the fraud target and any payment-processing function immediately; place a hold on any banking-detail change tied to this thread until independently verified out-of-band.
- Preserve the full thread family and NDR for the case record before any cleanup.
- Cross-reference `185.130.187.4` against the tenant the same way `103.69.224.136` is treated in Phase 08, it is a second attacker pivot.
