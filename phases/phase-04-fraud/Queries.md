# Phase 04 - The Fraud: Queries

> Query log for Phase 04. Focus is the BEC: isolating the fraudulent banking-change message, reconstructing the impersonated thread, identifying the target, and separating attacker IPs from platform infrastructure.

---

## Q14 - The Fraudulent Request

**Purpose:** Locate the fraudulent banking-detail change email and capture its core metadata.

**KQL Query**
```kql
EmailEvents
| where TimeGenerated between (datetime(2026-06-10) .. datetime(2026-06-20))
| where Subject has "Updated Banking Details"
| project Timestamp, SenderFromAddress, SenderMailFromAddress,
          RecipientEmailAddress, Subject, SenderIPv4, NetworkMessageId
| order by Timestamp asc
```

**Expected Result:** The message **"Updated Banking Details - Pacific IT Monthly"** is returned with its sender, recipient, and sending IP.

**Pivot Produced:** Fraud subject + the recipient and sender-IP pivots.

**Investigation Value:** Anchors the entire fraud phase on a single identified message and exposes the IPs and recipient used in the following queries.

---

## Q15 - The Thread They Mimicked

**Purpose:** Reconstruct the conversation the attacker grafted onto, using the subject family and timeline.

**KQL Query**
```kql
EmailEvents
| where TimeGenerated between (datetime(2026-06-10) .. datetime(2026-06-20))
| where Subject has "Updated Banking Details"
| project Timestamp, Subject, SenderFromAddress, RecipientEmailAddress,
          SenderIPv4, DeliveryAction
| order by Timestamp asc
```

**Expected Result:** The ordered thread family, `Updated Banking Details` → `Re:` → `FW:` → `Undeliverable: FW...` at 04:13 / 12:40 / 12:41 / 12:42.

**Pivot Produced:** The mimicked thread and its timeline.

**Investigation Value:** Proves the fraud was built on an existing trusted conversation, the social-engineering core of the BEC.

---

## Q16 - The Fraud Target

**Purpose:** Identify who the fraudulent banking-change request was steered toward.

**KQL Query**
```kql
EmailEvents
| where Subject has "Updated Banking Details"
| where Subject !startswith "Undeliverable"
| summarize Messages = count(), FirstSeen = min(Timestamp)
        by RecipientEmailAddress
| order by Messages desc
```

**Expected Result:** The finance/payment recipient who received the banking-change instruction.

**Pivot Produced:** Fraud target (payment processor).

**Investigation Value:** Names the human the attacker is attempting to manipulate into authorizing fraud, the objective of the operation.

---

## Q17 - Second Channel Reinforcement

**Purpose:** Determine whether the deception was reinforced beyond the single email (additional forwards/replies or a collaboration-channel nudge).

**KQL Query**
```kql
EmailEvents
| where TimeGenerated between (datetime(2026-06-10) .. datetime(2026-06-20))
| where Subject has "Updated Banking Details"
| summarize Events = count() by Subject, SenderIPv4, bin(Timestamp, 1m)
| order by Timestamp asc
```

**Supporting (collaboration channel):**
```kql
CloudAppEvents
| where TimeGenerated between (datetime(2026-06-10) .. datetime(2026-06-20))
| where ActionType has_any ("ChatCreated", "MessageSent", "Send")
| where RawEventData has "banking" or RawEventData has "Updated Banking"
| project TimeGenerated, ActionType, AccountDisplayName, RawEventData
| order by TimeGenerated asc
```

**Expected Result:** The forward/reply/undeliverable cluster (and any chat signal) reinforcing the request within the same short window.

**Pivot Produced:** Reinforcement pattern (urgency/credibility mechanism).

**Investigation Value:** Demonstrates the attacker applied multi-touch pressure rather than a single email, raising the fraud's success probability.

---

### Supporting query: Sender IP attribution

**Purpose:** Separate attacker-originated sending IPs from Microsoft platform infrastructure (e.g., NDR responses).

**KQL Query**
```kql
EmailEvents
| where Subject has "Updated Banking Details"
| summarize Messages = count(), Subjects = make_set(Subject) by SenderIPv4
| order by Messages desc
```

**Expected Result:** `103.69.224.136` and `185.130.187.4` attributed to the attacker; `20.190.190.224` attributable to Microsoft service infrastructure (NDR).

**Pivot Produced:** Clean attacker-vs-infrastructure IP split.

**Investigation Value:** Prevents misattributing platform-generated mail to the actor and adds `185.130.187.4` as a second attacker pivot.
