# Phase 04 - The Fraud: Queries

> Query log for Phase 04. These queries identify the fraudulent banking request, the payment thread it mimicked, the fraud target, second-channel reinforcement, and sender IP attribution.

---

## Q14 - The Fraudulent Request

**Purpose:** Locate the fraudulent banking-detail change message.

**KQL Query**
```kql
EmailEvents
| where Subject has "Updated Banking Details"
| project Timestamp,
          SenderFromAddress,
          SenderMailFromAddress,
          RecipientEmailAddress,
          Subject,
          SenderIPv4,
          NetworkMessageId
| order by Timestamp asc
```

**Expected Result:** `Updated Banking Details - Pacific IT Monthly`

**Pivot Produced:** Fraud subject and message metadata.

**Investigation Value:** Establishes the main BEC payload.

---

## Q15 - The Thread They Mimicked

**Purpose:** Find the legitimate payment workflow thread the attacker used as context.

**KQL Query**
```kql
EmailEvents
| where Subject has_any ("Vendor Payment", "Payment Schedule", "Review Required", "Q1")
| project Timestamp,
          Subject,
          SenderFromAddress,
          RecipientEmailAddress,
          SenderIPv4,
          NetworkMessageId
| order by Timestamp asc
```

**Expected Result:** `Q1 Vendor Payment Schedule - Review Required`

**Pivot Produced:** Mimicked payment thread.

**Investigation Value:** Shows the attacker studied existing payment workflow context before sending the fraud request.

---

## Q16 - The Fraud Target

**Purpose:** Identify who received the fraudulent banking-details request.

**KQL Query**
```kql
EmailEvents
| where Subject == "Updated Banking Details - Pacific IT Monthly"
| project Timestamp,
          Subject,
          SenderFromAddress,
          RecipientEmailAddress,
          SenderIPv4,
          NetworkMessageId
| order by Timestamp asc
```

**Expected Result:** `j.reynolds@lognpacific.org`

**Pivot Produced:** Fraud target, `j.reynolds@lognpacific.org`.

**Investigation Value:** Connects the fraud request to the finance target later impacted by mailbox rules.

---

## Q17 - Second Channel Reinforcement

**Purpose:** Identify the channel used to reinforce the fraud outside the email thread.

**KQL Query**
```kql
CloudAppEvents
| where Application has "Teams"
    or RawEventData has "Microsoft Teams"
    or RawEventData has "j.reynolds@lognpacific.org"
| project Timestamp,
          Application,
          ActionType,
          AccountDisplayName,
          RawEventData
| order by Timestamp asc
```

**Expected Result:** `Microsoft Teams`

**Pivot Produced:** Second channel, `Microsoft Teams`.

**Investigation Value:** Shows the attacker reinforced the BEC through a trusted collaboration channel.

---

## Supporting Query - Updated Banking Details Timeline

**Purpose:** Reconstruct the message chain and separate attacker infrastructure from platform-generated mail.

**KQL Query**
```kql
EmailEvents
| where Subject has "Updated Banking Details"
| project Timestamp,
          Subject,
          SenderFromAddress,
          RecipientEmailAddress,
          SenderIPv4,
          DeliveryAction,
          NetworkMessageId
| order by Timestamp asc
```

**Expected Result:** Timeline containing original, reply, forward, and undeliverable events.

**Pivot Produced:** Sender IPs `103.69.224.136`, `185.130.187.4`, and Microsoft platform IP `20.190.190.224`.

**Investigation Value:** Reconstructs the BEC timeline and prevents misattributing Microsoft-generated NDR activity to the attacker.