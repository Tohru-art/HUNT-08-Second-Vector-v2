# Phase 05 - Persistence Hunt: Queries

> Query log for Phase 05. These queries identify mailbox-rule persistence, concealment behavior, external forwarding, and the targeted mailbox.

---

## Q18 - The Concealment Rule

**Purpose:** Identify the mailbox rule created to hide payment-verification mail.

**KQL Query**
```kql
CloudAppEvents
| where ActionType == "New-InboxRule"
| where RawEventData has "Invoice Processing"
| project Timestamp,
          ActionType,
          AccountDisplayName,
          ObjectName,
          RawEventData
| order by Timestamp asc
```

**Expected Result:** Mailbox rule `Invoice Processing`.

**Pivot Produced:** Concealment rule name.

**Investigation Value:** Identifies the rule used to hide verification mail from the victim.

---

## Q19 - Where the Hidden Mail Goes

**Purpose:** Determine whether the concealment rule deleted messages or moved them.

**KQL Query**
```kql
CloudAppEvents
| where ActionType == "New-InboxRule"
| where RawEventData has "Invoice Processing"
| project Timestamp,
          ActionType,
          AccountDisplayName,
          ObjectName,
          RawEventData
| order by Timestamp asc
```

**Expected Result:** Messages were moved to a folder rather than deleted.

**Pivot Produced:** Move action, not delete action.

**Investigation Value:** Shows the attacker used stealthy concealment instead of destructive deletion.

---

## Q20 - The Exfiltration Rule

**Purpose:** Identify mailbox rules that forward mail externally.

**KQL Query**
```kql
CloudAppEvents
| where ActionType == "New-InboxRule"
| where RawEventData has_any ("ForwardTo", "RedirectTo", "ForwardAsAttachmentTo")
| project Timestamp,
          ActionType,
          AccountDisplayName,
          ObjectName,
          RawEventData
| order by Timestamp asc
```

**Expected Result:** External forwarding destination `merovingian1337@proton.me`.

**Pivot Produced:** Exfiltration destination, `merovingian1337@proton.me`.

**Investigation Value:** Confirms off-tenant mail exfiltration through an inbox rule.

---

## Q21 - The Both-Rules Target

**Purpose:** Confirm which mailbox both malicious rules targeted.

**KQL Query**
```kql
CloudAppEvents
| where ActionType == "New-InboxRule"
| where RawEventData has_any ("Invoice Processing", "merovingian1337@proton.me", "proton.me")
| project Timestamp,
          ActionType,
          AccountDisplayName,
          ObjectName,
          RawEventData
| order by Timestamp asc
```

**Expected Result:** `j.reynolds@lognpacific.org`

**Pivot Produced:** Targeted mailbox, `j.reynolds@lognpacific.org`.

**Investigation Value:** Links the mailbox-rule persistence directly to the Phase 04 fraud target.

---

## Supporting Query - All Inbox Rule Activity

**Purpose:** Review all inbox rule creation events in the case window.

**KQL Query**
```kql
CloudAppEvents
| where ActionType == "New-InboxRule"
| project Timestamp,
          ActionType,
          AccountDisplayName,
          ObjectName,
          RawEventData
| order by Timestamp asc
```

**Expected Result:** Shows both malicious inbox rules and their parameters.

**Pivot Produced:** Complete mailbox-rule timeline.

**Investigation Value:** Preserves a reproducible view of mailbox persistence activity.