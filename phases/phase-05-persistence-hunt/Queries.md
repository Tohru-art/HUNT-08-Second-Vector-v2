# Phase 05 - Persistence Hunt: Queries

> Query log for Phase 05. Focus is mailbox-rule persistence: the concealment rule, what it did with mail, the external forwarding rule, and the targeted mailbox.

---

## Q18 - The Concealment Rule

**Purpose:** Identify the mailbox rule the attacker created to hide verification mail.

**KQL Query**
```kql
CloudAppEvents
| where TimeGenerated between (datetime(2026-06-10) .. datetime(2026-06-20))
| where ActionType in ("New-InboxRule", "Set-InboxRule", "UpdateInboxRules")
| where RawEventData has "Invoice Processing"
| project TimeGenerated, ActionType, AccountDisplayName, IPAddress, RawEventData
| order by TimeGenerated asc
```

**Expected Result:** A rule-creation event naming the rule **"Invoice Processing"**.

**Pivot Produced:** Concealment rule name + creation event.

**Investigation Value:** Identifies the camouflage rule and the session/IP that created it.

---

## Q19 - Where the Hidden Mail Goes

**Purpose:** Determine whether the concealment rule deleted messages or moved them to a folder.

**KQL Query**
```kql
CloudAppEvents
| where ActionType in ("New-InboxRule", "Set-InboxRule", "UpdateInboxRules")
| where RawEventData has "Invoice Processing"
| extend Rule = parse_json(RawEventData)
| project TimeGenerated, AccountDisplayName,
          MoveToFolder = Rule.Parameters,
          RawEventData
| order by TimeGenerated asc
```

**Expected Result:** The rule action is a **move to a hidden folder**, not a delete.

**Pivot Produced:** Rule behavior, move (conceal), not delete.

**Investigation Value:** Establishes the attacker chose quiet concealment over destruction, which informs recovery (the mail still exists).

---

## Q20 - The Exfiltration Rule

**Purpose:** Find any inbox rule that forwards mail to an external address.

**KQL Query**
```kql
CloudAppEvents
| where TimeGenerated between (datetime(2026-06-10) .. datetime(2026-06-20))
| where ActionType in ("New-InboxRule", "Set-InboxRule", "UpdateInboxRules")
| where RawEventData has_any ("ForwardTo", "RedirectTo", "ForwardAsAttachmentTo")
| where RawEventData has "proton.me"
| project TimeGenerated, ActionType, AccountDisplayName, IPAddress, RawEventData
| order by TimeGenerated asc
```

**Expected Result:** A rule forwarding mail to **`merovingian1337@proton.me`**.

**Pivot Produced:** Exfil destination, `merovingian1337@proton.me`.

**Investigation Value:** Confirms live external exfiltration of correspondence and adds a high-value IOC.

---

## Q21 - The Both-Rules Target

**Purpose:** Confirm which mailbox both the concealment and exfiltration rules were created on.

**KQL Query**
```kql
CloudAppEvents
| where TimeGenerated between (datetime(2026-06-10) .. datetime(2026-06-20))
| where ActionType in ("New-InboxRule", "Set-InboxRule", "UpdateInboxRules")
| where RawEventData has_any ("Invoice Processing", "proton.me")
| extend TargetMailbox = tostring(parse_json(RawEventData).MailboxOwnerUPN)
| summarize Rules = make_set(ActionType) by TargetMailbox
```

**Expected Result:** Both rules resolve to **`j.reynolds@lognpacific.org`**.

**Pivot Produced:** Targeted mailbox, `j.reynolds@lognpacific.org`.

**Investigation Value:** Names the victim of the persistence and links it directly to the Phase 04 fraud target chain.
