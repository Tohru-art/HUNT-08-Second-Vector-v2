# Phase 07 - The Plant and the Trigger: Queries

> Query log for Phase 07. Focus is proving automation, not a human, drove the malicious mail behavior, by counting successful MFA, naming the automation app, locating the responsible table, and ordering the sequence.

---

## Q26 - Disprove the Innocent Explanation

**Purpose:** Test the "a logged-in user just forwarded an email" hypothesis by counting successful MFA-satisfied sign-ins at the time of the mail behavior.

**KQL Query**
```kql
SigninLogs
| where UserPrincipalName == "m.smith@lognpacific.org"
| where TimeGenerated between (datetime(2026-06-10) .. datetime(2026-06-20))
| where ResultType == 0
| where AuthenticationRequirement == "multiFactorAuthentication"
| summarize SuccessfulMFA = count()
```

**Expected Result:** `SuccessfulMFA == 0`.

**Pivot Produced:** Successful MFA count, 0 (no interactive human login).

**Investigation Value:** Eliminates the innocent-user explanation. If no human passed MFA, no human interactively performed the action.

---

## Q27 - Catch the Plant

**Purpose:** Identify the application responsible for the activity, distinguishing an automation app from the user's mail client.

**KQL Query**
```kql
SigninLogs
| where UserPrincipalName == "m.smith@lognpacific.org"
| summarize count() by AppDisplayName
| order by count_ desc
```

**Expected Result:** **Microsoft Flow Portal** surfaces as the application behind the activity.

**Pivot Produced:** Automation app, Microsoft Flow Portal.

**Investigation Value:** Names the planted automation, redirecting the investigation from mailbox client logs to the automation/Graph layer.

---

## Q28 - The Cause Behind the Forward

**Purpose:** Discover which telemetry table holds the activity responsible for the forward.

**KQL Query**
```kql
search *
| summarize count() by $table
| order by count_ desc
```

**Expected Result:** **`MicrosoftGraphActivityLogs`** is identified as the table carrying the responsible API activity.

**Pivot Produced:** Responsible table, `MicrosoftGraphActivityLogs`.

**Investigation Value:** Points the analyst at the Graph-layer telemetry that explains the forward, invisible to mailbox-only review.

---

## Q29 - Prove It With The Sequence

**Purpose:** Establish time ordering between the Graph API call and the resulting mail event to prove cause precedes effect.

**KQL Query**
```kql
MicrosoftGraphActivityLogs
| project TimeGenerated,
          IPAddress,
          Location,
          RequestMethod,
          AppId,
          ServicePrincipalId
| order by TimeGenerated asc
```

**Expected Result:** The Graph API call appears **before** the mail event in time order.

**Pivot Produced:** Sequence proof, Graph call → then mail event.

**Investigation Value:** Provides the cause-before-effect evidence that automation, not a human, triggered the forward, the evidentiary core of the phase.
