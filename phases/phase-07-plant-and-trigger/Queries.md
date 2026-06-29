# Phase 07 - The Plant and the Trigger: Queries

> Query log for Phase 07. These queries prove the mail behavior was automation-driven, not a human action, by checking MFA evidence, naming the automation app, identifying the responsible telemetry table, and validating sequence.

---

## Q26 - Disprove the Innocent Explanation

**Purpose:** Test whether a legitimate user completed MFA during the suspicious activity window.

**KQL Query**
```kql
SigninLogs
| where UserPrincipalName == "m.smith@lognpacific.org"
| project TimeGenerated,
          IPAddress,
          AuthenticationRequirement,
          AuthenticationDetails,
          ConditionalAccessStatus
| order by TimeGenerated asc
```

**Expected Result:** No successful MFA completion tied to the malicious activity, supporting a final successful MFA count of `0`.

**Pivot Produced:** Successful MFA count, `0`.

**Investigation Value:** Eliminates the idea that a legitimate human user performed the forwarding action interactively.

---

## Q27 - Catch the Plant

**Purpose:** Identify the application tied to the automation activity.

**KQL Query**
```kql
SigninLogs
| where UserPrincipalName == "m.smith@lognpacific.org"
| summarize count() by AppDisplayName
| order by count_ desc
```

**Expected Result:** `Microsoft Flow Portal`

**Pivot Produced:** Automation application, `Microsoft Flow Portal`.

**Investigation Value:** Connects the activity to Power Automate or Microsoft Flow rather than a normal mail client.

---

## Q28 - The Cause Behind the Forward

**Purpose:** Identify which table contains the responsible telemetry for the mail-driving action.

**KQL Query**
```kql
search *
| summarize count() by $table
| order by count_ desc
```

**Expected Result:** `MicrosoftGraphActivityLogs`

**Pivot Produced:** Responsible table, `MicrosoftGraphActivityLogs`.

**Investigation Value:** Redirects the analyst from mailbox-only review to Graph API telemetry.

---

## Q29 - Prove It With The Sequence

**Purpose:** Show the Graph API action occurred before the resulting mail event.

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

**Expected Result:** The Graph call appears before the mail event in the activity sequence.

**Pivot Produced:** Sequence proof, Graph call then mail event.

**Investigation Value:** Provides the cause-before-effect evidence that a planted automation, not a user at a keyboard, triggered the forward.