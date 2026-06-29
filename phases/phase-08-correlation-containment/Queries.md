# Phase 08 - Correlation and Containment: Queries

> Query log for Phase 08. Focus is single-actor correlation across the environment and the evidence basis for the containment ordering. Q34, Q35, and Q37 are response decisions grounded in prior-phase telemetry rather than standalone hunts; the supporting queries that justify them are listed.

---

## Q30 - The Automation Source IP

**Purpose:** Identify the source IP from which the automation issued mail-driving Graph requests.

**KQL Query**
```kql
MicrosoftGraphActivityLogs
| where RequestMethod == "POST"
| where RequestUri has "forward"
    or RequestUri has "sendMail"
    or RequestUri has "messages"
| project TimeGenerated,
          IPAddress,
          Location,
          RequestMethod,
          RequestUri,
          AppId,
          ServicePrincipalId
| order by TimeGenerated asc
```

**Expected Result:** Mail-action `POST` requests originate from **`20.150.129.194`**.

**Pivot Produced:** Automation source IP, `20.150.129.194`.

**Investigation Value:** Separates the machine half of the operation from the human attacker IP and provides the source for the flow's execution.

---

## Q31 - The Automation Identity

**Purpose:** Resolve the application identity behind the automation from its App ID.

**KQL Query**
```kql
SigninLogs
| where AppId == "7ab7862c-4c57-491e-8a45-d52a7e023983"
| distinct AppDisplayName, AppId
```

**Expected Result:** The App ID resolves to the automation identity tied to the Flow Portal / Power Automate.

**Pivot Produced:** Automation App ID, `7ab7862c-4c57-491e-8a45-d52a7e023983`.

**Investigation Value:** Turns "an automation did this" into a named, removable object for targeted containment and tenant hunting.

---

## Q32 - Name The Abused Service

**Purpose:** Name the legitimate platform service the attacker weaponized.

**KQL Query**
```kql
SigninLogs
| where AppId == "7ab7862c-4c57-491e-8a45-d52a7e023983"
   or AppDisplayName has_any ("Flow", "Power Automate")
| summarize count() by AppDisplayName, AppId
| order by count_ desc
```

**Expected Result:** Activity resolves to **Microsoft Power Automate** (surfaced via the Flow Portal app and App ID).

**Pivot Produced:** Abused service, Microsoft Power Automate.

**Investigation Value:** Identifies the sanctioned service used for serverless execution, explaining why the abuse blended into normal telemetry.

---

## Q33 - One Actor, Every Source

**Purpose:** Prove a single actor touched the environment by counting the in-scope telemetry tables the attacker IP appears in.

**KQL Query**
```kql
search "103.69.224.136"
| where TimeGenerated between (
    datetime(2026-06-10)
    ..
    datetime(2026-06-20)
)
| summarize by $table
| order by $table asc
```

**Expected Result:** The attacker IP appears in **7** in-scope telemetry tables.

**Pivot Produced:** Single-actor correlation across 7 tables.

**Investigation Value:** The cornerstone correlation finding, one IP threading through seven tables establishes a single coordinated operation.

---

## Q34 - Containment Ordering (Decision: supporting query)

**Purpose:** Confirm a live, persistent session exists, justifying session revocation as the first containment action.

**KQL Query**
```kql
SigninLogs
| where UserPrincipalName == "m.smith@lognpacific.org"
| where IPAddress == "103.69.224.136"
| summarize FirstSeen = min(TimeGenerated), LastSeen = max(TimeGenerated),
            SignIns = count()
```

**Expected Result:** A sustained session window confirming live access.

**Decision Produced:** First containment action, **revoke sessions**.

**Investigation Value:** Grounds the response ordering in evidence: the active session is the live foothold to cut first.

---

## Q35 - Where The Flow Is Removed (Decision: supporting query)

**Purpose:** Confirm the malicious automation is a Power Automate flow, locating its management plane.

**KQL Query**
```kql
SigninLogs
| where AppId == "7ab7862c-4c57-491e-8a45-d52a7e023983"
| distinct AppDisplayName, AppId
```

**Expected Result:** Confirms a Power Automate / Flow identity, managed outside Exchange and Entra.

**Decision Produced:** Removal location, **Power Platform Admin Center**.

**Investigation Value:** Directs containment to the correct admin plane; the flow cannot be removed from Exchange or Entra alone.

---

## Q36 - The Control That Never Fired

**Purpose:** Determine whether Conditional Access evaluated the compromised sign-ins.

**KQL Query**
```kql
SigninLogs
| where UserPrincipalName == "m.smith@lognpacific.org"
| project
    IPAddress,
    AuthenticationRequirement,
    ConditionalAccessStatus,
    ConditionalAccessPolicies,
    ResultType,
    ResultDescription
| order by TimeGenerated asc
```

**Expected Result:** `ConditionalAccessStatus == notApplied`, sign-ins succeeded with no CA evaluation.

**Pivot Produced:** Control gap, Conditional Access not applied.

**Investigation Value:** Identifies the structural control failure that allowed the entire chain, and the primary preventive fix.

---

## Q37 - Why Revoke Before Reset (Decision)

**Purpose:** Justify the revoke-before-reset ordering using session persistence and automation evidence.

**Basis (no new query, synthesis of prior telemetry):**
- Phase 02: `AuthenticationRequirement == singleFactorAuthentication` via persistent refresh token, the session survives independent of the password.
- Phase 07: automation executes on delegated authority, not an interactive logon.

**Decision Produced:** **Revoke sessions before resetting the password.** Active sessions (live refresh tokens) survive a password reset; resetting first leaves the attacker's session and flow intact.

**Investigation Value:** Codifies the most important response lesson of the investigation, containment sequencing, not just containment actions.
