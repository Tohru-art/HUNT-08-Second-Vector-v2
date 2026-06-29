# Phase 03 - Directory Recon: Queries

> Query log for Phase 03. Focus is the discovery stage, MFA-status profiling and group enumeration performed from the compromised session via Microsoft Graph.

---

## Q12 - MFA-Status Profiling

**Purpose:** Detect whether the attacker enumerated users' MFA / authentication-method posture to identify weakly protected accounts.

**KQL Query**
```kql
MicrosoftGraphActivityLogs
| where TimeGenerated between (datetime(2026-06-10) .. datetime(2026-06-20))
| where RequestMethod == "GET"
| where RequestUri has_any ("authentication/methods", "authenticationMethods",
                            "perUserMfaState", "/users")
| project TimeGenerated, IPAddress, RequestMethod, RequestUri, AppId,
          ServicePrincipalId, UserId
| order by TimeGenerated asc
```

**Expected Result:** A burst of `GET` requests against user and authentication-method endpoints from the compromised session.

**Pivot Produced:** Recon behavior, per-user MFA/authentication-method profiling.

**Investigation Value:** Confirms the attacker was qualifying targets by protection level, not browsing, establishing intent for the fraud that follows.

---

## Q13 - Group Enumeration

**Purpose:** Detect whether the attacker enumerated directory groups to map privilege and distribution structure.

**KQL Query**
```kql
MicrosoftGraphActivityLogs
| where TimeGenerated between (datetime(2026-06-10) .. datetime(2026-06-20))
| where RequestMethod == "GET"
| where RequestUri has "/groups"
| project TimeGenerated, IPAddress, RequestMethod, RequestUri, AppId,
          ServicePrincipalId, UserId
| order by TimeGenerated asc
```

**Expected Result:** `GET /groups` (and member-listing) requests from the compromised session.

**Pivot Produced:** Recon behavior, group enumeration.

**Investigation Value:** Reveals the privilege/distribution map the attacker built, which explains the target selection in Phases 04 and 05.

---

### Supporting query: Directory reads via AuditLogs (corroboration)

**Purpose:** Corroborate Graph-layer recon with any directory read operations recorded by Azure AD.

**KQL Query**
```kql
AuditLogs
| where TimeGenerated between (datetime(2026-06-10) .. datetime(2026-06-20))
| where OperationName has_any ("group", "member", "user")
| where Category == "DirectoryManagement" or Category == "UserManagement"
| project TimeGenerated, OperationName, InitiatedBy, TargetResources, Result
| order by TimeGenerated asc
```

**Expected Result:** Read/list operations aligning in time with the Graph recon burst.

**Pivot Produced:** Cross-source confirmation of the recon window.

**Investigation Value:** Strengthens attribution by corroborating Graph telemetry with native Azure AD audit records.
