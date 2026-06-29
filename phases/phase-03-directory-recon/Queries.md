# Phase 03 - Directory Recon: Queries

> Query log for Phase 03. These queries identify Microsoft Graph based MFA posture profiling and group enumeration from the compromised session.

---

## Q12 - MFA-Status Profiling

**Purpose:** Identify Graph activity used to profile user MFA or authentication registration posture.

**KQL Query**
```kql
MicrosoftGraphActivityLogs
| where RequestMethod == "GET"
| where RequestUri has_any ("userRegistrationDetails", "authentication", "authenticationMethods")
| project TimeGenerated,
          IPAddress,
          RequestMethod,
          RequestUri,
          AppId,
          ServicePrincipalId
| order by TimeGenerated asc
```

**Expected Result:** Requests referencing `userRegistrationDetails` or authentication-method posture.

**Pivot Produced:** MFA posture profiling through Microsoft Graph.

**Investigation Value:** Shows the attacker was checking identity security posture before later fraud and persistence steps.

---

## Q13 - Group Enumeration

**Purpose:** Identify Graph activity used to enumerate group membership or directory groups.

**KQL Query**
```kql
MicrosoftGraphActivityLogs
| where RequestMethod == "GET"
| where RequestUri has_any ("/groups", "memberOf", "transitiveMemberOf")
| project TimeGenerated,
          IPAddress,
          RequestMethod,
          RequestUri,
          AppId,
          ServicePrincipalId
| order by TimeGenerated asc
```

**Expected Result:** Graph requests showing group or membership enumeration.

**Pivot Produced:** Group enumeration behavior.

**Investigation Value:** Shows the attacker mapped authorization and distribution structure before targeting finance workflows.

---

## Supporting Query - Graph Recon From Attacker IP

**Purpose:** Review all Graph activity tied to the attacker IP around the investigation window.

**KQL Query**
```kql
MicrosoftGraphActivityLogs
| where IPAddress == "103.69.224.136"
| project TimeGenerated,
          IPAddress,
          RequestMethod,
          RequestUri,
          AppId,
          ServicePrincipalId
| order by TimeGenerated asc
```

**Expected Result:** Graph read activity aligned with the compromised session.

**Pivot Produced:** Graph-based discovery timeline.

**Investigation Value:** Provides a broader validation query to support the two specific recon findings.