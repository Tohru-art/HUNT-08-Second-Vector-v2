# Phase 02 - Session Scope

> **Investigation:** HUNT-08, Second Vector
> **Analyst:** Will-Garlens Pierre, SOC Analyst
> **Environment:** Log(N) Pacific, Microsoft Sentinel / Defender XDR
> **Phase Status:** Complete

## Objective

Explain *how* the attacker held an authenticated session against an MFA-enabled identity. Determine whether MFA was satisfied, bypassed, or simply never re-challenged, and measure the reach of the resulting session. This phase converts "the account is compromised" into "here is the exact mechanism that kept the attacker inside."

## Scope

- Sign-in telemetry for `m.smith@lognpacific.org` from attacker IP `103.69.224.136`
- Authentication requirement, Conditional Access evaluation, and result codes
- Session continuity analysis across the activity window
- No mail or directory analysis, this phase isolates the authentication mechanism only

## Data Sources

| Source | Role in this phase |
|---|---|
| `SigninLogs` | Authentication requirement, Conditional Access status/policies, result codes, session continuity |

## Findings Table

| Question | Finding | Evidence | Analyst Interpretation |
|---|---|---|---|
| Q07: How the Session Beat MFA | Token persistence via "Keep Me Signed In"; refresh token remained valid | `AuthenticationRequirement == singleFactorAuthentication` on attacker sign-ins | MFA was not solved by the attacker. A previously issued, still-valid refresh token was reused, so the platform only required single-factor on subsequent sign-ins. The bypass is **token reuse, not MFA defeat**. |
| Q08: The Control Surface That Let Them In | Conditional Access did not evaluate the session | `ConditionalAccessStatus == notApplied` | No CA policy was in scope for these sign-ins, so no policy could block, re-challenge, or session-control the attacker. The control surface that should have caught this never engaged. |
| Q09: Failed Attempts Before Entry | Failed sign-ins preceding the successful session _(populate exact count from your query output)_ | `ResultType != 0` records for the principal before the first `ResultType == 0` from the attacker IP | Shows the access attempt was not a clean single login, there is a probing pattern, useful for timeline anchoring and for distinguishing attacker activity from the user's own. |
| Q10: Blast Radius of One Token | Multiple first-party resources reachable from the single session _(populate the exact resource/app list from your query output)_ | Distinct `AppDisplayName` / `ResourceDisplayName` accessed under the attacker sign-ins | One reused token did not unlock a single app, it unlocked the user's full set of cloud resources (mail, directory, Graph). The blast radius of one token is the user's entire cloud surface. |
| Q11: One Continuous Session | Activity ties back to a single continuous session | Shared correlation across the attacker sign-ins from `103.69.224.136` | The attacker operated from one sustained session rather than re-authenticating repeatedly. This is why session revocation (not just password reset) is the correct containment lever. |

## Key Pivot Values

```
Auth requirement        : singleFactorAuthentication
Conditional Access      : notApplied
Mechanism               : Keep Me Signed In (KMSI) / refresh token reuse
Session continuity      : single sustained session from 103.69.224.136
```

## Analyst Assessment

The attacker never beat MFA. They inherited a session.

"Keep Me Signed In" issues a long-lived refresh token. As long as that refresh token stays valid, Azure AD can mint new access tokens without forcing a fresh interactive MFA challenge, which is exactly why the attacker's sign-ins show `singleFactorAuthentication`. Layer on `ConditionalAccessStatus == notApplied` and there was no policy in the path to force re-authentication, apply sign-in frequency, or block the anonymized source.

The combination is the whole story of this phase: a persistent token plus an absent Conditional Access evaluation equals an attacker who looks, to the platform, like an already-trusted session. This also dictates containment, because the foothold is a live refresh token, resetting the password alone does **not** evict the attacker. The session has to be revoked.

## Detection Opportunities

- **Single-factor on risky sign-in**, alert when `AuthenticationRequirement == singleFactorAuthentication` coincides with a non-zero risk level or a known-bad / anonymized IP.
- **Conditional Access coverage gap**, report on successful sign-ins where `ConditionalAccessStatus == notApplied` for privileged or finance-adjacent users; these are unprotected authentication paths.
- **Refresh-token longevity**, surface sessions where access continues well beyond the last interactive MFA event, indicating long-lived token reuse.

## MITRE ATT&CK Mapping

| Technique | ID | Justification |
|---|---|---|
| Use Alternate Authentication Material: Web Session Cookie | T1550.004 | Reuse of a persistent KMSI session / refresh token to maintain authenticated access without re-satisfying MFA |
| Valid Accounts: Cloud Accounts | T1078.004 | Continued operation as a legitimate cloud identity |
| Modify Authentication Process (control gap) | T1556 | Conditional Access not applied left the authentication path without enforced re-challenge |

## Response Considerations

- **Revoke sessions before resetting the password.** The persistence here is a live refresh token; a password reset does not invalidate already-issued refresh tokens on its own.
- Close the Conditional Access gap for this user class, require MFA on every sign-in for risky/anonymized sources and apply a sign-in frequency control.
- Treat the single continuous session as the unit of compromise when building the incident timeline.
