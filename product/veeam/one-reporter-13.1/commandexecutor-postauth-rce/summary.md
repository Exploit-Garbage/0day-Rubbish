# Veeam ONE Reporter Authenticated RCE / Privilege Escalation via CommandExecutor

## Summary

An authenticated remote code execution and privilege escalation vulnerability in Veeam ONE Reporter 13.1 allows a low-privilege PowerUser (role 2) to execute arbitrary OS commands with the privileges of the Veeam ONE Reporter service account (`.\VeeamSvc`, a member of local Administrators). The dashboard scheduling endpoint accepts a user-controlled `reportSettings.command` that is executed by `CommandExecutor.RunCommandAsync` without calling the `ValidateCommand` check, without privilege dropping, and without a whitelist. A one-minute periodic schedule with empty email recipients triggers the command chain, achieving local admin code execution from a non-admin delegated user.

## CVSS Score

- **Score**: 8.8 High
- **Vector**: CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H

## Affected Products

- **Product**: Veeam ONE Reporter
- **Versions**: 13.1 (other versions with the same schedule-command handling are likely affected)
- **Vendor**: Veeam Software

## Impact

- **Confidentiality**: Full control of the Reporter server as local admin
- **Integrity**: Arbitrary command execution as VeeamSvc (local Administrators member)
- **Availability**: Full control of monitoring/reporting infrastructure

## Mitigation

1. Drop privileges before executing the Command field (use a low-privilege account)
2. Whitelist allowed executables/scripts or sandbox command execution
3. Restrict the Command feature to Admin (role 1) only; PowerUser should not reach it
4. Validate command extensions and paths at runtime (call ValidateCommand in the execution path)
