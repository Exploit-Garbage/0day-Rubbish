# Xeams SMTP X-SM_SAVE_BODY_4DEBUGGING Arbitrary File Write Cron Root RCE

## Summary

A critical unauthenticated remote code execution vulnerability in Xeams mail server allows an attacker to write arbitrary files to any path on the host by setting the `X-SM_SAVE_BODY_4DEBUGGING` MIME header on an inbound SMTP message. The header value is treated as an absolute file path and the message body as the file content, with no path validation, no allowlist, and no authentication gate. When Xeams runs as root (the default lab deployment posture), an attacker writes a cron job into `/etc/cron.d/`, which crond executes as root every minute, yielding a complete unauthenticated root RCE. The entire chain depends only on SMTP (port 25 or 587), requires no HTTP, no credentials, and no license.

## CVSS Score

- **Score**: 9.8 Critical
- **Vector**: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H

## Affected Products

- **Product**: Xeams
- **Versions**: 10.3 build 6449 and versions sharing the `X-SM_SAVE_BODY_4DEBUGGING` rulesengine sink
- **Vendor**: Synametrics Technologies

## Impact

- **Confidentiality**: Full root read of the Xeams mail repository (all `.eml` envelope/subject/body) and the host filesystem; the RCE was pivoted to dump the mail store as a proof
- **Integrity**: Arbitrary root command execution on the mail server host; ability to alter mail, configuration, and cron
- **Availability**: Full control of the Xeams process and host; ability to stop the service or destroy data

## Exploitation Prerequisites

This is a **default-configuration unauthenticated RCE**. The `X-SM_SAVE_BODY_4DEBUGGING` header is read unconditionally on every inbound mail, the SMTP service accepts unauthenticated delivery (`reqAuthForLocal=false` is the global default), and the license check only disables spam scoring without returning (so the sink is reachable pre-license). The only deployment condition is that Xeams runs as root, which is required to write to `/etc/cron.d`; the lab deployment confirmed this. SMTP AUTH is offered on ports 25 and 587 but not enforced. Port 465 (SSL) shares the same handler pipeline but was not dynamically tested.

## Mitigation

1. Remove or gate the `X-SM_SAVE_BODY_4DEBUGGING` sink at `rulesengine/h.java:3393-3396`; the header is never set by product code (pure debug residue) and should be deleted entirely, or guarded by a `simulate.file.write` system property defaulting to off plus a hard license return
2. If the debug write is retained, enforce a path allowlist restricted to `$XEAMS_HOME/log/`, reject absolute paths and `..` traversal, and require relative paths only
3. Strip attacker-injectable `X-SM_*` headers at the SMTP DATA reader (`w/c.java`) on the inbound direction; only internally appended headers should be trusted
4. Do not run Xeams as root; writing to `/etc/cron.d` requires root, so privilege reduction breaks the cron chain
5. Default `reqAuthForLocal` to `true` so unauthenticated SMTP delivery is rejected

## Timeline

- **Discovered**: 2026-08-01
- **Public Disclosure**: 2026-08-10

## Credits

Discovered by 0day Rubbish Project using automated AI vulnerability research with multi-LLM ensemble (Claude, OpenAI, DeepSeek, GLM).
