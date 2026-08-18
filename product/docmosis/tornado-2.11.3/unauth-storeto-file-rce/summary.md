# Docmosis Tornado Unauthenticated Arbitrary File Write to Root RCE (storeTo=file: → cron)

## Summary

A critical unauthenticated arbitrary file write vulnerability in Docmosis Tornado 2.11.3 allows a remote attacker to write files to arbitrary filesystem paths. The Jersey REST API (`/api/*`) is reachable without authentication in local deployments because the authentication filter treats all `/api` paths as REST calls and skips session authentication; the `accessKey` validation also passes for empty/default keys when not in cloud mode. The `/api/render` endpoint accepts a `storeTo` parameter whose `file:` prefix directs the rendered document to an attacker-controlled path with no canonicalization or directory whitelist. By writing a valid cron line into `/etc/cron.d/`, an attacker achieves arbitrary command execution as `root` (the service runs as root by default).

## CVSS Score

- **Score**: 9.8 Critical
- **Vector**: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H

## Affected Products

- **Product**: Docmosis Tornado (document generation service)
- **Versions**: 2.11.3 (other versions with the same REST auth handling and storeTo file destination are likely affected)
- **Vendor**: Docmosis

## Impact

- **Confidentiality**: Full system compromise; root access to the host
- **Integrity**: Arbitrary file write anywhere on the filesystem, including cron, systemd units, or SSH keys
- **Availability**: Full control of the Docmosis host and all hosted services

## Mitigation

1. Enforce authentication for all `/api/*` endpoints regardless of REST call detection
2. Canonicalize `storeTo` paths and enforce a strict directory whitelist for file destinations
3. Run Docmosis Tornado as an unprivileged service account instead of `root`
4. Restrict the service to trusted networks and never expose it to the public Internet
5. Enable local file overwrite protection and validate destination paths at the dispatcher level
