# Microsip ASD — Unauthenticated UNC Binary-Planting RCE

## Summary

An unauthenticated remote code execution vulnerability in Microsip 2026 (ASD — Agente Servidor de Datos). The data-service agent `AgenteSD.exe` (FastAPI on 0.0.0.0:8555, running as LocalSystem) has no authentication middleware. The backup runner resolves a `gbak.exe` path from the user-controlled `path` request parameter via `os.path.join(install_path, "gbak.exe")` and executes it with `subprocess.run([gbak_path, "-Z"])` — no `shell=True`, but the binary path is fully attacker-controlled and accepts UNC paths, so pointing it at `\\attacker\share\gbak.exe` executes an attacker-supplied binary as LocalSystem (binary planting → RCE, CWE-426/CWE-94).

## CVSS Score

- **Score**: 9.8 Critical
- **Vector**: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H

## Affected Products

- **Product**: Microsip 2026 Eval (ASD data-service agent)
- **Versions**: 2026 Eval (other builds with the same backup-runner path handling are likely affected)
- **Vendor**: Microsip

## Impact

- **Confidentiality**: Full read of accounting/business data as LocalSystem
- **Integrity**: Arbitrary code execution in the ASD service context
- **Availability**: Full control of the Microsip host

## Mitigation

1. Validate/normalize `path`/`install_path`; reject UNC and non-install-directory paths
2. Resolve `gbak.exe` from a fixed application directory, never from user input
3. Do not run ASD as LocalSystem; use a least-privilege service account
4. Add authentication to the FastAPI endpoints
