# Loadbalancer.org ADC Deployment Template Command Injection to Root RCE

## Summary

An authenticated remote code execution vulnerability in Loadbalancer.org Enterprise ADC 8.13.8 allows an administrator in the `config` group to achieve root code execution through command injection in the deployment template feature. `LBDeploymentCLI::execute_raw` concatenates the user-controlled `service.action` value into an `exec()` command without escaping. The Apache user belongs to the `wheel` group, and `sudoers` permits `NOPASSWD: ALL` for `wheel`, so any injected `sudo` command escalates directly to root.

## CVSS Score

- **Score**: 8.8 High
- **Vector**: CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H

## Affected Products

- **Product**: Loadbalancer.org Enterprise ADC
- **Versions**: 8.13.8
- **Vendor**: Loadbalancer.org

## Impact

- **Confidentiality**: Full device compromise; `root` access
- **Integrity**: Arbitrary command execution on the load balancer
- **Availability**: Full control of the ADC device and the traffic it manages

## Mitigation

1. Escape or validate the `service.action` value before interpolation into the command line
2. Remove `wheel` from the sudoers `NOPASSWD: ALL` policy; apply least-privilege sudo rules
3. Restrict access to the deployment template feature to trusted administrators
4. Run the web application under an unprivileged account

## Credits

Discovered by 0day Rubbish Project using automated AI vulnerability research with multi-LLM ensemble (Claude, OpenAI, DeepSeek, GLM).
