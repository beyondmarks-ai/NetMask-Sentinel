# Security Policy

## Supported versions

Security fixes are applied to the latest version on the default branch. Older snapshots and generated development builds are not supported.

## Reporting a vulnerability

Do not disclose suspected vulnerabilities in a public issue, discussion, or pull request.

Use GitHub's private vulnerability reporting feature:

1. Open the repository's **Security** tab.
2. Select **Advisories**.
3. Select **Report a vulnerability**.
4. Include affected versions, reproduction steps, impact, and any suggested mitigation.

If private vulnerability reporting is not enabled on a fork, contact that repository's owner through a private channel. Do not include credentials, packet captures containing personal data, private IP inventories, or production logs unless an encrypted transfer method has been agreed upon.

## Scope

Reports concerning authentication bypass, unsafe packet parsing, remote code execution, credential exposure, cross-site scripting, CSRF bypass, dependency compromise, or public-target bypasses in the lab traffic generator are in scope.

The project is a defensive monitoring tool. Detection disagreements or false positives should be reported as model-quality issues unless they also create a security boundary failure.

## Disclosure process

A report will be acknowledged, triaged, and remediated according to severity. Public disclosure should wait until a fix is available and users have had a reasonable opportunity to update.