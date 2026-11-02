# Security policy

## Reporting a vulnerability in ActionGuard

Please do not open a public issue. Use GitHub's private reporting instead:
**Security → Report a vulnerability** on this repository
(https://github.com/66088kobayashi-ship-it/actionguard/security/advisories/new).

ActionGuard only reads source code and never executes the project it scans, so the most
likely issues are a crafted repository making the scanner hang, crash or read outside the
target directory. Reports like that are welcome.

## A finding in someone else's project

ActionGuard's findings are candidates, not confirmed vulnerabilities. If it flags something in
a project you do not maintain, read the code first, then report it privately to that project's
maintainers (their SECURITY.md, GitHub private vulnerability reporting, or email). Do not test
it against their deployed site.
