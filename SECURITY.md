# Security Policy

Security is the first priority of **sshpilot-vallet** at every step. The project
publishes SSH **public** keys that decide who can log into consuming hosts, so a
vulnerability here can translate directly into unauthorized server access. We take
reports seriously and appreciate coordinated disclosure.

## Supported versions

The project is pre-release (phase 1, in design). Until a first tagged release,
only the default branch (`develop`, and later `main`) is supported. Once releases
begin, this section will list the versions receiving security fixes.

## Reporting a vulnerability

**Please do not open a public GitHub issue for security problems.**

Report privately using either:

- **GitHub Private Vulnerability Reporting** — the "Report a vulnerability" button
  under the repository's **Security** tab (preferred; keeps the report attached to
  the repo), or
- **Email** — <sadeqn@gmail.com> with a subject beginning `[SECURITY]`.

If you want to encrypt the report, ask in a first low-detail message and we will
share a key.

### What to include

- A clear description of the issue and its impact.
- Steps to reproduce (proof-of-concept, affected endpoint/config, request/response
  samples with secrets redacted).
- Affected version/commit and your environment (data store, TLS mode, auth
  provider) where relevant.
- Any suggested remediation.

### What to expect

- **Acknowledgement** within **72 hours**.
- An initial **assessment and severity** within **7 days**.
- Regular updates until resolution, and credit in the release notes if you want it
  (tell us how you would like to be named, or to stay anonymous).

## Scope

In scope:

- The backend service and its published/consumed endpoints.
- Authentication, authorization, and owner isolation.
- `authorized_keys` output integrity and key ingest handling.
- TLS/certificate provisioning and secret handling.
- The managed-block helper and its delivery.

Out of scope (report elsewhere / not a vulnerability by themselves):

- The confidentiality of **public** keys — they are public by nature (the
  handle→keys *association* is metadata we minimize, so linkage leaks are still
  welcome reports).
- Denial-of-service via raw traffic volume against an unprotected deployment
  (deploy behind the documented rate limits / a proxy).
- Findings that require a compromised host, stolen device, or physical access
  already inside the trust boundary — unless they show a boundary being crossed.
- Reports generated solely by automated scanners with no demonstrated impact.

## Safe harbor

We will not pursue or support legal action against researchers who:

- act in good faith and avoid privacy violations, data destruction, and service
  degradation,
- test only against systems they own or are explicitly authorized to test, and
- give us reasonable time to remediate before public disclosure.

Thank you for helping keep sshpilot-vallet and the hosts that rely on it safe.
