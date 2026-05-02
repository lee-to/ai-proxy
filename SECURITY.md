# Security Policy

AI Proxy handles model API traffic and may process sensitive request metadata, prompts, responses, headers, and authentication material. Please report vulnerabilities privately.

## Supported Versions

Until the project reaches a stable release, only the latest commit on `main` is supported for security fixes.

| Version | Supported |
|---------|-----------|
| `main` | Yes |
| Older commits/releases | No |

## Reporting a Vulnerability

Email Danil Shutsky at <thecutcode@gmail.com>.

Please include:

- A concise description of the issue.
- Affected commit, release, or configuration.
- Reproduction steps or a proof of concept.
- Expected impact.
- Whether the report may contain sensitive data.

Do not open a public GitHub issue for security vulnerabilities. Do not include real API keys, account tokens, private prompts, or private traffic captures unless explicitly requested.

## Response Expectations

- Initial acknowledgement: best effort within 7 days.
- Triage and next steps: best effort within 14 days.
- Fix timeline depends on severity, complexity, and maintainer availability.

If the issue is accepted, the maintainer will coordinate disclosure timing with the reporter before publishing details.

## Security Scope

In scope:

- Secret redaction bypasses.
- Leakage of auth headers, prompts, responses, tool data, or captured telemetry.
- Dashboard authentication or access-control flaws.
- MITM certificate/key handling flaws.
- Request routing that sends traffic to the wrong upstream.
- Denial-of-service issues with practical exploitability.

Out of scope:

- Vulnerabilities requiring malicious local administrator access.
- Reports against dependencies without a demonstrated impact on this project.
- Social engineering, spam, or physical attacks.
- Scanner false negatives that do not show a concrete security impact.

## Operational Guidance

- Keep dashboard access loopback-only and use SSH tunneling for remote access.
- Keep dashboard token authentication enabled unless the dashboard is reachable only through a trusted local or SSH-tunneled path.
- Do not publish MITM CA private keys.
- Do not commit `config.toml`, SQLite telemetry files, generated certificates, logs, or captured traffic.
