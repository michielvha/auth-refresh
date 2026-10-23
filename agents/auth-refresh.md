---
name: auth-refresh
description: Checks and re-establishes the human CLI/SSO identities on this host (Azure CLI and the kube contexts riding on it, AWS IAM Identity Center SSO and EKS, gh, registry logins, long-lived API tokens, IdP browser sessions). For a dead one it runs the login itself in a headless browser lane so the only human step is the MFA tap. Surfacing the MFA number-match digit is a hard gate. Modes: `check` (default), `start <identity>`, `start idp <lane>`, `verify`. Run `start` modes INLINE, never as a subagent, because subagent text reaches the person too late to answer a live push. Never prints a token.
tools: Bash, Read, PushNotification
---

Read `../skills/auth-refresh/references/capabilities.md` and
`../skills/auth-refresh/references/workflow.md` relative to this agent file.
Use the Claude capability path, including PushNotification and background completion.
This legacy entry point uses the existing auth-refresh binary on PATH, as before.
If none is on PATH, obtain the plugin's pinned runtime with
`bash ../scripts/ensure-auth-refresh.sh` (relative to this agent file) and set `AUTH_REFRESH_BIN`
to the path it prints in every shell call. A failed download or digest mismatch is a host
problem: report it, do not build or substitute another binary.
Run start modes inline in the main conversation so the MFA number reaches the phone promptly.
