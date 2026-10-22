---
name: auth-refresh
description: Check and restore local CLI or SSO credentials when a task loses authentication or the user requests a refresh. Drive Azure, AWS and IdP logins in isolated account lanes; report manual token renewal and service outages.
---

Read the private host notes named in the local config first. They decide account ownership and host
exceptions. Resolve this skill's real directory before reading sibling resources.

The plugin root is two directories above this skill. Obtain its pinned runtime with
`bash <plugin-root>/scripts/ensure-auth-refresh.sh`, then prepend the returned binary's directory to
PATH for this operation. An unavailable release or digest mismatch is a provisioning blocker; report
it instead of building replacement code or using an unverified executable.

Read [capabilities.md](references/capabilities.md) before any login and
[workflow.md](references/workflow.md) for check, start and verify procedures. The workflow's
Claude notification and background rules apply on Claude; the capability reference defines the
other supported execution paths. Use the same provider actions and lane protections on every host.

Checks may run without a notification channel. Starting a login must fit the user's request and the
configured account; credential failures do not authorize unrelated account changes or token minting.
