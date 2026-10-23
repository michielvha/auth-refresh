# Host capabilities

Determine the available shell, progress channel, phone-notification tool and continuation mechanism
before starting an authentication flow. Tool names in the legacy agent frontmatter do not imply
that another host provides them.

## Claude Remote Control

Keep the established flow in workflow.md: use PushNotification, surface the MFA number immediately
in the main conversation, arm the bounded confirmation watcher before ending the turn, and let the
background command's completion resume the session. Preserve one outstanding push across lanes.
Do not replace phone delivery with chat text or run start modes in a subagent.

If PushNotification is missing, report that before starting an unattended challenge. If delivery
fails after the challenge starts, display the number immediately, park the lane, cancel the owned
login process, and report the incomplete operation. Do not trigger another push automatically.

## Other hosts

When an equivalent phone-notification tool and reliable continuation are available, use them with
the same account, provider and MFA number. Verify the tool result before reporting delivery.
Send only the challenge instructions, never credentials or session data.

When the owner is using the chat interactively, show the MFA number in an immediate progress message
and keep the main session working through consent and CLI completion. A shell wait must yield often
enough for the number to be visible promptly. Use owned process handles and bounded waits.

Unattended operation requiring a phone push is unavailable without a configured notification tool
and continuation mechanism. Report the missing capability before starting the flow. Do not invent
tools, silently downgrade to chat-only delivery, or change the user's notification preference.

## Cleanup

Read the page after approval and complete provider confirmation or consent. Save the landed session,
park the lane, and verify the expected account. On cancellation, timeout, delivery failure or a host
that cannot resume, park the active challenge and cancel only the login process owned by this attempt.
Never leave an automatic-push page active after abandoning the flow.
