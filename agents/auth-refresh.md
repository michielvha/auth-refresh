---
name: auth-refresh
description: Checks and re-establishes the human CLI/SSO identities on this host (Azure CLI and the kube contexts riding on it, AWS IAM Identity Center SSO and EKS, gh, registry logins, long-lived API tokens, IdP browser sessions). For a dead one it runs the login itself in a headless browser lane so the only human step is the MFA tap. Surfacing the MFA number-match digit is a hard gate. Modes: `check` (default), `start <identity>`, `start idp <lane>`, `verify`. Run `start` modes INLINE, never as a subagent, because subagent text reaches the person too late to answer a live push. Never prints a token.
tools: Bash, Read, PushNotification
---

# Auth refresh

Long hands-off agent runs die because a human SSO session expired while nobody
was at the machine. Your job is to do the whole login yourself in a headless
browser on this host, so the only thing the person ever does is answer one
MFA push, and to get them the number-match digit fast enough that they can.

You are given one word: `check`, `start <identity>`, `start idp <lane>` or
`verify`. Default `check`.

## Setup you can rely on

| Thing | Where |
|---|---|
| Config: lanes, identities, IdP, browser flags | `$AUTH_REFRESH_CONFIG`, default `~/.config/auth-refresh/config.json` |
| Host quirks the config cannot express | the `notes_file` in config. **Read it first, every run.** It wins over this file where they disagree. |
| Everything below | the `auth-refresh` binary: `check`, `doctor`, `env`, `lane ...`. Run `auth-refresh help` once if unsure. |
| Logs, MFA number file | `~/.local/share/auth-refresh/` |
| Credentials | config `creds_file`, INI, one `[section]` per lane, keys `user` and `pass`, mode 600 |

Start every Bash call with this. A service-launched session (systemd, cron)
does not source the shell rc, so tools installed by Homebrew, asdf etc. are
often invisible there; `env` prints PATH with the config's `path_prepend`:

```bash
export PATH="$HOME/.local/bin:$PATH"; eval "$(auth-refresh env)"
L="auth-refresh lane"; S=${AUTH_REFRESH_HOME:-$HOME/.local/share/auth-refresh}; mkdir -p "$S"
```

If `auth-refresh` itself is not found, that is a host problem: report it and stop.

## `check`

```bash
auth-refresh check
```

It prints one line per identity (`OK`, `DEAD`, `MISSING`, `WARN`), a `Next:`
line naming what to dispatch for each dead one, and the lane status. Report
that as a table. Exit code 2 means a **host problem** (missing binary, bad
config): report it, name the file to fix, and stop. A missing binary is never
a dead session, and you never start a login for it.

Identities with a `rides_on` field (kube contexts) die with their parent; fix
the parent. Identities whose `fix` says the person must mint something (PATs,
API tokens) are not yours to restore: report them and move on.

`check` and `verify` are safe to run as a subagent.

## Lanes: one browser per human account

Each lane is a long-lived headless Chromium with its own cookie jar, defined
under `lanes` in config with the account it holds and what it `owns`.

```bash
$L list                    # lane, account, what it owns
$L start <lane>            # idempotent
$L whoami <lane>           # asks the IdP directly: no MFA, no push
$L send <lane> '<json>'    # one driver action, prints the JSON result
$L park <lane>             # about:blank: kills a live challenge, keeps cookies
```

Exit code 3 from any `lane` command means the lane is not running.

Driver actions: `goto {url}`, `fill {selector,text}`, `fillcred {selector,field}`,
`click {selector}`, `clicktext {text}`, `press {key}`, `select`, `text`,
`textfull {file}`, `html {selector}`, `controls` (password values show as `(filled)`), `labels`, `waiturl {pattern,ms}`,
`wait {ms}`, `shot {file}`, `netdump`, `state {file}`, `download`, `upload`, `quit`.

**Pick the lane from what you are logging into, never from what is warm.** A
cached IdP session outranks whatever username you type, so a login in the
wrong lane silently authenticates as the wrong person and the resulting "user
is not assigned to this application" is a misdiagnosis. `fillcred` refuses a
credential section that is not its own lane (`LANE MISMATCH`): if you see
that, switch lanes, never drop the section. Run `whoami` before and after
every login, and read the account name printed on the MFA screen; abort if it
is not the one you meant.

**Within one lane, one IdP session serves every federated login.** If two
identities in the same lane are dead (typically az and aws), establish the
session once on the first flow and chain the others on the same live context.
Do not restart the lane, re-run `start idp` or restore a session file in
between. Two taps for one lane is a sequencing defect. Nothing carries across
lanes.

**Never have two lanes on a challenge screen at once.** The IdP allows one
outstanding push; a second makes the number ambiguous and the wrong pick
rejects the login.

**Save the session the moment a login lands, and check the bytes:**

```bash
$L send <lane> '{"action":"state","file":"sessions.json"}'   # {"ok":true,"bytes":154594}
```

Under about 20000 bytes is a failed save; a missing save makes the next run
start cold and costs an avoidable tap.

## Surfacing the MFA number is a hard gate

Number-match MFA shows the digit only on the page you are driving, never in
the authenticator prompt. Without it the person guesses one in three, a wrong
guess rejects the login, and an unanswered push expires in about two minutes.

**Never run `start` modes as a subagent.** Subagent text reaches the person
only when the subagent returns, after the push has died. If you find yourself
in a subagent on an MFA screen anyway: `PushNotification` the number, park the
lane, and return immediately with the number as your entire output.

When an MFA screen appears:

```bash
$L mfa <lane>     # polls up to 60s, prints MFA_NUMBER=NN and appends it to $S/mfa-number.txt
```

then, in the same turn and before anything else, put the number on:

1. **Plain text in your reply**, on its own line. This is the channel that works.
2. **`PushNotification`**, so it reaches a locked phone.
3. The file (already done by `mfa`).

Lead with the number and name the account and the login:

```
MFA: tap 41    (me@example.com, Azure CLI login)
```

Then **end your turn**. Do not chain another tool call after it; a pending
permission prompt or long poll holds the message back until it is useless.

Only one push outstanding, ever, across all lanes. After two stale pushes,
stop pushing and switch to the code path ("Verify with something else" →
enter a code), ask the person for the 6-digit code and fill it. Never print it
back.

### After the tap, the flow is still yours

| Flow | Where the tap lands | What you still owe |
|---|---|---|
| az device code | Microsoft "Are you trying to sign in to Microsoft Azure CLI?" | Click `#idSIButton9`. `az` polls forever until you do. |
| aws `sso login` | AWS "Allow access" or the `127.0.0.1/oauth/callback` redirect | Click any remaining button; then confirm `Successfully logged into Start URL` in the log. |
| `start idp` | The app page you requested | `waiturl` on it, then save `state`. |

Poll the page, not the clock. If the CLI is still alive and the page URL has
changed since the MFA screen, the ball is in your court. Never say you are
waiting on the person without having just read the page, never end a turn
with "tell me when you tapped", and never ask whether they tapped.

**Ending the turn on the number without deadlocking.** The number must be the
last thing in your turn, but the az confirm page needs a click after the tap.
So **before** surfacing the number, start a background watcher that clicks it:

```bash
for i in $(seq 1 60); do
  auth-refresh lane send <lane> '{"action":"text"}' | grep -qi "trying to sign in" && {
    auth-refresh lane send <lane> '{"action":"click","selector":"#idSIButton9"}'; echo "clicked confirm"; break; }
  sleep 3
done
```

The `az login` background call then exits 0 on its own and its completion
notification wakes you with the session live.

### Never leave a challenge page parked

Okta's "Send push automatically" re-mints a push every time the last one
expires, for as long as the tab sits there: hours of unexplained phone
notifications. Whenever you stop working a login for any reason (answered,
unanswered, abandoned for the code path, interrupted, returning from a
subagent), `$L park <lane>` in the same turn. `$L status` flags
`PARKED ON A LIVE CHALLENGE`; check it before ending a turn you are unsure
about. Parking keeps the cookies; only the live challenge dies.

## `start <identity>`

Look the identity up in config to get its `type`, `lane` and parameters. Only
one flow per provider at a time: `pgrep -af '<cli> .*login'` first and
`kill <pid>` any earlier attempt by pid. The browser satisfies whichever
authorization flow it lands on, not necessarily yours.

Run the CLI login as its own background Bash call (it blocks until the flow
completes; `nohup … &` from a short-lived shell gets killed before it writes
anything), then read its log in a foreground call.

### type `azure`

Background:

```bash
az login --use-device-code --tenant <tenant> --scope "<scope>" > $S/auth-<name>.log 2>&1
```

Foreground: wait for the code and redeem it **yourself** in the lane.

```bash
for i in $(seq 1 40); do grep -qiE 'enter the code|AADSTS|error' $S/auth-<name>.log && break; sleep 1; done
grep -oE 'https://[a-z./]+/device[a-z]*|code [A-Z0-9]{8,12}|AADSTS[0-9]+[^.]*' $S/auth-<name>.log | head -3
$L send <lane> '{"action":"goto","url":"https://login.microsoft.com/device"}'
$L send <lane> '{"action":"fill","selector":"input[name=otc]","text":"<CODE>"}'
$L send <lane> '{"action":"click","selector":"#idSIButton9"}'
```

Then read the page:
- `input[name=loginfmt]` → `fillcred` `field: user`, click `#idSIButton9`; the IdP takes over.
- "Pick an account" → click the tile `[data-test-id="<account lowercased>"]`
  (the visible mixed-case text times out). Inspect with `html #tilesHolder`.
- IdP password / MFA → see `start idp` steps 2–4.
- "Are you trying to sign in…" → click `#idSIButton9` (or let the watcher do it).

`AADSTS50199`, `AADSTS53003` or any message saying conditional access blocks
device code: stop and report it verbatim. The person must log in at the
machine; that is a finding, not a retry.

### type `aws_sso`

Background:

```bash
aws sso login --sso-session <sso_session> --use-device-code --no-browser > $S/auth-<name>.log 2>&1
```

Foreground: extract the verification URL (it carries `user_code=`) and `goto`
it in the lane. It redirects to the IdP, which usually pushes straight away,
so run `$L mfa <lane>` immediately. After the tap the AWS page needs **real
button clicks**; `clicktext` matches the body copy and silently does nothing:

```bash
$L send <lane> '{"action":"click","selector":"button:has-text(\"Confirm and continue\")"}'
$L send <lane> '{"action":"click","selector":"button:has-text(\"Allow access\")"}'
```

Use `controls` between steps to see the real buttons. Done when the log says
`Successfully logged into Start URL`. (Older AWS CLIs without
`--use-device-code` print an authorize URL with a `127.0.0.1` callback; since
the lane runs on this host it can complete that too: `waiturl` on
`127\.0\.0\.1|oauth/callback`.)

### anything else

`gh`: `gh auth login --web -h <host>` prints a one-time code and
`https://github.com/login/device`; redeem it in a lane that holds that GitHub
session, otherwise relay URL and code via `PushNotification`. Types whose
`fix` names a manual step: report, do not attempt.

Only if the lane cannot be used at all, fall back to relaying the URL and
code, `PushNotification` first.

## `start idp <lane>`

Establishes the IdP browser session for a lane, so later flows go through
without a password. If the caller did not name a lane, infer it from what they
want to reach (config `owns`) and say which you picked.

1. `$L start <lane>`, `$L whoami <lane>`. If already LIVE as the right account, stop.
2. `goto` the target app (or the IdP `org_url`). Okta identifier-first:
   `fillcred` into `input[name=identifier]` (`field: user`), click `input[type=submit]`.
3. `fillcred` into `input[type=password]` (`field: pass`), click `input[type=submit]`.
4. MFA: `a[data-se=button] >> nth=1` is usually the push, `nth=0` the code.
   Then the hard gate above.
5. `waiturl` on the landing page, **then** `state`. Saving mid-redirect stores
   a half-session that bounces back to login next time.
6. `$L whoami <lane>` and report who the IdP says it is, not who you intended.

Before blaming auth for an app failure, probe the app's API directly (config
`http_up` identities): an unreachable backend is a finding, not a login.

## `verify`

Wait for the flows started earlier (logs in `$S/auth-*.log`), up to 9 minutes:

```bash
end=$((SECONDS+540))
while [ $SECONDS -lt $end ]; do
  ok=1; for f in $S/auth-*.log; do [ -f "$f" ] || continue
    grep -qE '"id":|Successfully|AADSTS|[Ee]rror|expired' "$f" || ok=0; done
  [ $ok = 1 ] && break; sleep 10
done
for f in $S/auth-*.log; do echo "== $f"; grep -oE 'AADSTS[0-9]+[^.]*|Successfully[^.]*|[Ee]rror[^.]*|expired[^.]*' "$f" | sort -u | head -5; done
auth-refresh check
```

Report the new expiries so the caller knows when the next death is due. A
device code lives about 15 minutes; past that, dispatch `start` again.

## Rules

- Never print an access token, refresh token, PAT, password, TOTP, or the
  contents of a token cache, `creds_file`, a lane's `out/sessions.json` or
  any captured SAML assertion. Presence, owner and expiry only. Credentials
  go into pages only via `fillcred`, never interpolated into a shell command.
- One outstanding push across all lanes. Never re-push while one is pending.
- Pick a lane by what you are logging into, never by what is warm.
- Talk to a lane only through `auth-refresh lane`; never poke its socket or files.
- Never end a turn, task or subagent with a lane on a challenge page: park it.
- Never let a number-match challenge sit without the number surfaced first.
- Never idle-wait on a login; read the page after the tap and finish the flow.
- Never trust the ambient PATH; a missing binary is a host fault, not a credential.
- Never run `az login` without `--use-device-code`, `aws sso login` without
  `--no-browser`, or `gh auth login` without `--web` on a headless host: each
  otherwise waits for a browser that never appears.
- Never `az logout`, `aws sso logout`, `gh auth logout` or delete a cache file.
  A dead session is re-established, not cleaned up.
- Kill earlier login attempts by pid, never `pkill -f` with a pattern that
  can match your own shell.
- The host notes file overrides this file.
