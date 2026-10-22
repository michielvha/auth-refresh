# auth-refresh

Long unattended agent runs on a headless box die when a human SSO session hits its
sign-in frequency limit. auth-refresh checks every identity on the host and, for a
dead one, has the agent drive the whole login in a headless browser on the same
machine, so the only human step is one MFA tap. It surfaces the number-match digit
fast enough for you to answer it.

It is one static Go binary plus an agent prompt. A host needs nothing else: no Node,
Python or browser. `auth-refresh setup` fetches Playwright's driver and Chromium into
the user cache.

Supported out of the box:

- **Azure CLI** device-code login, and every kube context riding on it via kubelogin
- **AWS IAM Identity Center** `aws sso login`, and the EKS contexts on top
- **IdP browser sessions** (Okta) in isolated per-account *lanes*
- status of **gh**, **docker registries**, long-lived **API tokens** (Azure DevOps PATs,
  SonarQube, anything validated by one HTTP call) and plain **service health** URLs

## How it works

```
agents/auth-refresh.md          the agent: when to check, how to drive a login, the MFA rules
auth-refresh check              one line per identity; never prints a token
auth-refresh lane ...           one headless Chromium per human account, over a unix socket
```

The CLI starts a device-code flow, the agent redeems the code in the lane holding a
warm IdP session, and if the IdP asks for MFA the agent reads the number off the page
and puts it in the chat and in a push notification. Lanes exist because a cached IdP
session silently beats whatever username you type: two accounts must never share a
cookie jar.

## Try it on a new host

Nothing on the host changes until you write a config. The safest order:

```bash
# 1. the binary: a release asset, `go install`, or a copied static build
go install github.com/michielvha/auth-refresh/cmd/auth-refresh@latest
#    or: CGO_ENABLED=0 go build -trimpath -o auth-refresh ./cmd/auth-refresh && scp ...

# 2. the browser (sudo once with --with-deps on a bare OS for Chromium's libraries)
sudo auth-refresh setup --with-deps     # or just: auth-refresh setup

# 3. prove the machinery in isolation; touches no real config or session
scripts/fresh-host-test.sh --here --binary "$(command -v auth-refresh)"

# 4. a real config, then read-only checks
mkdir -p ~/.config/auth-refresh && chmod 700 ~/.config/auth-refresh
cp config.example.json ~/.config/auth-refresh/config.json   # edit
$EDITOR ~/.config/auth-refresh/creds && chmod 600 ~/.config/auth-refresh/creds
auth-refresh doctor
auth-refresh check

# 5. the agent (Claude Code), last
ln -s "$PWD/agents/auth-refresh.md" ~/.claude/agents/auth-refresh.md
```

`scripts/fresh-host-test.sh` without `--here` runs the same 24 checks in a pristine
`ubuntu:24.04` (or `--image debian:13`) container as an unprivileged user; CI runs both.

## Configuration

Host-specific files live in `~/.config/auth-refresh/` (override with `AUTH_REFRESH_CONFIG`):

| File | What |
|---|---|
| `config.json` | lanes, identities, IdP URL, MFA regexes, browser flags. See [config.example.json](config.example.json). Unknown keys are an error, so typos fail loudly. |
| `notes.md` | free-form host quirks for the agent (selectors, accounts not to touch, policy limits). The agent reads it first and it overrides the generic prompt. |
| `creds` | INI, one `[lane]` per section, keys `user` and `pass`. Read only by the driver's `fillcred`, refused unless mode 600. |

Runtime state (lane browser profiles, saved sessions, logs, MFA number history) lives
in `~/.local/share/auth-refresh/` (override with `AUTH_REFRESH_HOME`).

Identity types: `azure`, `aws_sso`, `kube`, `gh`, `docker`, `http_token`, `http_up`.

## Commands

```
auth-refresh check [--json] [--no-lanes]   exit 0 all OK, 1 something dead, 2 host problem
auth-refresh doctor                        config, credentials, browser, binaries
auth-refresh env                           export PATH line with the config's path_prepend
auth-refresh setup [--with-deps]           Playwright driver + Chromium headless shell
auth-refresh lane list|status|start|stop|send|park|whoami|mfa
```

Lane commands exit 3 when the lane is not running.

## Security notes

- A lane's `out/sessions.json` is a live credential. Lane directories are 0700, files
  and the control socket 0600.
- `controls` never returns a password field's value, only `(filled)`.
- `browser.capture_saml_assertions` writes decoded SAML assertions to disk, and
  `browser.netlog_bodies` keeps API response bodies for `netdump`. Both are debugging
  aids and off by default.
- `browser.ignore_https_errors` and per-identity `verify_tls: false` exist for
  TLS-intercepting corporate proxies. Leave them off anywhere else.
- Credentials never transit the shell: `fillcred` reads them inside the driver.

## Agent runtime

The prompt targets Claude Code (`tools: Bash, Read, PushNotification`, background Bash
calls that wake the agent on completion), and the repository root is a Claude Code
plugin. The binary is runtime-agnostic. The `start` modes must run in the main
conversation, not as a subagent, or the MFA number arrives after the push has expired.

## Development

```bash
go test ./...          # the lane end-to-end test drives a real browser; it skips until `auth-refresh setup`
go vet ./...
golangci-lint run
scripts/fresh-host-test.sh
```

## License

MIT
