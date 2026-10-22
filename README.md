# auth-refresh

Long unattended agent runs on a headless box die when a human SSO session hits its
sign-in frequency limit. auth-refresh checks every identity on the host and, for a
dead one, has the agent drive the whole login in a headless browser on the same
machine, so the only human step is one MFA tap. It surfaces the number-match digit
fast enough for you to answer it.

auth-refresh is a static Go binary plus an agent prompt. The browser is not pure
Go: `auth-refresh setup` downloads Playwright's driver (playwright-core and the
Node.js runtime it runs on, pinned to the version the binary was built against) and
Chromium's headless shell into your user cache. You do not install Node, Python or a
browser yourself, but setup needs network access to registry.npmjs.org, nodejs.org
and Playwright's browser CDN, and Chromium needs its system libraries (see below).

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

## Plugin installation

Auth-refresh is a separate plugin. It does not require vh-adlc. The same canonical skill and
provider workflow serve Claude, Codex and other clients that load Agent Plugins.

These instructions describe the feature candidate. The published main branch and the shared
marketplace must first pin this candidate, and a verified runtime release must be published.
Until the release lock is populated, the new skill reports that release provisioning is pending.
The existing Claude agent can still use an already installed auth-refresh binary on PATH.

In Claude Code, install directly from this repository:

```text
/plugin install auth-refresh --marketplace michielvha/auth-refresh
```

In Codex, add `michielvha/auth-refresh` as a marketplace in Plugins, then install auth-refresh.
The CLI equivalents are:

```sh
codex plugin marketplace add michielvha/auth-refresh
codex plugin add auth-refresh@auth-refresh
```

The shared `michielvha/vh-adlc` marketplace also offers auth-refresh as a separate selection;
install `auth-refresh@vhco-tools`. Installing vh-adlc alone does not enable auth-refresh.
Refresh the marketplace and the plugin in your client's native manager to update it. Uninstalling
the plugin leaves private config, credentials, CLI caches and lane sessions on disk.

The new skill's installer requires Bash and Python 3. It checks the pinned archive and binary
SHA-256 values before execution and verifies the cached binary on every reuse. It writes only
to your user cache. It never builds missing source or changes shell profiles.

### Notifications and compatibility

Claude Remote Control keeps PushNotification, immediate number delivery, the bounded confirmation
watcher and background completion. The legacy agent remains a thin entry point into the same
canonical workflow, with its existing tools and installed-binary bootstrap. The old 20 KB save
heuristic is removed: check the expected identity and actual restoration instead.

Other interactive hosts show the number immediately in chat and finish consent in the main session.
Unattended operation needs a working phone-notification tool and continuation mechanism. Missing
capability stops before a challenge; delivery failure parks the active challenge and suppresses
further pushes. Chat-only delivery is never reported as a phone push.

Native standalone installation has passed on Codex CLI and Claude CLI in isolated Linux profiles.
Phone delivery through the owner's Remote Control session, VS Code Local, and published remote
installation remain acceptance tests. Installation success alone does not establish those behaviors.

### Verified browser dependencies

`setup`, `doctor` and lane startup now check the managed runtime against the embedded
`internal/browserruntime/lock.json`. Setup verifies each upstream archive before extraction and
checks all pinned driver, Node.js and browser files before executing them. It rejects unexpected
driver code and refuses unverified external Node/CLI overrides. Existing corrupt caches are left
untouched with an error; select a fresh cache for recovery. `PLAYWRIGHT_DRIVER_PATH` and
`PLAYWRIGHT_BROWSERS_PATH` can select those managed directories.

The verified archive lock currently covers **Linux amd64**. Other browser platforms fail explicitly
until their archives are pinned and tested. This is separate from the Go binary's build targets.
Regenerate measured hashes with `python3 scripts/pin-browser-runtime.py`, then review the source
URLs and lock diff. The sources are the exact playwright-core npm package, Node.js distribution
and Chrome Headless Shell archive named in that lock. No browser payload is executed to generate it.

## Try it on a new host

There is no published release yet and the repository is not public, so build the
binary on a machine that has Go and copy it over. Nothing on the target host changes
until you write a config.

```bash
# 1. build a static binary (on the build machine)
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -o auth-refresh ./cmd/auth-refresh
#    macOS on Apple silicon: GOOS=darwin GOARCH=arm64
scp auth-refresh newhost:~/.local/bin/

# 2. Chromium's system libraries, once, with the OS package manager (see below)

# 3. the driver and browser, as the user that will run the lanes (not root)
auth-refresh setup        # downloads, then starts the browser once to prove it works

# 4. config, notes and credentials (see "Moving a config to another host")
auth-refresh doctor       # starts the exact pinned driver and Chromium, checks the config
auth-refresh check        # read-only; never touches a browser lane

# 5. the agent (Claude Code), last
ln -s "$PWD/agents/auth-refresh.md" ~/.claude/agents/auth-refresh.md
```

### System libraries

`setup` installs only into your user cache and never runs a package manager. The
headless shell links against NSS, GLib, ATK/AT-SPI, D-Bus, X11/xcb, xkbcommon,
GBM, ALSA, expat and udev; the bundled Node.js needs libstdc++. On Fedora, ask `dnf`
for exactly those libraries by soname, which avoids guessing package names:

```bash
sudo dnf install 'libnss3.so()(64bit)' 'libnssutil3.so()(64bit)' 'libnspr4.so()(64bit)' \
  'libglib-2.0.so.0()(64bit)' 'libgobject-2.0.so.0()(64bit)' 'libgio-2.0.so.0()(64bit)' \
  'libatk-1.0.so.0()(64bit)' 'libatk-bridge-2.0.so.0()(64bit)' 'libatspi.so.0()(64bit)' \
  'libdbus-1.so.3()(64bit)' 'libX11.so.6()(64bit)' 'libXcomposite.so.1()(64bit)' \
  'libXdamage.so.1()(64bit)' 'libXext.so.6()(64bit)' 'libXfixes.so.3()(64bit)' \
  'libXrandr.so.2()(64bit)' 'libxcb.so.1()(64bit)' 'libxkbcommon.so.0()(64bit)' \
  'libgbm.so.1()(64bit)' 'libexpat.so.1()(64bit)' 'libudev.so.1()(64bit)' \
  'libasound.so.2()(64bit)' 'libstdc++.so.6()(64bit)'
```

That list is the `NEEDED` entries of the headless shell and Node.js that
Playwright 1.62.1 downloads (read with `readelf -d`). If the browser still fails to
start, list what is missing and install that by soname the same way:

```bash
ldd ~/.cache/ms-playwright/chromium_headless_shell-*/chrome-headless-shell-linux64/chrome-headless-shell | grep 'not found'
```

On Debian or Ubuntu, Playwright's own `install-deps` knows the package names: run it
with the driver directory `auth-refresh setup` prints (by default
`~/.cache/ms-playwright-go/<version>`):
`sudo <driver dir>/node <driver dir>/package/cli.js install-deps chromium-headless-shell`.
Run `setup` itself as your normal user, not root.

### Moving a config to another host

Copy `config.json` and `notes.md` privately (`scp`, or paste them into an editor
over SSH); they name accounts and internal hosts, so do not put them in a repository
or a chat. Copy `creds` separately the same way, then `chmod 600` it. Paths written
as `~/...` (`creds_file`, `notes_file`, token `file`s, `path_prepend`) resolve
against the new home directory, so a different username needs no edits.

Before the first `check`, edit the copy for the new host:

- delete identities whose CLIs, kube contexts or tokens are not on it, and
  `path_prepend` entries that do not exist there (for example a Linuxbrew prefix);
- drop browser and TLS settings that only a corporate proxy needed
  (`chromium_args`, `ignore_https_errors`, per-identity `verify_tls: false`) unless
  the new host is behind the same proxy;
- delete `browser.capture_saml_assertions` and `browser.netlog_bodies` if present:
  those features were removed and the keys are now rejected by name.

Do not copy `~/.local/share/auth-refresh` (lane profiles and saved sessions) or any
CLI token cache. A clean trial starts cold, and every login is then exercised for real.

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
auth-refresh check [--json]     exit 0 all OK (WARN included), 1 something dead, 2 host problem
auth-refresh doctor             config, credentials, binaries; starts the pinned driver and Chromium
auth-refresh env                export PATH line with the config's path_prepend
auth-refresh setup              Playwright driver + Chromium headless shell into the user cache
auth-refresh lane list|status|start|stop|send|park|whoami|mfa
```

`check` runs CLI and HTTP probes only. A `DEAD` line means the credential is expired
or missing; a `WARN` line (RBAC `Forbidden`, timeout, unreachable API, an output it
does not recognise) means a login would not help, so it carries no fix.

`lane status` is passive: pid, saved session, the page's URL and whether it shows a
live challenge, read without navigating or waiting on the page. `lane whoami` asks
the IdP in a throwaway page and is refused unless the lane is parked on
`about:blank`, so it can never kill a login in progress.

Lane commands exit 3 when the lane is not running.

Managed runtime directories honor `PLAYWRIGHT_DRIVER_PATH` and `PLAYWRIGHT_BROWSERS_PATH`.
Unverified `PLAYWRIGHT_NODEJS_PATH` and `PLAYWRIGHT_CLI_PATH` overrides are refused.

## Security notes

- A lane's `out/sessions.json` is a live credential. Lane directories are 0700, files
  and the control socket 0600.
- `controls` never returns a password field's value, only `(filled)`.
- `browser.ignore_https_errors` and per-identity `verify_tls: false` exist for
  TLS-intercepting corporate proxies. Leave them off anywhere else.
- Credentials never transit the shell: `fillcred` reads them inside the driver.

## Agent runtime

The shared skill selects host capabilities. The legacy Claude agent retains
`tools: Bash, Read, PushNotification` and background completion behavior. The repository
contains native Claude and portable manifests. The binary is runtime-agnostic. The `start` modes must run in the main
conversation, not as a subagent, or the MFA number arrives after the push has expired.

## Development

```bash
go test ./...                    # lane tests drive a real Chromium; they skip until `auth-refresh setup`
AUTH_REFRESH_E2E=1 go test -count=1 -run 'TestLaneEndToEnd|TestProbe' ./internal/lane/   # fail instead of skip
go vet ./...
golangci-lint run
```

CI runs the same: the usual Go checks, then `setup` and the real-browser tests with
`AUTH_REFRESH_E2E=1` on an Ubuntu runner, against a fake IdP. Fedora has not been
through an acceptance run yet.

## License

MIT
