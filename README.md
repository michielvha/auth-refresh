# auth-refresh

Long unattended agent runs on a headless box die when a human SSO session hits its
sign-in frequency limit. auth-refresh checks every identity on the host and, for a
dead one, has the agent drive the whole login in a headless browser on the same
machine, so the only human step is one MFA tap. It surfaces the number-match digit
fast enough for you to answer it.

auth-refresh is a Go binary plus a shared agent workflow. Its plugin installer requires Bash,
curl and Python 3. `auth-refresh setup` downloads the pinned Playwright driver, its Node.js runtime
and Chromium's headless shell into your user cache. Node.js and Chromium do not need separate
installation. Browser setup needs access to registry.npmjs.org, nodejs.org and Playwright's browser
CDN, plus the system libraries listed below. Managed browser support currently covers Linux amd64.

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

Install the standalone plugin from this repository's default branch.
The plugin lock pins the signed runtime release `v0.2.0-rc.2`, with archive and binary hashes measured
from its verified assets. The existing Claude agent uses an installed binary on PATH, or provisions
the same pinned runtime when none is present.

In Claude Code, install directly from this repository:

```text
/plugin marketplace add https://github.com/michielvha/auth-refresh.git
/plugin install auth-refresh@auth-refresh
```

In Codex, add `michielvha/auth-refresh` as a marketplace in Plugins, then install auth-refresh.
The CLI equivalents are:

```sh
codex plugin marketplace add michielvha/auth-refresh
codex plugin add auth-refresh@auth-refresh
```

The shared marketplace integration is available on the default branch of
[vh-adlc](https://github.com/michielvha/vh-adlc). Add
`michielvha/vh-adlc` in Codex, or
`https://github.com/michielvha/vh-adlc.git` in Claude Code,
then install `auth-refresh@vhco-tools`. Installing vh-adlc alone does not enable auth-refresh.
Refresh the marketplace and the plugin in your client's native manager to update it. Uninstalling
the plugin leaves private config, credentials, CLI caches and lane sessions on disk.

The installer downloads the public runtime release and checks pinned archive and binary SHA-256
values before execution. It also verifies a cached binary on every reuse. It writes to your user
cache without changing shell profiles or requiring a Go toolchain. Private release deployments can
use authenticated `gh` as a fallback; the public release needs no GitHub credentials.

### Notifications and compatibility

The Claude Remote Control workflow uses PushNotification, immediate number delivery, a bounded
confirmation watcher and background completion. The legacy agent is an entry point into that same
workflow. A saved session is accepted by verifying its expected identity after restoration.

Other interactive hosts show the number immediately in chat and finish consent in the main session.
Unattended operation needs a working phone-notification tool and continuation mechanism. Missing
capability stops before a challenge; delivery failure parks the active challenge and suppresses
further pushes. Chat-only delivery is never reported as a phone push.

Native installation, update and uninstall are tested in disposable Codex CLI and Claude CLI profiles
on Linux and macOS through both GitHub marketplace routes. On macOS, Claude Desktop 3.6556.2 and
VS Code 1.142.0 with the Claude Code extension 2.1.309 passed discovery and a read-only missing-token
check through both routes. These GUI invocations used temporary user-scope installations. A
project-local plugin only loads in its corresponding working directory, not a Desktop scratch session.

Linux acceptance verified Azure, AWS and Okta logins and read-only AWS and Kubernetes identity
checks. The owner reports working Remote Control phone delivery; independent review
of the complete phone-login-to-continuation flow remains a release gate. macOS GUI acceptance
covers read-only invocation, not managed-browser logins. The managed browser remains limited to
Linux amd64; published macOS runtime binaries have verified integrity and executable check coverage.

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

## First-time setup

Create the local configuration files below for this machine. Install the provider CLIs you intend
to use and configure their accounts first. For AWS, the SSO session and profile must already exist in the AWS CLI config;
auth-refresh renews their credentials. Only list identities and contexts available on this machine.

### Get the CLI

The plugin provisions its verified runtime when invoked. If you also want to run the CLI directly,
clone this repository and use its installer:

```bash
git clone https://github.com/michielvha/auth-refresh.git
cd auth-refresh
AUTH_REFRESH_BIN=$(bash scripts/ensure-auth-refresh.sh)
"$AUTH_REFRESH_BIN" version
```

Use `"$AUTH_REFRESH_BIN"` for the following shell commands. A fresh shell can obtain the path again
by running the installer from the checkout. This uses the published signed release.

### Create config.json

Create the private configuration directory:

```bash
umask 077
mkdir -p ~/.config/auth-refresh
chmod 700 ~/.config/auth-refresh
```

In your local editor, create `~/.config/auth-refresh/config.json`. This minimal example defines one
Okta account lane and one AWS identity. Replace the example values with your IdP organization,
account, AWS SSO session, start URL and profile before using it:

```json
{
  "creds_file": "~/.config/auth-refresh/creds",
  "notes_file": "~/.config/auth-refresh/notes.md",
  "idp": {
    "kind": "okta",
    "org_url": "https://example.okta.com"
  },
  "lanes": {
    "work": {
      "account": "you@example.com",
      "owns": ["aws"]
    }
  },
  "identities": [
    {
      "name": "aws",
      "type": "aws_sso",
      "lane": "work",
      "sso_session": "work",
      "start_url": "https://d-0000000000.awsapps.com/start",
      "probe_profile": "work"
    }
  ]
}
```

[config.example.json](config.example.json) documents examples for Azure, Kubernetes, GitHub,
registries, manually issued tokens and service checks. Add only the entries you need. Use a separate
lane for each human account; identities belonging to the same account can share its lane.
Keep the TLS defaults unless your environment specifically requires a proxy configuration.

### Create notes.md

Create `~/.config/auth-refresh/notes.md` in your editor. Write the account ownership and login rules
an agent needs on this machine. For example:

```markdown
# Local authentication rules

The work lane must authenticate as you@example.com.
Use the work AWS SSO session and profile.
Do not switch other GitHub accounts or change global Git authentication.
Ask before starting a login outside the identities listed in config.json.
```

Replace those examples with your own rules. The workflow reads this file before acting. If you do
not need local notes, omit `notes_file` from the config instead of pointing it at a missing file.

### Create credentials and token files

For browser lanes, create `~/.config/auth-refresh/creds` in your local editor. Use one INI section
per lane; its section name must match the name under `lanes`. Enter your own username and password
locally, replacing both example values:

```ini
[work]
user=you@example.com
pass=replace-with-your-password
```

For the example above, restrict all three files after saving them (omit `notes.md` here if you did
not create that optional file):

```bash
chmod 600 ~/.config/auth-refresh/config.json ~/.config/auth-refresh/notes.md ~/.config/auth-refresh/creds
```

For a `http_token` identity, mint its token through the provider's normal UI and save it locally at
the identity's `file` path with mode `0600`. Token issuance remains manual. Provider CLI login caches
are managed by those CLIs. A checks-only configuration can omit `lanes`, `idp` and `creds_file`.

### Install the browser and check setup

Install the system libraries below, then run these commands as the normal user who will run the lanes:

```bash
"$AUTH_REFRESH_BIN" setup
"$AUTH_REFRESH_BIN" doctor
"$AUTH_REFRESH_BIN" check
```

`setup` verifies the downloads and starts the browser. `doctor` checks the config, configured CLI
binaries, credential-file permissions, notes and browser startup. `check` reports authentication
status without starting a login. Once these work, invoke the plugin to refresh one configured
identity and complete any MFA challenge on your own device. Browser sessions are created on this
machine during login and retained in its private runtime state.

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
  explicitly trusted TLS-intercepting proxies. Leave them off anywhere else.
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
CGO_ENABLED=1 AUTH_REFRESH_E2E=1 go test -race -count=1 ./...  # requires a C compiler on Linux
go vet ./...
golangci-lint run
```

CI runs the usual Go checks, then `setup` and real-browser tests with `AUTH_REFRESH_E2E=1`
on an Ubuntu runner against a fake IdP. Fedora 43 Linux amd64 has passed runtime provisioning,
browser startup and the fake-IdP browser suite. Phone delivery, desktop/VS Code invocation and the
complete live-provider matrix remain separate acceptance tests.

## License

MIT

## Verify a runtime release

Runtime releases include `checksums.txt` and `checksums.txt.sig`, signed with the VHCO Pro release
key. Download the archive and both checksum files with `gh release download`, then verify the
signature with [release-signing-key.asc](release-signing-key.asc) in an isolated GPG keyring.
The primary key fingerprint must be `9A5CD8F7CF9617B1C57F359ED61B8A7F2C06BAB6`.
Run `gpg --verify checksums.txt.sig checksums.txt`, then `sha256sum --check --ignore-missing checksums.txt`
(or `shasum -a 256 --check --ignore-missing checksums.txt` on macOS). The plugin lock pins independently
measured archive and binary hashes from these verified assets.

### Version automation

CI calls the SHA-pinned `vhco-pro/version-workflow` only after both `verify` and
`browser-e2e` succeed. It currently runs with `dry-run: true` and preview tagging
disabled: merging a change calculates a version but cannot create a tag or publish
a release. This staging step does not claim release acceptance.

Before enabling publication, complete the release acceptance gate, check the
calculated main-branch version is exactly the intended version, and configure a
release App using `RELEASE_APP_CLIENT_ID` and `RELEASE_APP_PRIVATE_KEY`. A reviewed
change can then pass those credentials to the shared workflow and enable tagging.
An App-created tag starts the existing signed, tag-triggered release workflow;
a tag pushed with `GITHUB_TOKEN` does not start another workflow.

After publication, verify the signature and all archive and extracted binary
hashes before updating `auth-refresh.lock.json` and the plugin manifests in a
separate checked change.
