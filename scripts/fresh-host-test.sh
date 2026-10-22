#!/usr/bin/env bash
# Proves auth-refresh works on a host that has nothing but the binary: no Go,
# Node, Python or browser. Runs in a throwaway container by default; with
# --here it runs the same steps on the current machine in an isolated
# AUTH_REFRESH_HOME/AUTH_REFRESH_CONFIG, touching no real config or session.
#
# Usage:
#   scripts/fresh-host-test.sh [--image ubuntu:24.04] [--binary path]   in a container
#   scripts/fresh-host-test.sh --here [--binary path]                   on this host
set -euo pipefail

inner() {
  local bin="$1" pass=0 fail=0
  ok() { echo "PASS  $1"; pass=$((pass + 1)); }
  ko() {
    echo "FAIL  $1"
    if [[ -n "${2:-}" ]]; then printf '      %s\n' "$2"; fi
    fail=$((fail + 1))
  }
  expect() { # expect <name> <want-substring> <cmd...>
    local name="$1" want="$2" out
    shift 2
    out=$("$@" 2>&1) || true
    if [[ "$out" == *"$want"* ]]; then ok "$name"; else ko "$name" "want '$want', got: ${out:0:400}"; fi
  }

  local t
  t=$(mktemp -d)
  export AUTH_REFRESH_HOME="$t/state" AUTH_REFRESH_CONFIG="$t/config.json"
  mkdir -p "$t/idp/api/v1/users"
  printf '{"profile":{"login":"alice@example.com"},"lastLogin":"2026-10-22T00:00:00Z"}' > "$t/idp/api/v1/users/me"
  printf '<html><body><input name="identifier"><p>Push notification sent. On your phone, tap 42 in Okta Verify.</p></body></html>' > "$t/challenge.html"
  printf '[work]\nuser=alice@example.com\npass=not-a-real-password\n' > "$t/creds"
  chmod 600 "$t/creds"
  cat > "$t/config.json" <<EOF
{
  "required_binaries": ["sh"],
  "creds_file": "$t/creds",
  "idp": {"kind": "okta", "org_url": "file://$t/idp"},
  "lanes": {"work": {"account": "alice@example.com", "owns": ["everything"]}},
  "identities": [
    {"name": "missing-token", "type": "http_token", "file": "$t/absent", "url": "https://example.com"},
    {"name": "local-down", "type": "http_up", "url": "http://127.0.0.1:9/"}
  ]
}
EOF

  expect "version" "auth-refresh" "$bin" version
  if [[ "${SKIP_SETUP:-}" != 1 ]]; then
    expect "doctor flags a missing browser" "auth-refresh setup" "$bin" doctor
    expect "setup downloads driver and chromium" "installed" "$bin" setup
  fi
  expect "doctor passes after setup" "installed" "$bin" doctor
  expect "check reports MISSING token" "MISSING" "$bin" check --no-lanes
  expect "check reports a dead service" "local-down" "$bin" check --no-lanes
  if "$bin" check --no-lanes >/dev/null 2>&1; then ko "check exits non-zero when something is dead"; else ok "check exits non-zero when something is dead"; fi

  expect "lane starts" "lane work up" "$bin" lane start work
  expect "lane start is idempotent" "already running" "$bin" lane start work
  expect "goto" '"ok": true' "$bin" lane send work "{\"action\":\"goto\",\"url\":\"file://$t/challenge.html\"}"
  expect "fillcred own lane" '"ok": true' "$bin" lane send work '{"action":"fillcred","selector":"input[name=identifier]","field":"user"}'
  expect "fillcred refuses another lane" "LANE MISMATCH" "$bin" lane send work '{"action":"fillcred","selector":"input","field":"user","section":"other"}'
  expect "mfa reads the number" "MFA_NUMBER=42" "$bin" lane mfa work --tries 3
  expect "status flags the live challenge" "PARKED ON A LIVE CHALLENGE" "$bin" lane status
  expect "status left the challenge up" "tap 42" "$bin" lane send work '{"action":"text"}'
  expect "park" '"url": "about:blank"' "$bin" lane park work
  expect "whoami asks the IdP" "LIVE as alice@example.com" "$bin" lane whoami work
  expect "state saves the session" '"bytes"' "$bin" lane send work '{"action":"state"}'
  expect "lane stops" "lane work stopped" "$bin" lane stop work
  expect "send to a stopped lane fails" "not running" "$bin" lane send work '{"action":"text"}'
  expect "lane restarts" "lane work up" "$bin" lane start work
  expect "lane stops again" "lane work stopped" "$bin" lane stop work

  local perms
  perms=$(stat -c '%a' "$AUTH_REFRESH_HOME/lanes/work" "$AUTH_REFRESH_HOME/lanes/work/out/sessions.json" | tr '\n' ' ')
  if [[ "$perms" == "700 600 " ]]; then ok "lane dir 700, session 600"; else ko "lane dir 700, session 600" "got $perms"; fi
  if grep -rq "not-a-real-password" "$AUTH_REFRESH_HOME"; then ko "password never written to state"; else ok "password never written to state"; fi

  rm -rf "$t"
  echo
  echo "$pass passed, $fail failed"
  [[ $fail -eq 0 ]]
}

if [[ "${1:-}" == "--inner-run" ]]; then
  inner "$2"
  exit $?
fi

image="ubuntu:24.04"
binary=""
here=false
while [[ $# -gt 0 ]]; do
  case "$1" in
    --image) image="$2"; shift 2 ;;
    --binary) binary="$2"; shift 2 ;;
    --here) here=true; shift ;;
    *) echo "unknown argument $1" >&2; exit 2 ;;
  esac
done

repo=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
if [[ -z "$binary" ]]; then
  binary="$(mktemp -d)/auth-refresh"
  (cd "$repo" && CGO_ENABLED=0 go build -trimpath -ldflags "-s -w -X main.version=fresh-host-test" -o "$binary" ./cmd/auth-refresh)
fi
binary=$(cd "$(dirname "$binary")" && pwd)/$(basename "$binary")

if [[ "$here" == true ]]; then
  SKIP_SETUP=1 exec "$repo/scripts/fresh-host-test.sh" --inner-run "$binary"
fi

# Root installs Chromium's system libraries, as an admin would once; an
# unprivileged user does everything else, like a real host.
docker run --rm -i \
  -v "$binary:/usr/local/bin/auth-refresh:ro" \
  -v "$repo/scripts/fresh-host-test.sh:/fresh-host-test.sh:ro" \
  "$image" bash -euo pipefail -c '
    export DEBIAN_FRONTEND=noninteractive
    apt-get update -qq >/dev/null && apt-get install -y -qq ca-certificates >/dev/null
    for b in go node nodejs python3 chromium google-chrome; do
      if command -v "$b" >/dev/null; then echo "image is not fresh: has $b"; exit 1; fi
    done
    auth-refresh setup --with-deps >/dev/null
    useradd -m tester
    su tester -c "bash /fresh-host-test.sh --inner-run /usr/local/bin/auth-refresh"
  '
