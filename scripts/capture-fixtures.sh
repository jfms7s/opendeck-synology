#!/usr/bin/env bash
# Records real DSM 7 responses as test fixtures in tests/fixtures/real/
# (git-ignored: even redacted, they describe one real NAS).
#
# Usage:   scripts/capture-fixtures.sh <host> <account> [port]     (port: 5001)
# Env:     PIN_SHA256=<fingerprint> trusts a self-signed certificate - only
#          if the NAS presents exactly that one. Use the SHA-256 fingerprint
#          the plugin's settings panel shows (or DSM › Control Panel ›
#          Security › Certificate). Without it, the certificate must be valid
#          for <host> against the system's CAs.
#
# The password and 2FA code are read from the terminal; they, and the session
# id, reach curl through stdin or private temporary files - never its command
# line, where other local users could read them in the process list. Serial
# numbers, MAC/IP addresses, UUIDs and hostnames are replaced with "REDACTED"
# before anything is written.
#
# With a 2FA code the login asks DSM to remember this device (like the
# plugin does), so the names of the fields it answers with - the device
# token's included - end up in login_keys.json. Only the key names are
# written, never the sid or device token. DSM then lists an
# "OpenDeckCapture" trusted device you can remove in your personal settings.
set -euo pipefail

usage="usage: $0 <host> <account> [port]"
host=${1:?$usage}
account=${2:?$usage}
port=${3:-5001}
# A bare IPv6 address needs brackets in a URL.
[[ $host == *:* && $host != \[* ]] && host="[$host]"
base="https://$host:$port/webapi"

private=$(mktemp -d)
chmod 700 "$private"
sid=""

cleanup() {
	if [[ -n $sid ]]; then
		post entry.cgi --data-urlencode "api=SYNO.API.Auth" --data-urlencode "version=6" \
			--data-urlencode "method=logout" --data-urlencode "session=OpenDeckCapture" \
			--data-urlencode "_sid@$private/sid" >/dev/null || true
	fi
	rm -rf "$private"
}
trap cleanup EXIT

curl_opts=(--silent --show-error --fail --max-time 15 --proto =https)
if [[ -n ${PIN_SHA256:-} ]]; then
	want=$(tr -d ':[:space:]' <<<"$PIN_SHA256" | tr '[:upper:]' '[:lower:]')
	# Fetch the certificate the NAS presents and check it is the pinned one.
	openssl s_client -connect "$host:$port" -servername "${host//[\[\]]/}" </dev/null 2>/dev/null |
		openssl x509 -outform DER >"$private/cert.der"
	got=$(sha256sum "$private/cert.der" | cut -d' ' -f1)
	if [[ $got != "$want" ]]; then
		echo "the NAS presents certificate $got, not the pinned $want - stopping" >&2
		exit 1
	fi
	# Then let curl accept only that certificate's public key, on every
	# connection (a self-signed DSM certificate never passes CA checks).
	spki=$(openssl x509 -inform DER -in "$private/cert.der" -pubkey -noout |
		openssl pkey -pubin -outform DER | openssl dgst -sha256 -binary | base64)
	curl_opts+=(--insecure --pinnedpubkey "sha256//$spki")
fi

out="$(cd "$(dirname "$0")/.." && pwd)/tests/fixtures/real"
mkdir -p "$out"

read -rsp "DSM password for $account: " password
echo
read -rp "2FA code (leave empty if the account has no 2FA): " otp
otp=${otp//[[:space:]]/}
(umask 077 && printf %s "$otp" >"$private/otp")
unset otp

post() {
	local path=$1
	shift
	curl "${curl_opts[@]}" "$base/$path" "$@"
}

redact='walk(if type == "object" then with_entries(
  if (.key | test("serial|uuid|wwn|(^|_)(mac|ip|ipv6|hostname|server_name)(_|$)"; "i"))
  then .value = "REDACTED" else . end) else . end)'

apis="SYNO.API.Auth,SYNO.Core.System.Utilization,SYNO.Core.System,SYNO.Storage.CGI.Storage,SYNO.Core.Upgrade.Server"
post query.cgi --data-urlencode "api=SYNO.API.Info" --data-urlencode "version=1" \
	--data-urlencode "method=query" --data-urlencode "query=$apis" | jq '.data' >"$out/api_info.json"
echo "wrote $out/api_info.json"

login_args=(--data-urlencode "api=SYNO.API.Auth" --data-urlencode "version=6"
	--data-urlencode "method=login" --data-urlencode "account=$account"
	--data-urlencode "passwd@-" --data-urlencode "session=OpenDeckCapture"
	--data-urlencode "format=sid")
[[ -s $private/otp ]] && login_args+=(--data-urlencode "otp_code@$private/otp"
	--data-urlencode "enable_device_token=yes" --data-urlencode "device_name=OpenDeckCapture")

login=$(printf %s "$password" | post entry.cgi "${login_args[@]}")
unset password
rm -f "$private/otp"
if ! sid=$(jq -er '.data.sid' <<<"$login"); then
	sid=""
	echo "login failed: $(jq -c '.error' <<<"$login")" >&2
	exit 1
fi
# From here on the trap logs this session out, whatever fails next.
(umask 077 && printf %s "$sid" >"$private/sid")
# Field names only (e.g. ["did","sid",...]): never the values.
jq '.data | keys' <<<"$login" >"$out/login_keys.json"
unset login
echo "wrote $out/login_keys.json"

capture() {
	local name=$1 api=$2 version=$3 method=$4 resp
	resp=$(post entry.cgi --data-urlencode "api=$api" --data-urlencode "version=$version" \
		--data-urlencode "method=$method" --data-urlencode "_sid@$private/sid")
	if jq -e '.success' <<<"$resp" >/dev/null; then
		jq "$redact | .data" <<<"$resp" >"$out/$name.json"
		echo "wrote $out/$name.json"
	else
		echo "$api $method failed: $(jq -c '.error' <<<"$resp")" >&2
	fi
}

capture utilization SYNO.Core.System.Utilization 1 get
capture system SYNO.Core.System 1 info
capture storage SYNO.Storage.CGI.Storage 1 load_info
capture update SYNO.Core.Upgrade.Server 1 check
