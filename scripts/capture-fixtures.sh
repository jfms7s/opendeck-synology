#!/usr/bin/env bash
# Records real DSM 7 responses as test fixtures in tests/fixtures/real/.
#
# Usage:   scripts/capture-fixtures.sh <host[:port]> <account>
# Env:     INSECURE=1 accepts a self-signed certificate for this one run.
#
# The password is read from the terminal and handed to curl on stdin, so
# it never appears in the process list. Serial numbers, MAC/IP addresses,
# UUIDs and hostnames are replaced with "REDACTED" before anything is written.
set -euo pipefail

host=${1:?usage: $0 <host[:port]> <account>}
account=${2:?usage: $0 <host[:port]> <account>}
[[ $host == *:* ]] || host="$host:5001"
base="https://$host/webapi"

curl_opts=(--silent --show-error --fail --max-time 15)
[[ ${INSECURE:-0} == 1 ]] && curl_opts+=(--insecure)

out="$(cd "$(dirname "$0")/.." && pwd)/tests/fixtures/real"
mkdir -p "$out"

read -rsp "DSM password for $account: " password
echo
read -rp "2FA code (leave empty if the account has no 2FA): " otp
otp=${otp//[[:space:]]/}

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
[[ -n $otp ]] && login_args+=(--data-urlencode "otp_code=$otp")

login=$(printf %s "$password" | post entry.cgi "${login_args[@]}")
unset password
if ! sid=$(jq -er '.data.sid' <<<"$login"); then
	echo "login failed: $(jq -c '.error' <<<"$login")" >&2
	exit 1
fi

logout() {
	post entry.cgi --data-urlencode "api=SYNO.API.Auth" --data-urlencode "version=6" \
		--data-urlencode "method=logout" --data-urlencode "session=OpenDeckCapture" \
		--data-urlencode "_sid=$sid" >/dev/null || true
}
trap logout EXIT

capture() {
	local name=$1 api=$2 version=$3 method=$4 resp
	resp=$(post entry.cgi --data-urlencode "api=$api" --data-urlencode "version=$version" \
		--data-urlencode "method=$method" --data-urlencode "_sid=$sid")
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
