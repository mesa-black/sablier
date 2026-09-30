#!/bin/sh
# Regression test: the fixture must produce exactly these verdicts.
# It exists because the risk model IS the product — if the discrimination
# between harvesting, signatures and noise breaks, the tool is worthless.
set -eu
cd "$(dirname "$0")/.."

./bin/sablier scan tests/fixtures/sample --out=/tmp/sablier-test.html --json=/tmp/sablier-test.json --quiet || true

check() {
	found=$(php -r '
		$f = json_decode(file_get_contents("/tmp/sablier-test.json"), true);
		$n = 0;
		foreach ($f as $x) { if ($x["verdict"] === $argv[1] && $x["algorithm"] === $argv[2]) { ++$n; } }
		echo $n;
	' "$1" "$2")
	if [ "$found" != "$3" ]; then
		echo "✗ $1 / $2: expected $3, got $found"
		exit 1
	fi
	printf '  ✓ %-24s %-10s %s\n' "$1" "$2" "$3"
}

echo
check compromised rsa      1   # RSA key for backups kept ten years
check clear       aes-256  2   # symmetric cryptography is not the subject
check watch       rsa-sign 2   # a signature cannot be harvested
check urgent      sha1     1   # a classical problem, not a quantum one
check noise       md5      1   # md5 as a cache key is not a vulnerability
echo

# --- live probe, against a server we control -------------------------------
# Pointing the tool at somebody else's host to test our own code is neither
# necessary nor polite. A local TLS server pinned to a classical group tests
# the path that matters, deterministically — and it is how the "Peer Temp Key"
# parsing bug was found in the first place.
if command -v openssl >/dev/null 2>&1; then
	tmp=$(mktemp -d)
	openssl req -x509 -newkey rsa:2048 -keyout "$tmp/k.pem" -out "$tmp/c.pem" \
		-days 2 -nodes -subj "/CN=localhost" 2>/dev/null
	openssl s_server -cert "$tmp/c.pem" -key "$tmp/k.pem" -accept 14433 -groups X25519 -quiet >/dev/null 2>&1 &
	server=$!
	sleep 2

	group=$(./bin/sablier probe 127.0.0.1:14433 2>/dev/null | grep -o 'X25519[A-Za-z0-9]*' | head -1)
	kill "$server" 2>/dev/null
	# `|| true` matters: wait returns the killed process's status, and set -e
	# would end the run here with everything reported as passing.
	wait "$server" 2>/dev/null || true
	rm -rf "$tmp"

	if [ "$group" = "X25519" ]; then
		printf '  ✓ %-24s %-10s %s\n' "probe" "group" "X25519"
	else
		echo "✗ probe: expected the classical group X25519, got \"${group:-nothing}\""
		exit 1
	fi
else
	echo "  · probe test skipped: no openssl binary"
fi
# --- STARTTLS dialogues ------------------------------------------------------
# Mail servers belong to other people; these dialogues are checked against a
# twenty-line local server instead.
tmp=$(mktemp -d)
openssl req -x509 -newkey rsa:2048 -keyout "$tmp/k.pem" -out "$tmp/c.pem" \
	-days 2 -nodes -subj "/CN=localhost" 2>/dev/null

port=14600
for proto in smtp imap pop3; do
	port=$((port + 1))
	php tests/starttls-server.php "$proto" "$port" "$tmp/c.pem" "$tmp/k.pem" >/dev/null 2>&1 &
	fake=$!
	sleep 1

	got=$(./bin/sablier probe "$proto://127.0.0.1:$port" 2>/dev/null | grep -c 'TLSv1' || true)
	kill "$fake" 2>/dev/null || true
	wait "$fake" 2>/dev/null || true

	if [ "$got" -ge 1 ]; then
		printf '  ✓ %-24s %-10s %s\n' "starttls" "$proto" "upgraded"
	else
		echo "✗ starttls $proto: no TLS after the upgrade"
		rm -rf "$tmp"
		exit 1
	fi
done
rm -rf "$tmp"

echo
echo "✓ the risk model still discriminates, and every transport reaches TLS"
