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
echo "✓ the risk model still discriminates"
