#!/bin/sh
# Regression test: the fixture must produce exactly these verdicts.
# It exists because the risk model IS the product — if the discrimination
# between harvesting, signatures and noise breaks, the tool is worthless.
set -eu
cd "$(dirname "$0")/.."

./bin/sablier scan tests/fixtures/sample --out=/tmp/sablier-test.html --json=/tmp/sablier-test.json --quiet || true

check() {
	found=$(php -r '
		$f = json_decode(file_get_contents(getenv("SABLIER_TEST_JSON") ?: "/tmp/sablier-test.json"), true);
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

# --- accepting a finding -----------------------------------------------------
# The two rules that keep this feature from emptying the tool: an accepted
# finding stays visible under its own verdict, and the acceptance expires.
acc=$(mktemp -d)/sablier.json
cp tests/fixtures/sample/sablier.json "$acc"
fp=$(php -r '
	$f = json_decode(file_get_contents("/tmp/sablier-test.json"), true);
	foreach ($f as $x) { if ($x["verdict"] === "urgent") { echo $x["fingerprint"]; break; } }
')

./bin/sablier accept "$fp" --reason="test" --until=2099-01-01 --declare="$acc" >/dev/null
export SABLIER_TEST_JSON=/tmp/sablier-acc.json
./bin/sablier scan tests/fixtures/sample --declare="$acc" --json=/tmp/sablier-acc.json --out=/tmp/sablier-acc.html --quiet || true
check accepted sha1 1

# The same acceptance, expired, must hand the finding back.
sed -i.bak 's/2099-01-01/2020-01-01/' "$acc"
./bin/sablier scan tests/fixtures/sample --declare="$acc" --json=/tmp/sablier-acc.json --out=/tmp/sablier-acc.html --quiet || true
check urgent sha1 1
rm -rf "$(dirname "$acc")"

unset SABLIER_TEST_JSON

# --- the pipeline verdict ----------------------------------------------------
# The baseline is what lets the tool live in a pipeline, and one rule separates
# it from a suppression file: a red finding it already recorded still stops the
# build. Only an acceptance clears it, because only an acceptance carries a
# reason, a date and a reviewer.
work=$(mktemp -d)
cp -R tests/fixtures/sample/. "$work/"
./bin/sablier scan "$work" --json="$work/baseline.json" --out="$work/r.html" --quiet >/dev/null || true

status() {
	code=0
	./bin/sablier scan "$work" --baseline="$work/baseline.json" --out="$work/r.html" --quiet >"$work/out.txt" 2>&1 || code=$?
	if [ "$code" != "$2" ]; then
		echo "✗ baseline $1: expected exit $2, got $code"
		cat "$work/out.txt"
		rm -rf "$work"
		exit 1
	fi
	printf '  ✓ %-24s %-10s %s\n' "baseline" "$1" "exit $2"
}

status "red" 2
for fp in $(php -r '
	$f = json_decode(file_get_contents($argv[1]), true);
	foreach ($f as $x) { if (in_array($x["verdict"], ["compromised", "urgent"], true)) { echo $x["fingerprint"], " "; } }
' "$work/baseline.json"); do
	./bin/sablier accept "$fp" --reason="regression test" --until=2099-01-01 --declare="$work/sablier.json" >/dev/null
done
status "decided" 0

# Nothing in the declaration moved; a single new file must still stop it.
printf '<?php\n\nreturn hash("sha1", $payload);\n' >"$work/src/NewToken.php"
status "new file" 2
rm -rf "$work"

# --- somebody else's inventory ----------------------------------------------
# The import is the whole claim that this tool is a judgement layer rather than
# another scanner: a CBOM produced elsewhere, crossed with a declaration
# written here, must come out with the same verdicts our own scan produces.
cbom=$(mktemp -d)
./bin/sablier scan tests/fixtures/sample --cbom="$cbom/round.json" --json="$cbom/scan.json" \
	--out="$cbom/r.html" --quiet >/dev/null || true
./bin/sablier judge "$cbom/round.json" --declare=tests/fixtures/sample/sablier.json \
	--json="$cbom/judged.json" --out="$cbom/j.html" --quiet >/dev/null || true

same=$(php -r '
	$key = static function (array $rows): array {
		$o = [];
		foreach ($rows as $r) { $o[$r["algorithm"]."|".$r["file"]] = $r["verdict"]; }
		ksort($o);
		return $o;
	};
	$a = $key(json_decode(file_get_contents($argv[1]), true));
	$b = $key(json_decode(file_get_contents($argv[2]), true));
	echo $a === $b && $a !== [] ? count($a) : "0";
' "$cbom/scan.json" "$cbom/judged.json")
if [ "$same" = "0" ]; then
	echo "✗ cbom: the round trip changed the verdicts"
	rm -rf "$cbom"
	exit 1
fi
printf '  ✓ %-24s %-10s %s\n' "cbom" "roundtrip" "$same verdicts"

# A CBOM from another tool, in a language this one cannot read at all.
export SABLIER_TEST_JSON="$cbom/foreign.json"
./bin/sablier judge tests/fixtures/cbom/foreign.json --declare=tests/fixtures/cbom/sablier.json \
	--json="$cbom/foreign.json" --out="$cbom/f.html" --quiet >/dev/null || true
check compromised rsa      1   # RSA encrypting a backup kept twelve years
check watch       rsa-sign 1   # the same algorithm signing: not harvestable
check clear       aes-256  1   # and the symmetric cipher next to it is fine
check urgent      sha1     1
unset SABLIER_TEST_JSON

# A location of "./.env.example" keeps its dot and loses its prefix: the first
# naive trim ate both, and .env is exactly the file this tool must keep reading.
if [ "$(php -r '
	foreach (json_decode(file_get_contents($argv[1]), true) as $x) {
		if ($x["file"] === ".env.example") { echo "ok"; break; }
	}
' "$cbom/foreign.json")" != "ok" ]; then
	echo "✗ cbom: a ./-prefixed dotfile location came out mangled"
	rm -rf "$cbom"
	exit 1
fi
printf '  ✓ %-24s %-10s %s\n' "cbom" "location" "./ stripped, dot kept"

# What it could not read must be named, not dropped.
if ! grep -q "Camellia" "$cbom/f.html"; then
	echo "✗ cbom: an unjudged component vanished instead of being printed"
	rm -rf "$cbom"
	exit 1
fi
printf '  ✓ %-24s %-10s %s\n' "cbom" "unjudged" "named"
rm -rf "$cbom"

# --- published vulnerabilities in declared libraries -------------------------
# The claim that separates this from the rest of the report: a library with a
# published hole is a problem today, not in 2035. Without the advisory file the
# same lock file must stay plain inventory — a tool that guesses in the absence
# of data is worse than one that says it did not look.
adv=$(mktemp -d)
./bin/sablier scan tests/fixtures/advisories --json="$adv/plain.json" --out="$adv/r.html" --quiet >/dev/null || true
./bin/sablier scan tests/fixtures/advisories --advisories=tests/fixtures/advisories/advisories.json \
	--json="$adv/judged.json" --out="$adv/r.html" --quiet >/dev/null || true

verdicts=$(php -r '
	$read = static function (string $file): array {
		$out = [];
		foreach (json_decode(file_get_contents($file), true) as $row) { $out[$row["algorithm"]] = $row; }
		return $out;
	};
	$plain = $read($argv[1]);
	$judged = $read($argv[2]);
	// phpseclib is rsa, firebase/php-jwt is rsa-sign, otphp is sha1.
	$was = $plain["rsa"]["verdict"] ?? "?";
	$now = $judged["rsa"]["verdict"] ?? "?";
	$refs = $judged["rsa"]["references"] ?? [];
	$untouched = $judged["sha1"]["verdict"] ?? "?";   // no advisory in the fixture
	echo $was === "watch" && $now === "urgent" && in_array("CVE-2023-27560", $refs, true) && $untouched === "watch"
		? "ok" : "was=$was now=$now untouched=$untouched";
' "$adv/plain.json" "$adv/judged.json")
if [ "$verdicts" != "ok" ]; then
	echo "✗ advisories: expected watch → urgent for the vulnerable library only ($verdicts)"
	rm -rf "$adv"
	exit 1
fi
printf '  ✓ %-24s %-10s %s\n' "advisories" "verdict" "watch → urgent"

# A medium or low advisory is attached, never promoted: the threshold is the
# one make cve applies to our own images, and it has to be visible.
low=$(php -r '
	foreach (json_decode(file_get_contents($argv[1]), true) as $row) {
		if ($row["algorithm"] === "aes-256") { echo $row["verdict"]; return; }
	}
	echo "absent";
' "$adv/judged.json")
if [ "$low" = "urgent" ]; then
	echo "✗ advisories: a low-severity advisory promoted a finding"
	rm -rf "$adv"
	exit 1
fi
printf '  ✓ %-24s %-10s %s\n' "advisories" "threshold" "low not promoted"

# The collection keeps what this tool inventories and counts the rest; a
# project's whole dependency tree does not belong under a cryptographic heading.
scoped=$(php -r '
	foreach (["Lang", "Value", "Catalogue", "Finding", "SourceFile", "Detector/DetectorInterface", "Detector/DependencyDetector", "Advisories"] as $class) {
		require "src/$class.php";
	}
	$report = ["Results" => [["Vulnerabilities" => [
		["PkgName" => "phpseclib/phpseclib", "VulnerabilityID" => "CVE-1", "Severity" => "HIGH", "FixedVersion" => "3.0.19"],
		["PkgName" => "symfony/http-kernel", "VulnerabilityID" => "CVE-2", "Severity" => "CRITICAL"],
		["PkgName" => "lodash", "VulnerabilityID" => "CVE-3", "Severity" => "HIGH"],
	]]]];
	$collected = Sablier\Advisories::fromScannerReport($report, "test", "/tmp");
	echo count($collected["packages"]) === 1 && $collected["other_vulnerable_packages"] === 2 ? "ok" : "no";
')
if [ "$scoped" != "ok" ]; then
	echo "✗ advisories: the collection must keep cryptographic packages and count the others"
	rm -rf "$adv"
	exit 1
fi
printf '  ✓ %-24s %-10s %s\n' "advisories" "scope" "crypto kept, rest counted"
rm -rf "$adv"

# --- published defects, cited rather than asserted -------------------------
# A CVE is a dated fact somebody else published; the post-quantum deadline is
# not one. The table must cover the first family and leave the second alone,
# or the report turns a horizon into an accusation.
refs=$(php -r '
	$rows = json_decode(file_get_contents($argv[1]), true);
	$byAlgorithm = [];
	foreach ($rows as $row) { $byAlgorithm[$row["algorithm"]] = $row["references"]; }
	$broken = $byAlgorithm["sha1"] ?? [];
	$quantum = $byAlgorithm["rsa"] ?? ["unexpected"];
	echo $broken === ["CVE-2005-4900"] && $quantum === [] ? "ok" : "no";
' /tmp/sablier-test.json)
if [ "$refs" != "ok" ]; then
	echo "✗ references: a broken algorithm must carry its CVE, a quantum deadline must not"
	exit 1
fi
printf '  ✓ %-24s %-10s %s\n' "references" "sha1" "CVE-2005-4900"

# --- the audit document ------------------------------------------------------
# The second report is read by people who did not write the code and may have
# to weigh it in a dispute. Three things must hold: every finding is numbered
# so the opinion can cite it, nothing about the auditor is invented, and the
# document exists in the three languages like everything else.
aud=$(mktemp -d)
./bin/sablier scan tests/fixtures/sample --out="$aud/t.html" --audit="$aud/a.html" \
	--json="$aud/a.json" --quiet >/dev/null || true

# One long line of HTML: count occurrences, not lines.
facts=$(grep -o '<tr><td class="n">' "$aud/a.html" | wc -l | tr -d ' ')
findings=$(php -r 'echo count(json_decode(file_get_contents($argv[1]), true));' "$aud/a.json")
if [ "$facts" != "$findings" ]; then
	echo "✗ audit: $findings findings but $facts numbered facts"
	rm -rf "$aud"
	exit 1
fi
printf '  ✓ %-24s %-10s %s\n' "audit" "facts" "$facts numbered"

# An absent auditor prints as a field to complete, never as a plausible name.
if ! grep -q 'class="todo"' "$aud/a.html"; then
	echo "✗ audit: an unsupplied identity was not flagged as missing"
	rm -rf "$aud"
	exit 1
fi
php -r '
	$d = json_decode(file_get_contents("tests/fixtures/sample/sablier.json"), true);
	$d["audit"] = ["client" => "Acme", "auditor" => "A. Lambert", "organisation" => "Acme Audit",
		"reference" => "T-1", "mandate" => "regression test", "statement" => "regression test"];
	file_put_contents($argv[1], json_encode($d, JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE));
' "$aud/declared.json"
./bin/sablier scan tests/fixtures/sample --declare="$aud/declared.json" --out="$aud/t.html" \
	--audit="$aud/signed.html" --quiet >/dev/null || true
if grep -q 'class="todo"' "$aud/signed.html" || ! grep -q 'A. Lambert' "$aud/signed.html"; then
	echo "✗ audit: a supplied identity did not reach the document"
	rm -rf "$aud"
	exit 1
fi
printf '  ✓ %-24s %-10s %s\n' "audit" "identity" "declared or flagged"

for lang in fr en es; do
	./bin/sablier scan tests/fixtures/sample --lang="$lang" --out="$aud/t.html" \
		--audit="$aud/$lang.html" --quiet >/dev/null || true
	if ! grep -q 'id="s10"' "$aud/$lang.html"; then
		echo "✗ audit: the $lang document is missing its tenth section"
		rm -rf "$aud"
		exit 1
	fi
done
printf '  ✓ %-24s %-10s %s\n' "audit" "languages" "fr en es"
rm -rf "$aud"

# --- signing ------------------------------------------------------------------
# A signature that verifies against whatever key came with it proves only that
# someone had a key; the expected key comes from the versioned declaration.
keydir=$(mktemp -d)
./bin/sablier keygen --out="$keydir/a.key" >"$keydir/a.out"
./bin/sablier keygen --out="$keydir/b.key" >"$keydir/b.out"
pub=$(grep -o '"signing_public_key": "[^"]*"' "$keydir/a.out" | cut -d'"' -f4)
other=$(grep -o '"signing_public_key": "[^"]*"' "$keydir/b.out" | cut -d'"' -f4)

php -r '
	$d = json_decode(file_get_contents("tests/fixtures/sample/sablier.json"), true);
	$d["signing_public_key"] = $argv[1];
	file_put_contents($argv[2], json_encode($d, JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE));
' "$pub" "$keydir/right.json"
php -r '
	$d = json_decode(file_get_contents("tests/fixtures/sample/sablier.json"), true);
	$d["signing_public_key"] = $argv[1];
	file_put_contents($argv[2], json_encode($d, JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE));
' "$other" "$keydir/wrong.json"

./bin/sablier scan tests/fixtures/sample --declare="$keydir/right.json" --sign="$keydir/a.key" \
	--out="$keydir/r.html" --quiet >/dev/null || true

signcheck() {
	if ./bin/sablier verify "$1" ${2:+--declare=$2} >/dev/null 2>&1; then result=valid; else result=rejected; fi
	if [ "$result" != "$3" ]; then
		echo "✗ signature $4: expected $3, got $result"
		rm -rf "$keydir"
		exit 1
	fi
	printf '  ✓ %-24s %-10s %s\n' "signature" "$4" "$3"
}

signcheck "$keydir/r.html.sig" "$keydir/right.json" valid "declared key"
signcheck "$keydir/r.html.sig" "$keydir/wrong.json" rejected "another key"
php -r '
	$b = json_decode(file_get_contents($argv[1]), true);
	$b["digest"] = str_repeat("0", 64);
	file_put_contents($argv[2], json_encode($b));
' "$keydir/r.html.sig" "$keydir/tampered.sig"
signcheck "$keydir/tampered.sig" "" rejected "tampered digest"
rm -rf "$keydir"

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
