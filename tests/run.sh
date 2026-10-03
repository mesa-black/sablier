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

# --- and the server stays out of the operator's way --------------------------
# Running the suite used to open two browser windows, because `serve` opens one
# for the person who typed it and could not tell a person from a pipe. Checked
# here rather than remembered, since the next window would be as surprising.
if grep -q "posix_isatty" bin/sablier; then
	printf '  ✓ %-24s %-10s %s\n' "serve" "quiet" "no browser opened for a script"
else
	echo "✗ serve: nothing stops it opening a browser in a pipeline"
	exit 1
fi

# --- the interview in a browser ----------------------------------------------
# The terminal version is for us; this one is for the room. Walk the whole
# flow the way a person would — start, the system's context, one subject
# answered, one skipped, the questions about the tool itself — and check that
# what comes out is the same declaration the CLI would have written.
web=$(mktemp -d)
cp -R tests/fixtures/sample/. "$web/"
rm -f "$web/sablier.json"
./bin/sablier serve "$web" --out="$web/sablier.json" --port=8791 >"$web/serve.log" 2>&1 &
server=$!
sleep 2

walk=$(php -r '
	$base = "http://127.0.0.1:8791";
	$post = static function (string $path, array $fields) use ($base): void {
		@file_get_contents($base.$path, false, stream_context_create(["http" => [
			"method" => "POST",
			"header" => "Content-Type: application/x-www-form-urlencoded",
			"content" => http_build_query($fields),
			"follow_location" => 0,
			"ignore_errors" => true,
		]]));
	};
	if (!str_contains((string) @file_get_contents($base."/"), "SABLIER")) { echo "no intro"; return; }
	$post("/start", []);
	$post("/subject", ["step" => "context", "service_until" => "2032", "regime" => "anssi"]);
	$post("/subject", ["step" => "subject", "action" => "answer", "name" => "backups", "retention" => "10", "harm" => "2", "note" => "ten years"]);
	$post("/subject", ["step" => "subject", "action" => "skip"]);
	$post("/feedback", ["missing" => "how many clients", "unclear" => "fingerprint"]);
	echo str_contains((string) @file_get_contents($base."/done"), "SABLIER") ? "ok" : "no done";
')
kill "$server" 2>/dev/null || true
wait "$server" 2>/dev/null || true
# Belt and braces: a server left holding the port would make the next run fail
# for a reason that has nothing to do with the code.
pkill -f "127.0.0.1:8791" 2>/dev/null || true

if [ "$walk" != "ok" ]; then
	echo "✗ web: the interview did not survive a full walk ($walk)"
	cat "$web/serve.log"
	rm -rf "$web"
	exit 1
fi

written=$(php -r '
	$d = json_decode(file_get_contents($argv[1]), true);
	$log = json_decode(file_get_contents($argv[2]), true);
	echo ($d["service_until"] ?? 0) === 2032
		&& ($d["regime"] ?? "") === "anssi"
		&& ($d["domains"]["backups"]["lifetime_years"] ?? -1) === 10
		&& count($log["record"] ?? []) === 2
		&& ($log["feedback"]["unclear"] ?? "") === "fingerprint"
		? "ok" : "no";
' "$web/sablier.json" "$web/session.json" 2>/dev/null)
if [ "$written" != "ok" ]; then
	echo "✗ web: the session did not write what was said"
	cat "$web/sablier.json" "$web/session.json" 2>/dev/null
	rm -rf "$web"
	exit 1
fi
printf '  ✓ %-24s %-10s %s\n' "web" "interview" "walked, declared, recorded"
rm -rf "$web"

# --- a lifetime has an author and a date ------------------------------------
# Acceptances expire and regulatory dates carry a verification date; a declared
# lifetime had neither, so one set in 2026 by somebody who left in 2028 still
# drove the verdicts in 2032 with nobody the wiser.
prov=$(mktemp -d)
cp -R tests/fixtures/sample/. "$prov/"
php -r '
	$d = json_decode(file_get_contents("tests/fixtures/sample/sablier.json"), true);
	$d["domains"]["backups"]["declared_by"] = "A. Durand";
	$d["domains"]["backups"]["declared_on"] = "2019-01-01";      // long stale
	$d["domains"]["session tokens"]["declared_on"] = date("Y-m-d");
	file_put_contents($argv[1], json_encode($d, JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE));
' "$prov/declared.json"
./bin/sablier scan "$prov" --declare="$prov/declared.json" --out="$prov/r.html" \
	--audit="$prov/audit.html" --quiet >/dev/null || true

if ! grep -q "A. Durand" "$prov/audit.html"; then
	echo "✗ provenance: the audit must say who declared a lifetime"
	rm -rf "$prov"
	exit 1
fi
if ! grep -q "2 ans" "$prov/audit.html" && ! grep -q "revues" "$prov/audit.html"; then
	echo "✗ provenance: a lifetime nobody revisited must be a blind spot"
	rm -rf "$prov"
	exit 1
fi
printf '  ✓ %-24s %-10s %s\n' "provenance" "author" "named, and stale after 2 years"

# A report that prints the command, the digest and a signature must say which
# build produced it.
if ! grep -q "Sablier 0.4.0" "$prov/audit.html"; then
	echo "✗ provenance: the audit must name the build that produced it"
	rm -rf "$prov"
	exit 1
fi
printf '  ✓ %-24s %-10s %s\n' "provenance" "version" "$(./bin/sablier --version)"
rm -rf "$prov"

# --- the system's own horizon, and whose deadline applies --------------------
# Two facts about the system rather than about its data, and both move every
# verdict under them: the last secret is written on the last day of service,
# and the expiry year depends on who the system answers to.
ctx=$(mktemp -d)
cp -R tests/fixtures/sample/. "$ctx/"
php -r '
	$d = json_decode(file_get_contents("tests/fixtures/sample/sablier.json"), true);
	unset($d["expiry_year"]);                 // the regime must set it
	$d["regime"] = "anssi";                   // 2030 rather than 2035
	$d["service_until"] = 2032;               // still writing in 2032
	file_put_contents($argv[1], json_encode($d, JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE));
' "$ctx/strict.json"

./bin/sablier scan "$ctx" --declare="$ctx/strict.json" --json="$ctx/strict.out.json" --out="$ctx/r.html" --quiet >/dev/null || true

# Backups keep data ten years. Writing until 2032 means the last record is
# exposed until 2042, not until 2036 — and the deadline it is measured against
# is ANSSI's 2030 rather than 2035, because the declaration says who we are.
exposure=$(php -r '
	foreach (json_decode(file_get_contents($argv[1]), true) as $row) {
		if ($row["verdict"] === "compromised") { echo str_contains($row["because"], "2042") ? "ok" : $row["because"]; return; }
	}
	echo "no compromised finding";
' "$ctx/strict.out.json")
if [ "$exposure" != "ok" ]; then
	echo "✗ context: the last record is written on the last day of service ($exposure)"
	rm -rf "$ctx"
	exit 1
fi
if ! grep -q '2030' "$ctx/r.html"; then
	echo "✗ context: the regime must set the expiry the report is measured against"
	rm -rf "$ctx"
	exit 1
fi
printf '  ✓ %-24s %-10s %s\n' "context" "regime" "ANSSI 2030, exposed to 2042"

# A system retired before its own crossing date never crosses: the one answer
# in this report that lets somebody do nothing, for a good reason.
php -r '
	$d = json_decode(file_get_contents("tests/fixtures/sample/sablier.json"), true);
	// Backups keep data ten years against a 2045 expiry, so they cross in
	// 2036 — and the service stops in 2030, six years before that.
	$d["expiry_year"] = 2045;
	$d["service_until"] = 2030;
	file_put_contents($argv[1], json_encode($d, JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE));
' "$ctx/short.json"
./bin/sablier scan "$ctx" --declare="$ctx/short.json" --out="$ctx/short.html" --calendar="$ctx/short.ics" --quiet >/dev/null || true
# The apostrophe is escaped in the HTML, so match on a piece without one.
if ! grep -q "avant la bascule de 2036" "$ctx/short.html"; then
	echo "✗ context: a system that stops before its crossing must say so"
	rm -rf "$ctx"
	exit 1
fi
if grep -q 'BEGIN:VEVENT' "$ctx/short.ics"; then
	echo "✗ context: a crossing the system never reaches is not an appointment"
	rm -rf "$ctx"
	exit 1
fi
printf '  ✓ %-24s %-10s %s\n' "context" "horizon" "retired before its crossing"
rm -rf "$ctx"

# --- the interview ------------------------------------------------------------
# The number nobody can state directly is derived from two they answer every
# week, and the larger one wins: data you must keep is data that can still be
# stolen. An answer the tool does not understand is asked again, never guessed.
iv=$(mktemp -d)
cp -R tests/fixtures/sample/. "$iv/"
rm -f "$iv/sablier.json"
# Two blank lines first: the interview opens with the system's horizon and the
# regime, and skipping both is a legitimate answer.
printf '\n\nbackups\n10\n2\nTen years of accounting in there.\nsession tokens\n0\n1\n\n' \
	| ./bin/sablier declare "$iv" --out="$iv/sablier.json" >/dev/null 2>&1 || true

derived=$(php -r '
	$d = json_decode(file_get_contents($argv[1]), true);
	$backups = $d["domains"]["backups"] ?? null;
	$tokens = $d["domains"]["session tokens"] ?? null;
	// Retention 10 beats harm 2; harm 1 beats retention 0.
	echo ($backups["lifetime_years"] ?? -1) === 10 && ($tokens["lifetime_years"] ?? -1) === 1
		&& ($backups["note"] ?? "") !== "" ? "ok" : "no";
' "$iv/sablier.json")
if [ "$derived" != "ok" ]; then
	echo "✗ interview: the lifetime must be the larger of retention and harm"
	cat "$iv/sablier.json"
	rm -rf "$iv"
	exit 1
fi
printf '  ✓ %-24s %-10s %s\n' "interview" "lifetime" "retention or harm, whichever is longer"

# The same name twice is one domain in two places. A dry run produced "accès
# technique" and "acces" for two areas, and keeping only the last path would
# have dropped half of what was said.
merged=$(php -r '
	foreach (["Lang", "Value", "Assessor", "Catalogue", "Finding", "SourceFile", "Declaration", "Interview"] as $class) {
		require "src/$class.php";
	}
	$merged = Sablier\Interview::merge([], [
		["name" => "accès", "paths" => ["src/A/*"], "lifetime" => 3, "note" => "une"],
		["name" => "accès", "paths" => ["src/B/*"], "lifetime" => 7, "note" => "deux"],
	]);
	$domain = $merged["domains"]["accès"];
	echo count($domain["paths"]) === 2 && $domain["lifetime_years"] === 7 ? "ok" : "no";
')
if [ "$merged" != "ok" ]; then
	echo "✗ interview: the same name twice must keep both places and the longer lifetime"
	exit 1
fi
printf '  ✓ %-24s %-10s %s\n' "interview" "same name" "two places, one domain"

# And the declaration it writes must produce the verdicts the fixture expects.
./bin/sablier scan "$iv" --json="$iv/out.json" --out="$iv/r.html" --quiet >/dev/null || true
if [ "$(php -r '
	$n = 0;
	foreach (json_decode(file_get_contents($argv[1]), true) as $row) {
		if ($row["verdict"] === "compromised") { ++$n; }
	}
	echo $n;
' "$iv/out.json")" != "1" ]; then
	echo "✗ interview: the written declaration did not reproduce the expected verdict"
	rm -rf "$iv"
	exit 1
fi
printf '  ✓ %-24s %-10s %s\n' "interview" "declaration" "scan agrees with the answers"
rm -rf "$iv"

# --- the date a domain crosses the line --------------------------------------
# The arithmetic has one answer and the report must print it rather than draw
# it: backups keep data ten years against a 2035 expiry, so anything encrypted
# from 2026 outlives the algorithm. And a domain that only signs never crosses
# anything, because a signature is not harvested — printing a date about it
# would be the chart's old bug, in words.
cross=$(mktemp -d)
./bin/sablier scan tests/fixtures/sample --out="$cross/r.html" --calendar="$cross/c.ics" --quiet >/dev/null || true
if ! grep -q "backups — 10 ans — bascule franchie depuis 2026" "$cross/r.html"; then
	echo "✗ crossings: expected backups to have crossed in 2026"
	rm -rf "$cross"
	exit 1
fi
if grep -q "session tokens" "$cross/r.html" && grep -q "bascule" "$cross/r.html" && \
	php -r 'exit(str_contains(file_get_contents($argv[1]), "session tokens — ") ? 0 : 1);' "$cross/r.html"; then
	echo "✗ crossings: a domain that only signs was given a crossing date"
	rm -rf "$cross"
	exit 1
fi
printf '  ✓ %-24s %-10s %s\n' "crossings" "date" "backups crossed in 2026"

# A past crossing is not an appointment: the calendar carries the ones ahead.
events=$(grep -c 'BEGIN:VEVENT' "$cross/c.ics" || true)
if [ "$events" != "0" ] || ! grep -q 'BEGIN:VCALENDAR' "$cross/c.ics"; then
	echo "✗ crossings: a calendar of past dates is a calendar nobody opens ($events events)"
	rm -rf "$cross"
	exit 1
fi

# Projected forward, the same domain has not crossed yet and must be bookable.
./bin/sablier scan tests/fixtures/sample --year=2020 --out="$cross/r.html" --calendar="$cross/future.ics" --quiet >/dev/null || true
if [ "$(grep -c 'BEGIN:VEVENT' "$cross/future.ics")" != "1" ]; then
	echo "✗ crossings: expected one event for a crossing still ahead"
	rm -rf "$cross"
	exit 1
fi
if [ "$(php -r '
	foreach (explode("\r\n", file_get_contents($argv[1])) as $line) {
		if (strlen($line) > 75) { echo "long"; return; }
	}
	echo "ok";
' "$cross/future.ics")" != "ok" ]; then
	echo "✗ crossings: iCalendar lines must fold at 75 octets"
	rm -rf "$cross"
	exit 1
fi
printf '  ✓ %-24s %-10s %s\n' "crossings" "calendar" "one event, folded to spec"
rm -rf "$cross"

# --- what hides in the files nobody reads ------------------------------------
# Three verifiable facts, and one photo that must stay silent. The silent one
# is the test that matters: a tool that cries wolf about an ordinary image
# loses the right to be believed about a backup key.
asset=$(mktemp -d)
./bin/sablier scan tests/fixtures/assets --json="$asset/out.json" --out="$asset/r.html" --quiet >/dev/null || true
shape=$(php -r '
	$rows = json_decode(file_get_contents($argv[1]), true);
	$byFile = [];
	foreach ($rows as $row) { $byFile[basename($row["file"])][] = $row; }
	$key = $byFile["logo-with-key.png"] ?? [];
	$payload = $byFile["banner-with-payload.png"] ?? [];
	$archive = $byFile["icon-is-an-archive.png"] ?? [];
	echo count($key) === 1 && $key[0]["algorithm"] === "rsa"
		&& count($payload) === 1 && $payload[0]["verdict"] === "declare" && $payload[0]["confidence"] !== "haute"
		&& count($archive) === 1 && $archive[0]["verdict"] === "declare"
		&& !isset($byFile["ordinary.png"])
		? "ok" : "no";
' "$asset/out.json")
if [ "$shape" != "ok" ]; then
	echo "✗ assets: expected one key finding, two to confirm, and silence on the ordinary image"
	cat "$asset/out.json"
	rm -rf "$asset"
	exit 1
fi
printf '  ✓ %-24s %-10s %s\n' "assets" "key" "reported once"
printf '  ✓ %-24s %-10s %s\n' "assets" "hidden" "payload and disguise, to confirm"
printf '  ✓ %-24s %-10s %s\n' "assets" "ordinary" "silent"
rm -rf "$asset"

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

# The auditor's identity is filled from their own file; the engagement is not,
# and a declaration that states a field wins over the convenience one.
cat >"$aud/identity.json" <<'IDENTITY'
{ "auditor": "A. Lambert", "organisation": "Lambert & Co", "client": "Wrong Client" }
IDENTITY
php -r '
	$d = json_decode(file_get_contents("tests/fixtures/sample/sablier.json"), true);
	$d["audit"] = ["client" => "Acme"];
	file_put_contents($argv[1], json_encode($d, JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE));
' "$aud/engagement.json"
SABLIER_IDENTITY="$aud/identity.json" ./bin/sablier scan tests/fixtures/sample --declare="$aud/engagement.json" \
	--out="$aud/t.html" --audit="$aud/merged.html" --quiet >/dev/null || true
if ! grep -q 'A. Lambert' "$aud/merged.html" || grep -q 'Wrong Client' "$aud/merged.html" || ! grep -q 'Acme' "$aud/merged.html"; then
	echo "✗ audit: the identity file must fill the blanks and lose every conflict"
	rm -rf "$aud"
	exit 1
fi
printf '  ✓ %-24s %-10s %s\n' "audit" "identity" "filled, declaration wins"

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

# --- one report succeeding another -------------------------------------------
# A chain nobody has to ask for: a second run over the same output path names
# the digest it replaces, inside what is signed. A pile of reports becomes an
# audit trail, and a missing link shows.
cp "$keydir/r.html.sig" "$keydir/first.sig"
./bin/sablier scan tests/fixtures/sample --declare="$keydir/right.json" --sign="$keydir/a.key" \
	--out="$keydir/r.html" --quiet >/dev/null || true
chain=$(php -r '
	$first = json_decode(file_get_contents($argv[1]), true);
	$second = json_decode(file_get_contents($argv[2]), true);
	echo !isset($first["previous"]) && ($second["previous"] ?? "") === $first["digest"] ? "ok" : "no";
' "$keydir/first.sig" "$keydir/r.html.sig")
if [ "$chain" != "ok" ]; then
	echo "✗ chain: the second report must name the first, and the first must name nobody"
	rm -rf "$keydir"
	exit 1
fi
# And the link is inside the signature: verification still passes.
signcheck "$keydir/r.html.sig" "$keydir/right.json" valid "chained report"
printf '  ✓ %-24s %-10s %s\n' "chain" "previous" "named and signed"
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

# --- a session handed over through a tunnel ----------------------------------
# A bind address is a bad judge of exposure: behind an SSH tunnel and a reverse
# proxy the server stays on the loopback and the link is still public. --expose
# mints the key anyway, --public prints the address to hand over, and the key is
# then required on every page.
exp=$(mktemp -d)
cp -R tests/fixtures/sample/. "$exp/"
rm -f "$exp/sablier.json"
./bin/sablier serve "$exp" --out="$exp/sablier.json" --port=8793 \
	--expose --public=https://audit.example.org >"$exp/serve.log" 2>&1 &
server=$!
sleep 2

key=$(sed -n 's#.*https://audit\.example\.org/?k=\([0-9a-f]*\).*#\1#p' "$exp/serve.log")
guard=$(php -r '
	$base = "http://127.0.0.1:8793";
	$code = static function (string $url): int {
		@file_get_contents($url, false, stream_context_create(["http" => ["ignore_errors" => true]]));
		foreach ($http_response_header ?? [] as $line) {
			if (preg_match("#^HTTP/\S+ (\d{3})#", $line, $m) === 1) { return (int) $m[1]; }
		}
		return 0;
	};
	printf("%d/%d", $code($base."/"), $code($base."/?k=".$argv[1]));
' "$key")
kill "$server" 2>/dev/null || true
wait "$server" 2>/dev/null || true
pkill -f "127.0.0.1:8793" 2>/dev/null || true

if [ -z "$key" ]; then
	echo "✗ expose: no key in the link that was handed over"
	cat "$exp/serve.log"; rm -rf "$exp"; exit 1
fi
printf '  ✓ %-24s %-10s %s\n' "expose" "--public" "named, keyed"
if [ "$guard" != "403/200" ]; then
	echo "✗ expose: the key is not enforced (got $guard, wanted 403/200)"
	cat "$exp/serve.log"; rm -rf "$exp"; exit 1
fi
printf '  ✓ %-24s %-10s %s\n' "expose" "guard" "403 without, 200 with"
rm -rf "$exp"

# --- telling an identifier from a security control ---------------------------
# Every line of this fixture was taken from a public repository during the
# false-positive measurement: 31 projects, 959 findings, and 89 of the 92 reds
# that were wrong. The rules that fixed it are subtle enough to rot quietly, so
# the verdicts are pinned here.
dg=$(mktemp -d)
./bin/sablier scan tests/fixtures/digests --json="$dg/d.json" --airgap --quiet >/dev/null 2>&1 || true
counts=$(php -r '
	$f = json_decode(file_get_contents($argv[1]), true);
	$v = [];
	foreach ($f as $x) { $v[$x["verdict"]] = ($v[$x["verdict"]] ?? 0) + 1; }
	printf("%d/%d/%d", $v["noise"] ?? 0, $v["urgent"] ?? 0, $v["clear"] ?? 0);
' "$dg/d.json")
rm -rf "$dg"
# Five identifiers, three real uses of a broken digest, one HMAC — and nothing
# at all for the call that only appears in a comment.
if [ "$counts" != "5/3/1" ]; then
	echo "✗ digests: identity and security no longer tell apart (noise/urgent/clear = $counts)"
	exit 1
fi
printf '  ✓ %-24s %-10s %s\n' "digests" "identity" "hash codes, locks and filenames are noise"
printf '  ✓ %-24s %-10s %s\n' "digests" "security" "tokens, fingerprints and KDFs stay red"
printf '  ✓ %-24s %-10s %s\n' "digests" "hmac" "a keyed digest is not its digest"

# --- a closed site: refuse, and print anyway ---------------------------------
# --airgap is not --no-probe with a different name. One skips a step, the other
# refuses the commands that would reach out — and still produces a PDF, because
# a report that cannot be printed cannot be signed or filed.
for forbidden in probe advisories; do
	if ./bin/sablier "$forbidden" --airgap example.org >/dev/null 2>&1; then
		echo "✗ airgap: $forbidden ran anyway"
		exit 1
	fi
done
printf '  ✓ %-24s %-10s %s\n' "airgap" "refuses" "probe and advisories stop, loudly"

gap=$(mktemp -d)
SABLIER_AIRGAP=1 ./bin/sablier scan tests/fixtures/sample --out="$gap/r.html" \
	--audit="$gap/a.html" --pdf="$gap/r.pdf" --quiet >/dev/null 2>&1 || true
if [ ! -s "$gap/r.pdf" ]; then
	echo "✗ airgap: no PDF without a browser"
	rm -rf "$gap"; exit 1
fi
head -c 8 "$gap/r.pdf" | grep -q "%PDF-1" || { echo "✗ airgap: that is not a PDF"; rm -rf "$gap"; exit 1; }
printf '  ✓ %-24s %-10s %s\n' "airgap" "pdf" "typeset without a browser"

# The accents have to survive the trip into Windows-1252, and a mangled
# conversion shows up as the same two bytes every time.
if LC_ALL=C grep -q $'\xc3\xa9' "$gap/r.pdf"; then
	echo "✗ airgap: the PDF carries double-encoded text"
	rm -rf "$gap"; exit 1
fi
LC_ALL=C grep -aq "ann.e" "$gap/a.html" 2>/dev/null || true
./bin/sablier scan tests/fixtures/sample --airgap --audit="$gap/a2.html" --pdf="$gap/a2.pdf" \
	--out="$gap/r2.html" --quiet >/dev/null 2>&1 || true
pages=$(LC_ALL=C grep -ac "/Type /Page" "$gap/a2.pdf" || true)
if [ "$pages" -lt 2 ]; then
	echo "✗ airgap: the typeset PDF has no pages ($pages)"
	rm -rf "$gap"; exit 1
fi
printf '  ✓ %-24s %-10s %s\n' "airgap" "encoding" "accents intact, pages numbered"

# The environment variable is how a site sets this for everybody, so it has to
# work without anybody passing a flag.
if SABLIER_AIRGAP=1 ./bin/sablier probe example.org >/dev/null 2>&1; then
	echo "✗ airgap: SABLIER_AIRGAP did not apply"
	rm -rf "$gap"; exit 1
fi
printf '  ✓ %-24s %-10s %s\n' "airgap" "env" "SABLIER_AIRGAP=1 is enough"
rm -rf "$gap"

# --- the interview as one file ----------------------------------------------
# For a room with no network: the questions baked into a page that talks to
# nothing, and answers that come back as a file. Three things make it safe to
# hand over — it fetches nothing, it carries no absolute path from the auditor's
# machine, and what comes back goes through the same merge as a typed answer.
sheet=$(mktemp -d)
# A declaration that already covers everything leaves nothing to ask, so the
# worksheet is generated against the fixture stripped of its own.
cp -R tests/fixtures/sample/. "$sheet/"
rm -f "$sheet/sablier.json"
./bin/sablier worksheet "$sheet" --out="$sheet/q.html" >/dev/null

external=$(grep -cE "https?://|<script[^>]*src=|<link[^>]*href=|@import" "$sheet/q.html" || true)
if [ "$external" != "0" ]; then
	echo "✗ worksheet: it reaches for something ($external references)"
	rm -rf "$sheet"; exit 1
fi
printf '  ✓ %-24s %-10s %s\n' "worksheet" "offline" "no reference leaves the file"

if grep -q "$PWD" "$sheet/q.html"; then
	echo "✗ worksheet: it carries an absolute path from this machine"
	rm -rf "$sheet"; exit 1
fi
printf '  ✓ %-24s %-10s %s\n' "worksheet" "paths" "nothing absolute travels with it"

subjects=$(php -r '
	$h = file_get_contents($argv[1]);
	preg_match("#<script id=\"data\"[^>]*>(.*?)</script>#s", $h, $m);
	$d = json_decode(str_replace("<\\/", "</", $m[1]), true);
	echo \count($d["subjects"] ?? []);
' "$sheet/q.html")
if [ "$subjects" != "2" ]; then
	echo "✗ worksheet: expected 2 subjects on the fixture, embedded $subjects"
	rm -rf "$sheet"; exit 1
fi
printf '  ✓ %-24s %-10s %s\n' "worksheet" "subjects" "the same two the interview raises"

cat > "$sheet/answers.json" <<'JSON'
{
  "format": 1,
  "context": {"who": "Marie Dupont", "regime": "anssi", "service_until": 2032},
  "answers": [
    {"name": "sauvegardes", "paths": ["deploy/*"], "lifetime": 10, "note": "dix ans de compta",
     "trust_anchor": false, "declared_by": "Marie Dupont"},
    {"name": "sauvegardes", "paths": ["src/Tokens.php"], "lifetime": 3, "note": "et les jetons",
     "trust_anchor": false, "declared_by": "Marie Dupont"}
  ],
  "record": [{"area": "deploy", "name": "sauvegardes", "seconds": 12.3, "skipped": false, "lifetime_years": 10}],
  "feedback": {"missing": "combien de clients", "unclear": ""}
}
JSON
./bin/sablier declare "$sheet" --import="$sheet/answers.json" \
	--out="$sheet/sablier.json" --log="$sheet/session.json" >/dev/null

check_import=$(php -r '
	$d = json_decode(file_get_contents($argv[1]), true);
	$s = $d["domains"]["sauvegardes"] ?? [];
	echo ($d["regime"] ?? "?"), "|", ($d["service_until"] ?? 0), "|", \count($d["domains"] ?? []), "|",
	     ($s["lifetime_years"] ?? 0), "|", \count($s["paths"] ?? []), "|", ($s["declared_by"] ?? "?"), "|",
	     (isset($s["declared_on"]) ? "dated" : "undated"), "|", (isset($d["domains"]["sauvegardes"]["note"]) && str_contains($s["note"], "jetons") ? "kept" : "lost");
' "$sheet/sablier.json")
# One name given twice is one domain holding both paths, the longer lifetime and
# both notes — exactly what the typed interview does, because it is the same code.
if [ "$check_import" != "anssi|2032|1|10|2|Marie Dupont|dated|kept" ]; then
	echo "✗ worksheet: the import did not merge like the interview ($check_import)"
	rm -rf "$sheet"; exit 1
fi
printf '  ✓ %-24s %-10s %s\n' "worksheet" "import" "merged like a typed answer"

feedback=$(php -r '$d = json_decode(file_get_contents($argv[1]), true); echo $d["feedback"]["missing"] ?? "";' "$sheet/session.json")
if [ "$feedback" != "combien de clients" ]; then
	echo "✗ worksheet: the session record lost what she said about the tool"
	rm -rf "$sheet"; exit 1
fi
printf '  ✓ %-24s %-10s %s\n' "worksheet" "record" "times and feedback kept"
rm -rf "$sheet"

# --- the network surface, pinned --------------------------------------------
# An inventory of where the cryptography lives is as sensitive as the system it
# describes, so the claim that matters on a classified network is not "we do not
# send your data anywhere" but "nothing here can". Sockets are allowed in four
# files, all of them behind the probe; this fails the build the day a detector
# grows one.
allowed="src/Probe.php src/SshProbe.php src/Transport/ImplicitTlsTransport.php src/Transport/StartTlsTransport.php"
found=$(grep -rlE "stream_socket_client|fsockopen|socket_create|curl_init|file_get_contents\(['\"]https?|fopen\(['\"]https?" src/ bin/sablier | sort | tr '\n' ' ')
expected=$(echo $allowed | tr ' ' '\n' | sort | tr '\n' ' ')
if [ "$found" != "$expected" ]; then
	echo "✗ network surface moved"
	echo "  expected: $expected"
	echo "  found   : $found"
	exit 1
fi
printf '  ✓ %-24s %-10s %s\n' "airgap" "sockets" "four files, all behind the probe"

# And the proof by execution, where the kernel can give us one: the same scan,
# run with no network at all, must produce the same report.
airgap=""
if command -v unshare >/dev/null 2>&1; then
	if unshare -rn true 2>/dev/null; then
		airgap="unshare -rn"
	elif sudo -n unshare -n true 2>/dev/null; then
		# A build runner usually gives root without a password and user
		# namespaces without root; take whichever of the two is on offer.
		airgap="sudo -n unshare -n"
	fi
fi
if [ -n "$airgap" ]; then
	air=$(mktemp -d)
	$airgap ./bin/sablier scan tests/fixtures/sample --out="$air/r.html" \
		--json="$air/r.json" --no-probe --quiet >/dev/null 2>&1 || true
	# Root inside the namespace writes root-owned files; read them back as the
	# measure of success rather than trusting an exit code.
	if [ -s "$air/r.html" ] && [ -s "$air/r.json" ]; then
		printf '  ✓ %-24s %-10s %s\n' "airgap" "no network" "scan completes with the stack removed"
	else
		echo "✗ airgap: the scan needs a network it should not need"
		sudo -n rm -rf "$air" 2>/dev/null || rm -rf "$air"; exit 1
	fi
	sudo -n rm -rf "$air" 2>/dev/null || rm -rf "$air"
else
	printf '  · %-24s %-10s %s\n' "airgap" "no network" "skipped: no namespaces on this machine"
fi

# --- what --quiet writes, and what it does not -------------------------------
# A pipeline asking for the verdict in the exit code must not find an
# unrequested 27 kB page at the root of the repository afterwards. It is still
# written when something downstream reads it back — the signature is filed
# beside it, so it has to exist.
out=$(mktemp -d)
root="$PWD"
cd "$out"
"$root/bin/sablier" scan "$root/tests/fixtures/sample" --quiet >/dev/null 2>&1 || true
if [ -e report.html ]; then
	echo "✗ --quiet wrote a report nobody asked for"
	cd "$root"; rm -rf "$out"; exit 1
fi
printf '  ✓ %-24s %-10s %s\n' "quiet" "no --out" "nothing written"

"$root/bin/sablier" scan "$root/tests/fixtures/sample" --quiet --out=asked.html >/dev/null 2>&1 || true
[ -s asked.html ] || { echo "✗ --out under --quiet wrote nothing"; cd "$root"; rm -rf "$out"; exit 1; }
printf '  ✓ %-24s %-10s %s\n' "quiet" "--out" "written"

"$root/bin/sablier" keygen --out=key.json >/dev/null 2>&1
"$root/bin/sablier" scan "$root/tests/fixtures/sample" --quiet --sign=key.json >/dev/null 2>&1 || true
if [ ! -s report.html ] || [ ! -s report.html.sig ]; then
	echo "✗ a signature under --quiet needs the report it is filed beside"
	cd "$root"; rm -rf "$out"; exit 1
fi
printf '  ✓ %-24s %-10s %s\n' "quiet" "--sign" "report kept"
cd "$root"
rm -rf "$out"

echo
echo "✓ the risk model still discriminates, and every transport reaches TLS"
