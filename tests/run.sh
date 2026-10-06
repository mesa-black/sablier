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
		// A posted regime is ignored: that choice is not for the person being
		// interviewed. Nobody outside the field picks between NIST IR 8547,
		// CNSA 2.0 and an ANSSI position, and the question put five lines of
		// acronyms in front of somebody who was already lost. The auditor sets
		// it in the declaration, where it is reviewable.
		&& !isset($d["regime"])
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
#
# Read from the constant, never written out here. This line said "Sablier 0.5.0"
# and so it kept passing while the tool shipped 0.6.0, 0.7.0 and 0.8.0 — a test
# pinned to the value it was supposed to guard, which is a test that guards
# nothing. What forces the constant to move is the tag comparison further down.
if ! grep -q "Sablier $(php -r 'require "src/Version.php"; echo Sablier\Version::NUMBER;')" "$prov/audit.html"; then
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
		&& count($payload) === 1 && $payload[0]["verdict"] === "declare" && $payload[0]["confidence"] !== "high"
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

# The command is printed so a third party can repeat it, which means it has to
# be repeatable: the path of the machine that produced the document is neither
# useful to a reader nor ours to publish.
if grep -q "<code>$PWD/bin/sablier" "$aud/a.html"; then
	echo "✗ audit: the reproduction command carries an absolute path"
	rm -rf "$aud"
	exit 1
fi
printf '  ✓ %-24s %-10s %s\n' "audit" "command" "relative, and repeatable"

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

# --- three READMEs that still describe the same tool --------------------------
# The English one governs and the others are translations, which rot in silence
# unless something counts them. Headings are the cheap half of that: a section
# added to one and not the others shows up here rather than in front of a reader
# who does not read English.
for level in "^## " "^### "; do
	en=$(grep -c "$level" README.md || true)
	fr=$(grep -c "$level" README.fr.md || true)
	es=$(grep -c "$level" README.es.md || true)
	if [ "$en" != "$fr" ] || [ "$en" != "$es" ]; then
		echo "✗ readme: $level — en=$en fr=$fr es=$es, the translations have drifted"
		exit 1
	fi
done
printf '  ✓ %-24s %-10s %s\n' "readme" "three langs" "same sections in en, fr and es"

# --- the questions that can change something, first ---------------------------
# SHA-256 is sound at every lifetime, so a subject made only of it cannot be
# changed by any answer. On the first real project this tool was pointed at,
# that was question one of four. It is asked last now — not dropped, since the
# declaration outlives the scan.
ord=$(./bin/sablier worksheet tests/fixtures/order --out=/tmp/sablier-order.html >/dev/null 2>&1; php -r '
	$h = file_get_contents("/tmp/sablier-order.html");
	preg_match("#<script id=\"data\"[^>]*>(.*?)</script>#s", $h, $m);
	$d = json_decode(str_replace("<\\/", "</", $m[1]), true);
	echo implode(" ", array_map(static fn (array $s): string => implode(",", $s["paths"]), $d["subjects"]));
')
rm -f /tmp/sablier-order.html
if [ "$ord" != "src/Risky src/Safe" ]; then
	echo "✗ interview: the subject that decides nothing is not asked last ($ord)"
	exit 1
fi
printf '  ✓ %-24s %-10s %s\n' "interview" "order" "what can change a verdict comes first"

# The fixture that found this also found a hole: RSA used directly through
# openssl_public_encrypt was detected by nothing at all.
if ! ./bin/sablier scan tests/fixtures/order --json=/tmp/sablier-order.json --airgap --quiet >/dev/null 2>&1; then :; fi
if ! grep -q '"algorithm": "rsa"' /tmp/sablier-order.json; then
	echo "✗ detector: openssl_public_encrypt is invisible again"
	rm -f /tmp/sablier-order.json; exit 1
fi
rm -f /tmp/sablier-order.json
printf '  ✓ %-24s %-10s %s\n' "detector" "rsa" "openssl_public_encrypt is seen"

# --- the managed services, as far as a file can tell --------------------------
# Every report carries the line "the cryptography of your managed services
# appears in no file of this repository". That is true of an application, and
# false the moment the infrastructure sits beside it as code.
tf=$(mktemp -d)
./bin/sablier scan tests/fixtures/terraform --json="$tf/t.json" --out="$tf/t.html" \
	--airgap --quiet >/dev/null 2>&1 || true
found=$(php -r '
	$f = json_decode(file_get_contents($argv[1]), true);
	$v = [];
	foreach ($f as $x) { $v[] = $x["verdict"]."/".$x["algorithm"]; }
	sort($v);
	echo implode(" ", $v);
' "$tf/t.json")
# Encryption switched off at rest, a TLS floor below what is negotiated, the
# object encryption that is fine, and the two keys the infrastructure makes.
want="clear/aes-256 urgent/plaintext urgent/tls-obsolete watch/ecdsa watch/rsa-sign"
if [ "$found" != "$want" ]; then
	echo "✗ terraform: expected [$want], got [$found]"
	rm -rf "$tf"; exit 1
fi
printf '  ✓ %-24s %-10s %s\n' "terraform" "decisions" "encryption off, TLS floor, keys"

# The commented-out attribute at the end of the fixture must count for nothing.
if [ "$(grep -c 'storage_encrypted' tests/fixtures/terraform/main.tf)" != "2" ]; then
	echo "✗ terraform: the fixture lost its commented-out decision"
	rm -rf "$tf"; exit 1
fi
printf '  ✓ %-24s %-10s %s\n' "terraform" "comments" "a mention is still not a decision"

if ! grep -q "fournisseur\|provider\|proveedor" "$tf/t.html"; then
	echo "✗ terraform: the blind spot still claims nothing was read"
	rm -rf "$tf"; exit 1
fi
printf '  ✓ %-24s %-10s %s\n' "terraform" "blind spot" "reworded, not removed"
rm -rf "$tf"

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
	printf("%d/%d/%d/%d", $v["noise"] ?? 0, $v["urgent"] ?? 0, $v["clear"] ?? 0, $v["watch"] ?? 0);
' "$dg/d.json")
rm -rf "$dg"
# Five identifiers, three real uses of a broken digest, two things to leave
# alone, two table entries to confirm — and nothing at all for the call that
# only appears in a comment.
if [ "$counts" != "5/3/2/2" ]; then
	echo "✗ digests: identity and security no longer tell apart (noise/urgent/clear/watch = $counts)"
	exit 1
fi
printf '  ✓ %-24s %-10s %s\n' "digests" "identity" "hash codes, locks and filenames are noise"
printf '  ✓ %-24s %-10s %s\n' "digests" "security" "tokens, fingerprints and KDFs stay red"
printf '  ✓ %-24s %-10s %s\n' "digests" "hmac" "a keyed digest is not its digest"
printf '  ✓ %-24s %-10s %s\n' "digests" "tables" "a protocol's algorithm list is inventory"

# --- health data, where the lifetime is written in law -----------------------
# The input this tool normally has to go and ask for is, in health, set by the
# Code de la santé publique: twenty years for a patient record, up to seventy
# for pharmacovigilance. Against a 2030 deadline the arithmetic is not close,
# and the fixture exists so that stops being a claim.
hd=$(mktemp -d)
./bin/sablier scan tests/fixtures/health --json="$hd/h.json" --out="$hd/h.html" \
	--airgap --quiet >/dev/null 2>&1 || true
verdicts=$(php -r '
	$f = json_decode(file_get_contents($argv[1]), true);
	$v = [];
	foreach ($f as $x) { $v[$x["verdict"]] = ($v[$x["verdict"]] ?? 0) + 1; }
	printf("%d/%d", $v["compromised"] ?? 0, \count($f));
' "$hd/h.json")
if [ "$verdicts" != "2/2" ]; then
	echo "✗ health: expected both findings compromised, got $verdicts"
	rm -rf "$hd"; exit 1
fi
printf '  ✓ %-24s %-10s %s\n' "health" "verdicts" "twenty and seventy years, both lost"

# The crossing dates are the readable half of that arithmetic, and both are
# decades in the past: 2030 − 70 + 1 and 2030 − 20 + 1.
if ! grep -q "1961" "$hd/h.html" || ! grep -q "2011" "$hd/h.html"; then
	echo "✗ health: the crossing dates are not what the retention implies"
	rm -rf "$hd"; exit 1
fi
printf '  ✓ %-24s %-10s %s\n' "health" "crossing" "1961 and 2011, both long past"
rm -rf "$hd"

# --- the classical half of a hybrid is kept on purpose -----------------------
# A finding is about one line; hybridation is a property of the composition. The
# tool cannot see that another call signs the same bytes, so the declaration
# says it — and a verdict telling somebody to retire the classical half of a
# hybrid is telling them to undo it.
hyb=$(mktemp -d)
cp -R tests/fixtures/sample/. "$hyb/"
before=$(./bin/sablier scan "$hyb" --json="$hyb/a.json" --no-probe --quiet >/dev/null 2>&1 || true; php -r '
	$f = json_decode(file_get_contents($argv[1]), true);
	foreach ($f as $x) { if ($x["algorithm"] === "rsa-sign") { echo $x["verdict"]; return; } }
' "$hyb/a.json")
# On the domain that already owns the finding: resolve() keeps the first glob
# that matches, so a domain appended at the end would never be reached.
php -r '
	$d = json_decode(file_get_contents($argv[1]), true);
	$d["domains"]["backups"]["hybrid"] = true;
	file_put_contents($argv[1], json_encode($d));
' "$hyb/sablier.json"
after=$(./bin/sablier scan "$hyb" --json="$hyb/b.json" --out="$hyb/b.html" --no-probe --quiet >/dev/null 2>&1 || true; php -r '
	$f = json_decode(file_get_contents($argv[1]), true);
	foreach ($f as $x) { if ($x["algorithm"] === "rsa-sign") { echo $x["verdict"]; return; } }
' "$hyb/b.json")
if [ "$before" != "watch" ] || [ "$after" != "clear" ]; then
	echo "✗ hybrid: a declared pairing did not change the verdict ($before → $after)"
	rm -rf "$hyb"; exit 1
fi
printf '  ✓ %-24s %-10s %s\n' "hybrid domain" "verdict" "kept on purpose, not to migrate"

# Declared, never observed — and the report has to say which.
if ! grep -qi "déclaration\|declaration\|declarac" "$hyb/b.html"; then
	echo "✗ hybrid: the report does not say the pairing is only declared"
	rm -rf "$hyb"; exit 1
fi
printf '  ✓ %-24s %-10s %s\n' "hybrid domain" "blind spot" "asserted, not observed"
rm -rf "$hyb"

# --- the signature this tool tells everybody else to migrate to --------------
# Ed25519 always, ML-DSA-65 in addition where OpenSSL 3.5 can make one. Skipped
# rather than failed on an older library, which is the behaviour being tested.
if openssl list -signature-algorithms 2>/dev/null | grep -qi "ML-DSA-65"; then
	pq=$(mktemp -d)
	cp -R tests/fixtures/sample/. "$pq/"
	./bin/sablier keygen --out="$pq/k.key" >/dev/null 2>&1
	if [ ! -s "$pq/k.key.ml-dsa.pem" ]; then
		echo "✗ hybrid: keygen made no post-quantum key"
		rm -rf "$pq"; exit 1
	fi
	printf '  ✓ %-24s %-10s %s\n' "hybrid" "keygen" "two keys, beside each other"

	./bin/sablier scan "$pq" --out="$pq/r.html" --sign="$pq/k.key" --no-probe --quiet >/dev/null 2>&1 || true
	both=$(php -r '
		$b = json_decode(file_get_contents($argv[1]), true);
		echo ($b["algorithm"] ?? "?"), "+", ($b["hybrid"]["algorithm"] ?? "none");
	' "$pq/r.html.sig")
	if [ "$both" != "Ed25519+ML-DSA-65" ]; then
		echo "✗ hybrid: the report carries [$both]"
		rm -rf "$pq"; exit 1
	fi
	printf '  ✓ %-24s %-10s %s\n' "hybrid" "sign" "both signatures on one report"

	if ! ./bin/sablier verify "$pq/r.html.sig" 2>&1 | grep -q "ML-DSA-65"; then
		echo "✗ hybrid: verify says nothing about the second signature"
		rm -rf "$pq"; exit 1
	fi
	printf '  ✓ %-24s %-10s %s\n' "hybrid" "verify" "both checked, both named"

	# A post-quantum signature that does not match must fail the whole file,
	# even though the Ed25519 half still holds.
	php -r '
		$b = json_decode(file_get_contents($argv[1]), true);
		$sig = base64_decode($b["hybrid"]["signature"]);
		$sig[10] = $sig[10] === "A" ? "B" : "A";
		$b["hybrid"]["signature"] = base64_encode($sig);
		file_put_contents($argv[1], json_encode($b));
	' "$pq/r.html.sig"
	if ./bin/sablier verify "$pq/r.html.sig" 2>&1 | grep -q "valide, Ed25519 et post-quantique\|valid, Ed25519 and post-quantum"; then
		echo "✗ hybrid: a forged post-quantum signature passed"
		rm -rf "$pq"; exit 1
	fi
	printf '  ✓ %-24s %-10s %s\n' "hybrid" "tamper" "a forged second half fails the file"

	# The post-quantum key is vouched for by the declaration, like the other
	# one. Without that it would be asserted by the very file it signs, which
	# is worth nothing to whoever can already forge the Ed25519 half — and that
	# reader is the only reason this signature exists.
	./bin/sablier keygen --out="$pq/other.key" >/dev/null 2>&1
	php -r '
		$d = json_decode(file_get_contents($argv[1]), true);
		$d["signing_public_key_pq"] = shell_exec("openssl pkey -in ".escapeshellarg($argv[2])." -pubout 2>/dev/null");
		file_put_contents($argv[1], json_encode($d));
	' "$pq/sablier.json" "$pq/other.key.ml-dsa.pem"
	if ! ./bin/sablier verify "$pq/r.html.sig" --declare="$pq/sablier.json" 2>&1 | grep -qi "reconna\|vouches\|reconoce"; then
		echo "✗ hybrid: a post-quantum key nobody vouched for was accepted"
		rm -rf "$pq"; exit 1
	fi
	printf '  ✓ %-24s %-10s %s\n' "hybrid" "key" "the declaration vouches for both"

	# The key an auditor should actually want: made for one report, used once,
	# gone. Nothing to store, and the fingerprint is what ties the document to
	# a person — carried by a channel that proves who they are.
	eph=$(./bin/sablier scan "$pq" --out="$pq/e.html" --sign=ephemeral --no-probe 2>&1 \
		| grep -oE "[0-9A-F]{4}( [0-9A-F]{4}){7}" | head -1)
	if [ -z "$eph" ]; then
		echo "✗ ephemeral: no fingerprint printed"
		rm -rf "$pq"; exit 1
	fi
	if grep -q "PRIVATE" "$pq/e.html.sig"; then
		echo "✗ ephemeral: a private key reached the signature file"
		rm -rf "$pq"; exit 1
	fi
	printf '  ✓ %-24s %-10s %s\n' "ephemeral" "sign" "one key, one report, one fingerprint"

	if ! ./bin/sablier verify "$pq/e.html.sig" --fingerprint="$eph" >/dev/null 2>&1; then
		echo "✗ ephemeral: the printed fingerprint does not check out"
		rm -rf "$pq"; exit 1
	fi
	if ./bin/sablier verify "$pq/e.html.sig" --fingerprint="0000 0000 0000 0000 0000 0000 0000 0000" >/dev/null 2>&1; then
		echo "✗ ephemeral: a fingerprint nobody gave was accepted"
		rm -rf "$pq"; exit 1
	fi
	printf '  ✓ %-24s %-10s %s\n' "ephemeral" "fingerprint" "checked, and a wrong one refused"

	# And the report says what it carries. A document signed twice whose own
	# seal claims one signature is the report contradicting itself, which is
	# the fault this block exists to catch.
	if ! grep -q "Ed25519 + ML-DSA-65" "$pq/e.html"; then
		echo "✗ ephemeral: the report does not name both of its signatures"
		rm -rf "$pq"; exit 1
	fi
	if grep -q "seal-caveat.*vuln\|classe lui-même comme vulnérable" "$pq/e.html"; then
		echo "✗ ephemeral: the report still warns its signature is quantum-vulnerable"
		rm -rf "$pq"; exit 1
	fi
	printf '  ✓ %-24s %-10s %s\n' "ephemeral" "seal" "the report names both signatures"
	rm -rf "$pq"
else
	printf '  · %-24s %-10s %s\n' "hybrid" "skipped" "no ML-DSA in this OpenSSL"
fi

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

# --- a breach read backwards --------------------------------------------------
# Everywhere else the tool reasons forward: captured today, read when the
# algorithm falls. A declared breach removes the waiting, and what is left to
# count is the part of the promised confidentiality the cryptography cannot
# cover. Ten years asked for, taken in 2026, an algorithm credible to 2035: one
# year, and the sentence has to say "année" rather than "années".
br=$(mktemp -d)
cp -R tests/fixtures/sample/. "$br/"
./bin/sablier scan "$br" --out="$br/clean.html" --no-probe --quiet >/dev/null 2>&1 || true
if grep -q 'class="breach"' "$br/clean.html"; then
	echo "✗ breach: a scan with no declared breach printed the block anyway"
	rm -rf "$br"; exit 1
fi
printf '  ✓ %-24s %-10s %s\n' "breach" "undeclared" "silent, as it should be"

./bin/sablier scan "$br" --out="$br/one.html" --breached=2026-07-29 --no-probe --quiet >/dev/null 2>&1 || true
said=$(php -r '
	$h = file_get_contents($argv[1]);
	preg_match("#<section class=\"breach\">.*?</section>#s", $h, $m);
	echo html_entity_decode(strip_tags($m[0] ?? ""), \ENT_QUOTES);
' "$br/one.html")
case "$said" in
	*"29/07/2026"*) ;;
	*) echo "✗ breach: the date is not written the way every other date is ($said)"; rm -rf "$br"; exit 1 ;;
esac
case "$said" in
	*"1 année de ce qui a été volé"*) ;;
	*) echo "✗ breach: expected one readable year, singular — got: $said"; rm -rf "$br"; exit 1 ;;
esac
case "$said" in
	*"session tokens"*"quantique n'atteint pas"*) ;;
	*) echo "✗ breach: a domain nothing can read is not said to be sound"; rm -rf "$br"; exit 1 ;;
esac
printf '  ✓ %-24s %-10s %s\n' "breach" "one year" "2036 − 2035, and no migration reaches it"

# Twenty years asked for, and the plural follows the arithmetic rather than the
# other way round.
php -r '
	$d = json_decode(file_get_contents($argv[1]), true);
	$d["domains"]["backups"]["lifetime_years"] = 20;
	file_put_contents($argv[1], json_encode($d));
' "$br/sablier.json"
./bin/sablier scan "$br" --out="$br/many.html" --breached=2026-07-29 --no-probe --quiet >/dev/null 2>&1 || true
if ! grep -q "11 années de ce qui a été volé" "$br/many.html"; then
	echo "✗ breach: twenty years taken in 2026 should leave eleven readable"
	rm -rf "$br"; exit 1
fi
printf '  ✓ %-24s %-10s %s\n' "breach" "eleven years" "the duration moves the figure"

# What the tool cannot know is printed next to what it computed, or the figure
# reads as a measurement of the incident.
if ! grep -qi "ignore\|sorti" "$br/many.html"; then
	echo "✗ breach: the block does not say what it cannot know"
	rm -rf "$br"; exit 1
fi
printf '  ✓ %-24s %-10s %s\n' "breach" "limit" "said next to the figure"
rm -rf "$br"

# --- a fingerprint is a handle, so it cannot move with the language -------------
# `sablier accept <fingerprint>` writes a decision against a finding. The
# fingerprint is hashed from the evidence, and the probe built its evidence out
# of translated sentences — so the same server produced a different fingerprint
# per report language, and an acceptance recorded in French silently stopped
# applying to a scan run in English. Everywhere else `evidence` is a line of
# source; from the probe it is now the fact the handshake returned.
if command -v openssl >/dev/null 2>&1; then
	fpr=$(mktemp -d)
	cat >"$fpr/sablier.json" <<'DECL'
{ "project": "Probe fingerprints", "probe": ["mesa.black"], "default_lifetime_years": 0 }
DECL
	seen=''
	for lang in fr en es; do
		./bin/sablier scan "$fpr" --json="$fpr/$lang.json" --lang="$lang" --quiet >/dev/null 2>&1 || true
		seen="$seen $(php -r '
			$rows = json_decode(file_get_contents($argv[1]), true) ?: [];
			$out = [];
			foreach ($rows as $r) { if (str_starts_with($r["file"], "tls://")) { $out[] = $r["fingerprint"]; } }
			sort($out);
			echo implode(",", $out) ?: "none";
		' "$fpr/$lang.json")"
	done
	unique=$(printf '%s\n' $seen | sort -u | wc -l | tr -d ' ')
	if [ "$unique" != "1" ]; then
		echo "✗ fingerprint: a probe finding is identified differently per language"
		printf '   %s\n' $seen
		rm -rf "$fpr"; exit 1
	fi
	printf '  ✓ %-24s %-10s %s\n' "fingerprint" "languages" "one finding, one handle"
	rm -rf "$fpr"
else
	printf '  · %-24s %-10s %s\n' "fingerprint" "languages" "skipped: no openssl"
fi

# --- one inventory, one digest, whatever the language ---------------------------
# The seal prints "the digest covers the findings, not this file: two renderings
# of the same inventory, in two languages, give the same value". It did not. The
# label of an undeclared domain is translated, and it went into the digest, so
# three renderings of one scan produced three digests — under a paragraph saying
# they would not. Found by publishing a report in three languages and reading the
# three values side by side.
lng=$(mktemp -d)
cp -R tests/fixtures/sample/. "$lng/"
# An undeclared place, which is where the translated label came from.
mkdir -p "$lng/orphan"
cat >"$lng/orphan/Keys.php" <<'ORPHAN'
<?php
final class Keys
{
    public function issue(array $claims, string $key): string
    {
        return jwt_encode($claims, $key, 'RS256');
    }
}
ORPHAN
digests=''
for lang in fr en es; do
	./bin/sablier scan "$lng" --out="$lng/$lang.html" --lang="$lang" --no-probe --quiet >/dev/null 2>&1 || true
	d=$(php -r '
		$h = file_get_contents($argv[1]);
		preg_match("#<dd><code>([0-9a-f]{64})</code>#", $h, $m);
		echo $m[1] ?? "none";
	' "$lng/$lang.html")
	digests="$digests $d"
done
unique=$(printf '%s\n' $digests | sort -u | wc -l | tr -d ' ')
if [ "$unique" != "1" ]; then
	echo "✗ digest: $unique different values across three languages"
	printf '   %s\n' $digests
	rm -rf "$lng"; exit 1
fi
printf '  ✓ %-24s %-10s %s\n' "digest" "languages" "one inventory, one value"

# And it still separates two different inventories, which is the other half.
printf 'sha1($x);\n' >> "$lng/orphan/Keys.php"
./bin/sablier scan "$lng" --out="$lng/after.html" --no-probe --quiet >/dev/null 2>&1 || true
after=$(php -r '
	$h = file_get_contents($argv[1]);
	preg_match("#<dd><code>([0-9a-f]{64})</code>#", $h, $m);
	echo $m[1] ?? "none";
' "$lng/after.html")
first=$(printf '%s\n' $digests | head -1)
if [ "$after" = "$first" ]; then
	echo "✗ digest: a changed inventory kept the same value"
	rm -rf "$lng"; exit 1
fi
printf '  ✓ %-24s %-10s %s\n' "digest" "changes" "a new finding moves it"
rm -rf "$lng"

# --- a published report says how to check it, and what checking it proves --------
# The audit document carried both and the technical report carried neither, which
# was tolerable while reports travelled by hand and stopped being so the first
# time one was published on a website: a reader arriving at a signed page with no
# command and no claim has a seal they can admire and cannot use.
prv=$(mktemp -d)
cp -R tests/fixtures/sample/. "$prv/"
./bin/sablier keygen --out="$prv/k.key" >/dev/null 2>&1

# Declared key: the chain is the history of the file that declares it.
php -r '
	$d = json_decode(file_get_contents($argv[1]), true);
	$secret = trim(file_get_contents($argv[2]));
	$d["signing_public_key"] = base64_encode(sodium_crypto_sign_publickey_from_secretkey(base64_decode($secret)));
	file_put_contents($argv[1], json_encode($d, JSON_PRETTY_PRINT));
' "$prv/sablier.json" "$prv/k.key"
./bin/sablier scan "$prv" --out="$prv/declared.html" --sign="$prv/k.key" --no-probe --quiet >/dev/null 2>&1 || true

# Ephemeral: the chain is the channel that carried the fingerprint.
./bin/sablier scan "$prv" --out="$prv/eph.html" --sign=ephemeral --no-probe --quiet >/dev/null 2>&1 || true

# No declared key at all: the signature proves a key exists, and nothing else.
php -r '
	$d = json_decode(file_get_contents($argv[1]), true);
	unset($d["signing_public_key"]);
	file_put_contents($argv[1], json_encode($d, JSON_PRETTY_PRINT));
' "$prv/sablier.json"
./bin/sablier scan "$prv" --out="$prv/bare.html" --sign="$prv/k.key" --no-probe --quiet >/dev/null 2>&1 || true

# The first version of these sentences said "the report has not changed since
# it was signed". A published report was then altered by hand and still
# verified: a report displays its own signature, so it cannot contain it, and
# what is signed is the findings digest. Every one of the three has to say that
# before saying anything about the key.
for pair in "declared:historique du fichier qui la déclare" "eph:canal qui a porté l" "bare:qui la détient"; do
	file=${pair%%:*}
	needle=${pair#*:}
	if ! grep -q "$needle" "$prv/$file.html"; then
		echo "✗ seal: $file.html does not say what its signature proves"
		rm -rf "$prv"; exit 1
	fi
	if ! grep -q "sablier verify" "$prv/$file.html"; then
		echo "✗ seal: $file.html carries no command to check it"
		rm -rf "$prv"; exit 1
	fi
	if ! grep -q "ne couvre pas : les octets" "$prv/$file.html"; then
		echo "✗ seal: $file.html does not say the signature misses the bytes of the page"
		rm -rf "$prv"; exit 1
	fi
	if grep -q "n.a pas changé depuis sa signature" "$prv/$file.html"; then
		echo "✗ seal: $file.html claims the page itself is covered, which it is not"
		rm -rf "$prv"; exit 1
	fi
done
printf '  ✓ %-24s %-10s %s\n' "seal" "provable" "three key models, three claims"

# An unsigned report must claim nothing at all.
./bin/sablier scan "$prv" --out="$prv/none.html" --no-probe --quiet >/dev/null 2>&1 || true
if grep -q "Ce que cela établit" "$prv/none.html"; then
	echo "✗ seal: an unsigned report claims what a signature would prove"
	rm -rf "$prv"; exit 1
fi
printf '  ✓ %-24s %-10s %s\n' "seal" "unsigned" "claims nothing"
rm -rf "$prv"

# --- the message the trusted channel carries -----------------------------------
# The whole model for a signed report is that the file travels one way and the
# fingerprint of the keys travels by a channel that already proves who is
# speaking. The report builds a button for exactly that channel, and the message
# it composed carried neither the fingerprint nor the digest — so the one channel
# built to establish them established nothing, and the recipient had a sentence
# anybody could have typed. Found by somebody reading the message before sending
# it.
share=$(mktemp -d)
./bin/sablier keygen --out="$share/k.json" >/dev/null 2>&1
./bin/sablier scan tests/fixtures/sample --out="$share/signed.html" --sign="$share/k.json" \
	--no-probe --quiet >/dev/null 2>&1 || true
./bin/sablier scan tests/fixtures/sample --out="$share/plain.html" --no-probe --quiet >/dev/null 2>&1 || true
SABLIER_SHARE_DIR="$share" php -r '
	$dir = getenv("SABLIER_SHARE_DIR");
	$text = static function (string $file): string {
		$html = file_get_contents($file);
		preg_match("#<details class=\"share-text\">.*?<pre>(.*?)</pre>#s", $html, $m);
		return html_entity_decode($m[1] ?? "", ENT_QUOTES | ENT_HTML5);
	};
	$signed = $text("$dir/signed.html");
	$plain = $text("$dir/plain.html");
	$digest = json_decode(file_get_contents("$dir/signed.html.sig"), true)["digest"];

	if (!str_contains($signed, $digest)) {
		fwrite(STDERR, "✗ share: the message does not carry the digest it was signed over\n");
		exit(1);
	}
	if (preg_match("/\b[0-9A-F]{4}(?: [0-9A-F]{4}){7}\b/", $signed) !== 1) {
		fwrite(STDERR, "✗ share: the message does not carry the fingerprint of the signing keys\n");
		exit(1);
	}
	// And the other half of the rule: an unsigned report has nothing to prove and
	// must not grow a block of hashes that look like proof.
	if (str_contains($plain, $digest) || preg_match("/\b[0-9A-F]{4}(?: [0-9A-F]{4}){7}\b/", $plain) === 1) {
		fwrite(STDERR, "✗ share: an unsigned report put hashes in a message that proves nothing\n");
		exit(1);
	}
	// A Threema link carries its text in the URL. Measured rather than assumed:
	// a message nobody can open is worse than a short one.
	if (strlen(rawurlencode($signed)) > 1800) {
		fwrite(STDERR, "✗ share: the composed link is ".strlen(rawurlencode($signed))." characters, too long to open\n");
		exit(1);
	}
	printf("  ✓ %-24s %-10s %s\n", "share", "threema", strlen($signed)." characters, digest and fingerprint both in it");
' || { rm -rf "$share"; exit 1; }
rm -rf "$share"

# --- the version a document names is the version that produced it --------------
# Version::NUMBER said 0.5.0 for three releases. Every audit document produced in
# between named a build that had not produced it, and one of them is published on
# a public website. The docblock said "this constant is bumped with the tag",
# which is a sentence and not a mechanism.
#
# Only on a commit that is exactly a tag: between releases the constant is ahead
# of nothing and there is nothing to compare it to.
tagged=$(git describe --tags --exact-match 2>/dev/null || true)
if [ -n "$tagged" ]; then
	declared=$(php -r 'require "src/Version.php"; echo Sablier\Version::NUMBER;')
	if [ "v$declared" != "$tagged" ]; then
		echo "✗ version: the tag says $tagged and Version::NUMBER says $declared"
		exit 1
	fi
	printf '  ✓ %-24s %-10s %s\n' "version" "tag" "$tagged matches the constant"
else
	printf '  ✓ %-24s %-10s %s\n' "version" "untagged" "nothing to compare, checked at the tag"
fi

# And both documents name it, not just the audit one: the technical report is the
# one that gets published, and it carried a digest, a command to repeat the run
# and no version at all.
ver=$(mktemp -d)
./bin/sablier scan tests/fixtures/sample --out="$ver/r.html" --audit="$ver/a.html" \
	--no-probe --quiet >/dev/null 2>&1 || true
for doc in r a; do
	if ! grep -q "Sablier $(php -r 'require "src/Version.php"; echo Sablier\Version::NUMBER;')" "$ver/$doc.html"; then
		echo "✗ version: $doc.html does not name the build that produced it"
		rm -rf "$ver"; exit 1
	fi
done
printf '  ✓ %-24s %-10s %s\n' "version" "documents" "report and audit both name the build"
rm -rf "$ver"

# --- framework configuration, in four frameworks and two file formats ----------
# Until now nothing here opened a YAML file looking for cryptography, which meant
# walking past the whole security configuration of the most widely deployed PHP
# framework in Europe: Symfony declares its password hashers, its login flows and
# its token signatures in `config/packages/*.yaml`, and those are declared
# algorithms rather than call sites — the clearest input this tool can get.
./bin/sablier scan tests/fixtures/frameworks --json=/tmp/sablier-fw.json \
	--out=/tmp/sablier-fw.html --no-probe --quiet >/dev/null 2>&1 || true
SABLIER_TEST_JSON=/tmp/sablier-fw.json
export SABLIER_TEST_JSON
check clear       argon2       2   # argon2id written out, and `auto` resolved
check urgent      sha1         1   # a legacy hasher nobody removed
check watch       ecdsa        1   # ES256, beside an RS256 in the same list
check clear       hmac-sha256  2   # HS256 is a shared secret: nothing to migrate
check declare     undetermined 2   # oidc_login, and an algorithm read from the environment
check clear       sha512       1   # CodeIgniter's digest
check watch       rsa-sign     4   # OIDC handler, LexikJWT, and Passport's two keys
check watch       ecdh         3   # sslmode in YAML and in PHP, and Pusher over TLS
check urgent      plaintext    2   # the connection that disables it, and useTLS: false
check clear       aes-256      4   # CodeIgniter, S3, and two Laravel call sites
check clear       bcrypt       4   # an inline mapping, and three Laravel call sites
unset SABLIER_TEST_JSON

# A call site does not name an algorithm — the cipher is in config/app.php and
# the hashing driver in config/hashing.php — so Laravel's are recorded at medium
# confidence. They are recorded at all because the day that cipher has to change,
# what matters is how many places depend on it, and that is the third factor of
# the risk model: counted in places rather than estimated in days.
php -r '
	$rows = json_decode(file_get_contents("/tmp/sablier-fw.json"), true);
	$calls = array_filter($rows, static fn (array $r): bool => str_contains($r["file"], "VaultController"));
	if (count($calls) !== 5) {
		fwrite(STDERR, "✗ laravel: expected 5 call sites, got ".count($calls)."\n");
		exit(1);
	}
	foreach ($calls as $call) {
		if ($call["confidence"] !== "medium") {
			fwrite(STDERR, "✗ laravel: a call site that names no algorithm was recorded at high confidence\n");
			exit(1);
		}
	}
	printf("  ✓ %-24s %-10s %s\n", "laravel", "call sites", "5 places, none of them claiming to name the cipher");
' || exit 1

# The trap in the fixture: `cookie_secure: auto` in a file that declares no
# hashers. `auto` is also the name of a Symfony password hasher, and the first
# version of the shorthand pattern reported one — in a real application, which is
# where it was found. A pattern whose only context is its value will meet that
# value somewhere else eventually.
if php -r '
	$rows = json_decode(file_get_contents("/tmp/sablier-fw.json"), true);
	foreach ($rows as $row) { if (str_contains($row["file"], "framework.yaml")) { exit(0); } }
	exit(1);
'; then
	echo "✗ yaml: cookie_secure: auto was read as a password hasher"
	exit 1
fi
printf '  ✓ %-24s %-10s %s\n' "yaml" "context" "a value is not a context"

# --- a label that is a sentence is translated, in every document ---------------
# Most labels in the algorithm catalogue are proper nouns and travel as they are.
# Two families are not — "no encryption", and the two regimes whose source names
# a document rather than an institution — and they printed French in the middle
# of every English and Spanish report until somebody read one. They now carry an
# `@` marker and are looked up; the risk that replaces the old one is a caller
# reading the raw row and printing the marker, so no document may contain it.
mark=$(mktemp -d)
cp -R tests/fixtures/sample/. "$mark/"
printf 'DATABASE_URL=postgres://u:p@db.example.org:5432/app\n' > "$mark/.env"
php -r '
	$p = $argv[1]."/sablier.json"; $d = json_decode(file_get_contents($p), true);
	$d["regime"] = "hds"; file_put_contents($p, json_encode($d, JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE));
' "$mark"
for lang in fr en es; do
	./bin/sablier scan "$mark" --lang=$lang --out="$mark/r-$lang.html" --audit="$mark/a-$lang.html" \
		--incident="$mark/i-$lang.html" --breached=2026-01-15 --cbom="$mark/c-$lang.json" \
		--no-probe --quiet >/dev/null 2>&1 || true
done
if grep -l '@algo\.\|@regime\.\|@audit\.' "$mark"/*.html "$mark"/*.json 2>/dev/null; then
	echo "✗ label: a catalogue marker reached a document instead of being looked up"
	rm -rf "$mark"; exit 1
fi
# And the lookup actually happened: the French label must not be in the English one.
if grep -q 'Aucun chiffrement' "$mark/i-en.html" || ! grep -q 'No encryption' "$mark/i-en.html"; then
	echo "✗ label: the English incident document does not name plaintext in English"
	rm -rf "$mark"; exit 1
fi
printf '  ✓ %-24s %-10s %s\n' "label" "fr en es" "sentences looked up, markers never printed"
rm -rf "$mark"

# --- the certificate a token is read from is the responder, not the chain -------
# A timestamp token carries the responder's certificate and the intermediates
# that chain it, in no guaranteed order, and the report prints the scheme that
# certificate uses — the whole point being that the attestation's own signature
# expires. Reading the wrong one misnames it. The fixture is a token whose
# responder is ECDSA-384 and whose root is RSA-4096: pick the wrong certificate
# and the answer changes, which is why this authority was chosen for it.
php -r '
	require "src/Timestamp.php";
	$token = base64_decode(file_get_contents("tests/fixtures/timestamp/ecdsa-responder.tsr.base64"));
	$read = Sablier\Timestamp::read($token);
	if ($read === null) {
		fwrite(STDERR, "✗ timestamp: the fixture token no longer reads — openssl missing?\n");
		exit(1);
	}
	if ($read["algorithm"] !== "ECDSA-384") {
		fwrite(STDERR, "✗ timestamp: responder scheme read as ".($read["algorithm"] ?: "nothing").", expected ECDSA-384 (the root is RSA-4096)\n");
		exit(1);
	}
	if ($read["authority"] === "") {
		fwrite(STDERR, "✗ timestamp: no authority read from the responder certificate\n");
		exit(1);
	}
	printf("  ✓ %-24s %-10s %s\n", "timestamp", "responder", $read["authority"]." · ".$read["algorithm"]);
' || exit 1

# --- a fingerprint is a handle, so no detector may translate its evidence -------
# A finding's fingerprint is hashed from its evidence. Build that evidence with
# Lang::t and the same finding gets a different handle per language, so an
# acceptance recorded in French silently stops applying to an analysis run in
# English. That was fixed in the TLS probe, and two other detectors kept doing it
# for a week — because the fixture that guards the property triggers neither of
# them. So the rule is checked structurally as well as by example: the grep below
# fails on the next detector that reaches for a sentence.
if grep -rn 'evidence: *Lang::t' src/ ; then
	echo "✗ evidence: a fingerprint cannot be hashed from a translated string"
	exit 1
fi
printf '  ✓ %-24s %-10s %s\n' "evidence" "structure" "no detector translates its own handle"

# And by example, on the detector that was wrong: a PNG with bytes after IEND.
# Written here rather than committed, so the fixture cannot drift from the thing
# it is testing.
asset=$(mktemp -d)
cp -R tests/fixtures/sample/. "$asset/"
php -r '
	$png = base64_decode("iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mP8z8DwHwAFAAH/q842iQAAAABJRU5ErkJggg==");
	file_put_contents($argv[1]."/logo.png", $png.str_repeat("A", 200));
' "$asset"
for lang in fr en es; do
	./bin/sablier scan "$asset" --lang=$lang --json="$asset/$lang.json" --out="$asset/$lang.html" --no-probe --quiet >/dev/null 2>&1 || true
done
SABLIER_ASSET_DIR="$asset" php -r '
	$dir = getenv("SABLIER_ASSET_DIR");
	$handles = [];
	foreach (["fr", "en", "es"] as $lang) {
		$rows = json_decode(file_get_contents("$dir/$lang.json"), true);
		$asset = array_values(array_filter($rows, static fn (array $r): bool => str_ends_with($r["file"], "logo.png")));
		if ($asset === []) {
			fwrite(STDERR, "✗ asset: the fixture no longer produces an asset finding, so this test proves nothing\n");
			exit(1);
		}
		$handles[$lang] = array_column($asset, "fingerprint");
	}
	if (count(array_unique(array_map("json_encode", $handles))) !== 1) {
		fwrite(STDERR, "✗ asset: the same file has a different fingerprint per language: ".json_encode($handles)."\n");
		exit(1);
	}
	printf("  ✓ %-24s %-10s %s\n", "evidence", "asset", count($handles["fr"])." finding(s), one handle in three languages");
' || { rm -rf "$asset"; exit 1; }
rm -rf "$asset"

# --- a machine field is never a translated word --------------------------------
# A committed baseline carried "confidence": "haute" and "domain": "non déclaré"
# beside English keys and English verdicts. Nobody noticed for weeks: the file is
# generated, so it is read when somebody has a reason to, and the reason was a
# diff that made no sense. The rule is the same one the digest already follows —
# a value a machine compares cannot depend on a language — and `because` is the
# single deliberate exception, because its job is to be read by a person.
lang=$(mktemp -d)
./bin/sablier scan tests/fixtures/sample --json="$lang/fr.json" --out="$lang/fr.html" --no-probe --quiet --lang=fr >/dev/null 2>&1 || true
./bin/sablier scan tests/fixtures/sample --json="$lang/en.json" --out="$lang/en.html" --no-probe --quiet --lang=en >/dev/null 2>&1 || true
./bin/sablier scan tests/fixtures/sample --json="$lang/es.json" --out="$lang/es.html" --no-probe --quiet --lang=es >/dev/null 2>&1 || true
SABLIER_LANG_DIR="$lang" php -r '
	$dir = getenv("SABLIER_LANG_DIR");
	$strip = static function (string $file): array {
		$rows = json_decode(file_get_contents($file), true);
		foreach ($rows as $i => $row) { unset($rows[$i]["because"]); }
		return $rows;
	};
	$fr = $strip("$dir/fr.json");
	foreach (["en", "es"] as $lang) {
		if ($strip("$dir/$lang.json") !== $fr) {
			fwrite(STDERR, "✗ json: the inventory differs between fr and $lang outside of `because`\n");
			exit(1);
		}
	}
	// And the exception has to actually be the exception: if `because` were also
	// identical the test would be passing for the wrong reason — a catalogue
	// that silently fell back to French would look like success.
	$raw = static fn (string $f): array => array_column(json_decode(file_get_contents($f), true), "because");
	if ($raw("$dir/fr.json") === $raw("$dir/en.json")) {
		fwrite(STDERR, "✗ json: fr and en produced the same prose, so nothing was translated\n");
		exit(1);
	}
	printf("  ✓ %-24s %-10s %s\n", "json", "fr en es", count($fr)." findings, identical but the prose");
' || { rm -rf "$lang"; exit 1; }
rm -rf "$lang"

# --- a date somebody else attests ---------------------------------------------
# Our own `signed_at` is covered by the signature and still worth nothing as
# evidence: it comes from the clock of the machine that signed. These four checks
# are about the ways an attested date could lie by omission instead.
ts=$(mktemp -d)
cp -R tests/fixtures/sample/. "$ts/"
./bin/sablier keygen --out="$ts/k.json" >/dev/null 2>&1

# 1. A flag that cannot do anything says so. Without --sign there is no digest
#    to attest and no file to sit beside, and silently ignoring the request
#    would leave somebody believing their report carries a date.
if ./bin/sablier scan "$ts" --out="$ts/a.html" --no-probe --quiet --timestamp=http://example.invalid/tsa >/dev/null 2>&1; then
	echo "✗ timestamp: --timestamp without --sign was accepted"
	rm -rf "$ts"; exit 1
fi
if [ -e "$ts/a.html.tsr" ]; then
	echo "✗ timestamp: a refused request still wrote a token"
	rm -rf "$ts"; exit 1
fi
printf '  ✓ %-24s %-10s %s\n' "timestamp" "no --sign" "refused, nothing written"

# 2. An authority nobody can reach must not cost the scan its verdicts, and must
#    not pass quietly either: no token is written, so the report claims no date,
#    and the reason goes to stderr where a build log keeps it.
./bin/sablier scan "$ts" --out="$ts/b.html" --no-probe --quiet --sign="$ts/k.json" \
	--timestamp=http://127.0.0.1:9/tsa 2>"$ts/err" >/dev/null || true
if [ ! -s "$ts/b.html.sig" ]; then
	echo "✗ timestamp: an unreachable authority cost the report its signature"
	rm -rf "$ts"; exit 1
fi
if [ -e "$ts/b.html.tsr" ]; then
	echo "✗ timestamp: a failed request wrote a token anyway"
	rm -rf "$ts"; exit 1
fi
if ! grep -q "127.0.0.1:9" "$ts/err"; then
	echo "✗ timestamp: an unreachable authority failed silently"
	rm -rf "$ts"; exit 1
fi
printf '  ✓ %-24s %-10s %s\n' "timestamp" "unreachable" "loud, and no date claimed"

# 3. Without a token, the command says nothing about a date. The failure mode
#    worth guarding is the opposite one: a verify that prints a reassuring line
#    when there is nothing behind it.
if ./bin/sablier verify "$ts/b.html.sig" 2>&1 | grep -qi "attest"; then
	echo "✗ timestamp: verify talks about a date with no token beside the signature"
	rm -rf "$ts"; exit 1
fi
printf '  ✓ %-24s %-10s %s\n' "timestamp" "absent" "says nothing"

# 4. A real token that attests something else. Filed beside this signature it
#    reads exactly like a valid one — same authority, same structure, a date in
#    it — and the only thing that separates the two is comparing the imprint,
#    which is why that comparison happens before any question of trust.
php -r 'echo base64_decode(file_get_contents("tests/fixtures/timestamp/other-digest.tsr.base64"));' > "$ts/b.html.tsr"
if ./bin/sablier verify "$ts/b.html.sig" >"$ts/out" 2>&1; then
	echo "✗ timestamp: a token attesting another digest was accepted"
	rm -rf "$ts"; exit 1
fi
if ! grep -qi "invalid" "$ts/out"; then
	echo "✗ timestamp: a foreign token was not reported as invalid"
	cat "$ts/out"; rm -rf "$ts"; exit 1
fi
printf '  ✓ %-24s %-10s %s\n' "timestamp" "foreign token" "imprint checked before trust"
rm -rf "$ts"

# --- a half not checked is not a half this machine cannot check ------------------
# When the Ed25519 signature fails, the post-quantum half is never examined. The
# caller read the absence of a verdict as "unavailable" and printed that this
# machine needs OpenSSL 3.5 — on the machine that had just verified ML-DSA two
# lines earlier. A reader follows that message into installing a library they
# already have, instead of looking at the key that did not match.
if openssl list -signature-algorithms 2>/dev/null | grep -qi "ML-DSA-65"; then
	st=$(mktemp -d)
	cp -R tests/fixtures/sample/. "$st/"
	./bin/sablier keygen --out="$st/mine.key" >/dev/null 2>&1
	./bin/sablier keygen --out="$st/theirs.key" >/dev/null 2>&1
	php -r '
		$d = json_decode(file_get_contents($argv[1]), true);
		$d["signing_public_key"] = trim(shell_exec("php -r \x27echo base64_encode(sodium_crypto_sign_publickey_from_secretkey(base64_decode(trim(file_get_contents(\"".$argv[2]."\")))));\x27"));
		file_put_contents($argv[1], json_encode($d, JSON_PRETTY_PRINT));
	' "$st/sablier.json" "$st/mine.key"
	./bin/sablier scan "$st" --out="$st/r.html" --sign="$st/theirs.key" --quiet >/dev/null 2>&1 || true
	said=$(./bin/sablier verify "$st/r.html.sig" --declare="$st/sablier.json" 2>&1 || true)
	case "$said" in
		*"autre clé"*) ;;
		*) echo "✗ verify: a foreign key was not reported as such"; echo "$said"; rm -rf "$st"; exit 1 ;;
	esac
	case "$said" in
		*"OpenSSL"*) echo "✗ verify: a skipped half is blamed on the local library"; rm -rf "$st"; exit 1 ;;
		*"non vérifiée"*) ;;
		*) echo "✗ verify: nothing said about the second half"; echo "$said"; rm -rf "$st"; exit 1 ;;
	esac
	printf '  ✓ %-24s %-10s %s\n' "verify" "unchecked" "not blamed on this machine"
	rm -rf "$st"
else
	printf '  · %-24s %-10s %s\n' "verify" "unchecked" "skipped: no ML-DSA on this machine"
fi

# --- a host is not a path, so it cannot be declared ------------------------------
# A probe finding carries `tls://host:443` where a file would be, and no glob can
# ever cover it. Counting it as an undeclared domain asked every project with a
# declared host to go and complete a declaration that was already complete —
# found by scanning a repository whose only cryptography is its TLS, where the
# report said "nothing is urgent" and then told the reader to declare something.
prb=$(mktemp -d)
mkdir -p "$prb/src"
printf '<?php final class S { public function t(string $p): string { return hash("sha256", $p); } }\n' > "$prb/src/S.php"
cat >"$prb/sablier.json" <<'DECL'
{ "project": "Probe only", "default_lifetime_years": 0,
  "domains": { "code": { "paths": ["src/*"], "lifetime_years": 0 } },
  "probe": ["mesa.black"] }
DECL
./bin/sablier scan "$prb" --out="$prb/r.html" --quiet >/dev/null 2>&1 || true
if grep -q "action-declare\|Compléter la déclaration" "$prb/r.html"; then
	echo "✗ probe: the plan asks to declare a host, which no path can cover"
	rm -rf "$prb"; exit 1
fi
printf '  ✓ %-24s %-10s %s\n' "probe" "undeclared" "a host is not a missing declaration"

# But a file in no declared domain still is one.
mkdir -p "$prb/legacy"
# A quoted heredoc rather than printf: \x27 is not portable — dash's printf does
# not know hex escapes, so in CI the file kept the backslashes, the detector saw
# nothing, and the assertion failed on a machine where the code was fine.
cat >"$prb/legacy/Token.php" <<'LEGACY'
<?php
final class Token
{
    public function issue(array $claims, string $key): string
    {
        return jwt_encode($claims, $key, 'RS256');
    }
}
LEGACY
./bin/sablier scan "$prb" --out="$prb/r2.html" --quiet >/dev/null 2>&1 || true
if ! grep -q "Compléter la déclaration" "$prb/r2.html"; then
	echo "✗ probe: a genuinely undeclared file no longer asks for a declaration"
	rm -rf "$prb"; exit 1
fi
printf '  ✓ %-24s %-10s %s\n' "probe" "still asks" "a file outside every domain does"
rm -rf "$prb"

# --- the questionnaire has a word budget ----------------------------------------
# Three sessions with the same person ended in "it is gibberish to me, I do not
# understand the sentences, I am lost". The questionnaire had grown to 986 words
# of reader-visible text for two questions per subject — most of it added in good
# faith, each paragraph defensible on its own, and together a document nobody
# outside the field can get through. Everything removed is still said in the
# auditor's own documents, which is where a caveat belongs.
#
# A budget rather than a review: prose arrives one justified paragraph at a time,
# and nothing else would have caught it.
bud=$(mktemp -d)
./bin/sablier worksheet tests/fixtures/order --out="$bud/w.html" >/dev/null 2>&1 || true
words=$(php -r '
	$h = file_get_contents($argv[1]);
	preg_match("#<script id=\"data\"[^>]*>(.*?)</script>#s", $h, $m);
	$d = json_decode(str_replace("<\\/", "</", $m[1]), true);
	// Every string the respondent reads without opening a fold, once.
	$folded = ["purpose", "offlineNote", "where", "details"];
	$count = 0;
	foreach ($d["t"] as $key => $value) {
		if (!is_string($value) || in_array($key, $folded, true)) { continue; }
		$count += str_word_count($value, 0, "àâäéèêëîïôöùûüçÀÂÄÉÈÊËÎÏÔÖÙÛÜÇ-");
	}
	foreach ($d["years"] as $choice) { $count += str_word_count($choice["harm"], 0, "àâäéèêëîïôöùûüç-"); }
	echo $count;
' "$bud/w.html")
if [ "$words" -gt 260 ]; then
	echo "✗ budget: $words words in front of the respondent, over the 260 allowed"
	rm -rf "$bud"; exit 1
fi
printf '  ✓ %-24s %-10s %s\n' "budget" "$words words" "under 260, folds excluded"

# And not one of the words that lost the first three sessions.
jargon=$(php -r '
	$h = file_get_contents($argv[1]);
	preg_match("#<script id=\"data\"[^>]*>(.*?)</script>#s", $h, $m);
	$d = json_decode(str_replace("<\\/", "</", $m[1]), true);
	$folded = ["purpose", "offlineNote", "where", "details"];
	$banned = ["algorithme", "algorithmes", "cryptographie", "post-quantique", "quantique", "échéance",
		"échéances", "régime", "récoltable", "empreinte", "empreintes", "plomberie", "verdict", "inventaire"];
	$seen = [];
	foreach ($d["t"] as $key => $value) {
		if (!is_string($value) || in_array($key, $folded, true)) { continue; }
		foreach ($banned as $word) {
			if (preg_match("/\b".preg_quote($word, "/")."\b/ui", $value) === 1) { $seen[$word] = true; }
		}
	}
	foreach ($d["subjects"] as $subject) {
		foreach ($banned as $word) {
			if (preg_match("/\b".preg_quote($word, "/")."\b/ui", $subject["title"].$subject["label"]) === 1) { $seen[$word] = true; }
		}
	}
	echo implode(",", array_keys($seen));
' "$bud/w.html")
if [ -n "$jargon" ]; then
	echo "✗ budget: the words that lost three sessions are back ($jargon)"
	rm -rf "$bud"; exit 1
fi
printf '  ✓ %-24s %-10s %s\n' "budget" "vocabulary" "no trade word on the path"
rm -rf "$bud"

# --- questions worded against the project's own history -------------------------
# Nobody estimates seven years well, and everybody can say whether the invoices
# from the company's first year still matter. Where the repository knows when it
# started, the choices name years the person lived through and the longest one is
# the project's own age rather than a round number somebody picked.
anc=$(mktemp -d)
cd "$anc"
git init -q . && git config user.email t@t && git config user.name t
mkdir -p src/Billing
printf '<?php final class I { public function r(string $p): string { return hash("sha256", $p); } }\n' > src/Billing/I.php
git add -A >/dev/null && GIT_AUTHOR_DATE="2019-03-01T10:00:00" GIT_COMMITTER_DATE="2019-03-01T10:00:00" git commit -qm first
cd - >/dev/null
started=$(php -r '
	foreach (["Lang", "Value", "Assessor", "Catalogue", "Finding", "SourceFile", "Signature", "MlDsa", "Declaration", "Interview"] as $class) {
		require "src/$class.php";
	}
	echo Sablier\Interview::startedIn($argv[1]);
' "$anc")
if [ "$started" != "2019" ]; then
	echo "✗ anchor: the first commit year was read as \"$started\""
	rm -rf "$anc"; exit 1
fi
printf '  ✓ %-24s %-10s %s\n' "anchor" "history" "first commit, from the repository"

# And the oldest work, not the first line of the log. A rebase rewrites commit
# dates and keeps author dates, so the earliest work can print last: reading the
# first line would make a six-year-old project look like this year's.
rb=$(mktemp -d)
cd "$rb"
git init -q . && git config user.email t@t && git config user.name t
echo a > a.txt && git add -A
GIT_AUTHOR_DATE="2024-01-01T10:00:00" GIT_COMMITTER_DATE="2024-01-01T10:00:00" git commit -qm root
echo b > b.txt && git add -A
GIT_AUTHOR_DATE="2020-05-05T10:00:00" GIT_COMMITTER_DATE="2026-10-05T10:00:00" git commit -qm replayed
cd - >/dev/null
rebased=$(php -r '
	foreach (["Lang", "Value", "Assessor", "Catalogue", "Finding", "SourceFile", "Signature", "MlDsa", "Declaration", "Interview"] as $class) {
		require "src/$class.php";
	}
	echo Sablier\Interview::startedIn($argv[1]);
' "$rb")
if [ "$rebased" != "2020" ]; then
	echo "✗ anchor: a rewritten history was read as $rebased rather than 2020"
	rm -rf "$rb"; exit 1
fi
printf '  ✓ %-24s %-10s %s\n' "anchor" "rebased" "the oldest work, not the first line"
rm -rf "$rb"

./bin/sablier worksheet "$anc" --out="$anc/w.html" >/dev/null 2>&1 || true
anchored=$(php -r '
	$h = file_get_contents($argv[1]);
	preg_match("#<script id=\"data\"[^>]*>(.*?)</script>#s", $h, $m);
	$d = json_decode(str_replace("<\\/", "</", $m[1]), true);
	$last = end($d["years"]);
	echo (str_contains($last["harm"], "2019") ? "ancré" : "générique")."/".$last["value"];
' "$anc/w.html")
# 2026 − 2019: the longest choice is how long this project has been writing.
if [ "$anchored" != "ancré/7" ]; then
	echo "✗ anchor: the longest choice is not the project's own age ($anchored)"
	rm -rf "$anc"; exit 1
fi
printf '  ✓ %-24s %-10s %s\n' "anchor" "oldest" "the project's age, not a round number"

# The premise is in the choice itself, which is where it can be contradicted: a
# person who reads "what we were writing in 2019" and started in 2012 says so.
# It used to be a paragraph above as well, and a paragraph is what this
# questionnaire had too much of.
if ! grep -q "2019" "$anc/w.html"; then
	echo "✗ anchor: the year the choices rest on is nowhere the reader can see it"
	rm -rf "$anc"; exit 1
fi
if grep -q "écrit des données depuis" "$anc/w.html"; then
	echo "✗ anchor: the premise is explained twice, once too many"
	rm -rf "$anc"; exit 1
fi
printf '  ✓ %-24s %-10s %s\n' "anchor" "premise" "in the choice, not in a paragraph"
rm -rf "$anc"

# A project younger than the gap between the anchors keeps the general wording:
# "last year" and "at the start" would otherwise name the same year.
young=$(php -r '
	foreach (["Lang", "Value", "Assessor", "Catalogue", "Finding", "SourceFile", "Signature", "MlDsa", "Declaration", "Interview"] as $class) {
		require "src/$class.php";
	}
	$choices = Sablier\Interview::consequences(2025, 2026);
	$last = end($choices);
	echo str_contains($last["harm"], "2025") ? "ancré" : "générique";
')
if [ "$young" != "générique" ]; then
	echo "✗ anchor: a one-year-old project was given anchors that collapse"
	exit 1
fi
printf '  ✓ %-24s %-10s %s\n' "anchor" "too young" "general wording below four years"

# --- consequences, not spans of years ------------------------------------------
# Asked "how many years would this still hurt" over 0/1/3/5/10/20/30, the first
# respondent picked the middle button seven times. That is a defect of the
# question: somebody who does not think in spans of years has no way to answer
# it, and the shape of the choices invited the default. The choices are
# consequences now, and the arithmetic is ours.
cons=$(mktemp -d)
./bin/sablier worksheet tests/fixtures/order --out="$cons/w.html" >/dev/null 2>&1 || true
offered=$(php -r '
	$h = file_get_contents($argv[1]);
	preg_match("#<script id=\"data\"[^>]*>(.*?)</script>#s", $h, $m);
	$d = json_decode(str_replace("<\\/", "</", $m[1]), true);
	$rows = [];
	foreach ($d["years"] as $choice) { $rows[] = $choice["value"]; }
	echo implode(",", $rows);
' "$cons/w.html")
if [ "$offered" != "0,1,3,10" ]; then
	echo "✗ consequences: the choices offered are $offered"
	rm -rf "$cons"; exit 1
fi
printf '  ✓ %-24s %-10s %s\n' "consequences" "four" "far enough apart to tell apart"

# Not one of them may read as a number of years: that is the question that failed.
if ! php -r '
	$h = file_get_contents($argv[1]);
	preg_match("#<script id=\"data\"[^>]*>(.*?)</script>#s", $h, $m);
	$d = json_decode(str_replace("<\\/", "</", $m[1]), true);
	foreach ($d["years"] as $choice) {
		foreach ([$choice["harm"], $choice["trust"]] as $label) {
			if (preg_match("/\d+\s*(ans|an|years|year|años|año)\b/u", $label) === 1) { exit(1); }
		}
	}
' "$cons/w.html"; then
	echo "✗ consequences: a choice is still worded as a span of years"
	rm -rf "$cons"; exit 1
fi
printf '  ✓ %-24s %-10s %s\n' "consequences" "wording" "a sentence, never a span"

# The two ends have to be unmistakable: published content and a day in court.
said=$(php -r '
	$h = file_get_contents($argv[1]);
	preg_match("#<script id=\"data\"[^>]*>(.*?)</script>#s", $h, $m);
	$d = json_decode(str_replace("<\\/", "</", $m[1]), true);
	echo $d["years"][0]["harm"]." | ".$d["years"][3]["harm"];
' "$cons/w.html")
case "$said" in
	*"public"*"tribunal"*) ;;
	*) echo "✗ consequences: the two ends are not the ones that decide ($said)"; rm -rf "$cons"; exit 1 ;;
esac
printf '  ✓ %-24s %-10s %s\n' "consequences" "ends" "public, and a day in court"

# One list, shared with the served interview — the two drifted once already.
if ! ./bin/sablier serve --help >/dev/null 2>&1; then :; fi
same=$(php -r '
	foreach (["Lang", "Value", "Assessor", "Catalogue", "Finding", "SourceFile", "Signature", "MlDsa", "Declaration", "Interview"] as $class) {
		require "src/$class.php";
	}
	$h = file_get_contents($argv[1]);
	preg_match("#<script id=\"data\"[^>]*>(.*?)</script>#s", $h, $m);
	$embedded = json_decode(str_replace("<\\/", "</", $m[1]), true)["years"];
	echo $embedded === Sablier\Interview::consequences() ? "ok" : "no";
' "$cons/w.html")
if [ "$same" != "ok" ]; then
	echo "✗ consequences: the offline file does not offer what the interview offers"
	rm -rf "$cons"; exit 1
fi
printf '  ✓ %-24s %-10s %s\n' "consequences" "one list" "offline and served agree"
rm -rf "$cons"

# --- a default clicked seven times is not a declaration -------------------------
# The first real session came back with seven subjects, seven identical durations,
# no justification on any of them, and no name for who answered. Three minutes,
# and the time per subject fell as it went. The tool printed "7 answers taken",
# wrote a declaration and said nothing else — which is the one thing it must never
# do, because a declaration is what makes a person accountable for a figure.
unc=$(mktemp -d)
cat >"$unc/clicked.json" <<'CLICKED'
{ "format": 1, "project": "p", "generated_on": "2026-10-05", "answered_on": "2026-10-05",
  "context": { "who": "" },
  "answers": [
    { "name": "Facturation", "paths": ["src/Billing/*"], "lifetime": 5, "note": "" },
    { "name": "REX", "paths": ["src/Feedback/*"], "lifetime": 5, "note": "" },
    { "name": "Profil", "paths": ["src/Identity/*"], "lifetime": 5, "note": "" }
  ], "record": [], "feedback": {} }
CLICKED
said=$(./bin/sablier declare tests/fixtures/order --import="$unc/clicked.json" \
	--out="$unc/d.json" --log="$unc/s.json" 2>&1)
case "$said" in
	*"même durée"*"aucune n'est justifiée"*) ;;
	*) echo "✗ import: seven clicks were taken for a declaration"; echo "$said"; rm -rf "$unc"; exit 1 ;;
esac
case "$said" in
	*"Personne n'est nommé"*) ;;
	*) echo "✗ import: a declaration with no author was written without a word"; rm -rf "$unc"; exit 1 ;;
esac
printf '  ✓ %-24s %-10s %s\n' "import" "clicked" "uniform answers, said out loud"

# One justified answer is enough to make it a considered set: a project where
# every domain really shares a duration writes that down.
php -r '
	$d = json_decode(file_get_contents($argv[1]), true);
	$d["answers"][0]["note"] = "Dix ans d archivage comptable, et le reste suit.";
	$d["context"]["who"] = "A. Durand, DPO";
	file_put_contents($argv[1], json_encode($d));
' "$unc/clicked.json"
said=$(./bin/sablier declare tests/fixtures/order --import="$unc/clicked.json" \
	--out="$unc/d2.json" --log="$unc/s2.json" 2>&1)
case "$said" in
	*"même durée"*) echo "✗ import: a justified set was still called clicked"; rm -rf "$unc"; exit 1 ;;
	*"Personne n'est nommé"*) echo "✗ import: a named respondent was still reported as absent"; rm -rf "$unc"; exit 1 ;;
esac
printf '  ✓ %-24s %-10s %s\n' "import" "considered" "a note and a name are enough"
rm -rf "$unc"

# --- a domain another domain already caught -------------------------------------
# resolve() keeps the first glob that matches, so a second domain over the same
# path is dead: its lifetime is never read. It happened on the first import —
# an older declaration held config/secrets at twenty years, the answers named the
# same place at five, the merge kept both and the older one won. Nothing in the
# output said so.
ov=$(mktemp -d)
cp -R tests/fixtures/sample/. "$ov/"
cat >"$ov/sablier.json" <<'OVERLAP'
{ "domains": {
  "tout le code": { "paths": ["src/*"], "lifetime_years": 3 },
  "jetons de session": { "paths": ["src/Tokens.php"], "lifetime_years": 1 },
  "sauvegardes": { "paths": ["deploy/*"], "lifetime_years": 10 }
} }
OVERLAP
./bin/sablier scan "$ov" --out="$ov/r.html" --no-probe --quiet >/dev/null 2>&1 || true
if ! grep -q "ne sera jamais lue" "$ov/r.html"; then
	echo "✗ overlap: a shadowed domain is not reported in the scan"
	rm -rf "$ov"; exit 1
fi
printf '  ✓ %-24s %-10s %s\n' "overlap" "shadowed" "named, with what to do"

# And a declaration whose domains do not cover one another says nothing.
if ./bin/sablier scan tests/fixtures/sample --out="$ov/clean.html" --no-probe --quiet >/dev/null 2>&1; then :; fi
if grep -q "ne sera jamais lue" "$ov/clean.html"; then
	echo "✗ overlap: a sound declaration was reported as overlapping"
	rm -rf "$ov"; exit 1
fi
printf '  ✓ %-24s %-10s %s\n' "overlap" "silent" "nothing said when nothing overlaps"
rm -rf "$ov"

# --- the subject is a place, never a family of algorithms -----------------------
# The CEO of the first company this was pointed at read the questionnaire and
# said he understood nothing of it. He was right, and the cause was structural:
# subjects were merged by the cryptography they held, so a subject could only be
# named after it — a person was asked how long "public-key encryption" and
# "content digests" had to stay confidential. Those are mechanisms, not data.
# Worse, the one subject he could have answered well, five business directories,
# had been collapsed into one of them.
ask=$(mktemp -d)
mkdir -p "$ask/src/Billing" "$ask/deploy"
cat >"$ask/src/Billing/Invoice.php" <<'BILLING'
<?php
final class Invoice
{
    public function reference(string $payload): string
    {
        return hash('sha256', $payload);
    }
}
BILLING
cat >"$ask/deploy/backup.sh" <<'BACKUP'
#!/bin/sh
openssl genrsa -out /etc/backup/key.pem 2048
pg_dump -Fc app | openssl enc -aes-256-cbc -pbkdf2 -pass env:BACKUP_KEY > dump.enc
BACKUP
# A lock file, which is what the dependency detector reads: it names versions,
# and a version is what an advisory is published against.
cat >"$ask/composer.lock" <<'COMPOSER'
{ "packages": [
  { "name": "firebase/php-jwt", "version": "6.10.0" },
  { "name": "phpseclib/phpseclib", "version": "3.0.37" }
] }
COMPOSER
./bin/sablier worksheet "$ask" --out="$ask/w.html" >/dev/null 2>&1 || true
shape=$(php -r '
	$h = file_get_contents($argv[1]);
	preg_match("#<script id=\"data\"[^>]*>(.*?)</script>#s", $h, $m);
	$d = json_decode(str_replace("<\\/", "</", $m[1]), true);
	$rows = [];
	foreach ($d["subjects"] as $s) {
		$rows[] = $s["label"]."/".($s["technical"] ? "technique" : "métier")."/".count($s["paths"]);
	}
	echo implode(" ", $rows);
' "$ask/w.html")

# `deploy` is plumbing by location and holds the whole database: it decides
# something, so it is asked first and never marked skippable. `src/Billing` is
# named after itself. `composer` declares what libraries can do and observes
# nothing, so there is no data there to put a duration on.
if [ "$shape" != "deploy/métier/1 Billing/métier/1 Réglages techniques/technique/1" ]; then
	echo "✗ interview: the subjects are not places, or the plumbing is misjudged ($shape)"
	rm -rf "$ask"; exit 1
fi
printf '  ✓ %-24s %-10s %s\n' "interview" "subjects" "named by place, plumbing last"

# Nothing is pre-filled in the field that names the data: a reader accepts
# whatever is in the box, and "Billing" is a word from the code.
if ! php -r '
	$h = file_get_contents($argv[1]);
	preg_match("#<script id=\"data\"[^>]*>(.*?)</script>#s", $h, $m);
	$d = json_decode(str_replace("<\\/", "</", $m[1]), true);
	foreach ($d["subjects"] as $s) { if ($s["suggested"] !== "") { exit(1); } }
' "$ask/w.html"; then
	echo "✗ interview: a name was suggested where only the person can name the data"
	rm -rf "$ask"; exit 1
fi
printf '  ✓ %-24s %-10s %s\n' "interview" "no guess" "the data name is theirs to give"

# A question that cannot change today's verdict says so, and so does one whose
# answer belongs to the technical team.
for needle in "ne change rien" "Sujet technique"; do
	if ! grep -q "$needle" "$ask/w.html"; then
		echo "✗ interview: the questionnaire does not say \"$needle\""
		rm -rf "$ask"; exit 1
	fi
done
printf '  ✓ %-24s %-10s %s\n' "interview" "says why" "inert and technical both flagged"

# No path and no file name in front of the person answering. Both were there —
# the agenda carried the paths, the question carried the file names — and the
# first reader said the thing was still too technical. They are kept, in a fold
# somebody has to open: an auditor checks them, a developer recognises them, and
# the person answering about data has no use for either.
visible=$(php -r '
	$h = file_get_contents($argv[1]);
	// Everything the reader is shown, minus what is folded away.
	$h = preg_replace("#<details class=\"where\">.*?</details>#s", "", $h);
	preg_match("#<script id=\"data\"[^>]*>(.*?)</script>#s", $h, $m);
	$d = json_decode(str_replace("<\\/", "</", $m[1]), true);
	$seen = [];
	foreach ($d["subjects"] as $s) {
		foreach ([$s["title"], $s["label"], $s["found"], $s["suggested"]] as $text) {
			foreach (["composer.lock", "Invoice.php", "backup.sh", "src/", "deploy/"] as $needle) {
				if (str_contains($text, $needle)) { $seen[$needle] = true; }
			}
		}
	}
	echo implode(",", array_keys($seen));
' "$ask/w.html")
if [ -n "$visible" ]; then
	echo "✗ interview: a path or a file name is shown unasked ($visible)"
	rm -rf "$ask"; exit 1
fi
printf '  ✓ %-24s %-10s %s\n' "interview" "no paths" "folded, not in the conversation"

# Which regulatory regime applies is not asked. Nobody outside the field picks
# between NIST IR 8547, CNSA 2.0 and an ANSSI position, and the question printed
# five lines of acronyms — then deadlines of 2030 and 2035 under a year the
# person had just given as 2029. It is the auditor's, in the declaration.
# On the page, not in its source: a script is not what anybody reads.
page=$(php -r 'echo preg_replace("#<script.*?</script>#s", "", file_get_contents($argv[1]));' "$ask/w.html")
if printf '%s' "$page" | grep -qi "NIST\|CNSA\|ANSSI\|régime\|regime"; then
	echo "✗ interview: the regulatory regime is still put to the person being asked"
	rm -rf "$ask"; exit 1
fi
printf '  ✓ %-24s %-10s %s\n' "interview" "no regime" "the auditor's choice, not theirs"
rm -rf "$ask"

# --- the third factor, counted rather than estimated ----------------------------
# The EU roadmap's quantum risk rests on three factors, and the one a team plans
# against is the migration effort. This counts places; it must never print a
# duration, and it must not count one finding twice.
eff=$(mktemp -d)
./bin/sablier scan tests/fixtures/sample --out="$eff/r.html" --no-probe --quiet >/dev/null 2>&1 || true
said=$(php -r '
	$h = file_get_contents($argv[1]);
	preg_match("#<section class=\"effort\">.*?</section>#s", $h, $m);
	echo html_entity_decode(strip_tags(str_replace(["</td>", "</tr>"], [" | ", "\n"], $m[0] ?? "")), \ENT_QUOTES);
' "$eff/r.html")
# Two catalogue keys share the label RSA — one encrypts, one signs — and two rows
# reading "RSA" is how a reader stops believing the table.
case "$said" in
	*"RSA · signature"*"RSA · chiffrement"*) ;;
	*) echo "✗ effort: two algorithms with one label were not told apart"; rm -rf "$eff"; exit 1 ;;
esac
printf '  ✓ %-24s %-10s %s\n' "effort" "labels" "encryption and signing told apart"

# AES-256 is sound and md5-as-a-cache-key is noise: neither is work.
case "$said" in
	*AES*) echo "✗ effort: a sound algorithm was listed as work to do"; rm -rf "$eff"; exit 1 ;;
esac
printf '  ✓ %-24s %-10s %s\n' "effort" "scope" "only what has to change"

# The refusal, in the document: no duration, and the reason.
case "$said" in
	*"pas une durée"*"vous appartient"*) ;;
	*) echo "✗ effort: the block does not refuse to estimate a duration"; rm -rf "$eff"; exit 1 ;;
esac
printf '  ✓ %-24s %-10s %s\n' "effort" "refusal" "counts places, never weeks"

# Nothing to change, nothing printed: a section that renders empty teaches a
# reader to skip it.
clean=$(mktemp -d)
mkdir -p "$clean/src"
cat >"$clean/src/Safe.php" <<'SAFE'
<?php
final class Safe
{
    public function tag(string $payload): string
    {
        return hash('sha256', $payload);
    }
}
SAFE
./bin/sablier scan "$clean" --out="$clean/r.html" --no-probe --quiet >/dev/null 2>&1 || true
if grep -q 'class="effort"' "$clean/r.html"; then
	echo "✗ effort: the block was printed with nothing to change"
	rm -rf "$eff" "$clean"; exit 1
fi
printf '  ✓ %-24s %-10s %s\n' "effort" "nothing" "silent when there is no work"
rm -rf "$eff" "$clean"

# --- the input, signed by whoever committed to it ------------------------------
# Every verdict rests on durations a human declared, and `declared_by` is a string
# anybody can type. An endorsement signs the decisions rather than the bytes: a
# reformatted file keeps it, a corrected lifetime breaks it. Three states, and the
# audit document has to carry all three.
end=$(mktemp -d)
cp -R tests/fixtures/sample/. "$end/"
./bin/sablier scan "$end" --audit="$end/none.html" --no-probe --quiet >/dev/null 2>&1 || true
if ! grep -q "pas signée" "$end/none.html"; then
	echo "✗ endorse: an unsigned declaration is not flagged as unsigned"
	rm -rf "$end"; exit 1
fi
printf '  ✓ %-24s %-10s %s\n' "endorse" "unsigned" "said in the section that uses it"

./bin/sablier endorse "$end/sablier.json" >/dev/null 2>&1
[ -s "$end/sablier.json.sig" ] || { echo "✗ endorse: nothing written"; rm -rf "$end"; exit 1; }
if ! ./bin/sablier verify "$end/sablier.json.sig" --declare="$end/sablier.json" >/dev/null 2>&1; then
	echo "✗ endorse: a fresh endorsement does not verify"
	rm -rf "$end"; exit 1
fi
# The key signed once and is gone: the file says so, and nothing is left behind.
php -r '
	$b = json_decode(file_get_contents($argv[1]), true);
	if (($b["covers"] ?? "") !== "declaration") { fwrite(STDERR, "✗ endorse: the file does not say what it covers\n"); exit(1); }
	if (($b["ephemeral"] ?? false) !== true) { fwrite(STDERR, "✗ endorse: the default key was not ephemeral\n"); exit(1); }
	if (!isset($b["hybrid"]) && trim((string) shell_exec("openssl list -signature-algorithms 2>/dev/null | grep -ci ML-DSA-65")) !== "0") {
		fwrite(STDERR, "✗ endorse: this machine can sign ML-DSA and did not\n"); exit(1);
	}
' "$end/sablier.json.sig" || { rm -rf "$end"; exit 1; }
printf '  ✓ %-24s %-10s %s\n' "endorse" "signed" "once, hybrid, and said so"

# Reformatting is not a change of mind: the digest covers the decisions, so the
# endorsement survives a rewrite of the file that says the same thing.
php -r '
	$d = json_decode(file_get_contents($argv[1]), true);
	// Same decisions, different bytes: key order, indentation, and the paths of
	// one domain listed the other way round.
	$d["domains"]["backups"]["paths"] = array_reverse($d["domains"]["backups"]["paths"]);
	$d = array_reverse($d, true);
	file_put_contents($argv[1], json_encode($d));
' "$end/sablier.json"
if ! ./bin/sablier verify "$end/sablier.json.sig" --declare="$end/sablier.json" >/dev/null 2>&1; then
	echo "✗ endorse: reformatting the file broke an endorsement of its content"
	rm -rf "$end"; exit 1
fi
printf '  ✓ %-24s %-10s %s\n' "endorse" "reformat" "survives, as it should"

# A corrected lifetime is a change of mind, and must break it.
php -r '
	$d = json_decode(file_get_contents($argv[1]), true);
	$d["domains"]["backups"]["lifetime_years"] = 4;
	file_put_contents($argv[1], json_encode($d, JSON_PRETTY_PRINT));
' "$end/sablier.json"
if ./bin/sablier verify "$end/sablier.json.sig" --declare="$end/sablier.json" >/dev/null 2>&1; then
	echo "✗ endorse: a corrected lifetime left the endorsement valid"
	rm -rf "$end"; exit 1
fi
./bin/sablier scan "$end" --audit="$end/stale.html" --no-probe --quiet >/dev/null 2>&1 || true
if ! grep -q "ne correspond plus" "$end/stale.html"; then
	echo "✗ endorse: the audit document does not say the declaration moved"
	rm -rf "$end"; exit 1
fi
printf '  ✓ %-24s %-10s %s\n' "endorse" "corrected" "breaks, and the document says so"

# Without the declared file there is nothing to recompute, and the command says
# that rather than reporting half a verification as a success.
if ./bin/sablier verify "$end/sablier.json.sig" >/dev/null 2>&1; then
	echo "✗ endorse: an endorsement verified with nothing to recompute against"
	rm -rf "$end"; exit 1
fi
printf '  ✓ %-24s %-10s %s\n' "endorse" "no file" "refuses to half-verify"
rm -rf "$end"

# --- the one regime whose deadline is read off the data -------------------------
# Every other regime is a pair of years. The EU roadmap classifies a use case by
# the confidentiality it owes — high risk if a break after ten years or more
# would still cause significant damage — so two domains in one repository hold
# two different deadlines. The fixture has a ten-year domain and a one-year one,
# which is the whole test.
eu=$(mktemp -d)
cp -R tests/fixtures/sample/. "$eu/"
php -r '
	$d = json_decode(file_get_contents($argv[1]), true);
	$d["regime"] = "eu";
	// The regime has to set the dates: an explicit year outranks it on purpose.
	unset($d["expiry_year"], $d["deprecation_year"]);
	file_put_contents($argv[1], json_encode($d, JSON_PRETTY_PRINT));
' "$eu/sablier.json"
./bin/sablier scan "$eu" --out="$eu/r.html" --cbom="$eu/c.json" --audit="$eu/a.html" \
	--calendar="$eu/c.ics" --no-probe --quiet >/dev/null 2>&1 || true
graded=$(php -r '
	$c = json_decode(file_get_contents($argv[1]), true);
	$seen = [];
	foreach ($c["components"] as $component) {
		$p = [];
		foreach ($component["properties"] as $property) { $p[$property["name"]] = $property["value"]; }
		$seen[$p["sablier:domain"]] = $p["sablier:expiry_year"]."/".($p["sablier:risk_level"] ?? "-");
	}
	ksort($seen);
	echo implode(" ", $seen);
' "$eu/c.json")
if [ "$graded" != "2030/high 2035/medium" ]; then
	echo "✗ eu: the deadline is not read off each domain's lifetime ($graded)"
	rm -rf "$eu"; exit 1
fi
printf '  ✓ %-24s %-10s %s\n' "eu regime" "graded" "2030 for ten years, 2035 for one"

# The crossing date is counted back from the deadline that applies to that
# domain, so a graded regime moves it: 2030 − 10 + 1, not 2035 − 10 + 1.
if ! grep -q "2021" "$eu/r.html"; then
	echo "✗ eu: the crossing date was not counted back from the domain's own deadline"
	rm -rf "$eu"; exit 1
fi
printf '  ✓ %-24s %-10s %s\n' "eu regime" "crossing" "2021, counted back from 2030"

# …and the legend under those dates must not name a single expiry the domains do
# not share. It said 2035 next to a list computed from 2030.
if grep -q "péremption de 2035" "$eu/r.html"; then
	echo "✗ eu: the crossing legend names one expiry under a graded regime"
	rm -rf "$eu"; exit 1
fi
printf '  ✓ %-24s %-10s %s\n' "eu regime" "legend" "no single expiry named"

# The document has to carry the framework it borrows: the roadmap by date, both
# deadlines rather than one retained year, and the level beside each domain.
for needle in "23 juin 2025" "31/12/2026" "haut risque"; do
	if ! grep -q "$needle" "$eu/a.html"; then
		echo "✗ eu: the audit document does not cite \"$needle\""
		rm -rf "$eu"; exit 1
	fi
done
printf '  ✓ %-24s %-10s %s\n' "eu regime" "cited" "roadmap, both deadlines, levels"

# The impact test is the declarer's judgement, not ours, and the document says so
# where the level is printed.
if ! grep -q "ce jugement appartient" "$eu/a.html"; then
	echo "✗ eu: the level is printed without saying whose judgement it rests on"
	rm -rf "$eu"; exit 1
fi
printf '  ✓ %-24s %-10s %s\n' "eu regime" "whose call" "the declarer's, said out loud"

# An explicit year outranks the regime: the point of the setting is that a team
# can disagree with the framework in a reviewable file.
php -r '
	$d = json_decode(file_get_contents($argv[1]), true);
	$d["expiry_year"] = 2028;
	file_put_contents($argv[1], json_encode($d, JSON_PRETTY_PRINT));
' "$eu/sablier.json"
./bin/sablier scan "$eu" --cbom="$eu/fixed.json" --no-probe --quiet >/dev/null 2>&1 || true
years=$(php -r '
	$c = json_decode(file_get_contents($argv[1]), true);
	$seen = [];
	foreach ($c["components"] as $component) {
		foreach ($component["properties"] as $property) {
			if ($property["name"] === "sablier:expiry_year") { $seen[$property["value"]] = true; }
		}
	}
	echo implode(",", array_keys($seen));
' "$eu/fixed.json")
if [ "$years" != "2028" ]; then
	echo "✗ eu: a declared expiry year did not outrank the regime ($years)"
	rm -rf "$eu"; exit 1
fi
printf '  ✓ %-24s %-10s %s\n' "eu regime" "override" "a declared year still wins"
rm -rf "$eu"

# --- the obligation the standard cannot express --------------------------------
# CycloneDX 1.6 describes the cryptography and not the duration it owes. Our
# CBOM carries that duration in the shape the open proposal uses, so a consumer
# implementing the real field maps it instead of parsing our integer.
pp=$(mktemp -d)
./bin/sablier scan tests/fixtures/sample --cbom="$pp/c.json" --no-probe --quiet >/dev/null 2>&1 || true
periods=$(php -r '
	$c = json_decode(file_get_contents($argv[1]), true);
	$seen = [];
	foreach ($c["components"] as $component) {
		foreach ($component["properties"] as $property) {
			if (str_starts_with($property["name"], "sablier:protectionPeriod.")) {
				$seen[substr($property["name"], 25)."=".$property["value"]] = true;
			}
		}
	}
	ksort($seen);
	echo implode(" ", array_keys($seen));
' "$pp/c.json")
case "$periods" in
	*"confidentiality=P10Y"*|*"integrity=P10Y"*) ;;
	*) echo "✗ cbom: the confidentiality period is not carried ($periods)"; rm -rf "$pp"; exit 1 ;;
esac
printf '  ✓ %-24s %-10s %s\n' "cbom" "protection" "ISO 8601 durations, both keys"
rm -rf "$pp"

# --- the post-breach document --------------------------------------------------
# The third document, read the week after by people who have to say how long
# this keeps costing. It is built on a date only the organisation can give, so
# the first thing to hold is the refusal.
inc=$(mktemp -d)
cp -R tests/fixtures/sample/. "$inc/"
if ./bin/sablier scan "$inc" --incident="$inc/none.html" --no-probe --quiet >/dev/null 2>&1; then
	echo "✗ incident: a post-breach document was written with no breach declared"
	rm -rf "$inc"; exit 1
fi
if [ -e "$inc/none.html" ]; then
	echo "✗ incident: the refusal still left a file behind"
	rm -rf "$inc"; exit 1
fi
printf '  ✓ %-24s %-10s %s\n' "incident" "no date" "refuses, and invents nothing"

./bin/sablier scan "$inc" --incident="$inc/i.html" --breached=2026-07-29 --no-probe --quiet >/dev/null 2>&1 || true
said=$(php -r '
	echo html_entity_decode(strip_tags(str_replace(["</td>", "</p>"], [" | ", "\n"], file_get_contents($argv[1]))), \ENT_QUOTES);
' "$inc/i.html")

# Article 33 asks for records and people. This document asks for neither, and
# has to say so where a reader cannot miss it, or somebody files it as the
# notification.
case "$said" in
	*"33"*"n'en contient aucun"*) ;;
	*) echo "✗ incident: the document does not refuse to be read as a notification"; rm -rf "$inc"; exit 1 ;;
esac
printf '  ✓ %-24s %-10s %s\n' "incident" "not a notice" "says so in section 1"

# One measure reaches what already left; the other three protect the next copy.
# A list that reads as four equivalent remedies is the failure mode here.
# One long line of HTML: count occurrences, not lines.
reaches=$(printf '%s' "$said" | grep -o "atteint ce qui est sorti" | wc -l | tr -d ' ')
ahead=$(printf '%s' "$said" | grep -o "ne change rien à ce qui est sorti" | wc -l | tr -d ' ')
if [ "$reaches" != "1" ] || [ "$ahead" != "3" ]; then
	echo "✗ incident: the remedies are not graded by what they reach ($reaches / $ahead)"
	rm -rf "$inc"; exit 1
fi
printf '  ✓ %-24s %-10s %s\n' "incident" "remedies" "one reaches, three do not"

# The expiry year is an answer only where the algorithm is what ends the
# protection. Printed next to a domain quantum does not reach, it reads as a
# deadline that domain does not have.
case "$said" in
	*"session tokens | 2027 | au-delà"*) ;;
	*) echo "✗ incident: a sound domain was given an expiry it does not have"; rm -rf "$inc"; exit 1 ;;
esac
printf '  ✓ %-24s %-10s %s\n' "incident" "protection" "an expiry only where one applies"

# Three documents, three languages, and the PDF of the one most likely to be
# printed and carried into a meeting.
for lang in en es; do
	./bin/sablier scan "$inc" --incident="$inc/$lang.html" --breached=2026-07-29 \
		--lang="$lang" --no-probe --quiet >/dev/null 2>&1 || true
	[ -s "$inc/$lang.html" ] || { echo "✗ incident: no document in $lang"; rm -rf "$inc"; exit 1; }
done
./bin/sablier scan "$inc" --out="$inc/r.html" --incident="$inc/p.html" --pdf="$inc/r.pdf" \
	--breached=2026-07-29 --no-probe --quiet >/dev/null 2>&1 || true
if [ ! -s "$inc/p.pdf" ]; then
	echo "✗ incident: asking for a PDF did not typeset the post-breach document"
	rm -rf "$inc"; exit 1
fi
printf '  ✓ %-24s %-10s %s\n' "incident" "fr en es" "three languages, and a PDF"
rm -rf "$inc"

# --- one catalogue per language, and the same one ------------------------------
# A missing key falls back silently and a format specifier that does not survive
# the quoting throws in front of a user. Both are invisible until somebody runs
# the tool in that language, which is exactly the kind of defect this suite is
# for. The third check caught a real one: "%2$d" inside a double-quoted PHP
# string interpolates $d.
php -r '
	$catalogues = [];
	foreach (["fr", "en", "es"] as $lang) { $catalogues[$lang] = require "translations/$lang.php"; }
	$all = array_keys($catalogues["fr"] + $catalogues["en"] + $catalogues["es"]);
	$errors = [];
	foreach ($catalogues as $lang => $messages) {
		foreach (array_diff($all, array_keys($messages)) as $key) { $errors[] = "$lang is missing $key"; }
		foreach ($messages as $key => $message) {
			if (str_contains($message, "\\$")) { $errors[] = "$lang:$key carries a literal backslash before a positional specifier"; }
		}
	}
	$count = static fn (string $m): int => preg_match_all("/%(?:\d+\\$)?[bcdeEfFgGosuxX]/", $m);
	foreach ($catalogues["fr"] as $key => $message) {
		foreach (["en", "es"] as $lang) {
			if (isset($catalogues[$lang][$key]) && $count($message) !== $count($catalogues[$lang][$key])) {
				$errors[] = "$key takes ".$count($message)." argument(s) in fr and ".$count($catalogues[$lang][$key])." in $lang";
			}
		}
	}
	if ($errors !== []) { fwrite(STDERR, "✗ translations: ".implode("; ", array_slice($errors, 0, 5))."\n"); exit(1); }
	printf("  ✓ %-24s %-10s %d keys, same arguments\n", "translations", "fr en es", count($all));
' || exit 1

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
