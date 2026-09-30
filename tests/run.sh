#!/bin/sh
# Test de non-régression : le jeu d'essai doit produire exactement ces verdicts.
# Il existe parce que le modèle de risque est le produit — si la discrimination
# entre récolte, signature et bruit se casse, l'outil ne vaut plus rien.
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
		echo "✗ $1 / $2 : attendu $3, obtenu $found"
		exit 1
	fi
	printf '  ✓ %-24s %-10s %s\n' "$1" "$2" "$3"
}

echo
check "COMPROMIS"               rsa      1   # clé RSA pour des sauvegardes gardées 10 ans
check "CONFORME"                aes-256  2   # le symétrique n'est pas le sujet
check "SURVEILLER"              rsa-sign 2   # une signature ne se récolte pas
check "CASSÉ AUJOURD'HUI"       sha1     1   # problème classique, pas quantique
check "PROBABLEMENT HORS SUJET" md5      1   # md5 en clé de cache n'est pas une faille
echo
echo "✓ le modèle de risque discrimine encore"
