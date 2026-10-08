# Dans une chaîne d'intégration

*← retour au [README](../README.fr.md)*

## Dans une chaîne d'intégration

Un rapport que personne ne compare est un verdict sur lequel personne n'agit, et tout
l'argument de cet outil est que la fenêtre se referme d'elle-même : le même code,
analysé l'an prochain, peut virer au rouge sans qu'une ligne ait bougé, et une
acceptation tombe à une date choisie des mois plus tôt. C'est donc la deuxième
exécution qui compte.

La référence est le rapport JSON d'une exécution précédente — pas de second format, et
un fichier destiné à être versionné à côté de la déclaration :

```bash
sablier scan . --json=.sablier/baseline.json --out=rapport.html   # une fois
git add .sablier/baseline.json                                    # relu comme n'importe quel fichier
```

Ensuite, chaque exécution s'y compare :

```bash
sablier scan . --baseline=.sablier/baseline.json --out=rapport.html
```

```
  référence : .sablier/baseline.json (12 constats)

    + 1 nouveau constat
        36d82f61  CASSÉ AUJOURD'HUI    sha1  src/NewToken.php:3
    ↑ 1 verdict aggravé
        d45d9d61  SURVEILLER → COMPROMIS  rsa   deploy/backup.sh:3
    ● 1 constat rouge déjà connu, sans décision
        d87d2d2b  CASSÉ AUJOURD'HUI    sha1  src/Tokens.php:17
    − 2 constats disparus : il est temps de rafraîchir la référence

  ✗ il faut revoir la copie : 3 décisions à prendre.
     Corriger, ou décider : sablier accept <empreinte> --reason="…" --until=AAAA-MM-JJ
```

Trois choses arrêtent la construction, et ce sont les trois qui demandent un humain :
un constat **nouveau**, un verdict **aggravé** — une acceptation tombée apparaît ici —
et un **constat rouge sur lequel personne n'a décidé**. Les constats disparus sont
imprimés et n'arrêtent rien ; ils sont la raison de rafraîchir la référence.

| Code | Signification |
|---|---|
| `0` | rien de nouveau, rien de rouge en attente — on passe |
| `2` | une décision est due |
| `1` | erreur d'usage : chemin manquant, référence illisible |

**La référence n'est pas un fichier de suppression.** Un constat rouge qu'elle
enregistre déjà arrête quand même la construction, à chaque exécution, jusqu'à ce que
quelqu'un le corrige ou l'accepte — avec une raison, une date d'expiration et un
relecteur, comme décrit plus haut. Une référence qui fait taire ce qu'elle enregistre
est la façon dont ces outils se vident d'eux-mêmes en six mois, et les dates de
celle-ci reviennent toutes seules.

Rafraîchir la référence est donc un commit délibéré, relu en revue comme tout le
reste. Une chaîne qui la régénère après chaque échec n'enregistre rien.

```yaml
name: cryptographie

on: [push, pull_request]

jobs:
  sablier:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v5

      - uses: shivammathur/setup-php@v2
        with:
          php-version: '8.4'
          extensions: sodium, openssl, json
          coverage: none

      - name: Récupérer Sablier
        run: git clone --depth 1 --branch v0.5.0 https://github.com/mesa-black/sablier.git "$RUNNER_TEMP/sablier"

      - name: Inventorier la cryptographie
        run: |
          php "$RUNNER_TEMP/sablier/bin/sablier" scan . \
            --baseline=.sablier/baseline.json \
            --out=sablier-report.html \
            --no-probe

      - uses: actions/upload-artifact@v4
        if: always()
        with:
          name: sablier-report
          path: sablier-report.html
```

Épinglez une étiquette plutôt qu'une branche : cet outil décide si votre construction
passe. `--no-probe` est délibéré — un exécuteur sonde vos serveurs depuis le réseau de
quelqu'un d'autre, ce qui mesure son chemin et non le vôtre ; lancez la sonde depuis une
machine qui atteint vos propres services, sur une planification. Et téléversez le
rapport `if: always()`, parce que l'exécution que vous voulez le plus lire est celle qui
a échoué.

Sans `--baseline`, le code de sortie est `2` uniquement quand un constat `COMPROMIS` est
présent. C'est assez pour essayer l'outil, pas assez pour vivre dans une chaîne.

`--quiet` n'écrit **aucun rapport à moins que vous n'en nommiez un**. Lancé à la main,
`scan` laisse un `report.html` à côté de vous parce que c'est ce que vous êtes venu
chercher ; lancé avec `--quiet`, il répond dans le code de sortie et n'écrit que les
fichiers que vous avez demandés par leur chemin. Un outil qui laisse une page non
demandée à la racine du dépôt de quelqu'un à chaque construction laisse de l'état
derrière lui.

## Les trois conteneurs, et ce qui est affirmé à leur sujet

Un outil qui lit où sont vos clés n'a pas à vous dire de lancer des images qu'il n'a pas
regardées. Trois sont nommées dans ce dépôt — `php:8.4-cli-alpine` pour les machines
sans PHP, `ghcr.io/phpstan/phpstan` pour l'analyse statique, et le scanner lui-même — et
une commande les revérifie toutes les trois :

```bash
make cve
```

Chacune des trois est épinglée **par empreinte**, pas seulement par étiquette.
Une étiquette est un nom, et un nom peut être redirigé ; `make cve` prouve
quelque chose sur des octets, et cette preuve ne vaudrait rien si les octets
pouvaient changer sous le nom à propos duquel elle a été faite. `make images`
affiche ce vers quoi ces étiquettes pointent aujourd'hui, pour qu'un déplacement
d'épingle soit une décision que quelqu'un prend plutôt qu'un événement qu'il
subit.

Elle échoue sur toute vulnérabilité haute ou critique, sur **les deux architectures** —
une étiquette multi-architecture, ce sont plusieurs images reconstruites à des moments
différents, et une affirmation qui ne vaut que pour le portable où elle a été faite n'est
pas une affirmation. Elle tourne en intégration continue à chaque poussée **et chaque
lundi**, parce qu'une image sans vulnérabilité connue aujourd'hui n'est pas une image
sans vulnérabilité connue en mars. Elle en a déjà attrapé une : un bulletin pcre2 arrivé
dans l'image PHPStan entre deux exécutions, quelques heures avant que l'amont la
reconstruise.

C'est le cas que la barrière doit traverser sans être désactivée, et il est arrivé le
jour même. `.trivyignore.yaml` porte cette décision — une déclaration que quelqu'un a
écrite et une date à laquelle elle cesse d'être vraie, exactement les deux choses que
`sablier accept` exige de quiconque utilise cet outil. Une entrée tient aujourd'hui :
**CVE-2026-103111**, pcre2 dans l'image PHPStan, correctif publié en amont et image pas
encore reconstruite ; les seules expressions régulières qui atteignent ce conteneur sont
celles de ce dépôt. Elle expire le 2026-10-22, après quoi la barrière repasse au rouge
plutôt que de rester verte en silence — ce qui est toute la différence entre une
décision et un fichier de suppression.

L'affirmation est exactement celle-là, pas plus large : *aucune vulnérabilité haute ou
critique connue, selon la base de Trivy au moment de l'analyse*. Rien n'est affirmé sur
les inconnues, ni sur les constats bas et moyens, qui sont visibles dans la même sortie.

L'image Alpine n'est pas un goût : à l'heure où ces lignes sont écrites, Trivy rapporte
**162 vulnérabilités hautes ou critiques dans `php:8.4-cli`** — dont 46 avec un
correctif disponible — et **aucune** dans `php:8.4-cli-alpine`. Les versions épinglées
dans le `Makefile` sont celles qu'utilisent `make cve`, le lanceur et l'intégration
continue, si bien que le chiffre ci-dessus est à une commande d'être contredit.

L'analyse statique tourne au **niveau max** (`make phpstan`), dans un conteneur pour la
même raison : ce projet ne livre aucun répertoire `vendor/`, et un outil de qualité
n'est pas une raison d'en commencer un.
