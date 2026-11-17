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
    runs-on: ubuntu-26.04
    steps:
      - uses: actions/checkout@v5

      - uses: shivammathur/setup-php@v2
        with:
          php-version: '8.4'
          extensions: sodium, openssl, json
          coverage: none

      - name: Récupérer Sablier
        run: git clone --depth 1 --branch v0.12.1 https://github.com/mesa-black/sablier.git "$RUNNER_TEMP/sablier"

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
passe. Épinglez l'exécuteur pour la même raison : `ubuntu-latest` est un nom qui passe à
un nouveau système selon le calendrier de quelqu'un d'autre, c'est pourquoi ce projet
nomme `ubuntu-26.04` et le déplace dans un commit à part. `--no-probe` est délibéré — un exécuteur sonde vos serveurs depuis le réseau de
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
regardées. Trois sont nommées dans ce dépôt — `php:8.5-cli-alpine` pour les machines
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
`sablier accept` exige de quiconque utilise cet outil. Les entrées ne sont pas listées
ici, parce qu'elles ne restent pas en place : chacune nomme un bulletin, dit pourquoi il
n'atteint pas l'usage que ce projet fait de l'image, et expire en semaines plutôt qu'en
mois. L'exécution planifiée du lundi repose la question, et une entrée échue fait
repasser la barrière au rouge plutôt que de la laisser verte en silence. Chaque entrée
est donc soit renouvelée, avec une nouvelle date et une déclaration revérifiée, soit
retirée dès qu'une image reconstruite la rend inutile — ce qui est toute la différence
entre une décision et un fichier de suppression. Le fichier et son historique disent ce
qui tient aujourd'hui.

L'affirmation est exactement celle-là, pas plus large : *aucune vulnérabilité haute ou
critique connue, selon la base de Trivy au moment de l'analyse*. Rien n'est affirmé sur
les inconnues, ni sur les constats bas et moyens, qui sont visibles dans la même sortie.

L'image Alpine n'est pas un goût. Quand le choix a été fait, le 2026-10-01, Trivy
rapportait **162 vulnérabilités hautes ou critiques dans `php:8.4-cli`** — dont 46 avec
un correctif disponible — et **aucune** dans `php:8.4-cli-alpine`. Ce chiffre est une
mesure passée, gardée parce qu'elle est la raison ; le lanceur est depuis passé à
`php:8.5-cli-alpine`. Les versions épinglées dans le `Makefile` sont celles qu'utilisent
`make cve`, le lanceur et l'intégration continue, si bien que la réponse d'aujourd'hui
est à une commande, et la contradiction aussi.

L'analyse statique tourne au **niveau max** (`make phpstan`), dans un conteneur pour la
même raison : ce projet ne livre aucun répertoire `vendor/`, et un outil de qualité
n'est pas une raison d'en commencer un.
