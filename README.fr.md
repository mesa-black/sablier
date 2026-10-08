# Sablier

Ce qui est chiffré dans votre projet, et **combien de temps ça tient**.

*[English](README.md) · [Español](README.es.md) — la version anglaise fait foi ;
celle-ci est une traduction, et l'écart se voit en intégration continue.*

## Pour commencer

**Ce qu'il fait.** Sablier lit un projet — son code, ses dépendances, ses
Dockerfiles, son Terraform, et, si vous le laissez faire, le TLS qu'un serveur
négocie réellement — liste toute la cryptographie qu'il y trouve, et donne à
chacune une **date de péremption**. Pas « ceci est faible », mais : *cet
algorithme protège une donnée qui doit rester secrète jusqu'en 2041, et il cesse
d'être digne de confiance en 2030.* Ce qui en sort est une page HTML qu'un humain
lit, signée, avec une date attestée par un tiers.

**Comment s'en servir, en trois commandes.**

```bash
sablier init /chemin/du/projet       # 1. une déclaration, préremplie depuis le code
sablier declare /chemin/du/projet    # 2. l'entretien — la seule donnée qu'aucun scanner n'a
sablier scan /chemin/du/projet       # 3. le rapport
```

L'étape 1 écrit `sablier.json` en devinant d'après ce qu'elle voit, pour que vous
partiez de quelque chose à corriger plutôt que d'un formulaire vide. L'étape 3
fonctionne seule si vous êtes pressé — `sablier scan .` et vous avez un rapport.

**L'étape 2 est l'outil.** Tout le reste n'est que de la lecture de fichiers. Un
scanner voit bien que vous utilisez AES-256 ; rien dans votre dépôt ne dit
combien de temps la donnée qu'il protège doit rester confidentielle, et ce seul
nombre décide si un constat est urgent ou sans objet. Sablier le demande donc, en
langage métier, domaine par domaine — un bulletin de paie, un dossier médical, un
jeton de session — et il enregistre qui a répondu, et quand. Un quart d'heure
avec la personne qui sait, une fois par an.

**Pourquoi ça compte, en un paragraphe.** Un adversaire qui enregistre aujourd'hui
votre trafic chiffré le déchiffrera le jour où la machine existera. Pour une
donnée qui doit rester secrète au-delà de la péremption de RSA et des courbes
elliptiques, **la date de compromission est le jour du chiffrement, pas celui de
l'attaque** — migrer plus tard protège donc ce qui vient après, et pas cette
donnée-là. C'est pour cela que la question n'est jamais « cet algorithme est-il
solide » mais « sa péremption tombe-t-elle avant ou après la fin de la
confidentialité qu'il transporte ».

**Ce qu'il n'est pas.** Pas un scanner de vulnérabilités — il lit ce que vous avez
*choisi*, pas ce qui est cassé aujourd'hui. Pas un rapport de conformité : il
produit un artefact, un inventaire cryptographique. Dans l'Union, cet artefact
est l'une des mesures que NIS 2 demande ; en dehors, le même inventaire répond au
cadre que vous retenez — l'outil porte NIST IR 8547, le CNSA 2.0 de la NSA et la
feuille de route européenne, et lequel s'applique est un champ de la déclaration
plutôt qu'un défaut. Dans les deux cas il ne dit rien de l'enregistrement auprès
d'une autorité ni de la déclaration des incidents. Et il n'a aucun avis qu'il ne vous montrera pas :
chaque constat imprime sa preuve, son empreinte, et une manière préremplie de le
contester.

**Et ensuite.** Signez le rapport et faites attester sa date par quelqu'un qui
n'est pas vous (`--sign`, `--timestamp`), classez le document d'audit
(`--audit`), mettez les dates de bascule dans un agenda (`--calendar`), et
rejouez-le une fois par an — les échéances bougent, et une durée de
confidentialité de neuf ans est conforme cette année et ne l'est plus l'an
prochain.

La formule est l'**inégalité de Mosca** (2015), simplifiée : le cadre est standard
et porte un nom, d'autres outils l'implémentent. [`docs/scoping.md`](docs/scoping.md)
les cite honnêtement et dit ce qui reste de nous — surtout un ensemble de refus, et
une sonde qui lit ce qu'un serveur négocie réellement plutôt que ce qu'un fichier
prétend.

État : **prototype**.

## Essayer

```bash
make demo                                   # projet d'essai + rapport
sablier init /chemin/du/projet              # une déclaration à corriger, pas un formulaire à remplir
make scan DIR=/chemin/du/projet LANG=fr     # un vrai projet
make scan DIR=/chemin/du/projet PDF=1       # …et un PDF à côté
make scan DIR=/chemin/du/projet AUDIT=1     # …et le document d'audit
make probe HOST=example.org                 # ce qu'un serveur négocie réellement
make test                                   # le modèle de risque discrimine-t-il toujours ?
```

**Pas de PHP sur cette machine ?** `./sablier` est le même outil à travers un
conteneur : il utilise l'interpréteur local quand il est en 8.4 ou plus récent, et
sinon exécute le code inchangé dans `php:8.4-cli-alpine`. Rien n'est installé, le
rapport est écrit par votre propre utilisateur, et les chemins sont résolus depuis
le répertoire où vous vous tenez — celui qui est monté, si bien que le lanceur
refuse un chemin en dehors plutôt que d'écrire un rapport qui disparaît avec le
conteneur.

```bash
cd /chemin/du/projet && /chemin/vers/sablier scan . --out=rapport.html
```

Les rapports existent en français, anglais et espagnol (`--lang=fr|en|es`).

**Sans rien lancer :** [`examples/report.html`](examples/report.html) est le
rapport technique du projet d'essai, et [`examples/audit.html`](examples/audit.html)
le document d'audit de la même analyse. Les deux sont régénérés à chaque version,
et chacun tient dans un seul fichier autonome — ouvrez-les depuis le disque.
[`examples/report.pdf`](examples/report.pdf) et
[`examples/audit.pdf`](examples/audit.pdf) sont ces deux mêmes documents tels que
l'outil les compose, treize et vingt-six kilo-octets : c'est ce que pèse un PDF
qu'aucun navigateur n'a imprimé. [`examples/worksheet.html`](examples/worksheet.html)
est l'entretien hors ligne tel qu'on le remet, [`examples/cbom.json`](examples/cbom.json)
le même inventaire en CycloneDX, et [`examples/crossings.ics`](examples/crossings.ics)
les dates de bascule en agenda. [`CHANGELOG.md`](CHANGELOG.md) dit ce que chaque
version a changé.

Le rapport est un fichier HTML autonome : aucune police distante, aucun script,
aucune requête. Un outil qui lit où sont les clés n'a pas à ouvrir une socket pour
afficher sa propre sortie.

## Documentation

Le README s'arrête ici volontairement. Tout ce qui suit est une page par sujet, dans les trois langues.

| | |
|---|---|
| [`docs/detection.fr.md`](docs/detection.fr.md) | Ce qu'il détecte, et à quel point il en est sûr |
| [`docs/declaring.fr.md`](docs/declaring.fr.md) | Déclarer les durées de confidentialité |
| [`docs/reports.fr.md`](docs/reports.fr.md) | Ce que disent les rapports, et à qui ils s'adressent |
| [`docs/judging.fr.md`](docs/judging.fr.md) | Juger l'inventaire de quelqu'un d'autre |
| [`docs/advisories.fr.md`](docs/advisories.fr.md) | Vulnérabilités publiées |
| [`docs/breach.fr.md`](docs/breach.fr.md) | Après une fuite |
| [`docs/pipeline.fr.md`](docs/pipeline.fr.md) | Dans une chaîne d'intégration |
| [`docs/signing.fr.md`](docs/signing.fr.md) | Signer un rapport, et le dater |
| [`docs/closed-network.fr.md`](docs/closed-network.fr.md) | Sur un réseau fermé |
| [`docs/design.fr.md`](docs/design.fr.md) | Comment c'est assemblé, et ce qu'il refuse |
| [`docs/how-it-works.md`](docs/how-it-works.md) | Comment ça marche, en trois schémas |
| [`docs/airgap.md`](docs/airgap.md) | La posture réseau fermé, en détail |
| [`docs/scoping.md`](docs/scoping.md) | Étude de cadrage : les autres outils, et ce qui reste de nous |
| [`docs/false-positives.md`](docs/false-positives.md) | Faux positifs : comment on en contexte un, et ce qui se passe ensuite |
| [`docs/declaration-session.fr.md`](docs/declaration-session.fr.md) | Mener l'entretien de déclaration avec quelqu'un |

## Premiers résultats

Première analyse sur un projet réel (Show me the REX, ~1 900 fichiers) : 17 constats,
**aucune alerte rouge** — et trois leçons qui ont changé l'outil immédiatement.

1. Le chiffrement des sauvegardes, l'opération la plus sensible du projet, **n'est pas
   dans le dépôt** : il vit dans un script sur le serveur. L'analyse statique seule ne
   verra jamais ce qui compte le plus, à moins que vous ne le déclariez.
2. La première version rapportait un `md5()` dans un test et une dépendance TOTP — dont
   le SHA-1 est imposé par la spécification — comme des ruptures. Deux faux positifs sur
   quinze constats suffisent à perdre le lecteur. D'où la séparation entre *inventaire*
   et *usage*, et le code de test classé hors sujet.
3. La sonde a trouvé ce qu'aucun fichier ne pouvait dire : le site négocie déjà
   **X25519MLKEM768**, un échange de clés post-quantique hybride. Rien dans le dépôt ne
   le mentionne.
