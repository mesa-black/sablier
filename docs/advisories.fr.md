# Vulnérabilités publiées

*← retour au [README](../README.fr.md)*

## Un trou que quelqu'un a déjà trouvé

Le reste de ce rapport discute de 2035. Un bulletin de sécurité dit que quelqu'un a
trouvé un chemin d'entrée avant que le rapport soit imprimé, ce qui le surclasse d'une
décennie.

```bash
sablier advisories .                       # collecter, une fois, exprès
sablier scan . --advisories=.sablier/advisories.json
```

La première commande est la seule de cet outil qui atteigne le réseau, et elle
l'atteint pour une base de données plutôt qu'avec votre inventaire : le scanner tourne
dans un conteneur épinglé, lit vos fichiers de verrouillage depuis un montage en
lecture seule, et écrit un fichier que vous pouvez lire et versionner. Une analyse ne
fait jamais rien de tout cela — aucun nom de paquet à vous ne quitte la machine pendant
qu'elle tourne.

Une bibliothèque déclarée portant une vulnérabilité publiée haute ou critique cesse
d'être du simple inventaire et devient **CASSÉ AUJOURD'HUI**, dans la même catégorie
que MD5 et SHA-1 : un défaut qui ne doit rien au quantique et qui passe avant toute
migration. Les numéros de bulletin sont imprimés avec, liés à NIST, GitHub ou OSV selon
qui les a émis.

Trois lignes le tiennent en place :

- **seules les bibliothèques que cet outil inventorie déjà sont jugées.** Un projet a
  des dizaines de dépendances vulnérables, et un rapport qui les liste toutes enterre la
  cryptographie sur laquelle on l'interrogeait. Les autres sont comptées dans les angles
  morts, pour que le lecteur sache qu'elles ont été vues et laissées ;
- **haut et critique élèvent un verdict ; moyen et bas sont attachés, pas promus.** Le
  même seuil que `make cve` applique à nos propres conteneurs ;
- **sans le fichier, le rapport dit que la question n'a pas été posée** plutôt que de
  laisser entendre que la réponse était non. Cette phrase est dans les angles morts de
  toute analyse lancée sans lui.

## Citer un défaut, et ne pas citer une échéance

Un constat cassé aujourd'hui porte le défaut publié sur lequel il repose — SHA-1 son CVE
de collision, MD5 le sien, RC4 et 3DES les leurs, TLS 1.0 et 1.1 les deux attaques qui
les ont retirés — imprimé à côté du verdict, lié à l'entrée NIST qu'un lecteur peut
aller vérifier sans nous croire sur parole.

RSA et les courbes elliptiques n'en portent aucun, et c'est tout le propos. Un CVE est
un fait daté que quelqu'un d'autre a publié ; la péremption post-quantique est un
horizon réglementaire, cité comme tel dans les références normatives du rapport
d'audit. Classer le second sous le premier transformerait une échéance en accusation,
et c'est le genre de glissement que cet outil existe pour refuser.

Les numéros voyagent avec l'inventaire : `references` dans la sortie JSON, et
`externalReferences` de type `advisories` dans le CBOM, là où tout consommateur sait
déjà les lire.
