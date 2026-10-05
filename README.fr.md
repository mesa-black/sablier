# Sablier

Ce qui est chiffré dans votre projet, et **combien de temps ça tient**.

*[English](README.md) · [Español](README.es.md) — la version anglaise fait foi ;
celle-ci est une traduction, et l'écart se voit en intégration continue.*

*Étude de cadrage : [docs/scoping.md](docs/scoping.md)*

Sablier lit un projet, inventorie sa cryptographie, et croise cet inventaire avec
la seule information qu'aucun scanner ne peut trouver seul : **combien de temps
chaque catégorie de donnée doit rester confidentielle.** De ce croisement sort la
seule question qui compte aujourd'hui sur le post-quantique :

> Une donnée chiffrée aujourd'hui avec RSA ou une courbe elliptique, et qui doit
> rester secrète au-delà de la péremption de ces algorithmes, est **déjà perdue**.
> La migration protège ce qui vient après elle, pas cette donnée-là.

C'est le modèle *récolter maintenant, déchiffrer plus tard* : un adversaire capture
aujourd'hui ce qu'il déchiffrera demain. Pour la donnée concernée, la date de
compromission est le jour où elle a été chiffrée, pas le jour de l'attaque.

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

`--pdf=FICHIER` écrit aussi un PDF, composé ici plutôt qu'imprimé par un navigateur
emprunté. A4, les trois polices que tout lecteur possède déjà, les dix sections
numérotées, les durées déclarées, et la chronologie dessinée en opérateurs
vectoriels — la seule figure qui porte l'argument, donc elle voyage au lieu d'être
abandonnée.

Cela a remplacé une chasse à Chrome dans quatorze emplacements et un conteneur
Chromium épinglé. Le fichier est plus sobre : pas de couleur au-delà des barres,
aucune typographie à proprement parler. Il est aussi dix-huit fois plus petit, il
porte **un numéro de page sur chaque page** — ce que le navigateur ne nous aurait
jamais donné, puisque Chrome ignore le CSS qui l'imprimerait — et il ne peut pas
échouer faute de quelque chose à emprunter. C'est cette dernière propriété qui
comptait : sur un site fermé il n'y a ni navigateur à trouver ni image à tirer, et
un rapport qu'on ne peut pas imprimer est un rapport qu'on ne peut ni signer ni
classer.

Il lui faut l'extension PHP `dom`, activée dans toute installation standard et dans
le conteneur que ce projet embarque. Sans elle, l'outil le dit, et le HTML s'imprime
toujours en PDF depuis n'importe quel navigateur, puisqu'il embarque une feuille
d'impression qui force la palette claire et garde les graphiques, les constats et le
bloc de sonde hors des sauts de page.

## Ce qu'il dit de lui-même

Ce dépôt porte sa propre déclaration et est analysé à chaque construction, le
résultat étant comparé à `.sablier/baseline.json`. Neuf constats : six signatures
Ed25519, deux empreintes SHA-256 qu'il a raison de laisser tranquilles, et un
qu'il classe comme identifiant plutôt que comme contrôle — notre propre fonction
d'empreinte, ce qu'elle est exactement.

La déclaration exclut quatre chemins, et un lecteur a droit à la raison de chacun :

| exclu | pourquoi |
|---|---|
| `src/Detector/*` | les détecteurs contiennent les motifs — la chaîne `rsa` y est ce qui trouve RSA, pas un usage de RSA |
| `src/Probe.php` | la même chose, pour la poignée de main qu'il lit |
| `tests/fixtures/*` | de la cryptographie plantée exprès, pour que les tests aient quelque chose à trouver |
| `tests/run.sh` | le `openssl genrsa` que la suite lance pour se fabriquer une clé |

Analysé en retirant cette liste, le dépôt produit 47 constats au lieu de neuf et
**pas un seul n'est rouge** : douze chaînes de motifs dans les détecteurs,
vingt-trois dans les jeux d'essai, et le reste déjà rapporté. La liste ne cache
rien ; elle est passée de huit entrées à quatre le jour où on a vérifié, parce que
quatre d'entre elles excluaient des fichiers qui ne contenaient rien.

La déclaration a dû elle aussi être mise au niveau que cet outil exige de tout le
monde. Elle porte maintenant `declared_by` et `declared_on`, et un
`service_until`, parce que le rapport imprimait notre propre horizon manquant dans
ses angles morts — c'est l'outil qui fonctionne, et ce n'était pas une façon
agréable de l'apprendre.

## À quelle fréquence il se trompe

Mesuré, pas affirmé : **31 dépôts PHP publics, 959 constats, 21 rouges, 3 d'entre
eux faux — 14 %.** Avant cette mesure, c'était 92 %, et les neuf rouges sur dix qui
étaient faux tenaient tous à la même poignée d'erreurs : `mcrypt_*` rapporté comme
DES, des codes de hachage d'objets et des noms de verrous lus comme des contrôles de
sécurité, HMAC-MD5 déclaré cassé, un appel trouvé dans un commentaire.

[`docs/false-positives.md`](docs/false-positives.md) donne la méthode, les
correctifs, le jugement sur chaque rouge restant, et les dépôts pour reproduire —
y compris les six qui n'ont jamais servi au réglage, où le taux remontait à 63 %
tant que les règles n'ont pas été rendues générales plutôt que particulières.

Trois faux positifs subsistent, documentés plutôt que masqués. Le rappel n'a pas
bougé : chaque constat réel du premier corpus est toujours rapporté.

## Les services managés, autant qu'un fichier puisse le dire

Chaque rapport porte le même aveu : la cryptographie de votre base de données, de
votre stockage objet et de votre terminaison TLS n'apparaît dans aucun fichier du
dépôt. C'est vrai d'une application. Ça cesse de l'être dès que l'infrastructure est
déclarée en code à côté.

Les fichiers `.tf` sont lus pour les décisions que quelqu'un a écrites —
`storage_encrypted = false`, un `minimum_protocol_version` sous ce qui se négocie
encore, le chiffrement serveur d'un seau et à qui appartient la clé, les clés que
l'infrastructure se fabrique, une clé KMS asymétrique. Une base managée qui garde dix
ans de comptabilité avec le chiffrement désactivé, c'est le même constat qu'un script
de sauvegarde sans chiffrement : le fournisseur ne change pas l'arithmétique.

Ce qui est lu là, c'est l'**intention**, pas le résultat : l'angle mort est donc
reformulé et non supprimé. Ce que le fournisseur fait réellement de cette déclaration
— ses propres clés, ses propres algorithmes, sa terminaison TLS — reste hors du
rapport.

## Deux sources, parce qu'un dépôt peut se tromper

La sonde couvre HTTPS, SMTP, IMAP, POP3, PostgreSQL, MySQL, LDAP, et les ports à TLS
implicite d'AMQP, Redis et MQTT — plus **SSH**, qui ne devient jamais du TLS et a
donc son propre lecteur : il prend la bannière et le KEXINIT du serveur, là où
apparaît `sntrup761x25519` quand quelqu'un a activé un échange de clés post-quantique
qu'aucun fichier du dépôt ne mentionne. Il envoie une bannière, lit un paquet et
raccroche : jamais de clé, jamais de mot de passe, jamais assez loin pour être une
tentative d'authentification.

**L'analyse statique** lit ce que le code déclare. **La sonde** effectue une poignée
de main TLS ordinaire et rapporte ce que le serveur négocie réellement — les deux se
contredisent assez souvent pour que ne rapporter que la première soit trompeur. Un
projet sans la moindre cryptographie post-quantique dans son code peut déjà être
protégé par son CDN ; un projet qui a tout configuré correctement peut être terminé
par un intermédiaire qui défait ce travail.

```
$ make probe HOST=example.org

  protocole négocié            TLSv1.3
  suite cryptographique        TLS_AES_256_GCM_SHA384 (256 bits)
  groupe négocié               X25519MLKEM768
  signature du certificat      ecdsa-with-SHA256
  versions acceptées           TLSv1.2, TLSv1.3
```

La sonde n'a sa place que contre des hôtes dont vous êtes responsable.

## Déclarer les durées de confidentialité

```bash
sablier declare /chemin/du/projet
```

L'entretien qui remplit la seule information qu'aucun scanner ne sait lire, mené
avec la personne qui connaît la réponse plutôt qu'avec celle qui a écrit le code.
Il ne demande jamais une durée de confidentialité : il demande **combien de temps
devez-vous garder ça** — un fait légal que quelqu'un connaît déjà — et **si ça
fuitait aujourd'hui, pendant combien de temps ça ferait encore du tort**, puis
retient la plus grande des deux, parce qu'une donnée qu'on doit garder est une
donnée qu'on peut encore voler. Il dit laquelle des deux a gagné, pour qu'on
puisse contester le raisonnement plutôt que le chiffre.

Les questions portent sur les zones que l'analyse a effectivement trouvées non
déclarées, dans l'ordre de ce qu'elles couvrent, et une zone peut être passée :
elle reste alors non déclarée et le rapport le dit dans ses angles morts. Une
durée que personne n'a choisie serait pire qu'un trou, parce que le verdict
au-dessus porterait la même typographie assurée que le reste.

**Pour une séance avec quelqu'un dans la pièce**, `sablier serve /chemin` ouvre le
même entretien dans un navigateur : un sujet par page, un chronomètre que la
personne voit, un bouton qui le déclenche, et à la fin le rapport que ses réponses
ont produit — plus deux questions sur l'entretien lui-même, parce que la séance
existe autant pour corriger l'outil que pour remplir une déclaration. Le serveur
est lié à la boucle locale et meurt avec la commande.

**À distance**, ajoutez `--expose` et le serveur génère une clé dans le lien ;
`--public=` affiche l'adresse à transmettre, pour le cas où un tunnel et un proxy
inverse portent un serveur qui ne quitte jamais la boucle locale. Une adresse
d'écoute juge mal l'exposition : c'est donc l'opérateur qui le dit. Terminez le TLS
au niveau du proxy — `docs/declaration-session.fr.md` donne les trois façons de
mener la séance quand la personne n'est pas dans la pièce, et ce que chacune coûte
à la mesure.

Chaque durée porte **qui l'a déclarée et quand** : le rapport d'audit imprime les
deux à côté du nombre, et une durée que personne n'a revue depuis deux ans devient
un angle mort — les acceptations expirent, les dates réglementaires portent une
date de vérification, et jusqu'ici la seule information qui décide de chaque
verdict n'avait ni l'une ni l'autre.

Le protocole — ce qu'il faut mesurer pendant la séance, et quel résultat
falsifierait toute la thèse de cet outil — existe en
[anglais](docs/declaration-session.md), [français](docs/declaration-session.fr.md)
et [espagnol](docs/declaration-session.es.md), parce que tous les auditeurs ne
lisent pas l'anglais et qu'une séance menée depuis une page à moitié comprise
mesure la mauvaise chose. Chacun renvoie vers un aide-mémoire d'une page pour la
séance elle-même : [quoi demander, et quoi répondre quand ça
bloque](docs/session-script.fr.md).

Sans déclaration, l'outil applique une durée par défaut et le dit. Avec une
déclaration, il devient utile. Voir
[`examples/declaration.json`](examples/declaration.json).

```json
{
  "expiry_year": 2035,
  "probe": ["example.org"],
  "domains": {
    "sauvegardes":     { "paths": ["deploy/backup.sh"], "lifetime_years": 10 },
    "contenu public":  { "paths": ["templates/*"],      "lifetime_years": 0 }
  }
}
```

Ce fichier est le seul artefact du projet qui engage des personnes plutôt que de
l'outillage. Il se lit, se discute et se versionne.

[`examples/starter.json`](examples/starter.json) est une déclaration à **corriger**
plutôt qu'un fichier à remplir : une douzaine de domaines courants avec leurs durées
habituelles et une note expliquant ce qui pèse sur chaque réponse. Corriger une
proposition fait apparaître des désaccords qu'un fichier vide dissimule, et c'est
plus rapide.

Un domaine peut aussi être déclaré `"hybrid": true`, ce qui signifie que ses
algorithmes classiques sont associés à un algorithme post-quantique. Un constat
porte sur une ligne, et l'hybridation est une propriété de la composition : rien
dans le code ne montre qu'un autre appel signe les mêmes octets. C'est donc la
déclaration qui le dit, le verdict cesse de vous demander de retirer la moitié
classique — ce qui reviendrait à défaire l'hybridation que les références
exigent — et les angles morts enregistrent que la paire est affirmée et non
observée. Ce dépôt déclare ainsi son propre domaine de signature, puisque la
v0.5.0 signe chaque rapport en Ed25519 et ML-DSA-65 sur les mêmes octets.

Une de ces notes compte plus que les autres : **la durée d'une sauvegarde est le
maximum de tout ce qu'elle contient.** Elle hérite du domaine le plus long que vous
avez déclaré, quel qu'il soit. Cette seule ligne est l'origine de la plupart des
verdicts rouges.

## Les données de santé, où la durée est écrite dans la loi

```bash
cp examples/health.json /chemin/du/projet/sablier.json   # à corriger, puis à faire signer par le DPO
sablier scan /chemin/du/projet --out=rapport.html
```

L'information que cet outil doit habituellement aller chercher — combien de temps
ça doit rester confidentiel — est, en santé, fixée par le Code de la santé
publique. Un dossier patient est conservé **vingt ans** à compter du dernier
séjour ou de la dernière consultation externe (R1112-7), dix ans à compter du
décès si le patient meurt moins de dix ans après son dernier passage, et le délai
court jusqu'au 28e anniversaire du titulaire s'il devait s'achever avant. Une
dispensation de vaccin au dossier pharmaceutique, c'est **vingt et un ans**
(R1111-20-12). Un dossier médical partagé, dix ans à compter de sa clôture
(L1111-18). Les vigilances sanitaires, à défaut d'autre règle, **soixante-dix
ans** à compter du retrait du produit du marché.

`"regime": "hds"` place l'autre côté de l'inégalité à 2030 — la date de l'ANSSI,
puisqu'il s'agit de données sensibles. L'arithmétique n'est alors pas serrée :

```
DATES DE BASCULE
  · sauvegardes — 70 ans — bascule franchie depuis 1961
  · dossier patient — 20 ans — bascule franchie depuis 2011
```

Un dossier patient chiffré aujourd'hui avec RSA, et qui doit rester confidentiel
vingt ans, a franchi sa bascule il y a quinze ans. C'est une soustraction entre un
texte de loi et une échéance réglementaire, pas une prédiction.

[`examples/health.json`](examples/health.json) est une déclaration à **corriger** :
chaque durée porte l'article qui la fonde, et `declared_by` est laissé vide
exprès — le rapport d'audit imprime qui a signé chaque chiffre et quand, et dans
ce contexte cette personne est le délégué à la protection des données.

**Ce que cela ne fait pas : auditer une certification HDS.** Ce référentiel
couvre l'hébergement — sécurité physique, personnel, continuité, gestion des
incidents, sur une base ISO 27001 / 20000-1 / 27018 — et la cryptographie n'en
est qu'une tranche étroite. Sablier répond à une question que le dossier HDS
pose, et la documente dans une forme qui tient devant un auditeur ; il ne
certifie rien.

## Quand l'échéance se lit sur la donnée

Tous les régimes ci-dessus sont un couple d'années. Un seul ne l'est pas :

```bash
# sablier.json : { "regime": "eu" }
cp examples/eu.json /chemin/du/projet/sablier.json
```

La *feuille de route coordonnée pour la transition vers la cryptographie
post-quantique* du groupe de coopération NIS (23 juin 2025) ne fixe pas une date
pour tout le monde. Elle classe chaque cas d'usage par la confidentialité qu'il
doit, et donne à chaque classe sa propre fin :

> « this document considers a use case as **high-risk if compromising
> confidentiality after 10 years or more would still cause significant damage** »
>
> « For high-risk use cases, quantum-vulnerable public-key mechanisms **shall not
> be used stand-alone after the end of 2030**, analogously **after the end of 2035
> for medium-risk** »

Ce classement tourne sur la seule entrée que cet outil demande et que personne
d'autre ne collecte. Sous `eu`, l'échéance se lit donc par domaine : dix ans ou
plus de confidentialité — ou un `trust_anchor` qui signe du logiciel, l'exemple
que la feuille de route donne elle-même du cas à fort impact — placent un domaine
en **haut risque, 2030** ; plus court, c'est **risque moyen, 2035**. Deux domaines
dans un dépôt, deux échéances, à partir de la déclaration déjà écrite. Le rapport
d'audit imprime le niveau à côté de chaque domaine, et les deux dates au lieu
d'une seule année retenue.

Ce que l'outil ne reprend pas, c'est le jugement. Le critère de la feuille de
route est qu'une compromission après cette durée *causerait encore un dommage
significatif* — et déclarer dix ans, **c'est** porter ce jugement. Le document le
dit là où le niveau est imprimé, au lieu de présenter un niveau calculé comme une
constatation.

Une raison de plus en 2026 : le **Milestone 1, au 31/12/2026**, liste parmi ses
First Steps « Support mature cryptographic asset management », « Create dependency
maps » et « Perform quantum risk analysis » — et recommande le CBOM comme format
d'inventaire. Un scan produit l'inventaire et l'analyse de risque. La carte des
dépendances, non, et c'est écrit dans les angles morts plutôt que laissé entendre.

### L'obligation que le standard ne sait pas écrire

CycloneDX 1.6 décrit la cryptographie et pas la durée qu'elle doit. Aucun champ ne
dit « ceci doit rester confidentiel dix ans » — l'entrée sur laquelle repose
chaque verdict ici, et la raison pour laquelle on peut recommander le CBOM comme
format tout en laissant le classement du risque à un humain.
[CycloneDX/specification#1126](https://github.com/CycloneDX/specification/issues/1126)
propose `protectionPeriod` sur `relatedCryptoMaterialProperties`, clés
`confidentiality` et `integrity`, avec une durée ISO 8601, visé pour la 2.0.

En attendant, notre CBOM porte la même forme sous son propre espace de noms, pour
qu'un consommateur qui implémentera le vrai champ la transpose mécaniquement au
lieu d'analyser notre entier :

```json
{ "name": "sablier:protectionPeriod.confidentiality", "value": "P10Y" }
```

La proposition porte aussi un `until` absolu, et pas nous : cette date dépend du
moment où chaque enregistrement a été écrit, c'est-à-dire exactement ce que
l'outil dit ailleurs ne pas savoir.

## Comment c'est assemblé

Deux points d'extension, parce que l'étude de cadrage nomme deux axes qui vont
réellement croître — et rien d'autre n'obtient une interface.

```
DetectorInterface   une façon de trouver de la cryptographie dans un type de fichier
  PhpDetector · ShellDetector · KeyMaterialDetector
  ServerConfigDetector · DependencyDetector

ReporterInterface   une façon de rendre une analyse
  HtmlReporter · AuditReporter · CbomReporter · JsonReporter
```

`Scanner` parcourt une arborescence et ne sait rien de la cryptographie ; la liste
des détecteurs est composée dans `bin/sablier` et lui est passée. Ajouter un langage
veut dire écrire un détecteur et l'enregistrer, jamais modifier le scanner.
`Analysis` porte tout ce dont un rapporteur a besoin, si bien qu'ajouter un fait au
rapport ne change pas la signature de tous les rendus.

Tout le reste reste concret. `Catalogue`, `Assessor`, `Declaration` et `Lang` ont une
implémentation chacun et aucune seconde en vue : une interface avec une seule
implémentation et aucune perspective d'une autre est un coût sans acheteur.

## Le rapport conclut

Des constats ne sont pas une décision. La dernière section est un plan d'action
ordonné, dérivé de ce qui a réellement été trouvé — quoi faire en premier, et
pourquoi ça passe en premier.

Il prend des positions que la plupart des inventaires évitent. Quand une donnée est
déjà récoltable, la première action n'est pas « migrer » : c'est décider du sort de
la donnée déjà émise, parce que la migration ne peut pas l'atteindre. Quand rien ne
brûle, il le dit franchement, parce que remplacer de la cryptographie qui tient coûte
du temps et n'améliore rien. Et quand la plupart des constats portent sur des
domaines non déclarés, finir la déclaration passe avant tout le reste — jusque-là,
les verdicts au-dessus sont des approximations livrées dans une typographie assurée.

Un bouton de partage remet le résumé à **Threema**, qui ouvre une application locale
avec du texte brut. Rien n'atteint un serveur tiers, ce qui est le seul partage que
cet outil puisse offrir sans contredire son propre pied de page.

Threema est le canal de la maison pour tout ce que cet outil remet, et la raison est
arithmétique plutôt qu'affaire de goût : il est chiffré de bout en bout, il
authentifie la personne et non un domaine, et la clé qui compte se vérifie en scannant
un code devant quelqu'un. C'est exactement la propriété dont un audit a besoin quand
il envoie une **empreinte** — voir plus bas : le rapport peut partir par courriel,
l'empreinte ne doit pas partir par la même voie.

`threema://` est un schéma de téléphone. Sur un ordinateur qui ne l'a jamais
enregistré, le navigateur refuse le lien : le résumé qu'il aurait porté est donc
imprimé dans un dépliant sous le bouton, sélectionnable d'un clic.

## Le troisième facteur, compté et non estimé

Le risque quantique de la feuille de route européenne repose sur trois choses : la
faiblesse de la cryptographie, l'impact d'une rupture, et *« the estimated time
and effort required to migrate »*. Cet outil mesurait les deux premières et ne
disait rien de la troisième — celle sur laquelle une équipe planifie réellement,
et celle à laquelle chaque éditeur répond par un chiffre invérifiable.

Le rapport compte donc ce qu'il y a à changer, par algorithme : appels, fichiers,
domaines, combien d'entrées sont déclarées plutôt qu'observées à un appel, et
combien nomment l'algorithme dans une variable ou une configuration au lieu de
l'appel lui-même. Ce dernier compte est la définition que la feuille de route
donne de l'agilité cryptographique — *« a modular way that enables replacing the
cryptographic components »* — observée au lieu d'être affirmée, et il désigne les
appels les moins coûteux à reprendre.

Chaque chiffre est déjà dans l'inventaire ; aucun n'est une inférence. Deux
entrées du catalogue qui partagent un libellé sont distinguées par leur usage,
parce que deux lignes qui affichent « RSA » sont la façon dont un lecteur cesse de
croire un tableau. Un algorithme sain, ou une empreinte utilisée comme clé de
cache, n'est pas du travail et n'est pas listé. Sans rien à changer, le bloc ne
s'affiche pas.

**Ce qu'il ne fera pas, c'est en tirer une durée.** Huit appels dans un fichier
derrière une même fonction sont une après-midi ; huit répartis sur six services
avec un protocole entre eux sont un trimestre, et rien dans un dépôt ne distingue
les deux. Un outil qui imprimerait « trois semaines » inventerait le seul chiffre
du rapport qu'on ne peut pas vérifier — et serait cru, précisément parce que c'est
le chiffre dont quelqu'un avait besoin. Le compte est de nous ; l'estimation est
du lecteur, et le bloc le dit à l'endroit où sont les chiffres.

## Constats erronés

Deux choses différentes s'appellent un faux positif, et elles ne vont pas au même
endroit. Le rapport le dit sous chaque constat, avec le texte exact à utiliser.

**L'outil a raison, mais le constat est accepté ici.** C'est une décision de projet :
elle vit donc dans la déclaration, à côté des durées de vie des données — un fichier
versionné, ce qui veut dire que la revue se fait en revue de code, sans service et
sans base de données :

```bash
sablier accept a3f1c2 --reason="SHA-1 imposé par la spécification TOTP" --until=2027-04-01
```

Trois règles sont appliquées plutôt que suggérées, parce qu'un fichier de suppression
facile à écrire est la façon dont ces outils se vident d'eux-mêmes en six mois :

- **un constat accepté ne disparaît pas.** Il passe dans sa propre section, en
  portant le verdict qu'il aurait eu, la raison donnée et la date ;
- **une acceptation expire.** `until` est obligatoire, et le constat revient tout
  seul le jour où elle tombe — de la même façon que la fenêtre se referme toute
  seule ;
- **la raison est obligatoire et écrite pour un humain.** C'est ce que la personne
  qui approuve le changement lit réellement.

Une acceptation est indexée sur l'évidence et non sur le numéro de ligne : elle tombe
donc quand la ligne qu'elle visait change matériellement. C'est voulu : le code a
bougé, la décision mérite un second regard.

**L'outil a tort.** C'est une règle à corriger, et sa place est ici. Chaque constat
porte un lien qui ouvre un signalement pré-rempli — le lien ouvre votre navigateur sur
un formulaire que vous remplissez vous-même ; le fichier, lui, n'envoie toujours rien.

## La date, pas la barre

Une barre face à un trait vertical demande au lecteur de faire la soustraction. Cette
soustraction a une seule réponse et c'est une date : le rapport l'imprime donc sous le
graphique :

```
DATES DE BASCULE
  · sauvegardes — 10 ans — bascule franchie depuis 2026
  · authentification — 3 ans — bascule le 1er janvier 2033
```

Une donnée chiffrée l'année Y reste sensible jusqu'à Y plus sa durée : l'année de
bascule est donc `péremption − durée + 1`, la première année dont la production
survit à l'algorithme qui la protège. Avant elle, le domaine tient ; à partir d'elle,
tout ce qui est émis est déjà perdu le jour où l'algorithme tombe — et migrer plus
tard ne revient pas en arrière.

Deux conditions, parce qu'une date portant sur le mauvais domaine est pire que pas de
date du tout. Elle porte sur la **confidentialité**, puisqu'une signature ne se
récolte pas ; et sur un algorithme **qu'un ordinateur quantique casse**, puisqu'un
domaine protégé par AES ou ML-KEM peut garder une donnée un siècle sans rien
franchir. Colorer sur la seule durée était un bogue que ce projet a déjà corrigé une
fois, dans le graphique ; c'est le même bogue en toutes lettres, et le test de
régression vérifie le silence.

Le plan d'action cesse de dire « rejouez ceci une fois par an » et nomme le
rendez-vous : *Prochaine bascule : authentification, le 1er janvier 2033.*

```bash
sablier scan . --calendar=bascules.ics
```

`--calendar` écrit celles encore à venir en iCalendar — un événement d'une journée par
domaine, replié à 75 octets comme la spécification l'exige, parce qu'un outil qui
passe son rapport à dire aux gens de lire la norme n'a pas le droit d'en ignorer une.
Une date dans un rapport se lit une fois ; une date dans un agenda interrompt
quelqu'un en 2033, et c'est la seule version qui marche.

## Deux rapports, pour deux salles

`--audit=FICHIER` écrit un second document à partir de la même analyse. Pas un mode du
premier : un autre document, pour un autre lecteur.

Le rapport technique se lit à côté d'un éditeur, par quelqu'un qui peut agir. Le
rapport d'audit se lit par un client, un comité, un assureur, un avocat — des gens qui
n'ont pas écrit le code et qui devront peut-être le peser dans un litige. Il emprunte
sa forme aux rapports d'expertise plutôt qu'aux tableaux de bord :

- **les faits et l'avis sont séparés, et numérotés.** La section 5 constate, dans un
  tableau numéroté ; la section 7 conclut, en citant les numéros sur lesquels elle
  s'appuie. Un lecteur peut accepter un fait et contester l'avis bâti dessus, ce qui
  est précisément ce que fait un contre-interrogatoire ;
- **l'information qui décide du résultat est imprimée en entier.** Chaque verdict
  dépend de durées qu'un humain a déclarées : la section 6 les reproduit et dit
  franchement que l'outil ne peut ni les vérifier ni les déduire du code ;
- **les limites forment une section numérotée**, à la même taille que le reste ;
- **les références sont citées avec la date de leur dernière vérification** — une
  échéance citée de mémoire ne vaut rien devant quelqu'un payé pour la vérifier ;
- **un glossaire** des sept termes dont le document a besoin, pour qu'on ne demande
  pas au lecteur de savoir déjà ce qu'est la récolte ;
- **rien de l'auditeur n'est inventé.** Un nom absent s'imprime comme un champ à
  compléter, et une déclaration absente comme une déclaration qui reste à rédiger,
  dater et signer. Un rapport qui invente un auditeur plausible est un faux aux
  bonnes intentions.

L'identité vient de deux fichiers, parce qu'on demandait deux choses différentes à un
seul bloc. **La mission** change à chaque engagement et se relit avec le projet
qu'elle concerne : elle vit donc dans la déclaration versionnée :

```json
"audit": {
  "client": "Example SAS",
  "reference": "AUD-2026-014",
  "mandate": "Établir l'exposition des données confidentielles à la récolte."
}
```

**L'auditeur** appartient à une personne et non à un projet, et taper son nom dans le
dépôt de chaque client est la façon dont il devient périmé dans l'un d'eux. Il tient
une fois dans `~/.config/sablier/identity.json` (ou là où pointe `SABLIER_IDENTITY`),
et se remplit tout seul à chaque mission :

```json
{
  "auditor": "A. Lambert",
  "organisation": "Lambert & Co",
  "statement": "Les constats de la section 5 ont été produits par l'outil nommé en section 1…"
}
```

Le fichier d'identité remplit ce que la déclaration laisse vide et perd tous les
conflits : le fichier versionné est celui que quelqu'un a relu.
`examples/identity.json` en est le modèle.

Il n'y a pas de YAML ici et il n'y en aura pas : PHP n'embarque aucun analyseur YAML,
donc le supporter signifie soit une dépendance que ce projet refuse, soit un analyseur
écrit à la main — et un analyseur YAML fait maison est un passif, pas une
fonctionnalité.

```bash
sablier scan . --out=rapport.html --audit=audit.html --pdf=rapport.pdf --sign=sablier.key
```

Avec `--pdf`, le document d'audit obtient son propre PDF à côté du technique — c'est
celui qu'on imprime, qu'on signe et qu'on classe. Les deux existent en français,
anglais et espagnol, et les deux portent la même empreinte : la section 10 l'imprime,
avec la commande qu'un tiers exécute pour vérifier la signature.

Ce que l'outil ne prétend pas : rien de tout cela ne rend un document recevable où que
ce soit. L'auditeur le signe et le défend ; Sablier produit les faits, la méthode, les
limites et l'arithmétique, dans une forme qui survit à une lecture faite par quelqu'un
qui y cherche un trou.

## Juger l'inventaire de quelqu'un d'autre

Les détecteurs ne sont pas le terrain où cet outil peut gagner. CycloneDX 1.6 est un
format publié, plusieurs scanners l'émettent, et ils ont des équipes derrière eux. Ce
que personne d'autre ne fait, c'est croiser un inventaire avec **combien de temps la
donnée qu'il protège doit rester secrète**. L'inventaire peut donc venir d'ailleurs :

```bash
sablier judge cbom.json --declare=sablier.json --out=rapport.html
```

Un CBOM produit par un autre scanner — en Java, en Python, en Go, un langage que ce
projet n'analysera jamais — ressort de cette commande avec un domaine, une durée et un
verdict attachés à chaque composant. Les emplacements du CBOM sont confrontés aux
`paths` de votre déclaration exactement comme le ferait une analyse locale :

```
  example-service — inventaire importé de another-scanner 2.1.0, 3 emplacements, 5 constats

    COMPROMIS                1
    CASSÉ AUJOURD'HUI        1
    SURVEILLER               2
    CONFORME                 1
```

Trois choses sont refusées à l'entrée, et ce sont elles qui rendent l'import utilisable
plutôt que flatteur :

- **la détection n'est pas la nôtre, et le rapport le dit** — dans les angles morts,
  avec le nom de l'outil qui l'a produite. Nous jugeons ce qu'on nous a remis ; que ce
  scanner ait lu le code correctement est l'affirmation de son auteur ;
- **un algorithme que cet outil ne connaît pas n'est jamais deviné.** Il est compté et
  nommé dans le rapport (`Composants du CBOM laissés sans jugement … : 2 (Camellia,
  TLS)`), parce qu'un importateur qui laisse tomber en silence ce qu'il n'a pas compris
  fabrique exactement la fausse assurance que ce projet existe pour refuser ;
- **l'empreinte est recalculée, jamais lue dans le fichier.** Un CBOM capable
  d'affirmer l'empreinte d'une acceptation existante traverserait directement la
  décision qui lui est attachée.

Une distinction survit au voyage, que la plupart des inventaires perdent : CycloneDX
enregistre la **primitive**, donc RSA qui signe arrive comme une signature et RSA qui
chiffre comme un transport de clé — et cet outil traite la première comme non
récoltable et le second comme récoltable, ce qui est tout le modèle de risque.

L'autre sens, c'est `--cbom=FICHIER`, sur `scan` comme sur `judge` :

```bash
sablier scan . --cbom=cbom.json --out=rapport.html
```

Les constats sortent en composants `cryptographic-asset` CycloneDX 1.6, avec le
verdict, le domaine, la durée qui l'a produit et l'empreinte portés en propriétés
`sablier:`. Deux choses ne sont délibérément pas écrites : un
`nistQuantumSecurityLevel` autre que zéro — zéro est ce qu'un ordinateur quantique
casse, et revendiquer les niveaux 1 à 5 pour tout le reste serait inventer des
chiffres — et un OID, qui n'est jamais deviné. La prise en charge des actifs
cryptographiques est récente dans les outils qui consomment des CBOM ; si le vôtre
rejette quelque chose que nous émettons, c'est une règle à corriger et sa place est
dans ce dépôt.

## Ce qui se cache dans les fichiers que personne ne lit

Les images, polices et archives d'un dépôt sont copiées, relues par personne et
livrées. C'est aussi un endroit commode pour laisser quelque chose. Trois contrôles,
classés par ce qu'ils prouvent réellement :

- **du matériel de clé dans un actif binaire.** Un en-tête PEM dans un `.png` n'est pas
  un accident — et il était déjà trouvé, parce que le détecteur de clés lit tous les
  fichiers et pas seulement ceux dont le nom ressemble à une clé. Ce qui est nouveau,
  c'est la phrase qui dit où : *« Bloc de clé trouvé à l'octet 73 d'un fichier .png. Un
  actif binaire n'est pas un endroit où du matériel de clé arrive par accident. »* ;
- **des octets après la fin de l'image.** Un PNG finit à `IEND`, un JPEG à `FFD9`, et un
  fichier qui continue au-delà porte autre chose. Rapporté comme **à confirmer**, avec
  le nombre d'octets, jamais comme un verdict : un profil colorimétrique et une archive
  exfiltrée se ressemblent vus d'ici, et un seul des deux est un problème ;
- **une extension qui ment sur le contenu.** Les octets magiques disent ce qu'est un
  fichier. Un `.png` qui commence par `PK\x03\x04` est un zip, ce qui mérite un coup
  d'œil et rien de plus.

Ce n'est délibérément **pas** de la détection de stéganographie, et le rapport le dit
dans ses angles morts. Un message caché dans les bits de poids faible d'une image est un
problème de recherche dont le taux de faux positifs enterrerait chaque constat réel que
cet outil imprime. Un outil qui crie au loup à propos de photos de vacances perd le
droit d'être cru à propos d'une clé de sauvegarde — c'est pourquoi le test de régression
qui compte le plus ici est celui qui vérifie le silence sur une image ordinaire.

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

## Quand le trou a déjà servi

Un avis de sécurité dit que quelqu'un a trouvé une entrée. Une fuite dit que
quelqu'un est passé par là, et toute l'arithmétique de cet outil se lit alors à
l'envers.

```bash
sablier scan . --breached=2026-07-29
```

Partout ailleurs ici le raisonnement va vers l'avant : un adversaire capture
aujourd'hui ce qu'il lira quand l'algorithme tombera. Après une fuite il
n'attend plus — il l'a — et la seule question qui reste est la part de la
confidentialité demandée que la cryptographie peut encore tenir. Des données
sorties en année F doivent rester secrètes jusqu'en F + durée ; l'algorithme qui
les protège cesse d'être crédible à la péremption du régime ; ce qui se trouve
entre les deux est la part qui devient lisible, et migrer après ne la rattrape
pas.

La date se pose sur le domaine, parce qu'une table volée n'est pas une
affirmation sur tout le système :

```json
{ "name": "backups", "lifetime_years": 10, "breached": "2026-07-29" }
```

En ligne de commande elle s'applique à tous les domaines d'un coup, ce qui est
le pire cas et doit se lire comme tel. Chaque domaine touché reçoit alors une
ligne :

- **le clair perd toute la durée.** Rien n'a besoin de tomber pour que ces
  données soient lisibles, puisque rien ne les protégeait ;
- **un algorithme que le quantique atteint perd la fin.** Dix ans demandés, une
  sortie en 2026, un algorithme crédible jusqu'en 2035 : une année de ce qui a
  été volé devient lisible, et aucune migration ne la rattrape ;
- **un algorithme que le quantique n'atteint pas ne perd rien**, et la ligne le
  dit au lieu de se taire.

Trois refus empêchent cela de devenir un générateur de notifications de
violation. L'outil **compte des années, jamais des personnes** — combien
d'enregistrements sont sortis est une affaire pour l'équipe d'incident, combien
de temps ils continuent de nuire est la question que personne d'autre ne pose.
Il ne parle que des **domaines que quelqu'un a déclarés touchés**. Et il **dit ce
qu'il ne peut pas savoir** : il ignore ce qui est réellement sorti, si c'est
sorti chiffré, et si les clefs sont parties avec, et cette phrase est imprimée à
côté du chiffre.

Ce n'est pas non plus une prétention de prévention. Les fuites qui font les
titres sont des identifiants volés et des équipements non corrigés, et rien dans
cet outil n'en aurait arrêté une. Ce qu'il sait faire, c'est répondre à la
question posée la semaine suivante : combien de temps le dommage dure.

### Le document de la semaine suivante

Le bandeau ci-dessus vit dans le rapport technique, qui se lit à côté d'un
éditeur. La semaine qui suit une fuite, la question est posée dans une autre
pièce — par un DPO, un service juridique, un comité — et la réponse doit être
assez courte pour être lue d'un seul trait :

```bash
sablier scan . --breached=2026-07-29 --incident=incident.html
```

Six sections, une page ou deux : ce que le document est et n'est pas, ce qui a
été déclaré sorti et par qui, combien de temps chaque domaine reste protégé, ce
qui peut encore être fait, la méthode et ses limites, l'empreinte. Il ne
ressemble pas au rapport d'audit — sans serif, pas de sommaire — parce que deux
documents issus de la même analyse qui se ressemblent, c'est ainsi qu'on classe
le mauvais. [`examples/incident.html`](examples/incident.html) en est un, avec
son [PDF](examples/incident.pdf).

Trois refus :

- **ce n'est pas une notification.** L'article 33 demande les catégories et le
  nombre approximatif de personnes et d'enregistrements concernés. Ce document
  n'en contient aucun, le dit en section 1, et nomme à qui cette obligation
  appartient ;
- **il refuse d'être écrit sans date.** Pas de fuite déclarée, pas de document —
  un rapport post-fuite produit par un outil qui a décidé tout seul qu'il y avait
  une fuite est pire que pas de rapport ;
- **il classe les mesures par ce qu'elles atteignent.** Renouveler les clés,
  rechiffrer ce qui est encore détenu et notifier sont tous nécessaires, et aucun
  ne touche aux données déjà sorties. Une mesure le fait — réduire la
  conservation là où la durée est un choix et non un plancher légal — et le
  document dit laquelle, au lieu d'aligner quatre mesures qui se lisent comme
  équivalentes.

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

## L'entretien en un seul fichier

```bash
sablier worksheet /chemin/du/projet --out=questionnaire.html   # [--lang=fr|en|es]
# … la personne le remplit, où elle veut, et rend un fichier
sablier declare /chemin/du/projet --import=reponses.json
```

Une page qui ne communique avec rien : les sujets et les questions intégrés, pas de
serveur, pas de port, pas de requête. Elle s'ouvre depuis une clé USB ou une pièce
jointe, se remplit dans un navigateur câble débranché, et ce qui revient est un bloc de
JSON que la personne peut enregistrer ou copier.

Elle existe pour les salles où l'entretien servi ne peut pas entrer — un réseau fermé,
un client qui ne lancera pas de commande, une machine à laquelle personne n'a le droit
de se connecter — et elle supprime le tunnel, le certificat et la question de savoir si
le portable de l'auditeur est sain, pour tous les autres aussi.

Ce qui voyage est le point : le fichier ne porte **aucun chemin absolu** de la machine
qui l'a écrit, et ce qui revient porte des durées et les noms que la personne a donnés,
jamais l'inventaire qui les a produits. Les deux sont vérifiés à chaque exécution. Le
rapport est ensuite calculé par l'auditeur, là où il doit l'être.

Les règles de fusion ne sont pas réimplémentées dans le navigateur. La page collecte
des réponses ; `--import` les fait passer par le même code qu'un entretien tapé, si
bien qu'un nom donné deux fois veut dire la même chose — un seul domaine, les deux
chemins, la durée la plus longue — où qu'il ait été donné.

### Ce que la personne lit, et son budget

Trois séances avec le même dirigeant se sont terminées par *« c'est du charabia
pour moi, je ne comprends pas les phrases, je suis perdu »*. La troisième fois,
le document avait atteint **986 mots** à traverser pour répondre à deux
questions par sujet — avec *empreinte* cinq fois, et *algorithme*, *échéance*,
*régime*, *déclaration*, *plomberie* sur le chemin. Presque tout avait été
ajouté de bonne foi, un paragraphe défendable à la fois, chacun expliquant ce
que l'outil ne pouvait pas savoir ou pourquoi une question était posée.

Tout ce qui a été retiré est toujours dit — dans le rapport d'audit, là où une
réserve appartient : il est lu par qui doit peser les chiffres, pas par qui en
fournit un. Il reste **235 mots**, et un test échoue au-delà de 260. Un budget
plutôt qu'une relecture, parce que la prose arrive un paragraphe justifié à la
fois et que rien d'autre ne l'aurait attrapée. Un second test échoue si un mot
de métier revient sur le chemin.

Deux questions sont parties aussi. La cryptographie trouvée à un endroit est
maintenant derrière un pli, avec les noms de fichiers : vrai, et sans usage pour
qui répond sur des données. Et **le régime réglementaire n'est plus demandé** —
personne hors du domaine ne choisit entre NIST IR 8547, CNSA 2.0 et un avis de
l'ANSSI, et la question affichait cinq lignes d'acronymes, puis des échéances de
2030 et 2035 sous une année que la personne venait de donner à 2029. C'est à
l'auditeur de le fixer, dans la déclaration, où il est relisible ; l'import le
dit quand il est resté au défaut.

Ce qui survit est la seule chose dont la personne en face est l'autorité : de
quelles données il s'agit, dans ses mots, et ce que ça coûterait si elles
sortaient.

## Sur un réseau qui n'en a pas

```bash
sablier scan /chemin/du/projet --airgap --out=rapport.html --pdf=rapport.pdf
```

`--airgap` refuse au lieu de désactiver. `--no-probe` est une commodité : il saute une
étape que vous auriez pu lancer ; sur un site fermé c'est la mauvaise forme, parce
qu'un drapeau qu'on peut oublier est un drapeau qu'on oubliera. Donc `sablier probe` et
`sablier advisories` s'arrêtent avec un message nommant quoi faire à la place, tout
conteneur est refusé puisqu'un conteneur se télécharge, et un hôte de sonde déclaré est
sauté et **écrit dans les angles morts** plutôt qu'abandonné en silence. Un site le
règle une fois pour tout le monde avec `SABLIER_AIRGAP=1`.

Le PDF n'a alors aucun navigateur à emprunter ni conteneur d'où en tirer un : il est
donc composé ici. A4, les trois polices que tout lecteur possède déjà, et un numéro de
page sur chaque page — la seule chose que l'export par navigateur ne sait pas faire,
puisque Chrome ignore le CSS qui en porterait un. Plus sobre que le HTML imprimé, et il
existe, ce qui est tout l'argument : un rapport qu'on ne peut pas imprimer ne peut être
ni signé ni classé.

Rien dans cet outil n'atteint le réseau à moins que vous ne nommiez un hôte. Les
sockets n'existent que dans quatre fichiers — `Probe.php`, `SshProbe.php` et les deux
transports — tous derrière `sablier probe` et l'étape de sonde d'une analyse, que
`--no-probe` supprime. `sablier advisories` est la seule commande qui sort, et elle sort
pour une base de vulnérabilités plutôt qu'avec votre inventaire.

Cette affirmation est épinglée par un test plutôt qu'affirmée : la liste des fichiers
autorisés à ouvrir une socket est vérifiée à chaque exécution, et la construction casse
le jour où un détecteur en acquiert une. Là où le noyau le permet, la suite lance aussi
une analyse complète avec la pile réseau retirée (`unshare -rn`) et compare le
résultat.

C'est important parce que c'est la sortie qui est sensible. Un inventaire de là où vit
la cryptographie d'un système est aussi sensible que le système lui-même : sur un
réseau fermé, la question n'est donc pas de savoir si un outil promet de ne rien
envoyer, mais s'il le *peut*. Il n'y a aucune télémétrie, aucune vérification de mise à
jour, aucune dépendance à aller chercher : quatre lignes d'autochargeur, PHP 8.4, et un
dépôt que quelqu'un peut lire en une après-midi avant de l'y porter.

## Signer un rapport, avec la signature qu'on vous dit d'adopter

```bash
sablier keygen                                   # deux clés, Ed25519 et ML-DSA-65
sablier scan /chemin --sign=sablier.key --out=rapport.html
sablier verify rapport.html.sig --declare=sablier.json
```

Pendant trois versions, cet outil a dit aux gens de migrer leurs signatures avant 2030
et a signé ses propres rapports en Ed25519 seul — et il le disait, dans ses propres
constats. La raison n'était pas la paresse : **PHP ne sait pas le faire.** libsodium
n'expose aucune signature post-quantique, et ext-openssl lit une clé ML-DSA mais refuse
de signer avec, parce que son interface prend un condensat et que ML-DSA est un schéma
pur, sans rien à pré-hacher. `openssl_sign` répond `invalid digest`.

Le **binaire** openssl, lui, sait, à partir de la 3.5, et c'est celui que la sonde
emprunte déjà. Un rapport porte donc maintenant deux signatures : Ed25519, vérifiable
partout où PHP tourne, et ML-DSA-65 en plus. Trois règles gardent cela honnête :

- **en plus, jamais à la place** — remplacer l'une par l'autre rendrait les rapports
  invérifiables pour qui a la bibliothèque plus ancienne, c'est-à-dire presque tout le
  monde. C'est aussi ce que l'ANSSI demande et ce que cet outil cite : l'hybridation ;
- **emprunté, jamais implémenté** — une signature à base de réseaux euclidiens écrite à
  la main, dans un outil dont tout le crédit tient à ce qu'il n'invente pas de
  cryptographie, serait la pire chose qu'il puisse livrer ;
- **dit à voix haute quand elle est absente** — sur un OpenSSL plus ancien, le rapport
  indique qu'il porte une seule signature et pourquoi, et `verify` distingue *ne
  correspond pas* de *n'a pas pu être vérifiée ici*. Confondre les deux transformerait
  une bibliothèque manquante en accusation de faux.

### Une clé qui signe une fois

```bash
sablier scan /chemin --sign=ephemeral --out=rapport.html
#   Clé créée pour ce rapport, utilisée une fois, détruite. Empreinte des deux clés :
#       7D52 D126 6B6B EA5D 58D4 1FE8 48D4 AFD9
sablier verify rapport.html.sig --fingerprint="7D52 D126 …"
```

`--sign=ephemeral` fabrique la paire pour ce rapport, signe, et détruit les moitiés
privées avant que la commande ne rende la main. Rien à conserver, rien à voler, rien à
faire tourner — et une clé qui ne pourra jamais signer un second document, propriété
qu'une clé de longue durée n'a pas.

Ce qui rattache alors le rapport à une personne est l'**empreinte**, pas un fichier :
une ligne, portée par un canal qui prouve déjà qui parle. Une clé publique ML-DSA fait
2,7 ko et personne ne colle ça dans un message ; seize octets de SHA-256 sur les deux
clés tiennent dans une phrase, et le destinataire confronte le fichier à cette ligne.
Les clés d'hôte SSH sont authentifiées ainsi depuis trente ans.

**Le rapport et l'empreinte ne doivent pas voyager par la même voie.** Qui peut altérer
l'un en vol peut altérer l'autre, et toute la garantie s'effondre. Le rapport par
courriel, l'empreinte par Threema ou de vive voix — pas les deux par courriel.

Le rapport d'audit imprime l'empreinte dans sa section intégrité, pour qu'un lecteur qui
tient le document des mois plus tard ait encore de quoi comparer.

Pour une clé de longue durée à la place, les deux moitiés sont reconnues par la
déclaration versionnée, `signing_public_key` et `signing_public_key_pq`. Une clé
post-quantique affirmée par le seul fichier qu'elle signe ne vaudrait rien pour le seul
lecteur pour qui cette signature existe : celui qui sait déjà forger l'autre moitié.

### Ce qui est réellement signé

**Une empreinte des constats, pas le fichier.** Deux exécutions du même inventaire
diffèrent octet par octet — une date de rendu, une durée — tout en disant exactement la
même chose ; deux rendus dans deux langues donnent la même empreinte.

**Chaque rapport nomme celui qui le précède.** Une seconde exécution vers le même chemin
de sortie lit la signature qu'elle s'apprête à remplacer et enregistre cette empreinte à
l'intérieur de ce qu'elle signe, sans drapeau à retenir — un dossier de rapports est
donc une piste d'audit et non un tas de fichiers, et `sablier verify nouveau.sig
--previous=ancien.sig` dit si le maillon tient. Un rapport qui revendique un
prédécesseur le dit même quand le fichier antérieur n'est pas sous la main : quelqu'un
qui tient un document apprend qu'un autre existe.

Avec une clé éphémère, chaque maillon est signé par une paire différente : la chaîne est
alors une suite de déclarations authentifiées séparément qui se citent, plutôt qu'une
clé qui répond de toutes. Le destinataire a besoin de chaque empreinte, et le rapport
d'audit imprime la sienne.

Il n'y a pas de chaîne de blocs ici et il n'y en aura pas. Une chaîne à soi, c'est un
nœud, c'est-à-dire une personne : pas plus digne de confiance que la signature qu'elle
remplacerait. Une chaîne publique veut dire que l'empreinte quitte la machine, ce qui
casse la promesse du pied de page du rapport. Quand une date doit être opposable à
quelqu'un qui ne vous fait pas confiance, une autorité d'horodatage y répond en une
requête.

### Signer l'entrée, pas seulement la sortie

Un rapport est signé, vérifié, chaîné — et les durées sur lesquelles repose
chacun de ses verdicts étaient une chaîne de caractères que n'importe qui pouvait
taper dans `declared_by`. Le seul artefact ici qui engage des personnes était le
seul que personne ne signait.

```bash
sablier endorse sablier.json         # clé éphémère, détruite avant le retour
sablier verify sablier.json.sig --declare=sablier.json
```

Ce qui est signé, ce sont les **décisions et pas les octets** : le régime, les
durées, les chemins, les trust anchors, les notes et les auteurs, domaines et
chemins triés. Remettre le fichier en forme, réordonner ses clés, retailler une
note — l'endossement tient. Corriger une durée, ajouter un chemin, changer de
régime — il casse, et c'est ce qu'attend quelqu'un qui a endossé ce fichier.

Le rapport d'audit imprime alors l'une de trois choses, dans la section même qui
reproduit les durées : endossée à telle date, avec l'empreinte des clés ; **non
signée**, avec la commande qui y remédie ; ou — le cas intéressant — une signature
qui ne correspond plus, c'est-à-dire que le fichier sur lequel ce rapport repose
n'est pas celui que quelqu'un a contresigné.

La clé est éphémère par défaut, comme celle des rapports. Une déclaration endossée
à la fin d'un entretien, devant la personne qui l'a déclarée, est exactement le
cas pour lequel cette clé a été inventée : rien à stocker, rien à renouveler, et
l'empreinte voyage par le canal qui prouve déjà qui elle est.

## Les trois conteneurs, et ce qui est affirmé à leur sujet

Un outil qui lit où sont vos clés n'a pas à vous dire de lancer des images qu'il n'a pas
regardées. Trois sont nommées dans ce dépôt — `php:8.4-cli-alpine` pour les machines
sans PHP, `ghcr.io/phpstan/phpstan` pour l'analyse statique, et le scanner lui-même — et
une commande les revérifie toutes les trois :

```bash
make cve
```

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

## Ce que l'outil refuse de faire

- **Deviner.** Un algorithme venant d'une variable est rapporté comme indéterminé, avec
  son emplacement. Un inventaire faux est pire qu'un inventaire incomplet, parce que
  personne ne vérifie un inventaire deux fois.
- **Prédire.** La date de péremption utilisée est l'échéance réglementaire (2035 par
  défaut, configurable), pas une prophétie sur l'arrivée d'un ordinateur quantique.
- **Crier.** La cryptographie symétrique forte est rapportée comme conforme, une
  signature n'est pas traitée comme une fuite, un `md5()` servant de clé de cache est
  classé hors sujet, et une dépendance déclarée n'est jamais une alerte rouge — c'est un
  usage à confirmer.
- **Corriger tout seul.** Réécrire de la cryptographie sans comprendre le contexte est
  un générateur d'incidents.
- **Partir.** Aucun compte, aucun téléversement, aucune télémétrie, aucune dépendance.

## Ce qu'il ne voit pas

Le rapport imprime ses propres angles morts, à la même taille que tout le reste : la
cryptographie des services managés, la négociation TLS réelle des hôtes non déclarés,
les clés détenues dans un HSM, et les durées de vie que personne n'a déclarées.

Un inventaire qui ne dit pas ce qu'il n'a pas regardé n'est pas un inventaire.

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
