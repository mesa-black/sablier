# Déclarer les durées de confidentialité

*← retour au [README](../README.fr.md)*

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

## Quel pays vous audite, ce qui n'est pas quelle échéance vous retenez

Deux questions différentes, et elles partageaient un seul champ. Un **régime**
répond à *quand cette cryptographie périme* — emprunté à l'autorité que le
déclarant accepte, et c'est pourquoi une entité allemande est parfaitement libre
de retenir le 2030 de l'ANSSI. Une **juridiction** répond à *quelle transposition
nationale va m'auditer*. `hds` était la preuve que les deux étaient emmêlées :
l'hébergement de données de santé français, rangé à côté du CNSA 2.0 de la NSA.

```jsonc
// sablier.json
{ "regime": "eu", "jurisdiction": "fr" }
```

Un code ISO à deux lettres, et il est **déclaré, jamais déduit de `--lang`** — les
documents le disent en toutes lettres. Une langue n'est pas un pays : un rapport
en anglais pour une entité allemande, un rapport en espagnol pour la filiale
mexicaine d'un groupe belge. Lire la juridiction dans la langue du lecteur serait
exactement l'hypothèse silencieuse que cet outil refuse partout ailleurs.

Ce que la couche européenne apporte est identique pour les vingt-sept, et le
document d'audit le nomme désormais : **directive (UE) 2022/2555**, du 14 décembre
2022, JO L 333/80, à transposer *« by 17 October 2024 »* selon son article 41, et
dont l'article 21 §2 h) range parmi les mesures de gestion du risque *« policies
and procedures regarding the use of cryptography and, where appropriate,
encryption »*. C'est l'obligation que cet inventaire sert, et elle vaut quel que
soit l'avancement de chaque transposition — plusieurs sont encore inachevées.

**Sablier connaît les vingt-sept États membres.** Déclarez `jurisdiction: de`
et le document d'audit imprime l'autorité allemande, son portail d'enregistrement
et la date à laquelle chacun a été relevé ; déclarez `jurisdiction: pl` et il
imprime celle de la Pologne. Ce qu'il connaît pour chacun, c'est l'autorité
nationale de cybersécurité que publie l'ENISA, et la date de ce relevé.

Quatre États membres en disent davantage aujourd'hui, chacun lu sur le site de sa
propre autorité : la **France**, son référentiel — le ReCyF — et le portail par
lequel les entités s'enregistrent ; l'**Allemagne**, sa loi de transposition, en
vigueur depuis le 6 décembre 2025, et le portail du BSI ; la **Belgique**, le
référentiel CyberFundamentals, que le CCB recommande à toutes les entités NIS 2
parce qu'une implémentation validée donne une présomption de conformité ; et
l'**Espagne**, le fait que sa transposition est encore un avant-projet de loi, et
que l'INCIBE écrit elle-même que les autorités compétentes et le point de contact
unique doivent l'attendre.

Les vingt-trois autres impriment leur autorité et rien à côté. Cela veut dire que
personne n'a encore lu leur site — pas qu'il n'y a rien à y lire.

Ce qu'il ne conserve **délibérément pas**, c'est un statut de transposition.
Les pages pays de la Commission donnaient un état des lieux de mi-2025, plusieurs
États membres ont bougé depuis, et un statut figé dans une release est un fait
réglementaire qui périme entre deux versions de cet outil et se lit pourtant
comme courant. Les documents citent donc la page vivante de la Commission — une
seule adresse pour les vingt-sept, qui se met à jour d'elle-même — au lieu d'en
recopier un verdict.

Deux choses de plus sont imprimées pour chaque État membre. La date à laquelle le nom de l'autorité a
été relevé, pour la raison même qui fait exister `deadlines_checked_on` : un fait
réglementaire sans date est un fait que personne ne peut faire vieillir. Et une
réserve, parce que plusieurs États membres désignent aussi des autorités
sectorielles : c'est la porte par laquelle on commence, pas nécessairement celle
qui vous audite.

Une juridiction déclarée hors de l'Union — `ch`, `uk`, `us` — n'a pas de ligne,
et le document le dit plutôt que d'attraper l'agence la plus plausible.

Et cet inventaire n'est pas un rapport de conformité NIS 2. Il produit l'une des
mesures que la directive demande. L'enregistrement auprès de l'autorité et la
déclaration des incidents sont des obligations qui pèsent sur l'entité, et
l'outil ne dit rien ni de l'une ni de l'autre.

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
