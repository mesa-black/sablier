# Signer un rapport, et le dater

*← retour au [README](../README.fr.md)*

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

**Et la page, à côté.** Cette empreinte ne peut pas couvrir la page qui l'affiche —
un fichier qui imprime sa propre signature devrait la contenir avant qu'elle soit
calculée —, si bien que jusqu'à la 0.13.1 un rapport publié et modifié à la main se
vérifiait encore. Chaque page est désormais aussi signée telle qu'elle est, une fois
écrite : `report.html.page.sig` à côté de `report.html`, et de même pour le document
d'audit, le document post-compromission et les PDF quand ils sont demandés. Ce qui est
signé est le SHA-256 du fichier exact — une empreinte qui change complètement dès qu'un
seul caractère change —, avec la même clé et les deux mêmes schémas, et la signature
nomme l'empreinte des constats que la page affiche. Comme c'est un fichier à part, elle
n'a pas à se trouver dans la page, et le problème de l'autoréférence disparaît.

```bash
sablier verify report.html.sig --declare=sablier.json    # les constats, puis la page
sablier verify audit.html.page.sig --declare=sablier.json # une page seule
```

`verify` sur le `.sig` d'un rapport vérifie le `.page.sig` posé à côté quand il existe,
avec les mêmes clés, et donne la taille de la page en octets. Une page qui ne correspond
plus échoue, avec le mot *modifiée* et la taille signée face à la taille actuelle (depuis
la 0.13.2 la taille est dans ce qui est signé, `sablier-page/2` ; les fichiers de la
0.13.1, `sablier-page/1`, se vérifient toujours) ;
une signature de page faite par une autre clé, sur d'autres constats, ou sans la moitié
post-quantique que porte la signature des constats, échoue aussi. Un rapport antérieur à
la 0.13.1 n'en a pas, et on le lui dit — une remarque, pas un échec. Ce qu'aucune
signature n'empêche : qui détient la clé peut signer une autre page ; c'est à cela que
servent la clé déclarée et les dates attestées ci-dessous. Contrairement à la signature
des constats, une signature de page n'est pas conservée d'une exécution à l'autre : une
page porte la date de son rendu, donc une nouvelle page reçoit une nouvelle signature
(elle n'est gardée que si le fichier est identique).

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

Il n'y a pas de blockchain ici et il n'y en aura pas. Une chaîne à soi, c'est un
nœud, c'est-à-dire une personne : pas plus digne de confiance que la signature qu'elle
remplacerait. Une chaîne publique veut dire que l'empreinte quitte la machine, ce qui
casse la promesse du pied de page du rapport. Quand une date doit être opposable à
quelqu'un qui ne vous fait pas confiance, une autorité d'horodatage y répond en une
requête — c'est la section suivante.

### Une date attestée par quelqu'un d'autre

Toutes les signatures ci-dessus prouvent deux choses et pas une troisième : **quelle
clé a signé, et quels constats elle a signés.** Le champ `signed_at` est couvert par la
signature, donc il n'est pas modifiable après coup — et il est lu sur l'horloge de la
machine qui a signé, la vôtre. Antidater un rapport ne coûte rien, et le chaînage n'y
change rien : une seule clé tient tous les maillons, donc la chaîne entière peut être
reconstruite dans l'ordre et se vérifiera parfaitement. Ces sceaux répondent à *qui* et
à *quoi*. Rien en eux ne répond à *quand*.

```bash
sablier scan . --sign=sablier.key --timestamp=https://tsa.exemple.org/tsr
```

Une autorité d'horodatage reçoit l'empreinte, jamais le document, et renvoie un jeton
signé disant que cette empreinte lui a été présentée à cet instant. Elle n'a aucun
intérêt dans vos conclusions, et c'est tout l'intérêt.

**C'est l'empreinte qui est attestée** — pas la signature, pas le fichier. Elle est
imprimée dans le rapport, donc l'attestation se vérifie sans aucune référence à cet
outil :

```bash
openssl ts -verify -digest <l'empreinte imprimée dans le rapport> \
  -in report.html.tsr -CAfile <la racine de l'autorité>
```

C'est aussi pourquoi le jeton est un fichier à part, en DER brut à côté du `.sig` :
c'est exactement ce que lit la commande `openssl ts` d'origine. Et il survit à une clé
éphémère — la clé est détruite, la date attestée non.

**Il n'y a pas d'autorité par défaut.** Qui atteste vos dates est une décision, comme
le régime et les durées, et un défaut la prendrait pour vous dans une juridiction que
vous n'avez pas choisie. L'option prend une URL ou ne fait rien.

`sablier verify` ramasse le jeton tout seul quand il est déposé à côté de la signature,
et rapporte quatre états plutôt que deux, parce que les confondre serait mentir :

| | sens |
|---|---|
| date attestée, vérifiée | la signature de l'autorité tient, jusqu'à une racine de confiance de cette machine |
| date attestée, chaîne non vérifiée | l'empreinte correspond à ce rapport ; aucune chaîne vers une racine de confiance n'a pu être construite — autorité auto-signée ou intermédiaire manquant, pas une falsification. Passez `--timestamp-ca=<fichier>` |
| invalide | le jeton atteste une autre empreinte, ou il a été modifié. Cela fait échouer la commande |
| invérifiable ici | pas d'openssl, ou aucun magasin de certificats pour vérifier |

L'empreinte est comparée **avant** toute question de confiance, et cet ordre est le
point : `openssl ts -verify` s'arrête sur une chaîne qu'il ne sait pas construire, donc
sans cette comparaison « je n'arrive pas à établir la chaîne » et « ce jeton parle d'un
tout autre document » revenaient comme la même réponse.

**La limite, imprimée dans le rapport plutôt que laissée à découvrir.** Une autorité
d'horodatage signe en RSA ou en ECDSA, que le catalogue de cet outil classe comme
vulnérables au quantique. Un jeton est une preuve pour un litige dans les prochaines
années, pas pour 2040 ; conserver une date au-delà veut dire la réattester tant que le
schéma tient. Un outil qui passe quarante pages à dire que les signatures périment ne
s'accorde pas une exception pour celle dont il dépend.

### Une date qu'il n'est besoin de croire de personne

Un jeton répond à *quand* par la parole de quelqu'un, signée avec un schéma qui
expire. Une preuve OpenTimestamps y répond par l'arithmétique :

```bash
sablier scan . --sign=sablier.key --anchor=opentimestamps
```

L'empreinte que les jetons attestent est ancrée dans la chaîne Bitcoin, et
`report.html.ots` est écrit à côté de la signature : une suite d'opérations SHA-256
qui mène de l'empreinte à la racine de Merkle d'un bloc. La vérifier, c'est
recalculer ces empreintes et comparer le résultat à trente-deux octets d'un en-tête
de bloc que des milliers de machines indépendantes détiennent. Ni signature, ni
certificat, ni autorité — et le client officiel lit le fichier :

```bash
pip install opentimestamps-client
ots verify -d <l'empreinte affichée dans le rapport> report.html.ots
```

**Ici il y a un défaut**, alors que `--timestamp` n'en a pas, et la différence en est
la raison. Une autorité RFC 3161 *est* la preuve : la choisir, c'est choisir qui
croire. Un calendrier OpenTimestamps ne l'est pas : il agrège des empreintes et paie
une transaction Bitcoin, et la preuve qu'il rend se vérifie sans lui, contre la
chaîne. Un calendrier ne peut pas rendre une date fausse — un chemin qui ne mène pas
à un vrai bloc ne se vérifie pas — et au pire il échoue à ancrer. `opentimestamps`
désigne donc les calendriers qu'utilise le client officiel (tenus par trois
opérateurs différents), et des URL explicites marchent aussi, répétables ou séparées
par des virgules :

```bash
sablier scan . --sign=sablier.key --anchor=opentimestamps,https://calendar.example.org
```

Ce que reçoit un calendrier n'est pas l'empreinte mais l'empreinte de l'empreinte
suivie de seize octets aléatoires, comme le fait le client officiel : l'empreinte est
imprimée dans un rapport qui peut être public, et envoyée telle quelle elle
permettrait aux journaux d'un calendrier de relier ce rapport à l'adresse qui l'a
soumis. L'aléa est dans la preuve.

**Ce n'est pas immédiat.** Un calendrier met ses empreintes dans une transaction
toutes les quelques heures ; tant que cette transaction n'est pas dans un bloc, la
preuve est *en attente* et dit seulement quels calendriers interroger.
`sablier verify` les interroge, et quand le bloc existe il complète la preuve et
réécrit le `.ots` — la seule écriture que fait jamais cette commande, et seulement
quand le fichier a gagné une attestation Bitcoin. Une preuve seule, sans la
signature, se complète et se vérifie de la même façon :

```bash
sablier anchor report.html.ots
```

Les règles sont celles des jetons : refusé sous `--airgap`, bruyant sur stderr et non
fatal quand aucun calendrier ne répond (aucun `.ots` n'est écrit, donc le rapport
n'affirme rien), et **l'ancrage le plus ancien est conservé** : une preuve qui couvre
déjà cette empreinte est complétée sur place, jamais remplacée par une plus récente.

**D'où vient l'en-tête de bloc, et pourquoi on ne le croit pas.** Vérifier une
attestation Bitcoin demande l'en-tête du bloc qu'elle nomme. Par ordre de préférence :
un nœud Bitcoin Core à vous, quand `SABLIER_BITCOIN_RPC` en nomme un
(`http://user:password@host:8332`) ; sinon deux explorateurs tenus par des
entreprises différentes, blockstream.info et mempool.space, qui doivent rendre les
mêmes 80 octets — un désaccord fait échouer la vérification bruyamment ; sur un site
fermé, l'en-tête recopié à la main, `--block-header=<160 caractères hexadécimaux>`.

Aucun n'est cru. On ne croit pas l'explorateur, on vérifie ce qu'il donne :

- la racine de Merkle de l'en-tête doit être l'engagement que calcule la preuve ;
- le double SHA-256 de l'en-tête doit être inférieur ou égal à la cible que déclare
  son propre champ `nBits` — n'importe qui peut écrire un en-tête, seul le minage en
  produit un dont l'empreinte est aussi petite ;
- et cette cible doit être inférieure ou égale à un plancher tiré de vrais blocs de
  la chaîne principale, un par an depuis 2015, le dernier du 14/11/2026 — un en-tête
  peut déclarer une cible triviale et l'atteindre en une seconde, et c'est ce qui le
  refuse. Le plancher est le plus strict de l'époque de la hauteur et de l'époque de
  l'heure que porte l'en-tête, et une heure que sa hauteur ne permet pas est refusée
  d'emblée : les deux sont écrites par le faussaire, aucune ne choisit seule la
  difficulté.

Une source qui mentirait devrait donc miner un bloc à une difficulté proche de celle
de son époque ; pour toute preuve que fait cet outil, celle de novembre 2026. Ce que
la vérification du travail n'établit pas, c'est que le bloc est dans la chaîne que
tout le monde suit : l'accord de deux explorateurs, ou votre propre nœud, couvre
cette moitié. Et le plancher est la difficulté d'une époque : une preuve qui
revendique une hauteur très ancienne ne coûte à forger que ce que coûtait le minage
d'un bloc cette année-là.

**Les limites.** Elle prouve *quand* — au plus tard ce bloc — et rien sur *qui* :
c'est le rôle de la signature. Face à un ordinateur quantique, la preuve elle-même
n'est faite que d'empreintes (SHA-256, parfois RIPEMD-160) : l'algorithme de Grover
divise leur marge par deux sans les casser, si bien qu'à la différence des jetons
elle n'expire pas avec RSA. Que la chaîne Bitcoin garde son consensus à travers cette
transition — son minage, ses signatures — est hors de ce que la preuve peut dire.

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
