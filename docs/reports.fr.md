# Ce que disent les rapports, et à qui ils s'adressent

*← retour au [README](../README.fr.md)*

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

## Composer le rapport en PDF

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
