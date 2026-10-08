# Après une fuite

*← retour au [README](../README.fr.md)*

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
