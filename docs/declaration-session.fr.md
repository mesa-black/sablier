# La séance de déclaration

*[English](declaration-session.md) · [Español](declaration-session.es.md) —
l'aide-mémoire à avoir en main pendant la séance est
[ici](session-script.fr.md).*

La seule expérience qui peut tuer ce projet, menée exprès plutôt que par
accident.

Chaque verdict de chaque rapport repose sur un nombre qu'aucun scanner ne sait
lire : combien de temps chaque catégorie de donnée doit rester confidentielle.
L'étude de cadrage le dit, et dit ce qui falsifierait la thèse — *la personne
n'arrive pas à répondre à « combien de temps ça doit rester secret » pour la
plupart de ses domaines*. Tant qu'une séance n'a pas eu lieu en dehors de ce
dépôt, c'est une opinion.

Cette page existe pour rendre la séance mesurable, et elle est écrite **avant**
la première, pour que le résultat ne puisse pas être rationalisé après coup.

## Ce qu'on mesure, décidé d'avance

| | Quoi | Qui l'enregistre |
|---|---|---|
| **Le temps** | Le total, et le temps par sujet. L'hésitation *est* la mesure, et demander à quelqu'un de se chronométrer pendant qu'il réfléchit, c'est l'empêcher de réfléchir. | l'outil, avec `--log` |
| **L'assurance** | Répondu sans hésiter, répondu après discussion, ou bloqué. Les secondes par sujet sont un bon indice ; la croix est votre jugement. | vous |
| **Les désaccords** | Chaque fois que la réponse contredit ce qu'on aurait supposé. Les minutes les plus instructives de la séance : elles disent que nos valeurs par défaut sont fausses, et elles ne se devinent pas depuis un bureau. | vous |

```bash
sablier declare /chemin/du/projet --log=session.json
```

Le journal contient, par sujet : le nom donné par la personne, les deux
chiffres, la durée qui en découle, les sujets passés et les secondes passées
dessus. Un chiffre retranscrit après coup est un chiffre arrondi vers le
résultat qu'on espérait.

## Ce qui falsifierait la thèse

Si la plupart des sujets finissent **bloqués**, le problème n'est pas l'outil et
aucun détecteur supplémentaire n'y changera rien. Il faudrait poser la question
autrement — en partant d'ailleurs, ou avec quelqu'un d'autre — et c'est le
produit qui doit changer, pas la documentation.

L'enregistrer honnêtement est tout l'intérêt. Une séance qui ne produit qu'une
déclaration remplie ne prouve rien ; une séance qui produit trois blocages sur
six apprend plus qu'un mois de travail.

## Le déroulé

**Avant**, seul, dix minutes :

```bash
sablier scan /chemin/du/projet --out=avant.html
```

Gardez ce rapport : c'est la comparaison d'« après », et les zones qu'il liste
comme non déclarées sont les questions que l'entretien posera.

**Pendant**, avec la personne :

```bash
sablier declare /chemin/du/projet --log=session.json
```

L'entretien avance sujet par sujet. Chacun s'ouvre sur une description en
français courant de **ce que l'outil a trouvé là** — un coffre à secrets, des
réglages lus au démarrage, une empreinte calculée sur du contenu — avec les
noms de fichiers en dessous pour qui les connaît. Aucun nom d'algorithme,
aucun chemin en titre : un premier passage à blanc affichait « `.env` —
cryptographie relevée : Aucun chiffrement », ce qui perd une personne non
technique en deux lignes et emporte la séance avec elle.

Puis trois questions, dont aucune n'est une durée de confidentialité :

- **si quelqu'un en obtenait une copie, de quoi parlerait-on, dans vos mots ?**
  La réponse nomme le domaine, et c'est la sienne, pas la nôtre ;
- **combien d'années devez-vous garder ça ?** La conservation est un fait légal
  que quelqu'un connaît déjà — une obligation comptable, un règlement, un
  contrat. Personne n'hésite là-dessus ;
- **si ça sortait aujourd'hui, pendant combien d'années ça ferait encore du
  tort ?** En général plus court que la conservation. Parfois beaucoup plus
  long, et cet écart vaut à lui seul la séance.

La durée retenue est la plus grande des deux, parce qu'une donnée qu'on doit
garder est une donnée qu'on peut encore voler. L'outil dit laquelle des deux a
gagné, pour qu'on puisse contester le raisonnement plutôt que le chiffre.

Deux règles pour qui mène la séance :

- **ne répondez pas à sa place.** La tentation est énorme, surtout sur du code
  que vous avez écrit. Une durée que vous avez soufflée ne mesure rien ;
- **laissez passer.** Un sujet sans réponse reste non déclaré et sera calculé
  avec la durée par défaut, ce que le rapport écrit dans ses angles morts.
  C'est un résultat, pas un échec — et c'est précisément celui qui falsifie la
  thèse.

**Après**, devant elle :

```bash
sablier scan /chemin/du/projet --out=apres.html --audit=audit.html
```

Ouvrez les deux rapports côte à côte. Les verdicts qui ont bougé sont ce que
son heure a produit — et si rien n'a bougé, dites-le : ça veut dire que les
valeurs par défaut étaient déjà justes, et c'est bon à savoir.

## La feuille

Recopiez-la, remplissez-la pendant la séance, gardez-la avec la déclaration.

```
Projet :                        Date :
Personne :                      Son métier :
Durée totale :                  minutes

Sujet                  Nom donné            Conservation  Tort  Durée  Sûre / Discutée / Bloquée
─────────────────────  ───────────────────  ────────────  ────  ─────  ─────────────────────────

Désaccords avec ce qu'on aurait supposé :
  ·

Ce qu'elle a demandé et que l'outil n'a pas su dire :
  ·

Verdicts qui ont bougé entre avant.html et apres.html :
  ·
```

## Show me the REX, première séance

Quatre sujets, dans l'ordre où l'entretien les soulève. Comptez vingt minutes.

| Sujet | Ce que la personne verra |
|---|---|
| `.env`, `.env.dev`, `.env.test` | des réglages lus au démarrage : à qui l'application se connecte, avec quel compte et quel mot de passe |
| `config/secrets` | un coffre à secrets — mots de passe, clés, jetons, chiffrés, qui protège tout le reste |
| `src/Feedback` | une empreinte calculée sur du contenu |
| `src/Identity` | une empreinte dans l'échange OAuth |

Les deux images mal nommées n'y sont **délibérément pas** : un `.png` qui est
un JPEG est une confirmation de développeur, pas une décision métier, et y
passer une des vingt minutes serait gâcher la seule heure qui compte.

Le coffre est la ligne à surveiller. Un passage à blanc répondant « quinze ans »
à la question du tort fait basculer ce constat en **COMPROMIS** et place sa date
de bascule à *déjà franchie* — un rapport qui passe d'aucun rouge à un rouge,
sur la foi d'une phrase dite à voix haute. L'arithmétique n'est pas la partie
intéressante. Ce qu'elle dit avant de donner le chiffre, si.
