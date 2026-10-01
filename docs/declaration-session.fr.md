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

## À distance

La séance marche aussi quand la personne n'est pas dans la pièce, et il y a
trois façons de faire, par ordre de ce qu'elles coûtent à la promesse de
l'outil.

**1. Partage d'écran, et c'est elle qui clique.** Vous partagez, vous lui
donnez le contrôle, elle répond. Rien à exposer, rien à configurer, et les
temps mesurés sont les siens. C'est la réponse par défaut, et pour une
première séance c'est la bonne.

**2. Partage d'écran, et c'est vous qui tapez.** Plus simple à organiser, et
il faut savoir ce qu'on perd : vous reformulez en tapant, et le chronomètre
mesure votre frappe autant que son hésitation. À réserver aux cas où le
contrôle à distance n'est pas possible, et à noter sur la feuille.

**3. Un tunnel jusqu'à votre machine.** Le serveur reste chez vous, le trafic
passe chiffré, et la personne ouvre un lien :

```bash
# sur votre machine : le serveur reste sur la boucle locale, le tunnel le porte
sablier serve /chemin/du/projet --expose --public=https://audit.exemple.org

# puis un tunnel vers une machine que vous contrôlez, qui proxifie ce nom
ssh -N -R 8765:127.0.0.1:8765 vous@votre-serveur
```

`--expose` existe parce que l'adresse d'écoute juge mal l'exposition : derrière
un tunnel et un proxy, le serveur ne quitte jamais la boucle locale et le lien
est public quand même. Il génère **une clé** et la met dans le lien — sans
elle, c'est 403 — et `--public` affiche l'adresse exacte à transmettre, pour que
personne ne retape un nom d'hôte devant un client. Ce n'est pas de
l'authentification : qui a le lien peut répondre. C'est assez pour qu'un
entretien qui écrit une déclaration et lance une analyse ne soit pas ouvert à
qui devine le nom.

Terminez le TLS sur la machine qui tient le tunnel — la clé voyage dans le
lien, et un outil dont le sujet est la cryptographie ne distribue pas une
adresse en `http://`. C'est l'en-tête `X-Forwarded-Proto` du proxy qui dit au
serveur de marquer son cookie `Secure`. Avec Tailscale ou un tunnel Cloudflare,
c'est la même forme avec moins à configurer.

Trois règles si vous prenez cette voie : ne diffusez le lien qu'à la personne
interrogée, arrêtez le serveur à la fin de la séance (Ctrl-C), et n'exposez
jamais la machine d'un client — c'est la vôtre qui sert, et c'est elle qui
écrit les fichiers.

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

Quatre sujets, dans l'ordre où l'entretien les soulève. Comptez vingt-cinq
minutes, quarante avec le rapport lu devant la personne.

| # | Sujet | Ce que la personne verra |
|---|---|---|
| 1 | 5 endroits — `src/Billing`, `src/Entity`, `src/Feedback`, `src/Identity`, `src/Security` | une empreinte calculée sur un contenu |
| 2 | `.env`, `.env.dev`, `.env.test` | des réglages lus au démarrage : à qui l'application se connecte, avec quel compte et quel mot de passe |
| 3 | `composer` | du chiffrement à clé publique — pour que seul le destinataire puisse relire, ou pour protéger une sauvegarde |
| 4 | `config/secrets` | un coffre à secrets — mots de passe, clés, jetons, chiffrés, qui protège tout le reste |

L'ordre vient du nombre de fichiers, pas de l'importance : le sujet qui en
couvre le plus passe en premier. Le premier est donc le plus abstrait des
quatre, et c'est un mauvais tirage — si la personne décroche là, notez-le,
c'est la règle de tri qu'il faudra revoir et pas la question.

Les deux images mal nommées n'y sont **délibérément pas** : un `.png` qui est
un JPEG est une confirmation de développeur, pas une décision métier.

### Le sujet qui couvre cinq endroits

Il y avait huit sujets la semaine dernière, dont cinq posaient exactement la
même question dans cinq dossiers différents. L'entretien les regroupe
maintenant : une description, une question, et les cinq endroits nommés sous le
formulaire. La déclaration écrite à la fin couvre les cinq chemins d'un seul
domaine.

Ce qu'il faut écouter, parce que c'est le point que la séance doit trancher :

- elle répond **une seule chose** (« des jetons », « des empreintes de
  fichiers ») → le regroupement est juste, et il n'y a rien à changer ;
- elle hésite et dit **« ça dépend des endroits »** → le regroupement est trop
  grossier, il faut redécouper, et c'est elle qui vient de nous dire comment.

Notez ses mots, pas seulement sa conclusion.

### La ligne à surveiller

Le coffre, sujet 4. Un passage à blanc répondant « vingt ans » à la question du
tort fait basculer ce constat en **COMPROMIS** et place sa date de bascule à
*déjà franchie* — un rapport qui passe d'aucun rouge à un rouge, sur la foi
d'une phrase dite à voix haute. L'arithmétique n'est pas la partie
intéressante. Ce qu'elle dit avant de donner le chiffre, si.
