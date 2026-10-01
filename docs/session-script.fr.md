# Conduire l'entretien — aide-mémoire

Une page à avoir sous les yeux pendant la séance. Le protocole et ce qu'il faut
mesurer sont dans [`declaration-session.md`](declaration-session.md) ; ceci est
le script.

```bash
sablier declare /chemin/du/projet --log=session.json
```

## Ce que la personne entend

L'outil ouvre chaque sujet par ce qu'il a trouvé, sans un mot technique, puis
pose trois questions. Exemple réel :

> **Sujet 1 sur 4 · 3 fichiers**
>
> Ici, l'application garde des réglages qu'elle lit au démarrage : à qui elle se
> connecte, avec quel compte, et avec quel mot de passe. Ce n'est pas chiffré —
> c'est un fichier de configuration.
> *Dans : .env, .env.dev, .env.test*
>
> 1. **Si quelqu'un en obtenait une copie, de quoi parlerait-on, dans vos mots ?**
> 2. **Combien d'années devez-vous garder ça ?** (une loi, un contrat, ou votre propre règle ; 0 si rien ne l'impose)
> 3. **Si ça sortait aujourd'hui, pendant combien d'années est-ce que ça ferait encore du tort ?** (0 si c'est public ou sans conséquence)

La durée retenue est **la plus grande des deux** — une donnée qu'on garde est
une donnée qu'on peut encore voler — et l'outil dit laquelle a gagné, pour
qu'on puisse contester le raisonnement plutôt que le chiffre.

## Quand ça coince

| Ce qu'elle dit | Ce que vous répondez |
|---|---|
| « Je ne sais pas. » | « Qui le saurait, dans la maison ? » Notez le nom, passez le sujet. **Un sujet passé est un résultat**, pas un échec. |
| « Pour toujours. » | « Est-ce qu'une loi ou un contrat le dit ? » Sinon : « Dans trente ans, est-ce que ça gêne encore quelqu'un ? » Un nombre, même grand, vaut mieux qu'un mot. |
| « Ça ne sortira jamais. » | « D'accord — la question est : *si* ça sortait. » Ne négociez pas ce point, c'est toute la méthode. |
| « Trois mois. » | Arrondissez à 1 an, ou mettez 0 si c'est vraiment éphémère. Dites-le à voix haute. |
| « C'est toi l'expert, tu mettrais quoi ? » | « Je ne peux pas répondre à votre place : c'est exactement l'information que l'outil ne sait pas lire. » **C'est le piège qui annule la mesure.** |
| Un chiffre qui vous paraît faux | Ne corrigez pas. **Notez le désaccord** : c'est la minute la plus instructive de la séance. |
| « Pourquoi vous me demandez ça ? » | « Parce que c'est la seule chose qu'aucun outil ne peut deviner, et qu'elle change le verdict du rapport. » |

## Ce qu'il ne faut pas faire

- **Répondre à sa place.** Une durée que vous avez soufflée ne mesure rien.
- **Justifier l'outil.** Si une question est mal comprise, c'est une donnée à
  noter, pas un malentendu à réparer.
- **S'excuser des questions.** Elles sont courtes et elles sont les bonnes.
- **Enchaîner.** Laissez le silence : les hésitations sont chronométrées, et
  c'est elles qu'on mesure.

## À la fin, devant elle

```bash
sablier scan /chemin/du/projet --out=apres.html --audit=audit.html
```

Ouvrez le rapport d'avant et celui d'après côte à côte, et montrez ce qui a
bougé. Si rien n'a bougé, dites-le : ça veut dire que les durées par défaut
étaient déjà justes, et c'est une information.

Trois phrases pour conclure, dans cet ordre :

1. « Voilà ce que votre heure a produit : *tel* verdict a changé. »
2. « Ce fichier est relisable et versionné — vous pouvez le contester plus tard. »
3. « Ce qui reste sans réponse est écrit comme tel dans le rapport : on n'a rien inventé à votre place. »

## La feuille

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
