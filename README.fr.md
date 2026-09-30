# Sablier

*English: [README.md](README.md)*

Ce qui est chiffré chez vous, et **jusqu'à quand ça tient**.

Sablier lit un projet, inventorie sa cryptographie, et croise cet inventaire avec
une information qu'aucun outil ne possède : **combien de temps chaque donnée doit
rester confidentielle.** De ce croisement sort la seule question qui compte
aujourd'hui sur le post-quantique :

> Une donnée chiffrée aujourd'hui avec RSA ou une courbe elliptique, et qui doit
> rester secrète au-delà de la péremption de ces algorithmes, **est déjà perdue**.
> La migration protégera ce qui viendra après, pas elle.

C'est le modèle *récolte maintenant, déchiffrement plus tard* : un adversaire
capture aujourd'hui ce qu'il déchiffrera plus tard. Pour la donnée concernée, la
date de compromission est le jour du chiffrement, pas le jour de l'attaque.

État : **prototype**. Le cadrage complet — problème, état de l'art, limites
assumées, modèle de risque — est dans [`docs/cadrage.fr.md`](docs/cadrage.fr.md).

## Essayer

```bash
make demo                                   # jeu d'essai + rapport
make scan DIR=/chemin/vers/projet           # un vrai projet
make test                                   # le modèle discrimine-t-il encore ?
```

Le rapport est un fichier HTML autonome : aucune police distante, aucun script,
aucune requête. Un outil qui lit là où sont les clés ne doit pas ouvrir de socket
pour afficher son propre résultat.

## Déclarer ses durées de confidentialité

Sans déclaration, l'outil applique une durée par défaut et le dit. Avec, il
devient utile. Voir [`examples/showmetherex.json`](examples/showmetherex.json).

```json
{
  "expiry_year": 2035,
  "domains": {
    "sauvegardes": { "paths": ["deploy/backup.sh"], "lifetime_years": 10 },
    "contenu public": { "paths": ["templates/*"], "lifetime_years": 0 }
  }
}
```

Ce fichier est le seul artefact du projet qui engage des humains plutôt qu'une
machine. Il se relit, il se discute, il se versionne.

## Ce que l'outil refuse de faire

- **Deviner.** Un algorithme qui vient d'une variable est signalé comme
  indéterminé, avec son emplacement. Un inventaire faux est pire qu'un
  inventaire incomplet : personne ne le vérifie deux fois.
- **Prédire.** La date de péremption employée est l'échéance réglementaire
  (2035 par défaut, paramétrable), pas une prophétie sur l'arrivée d'un
  calculateur quantique.
- **Crier.** Le symétrique fort est déclaré conforme, une signature n'est pas
  traitée comme une fuite, un `md5()` en clé de cache est rangé hors sujet, et
  une dépendance déclarée n'est jamais une alerte rouge — c'est un usage à
  confirmer.
- **Corriger tout seul.** Réécrire de la cryptographie sans comprendre le
  contexte est un générateur d'incidents.
- **Sortir.** Aucun compte, aucun envoi, aucune télémétrie, aucune dépendance.

## Ce qu'il ne voit pas

Le rapport imprime lui-même ses angles morts, à la même taille que le reste :
cryptographie des services gérés, négociation TLS réelle à l'exécution, clés en
HSM, et la durée de vie des données quand personne ne l'a déclarée.

Un inventaire qui ne dit pas ce qu'il n'a pas regardé n'est pas un inventaire.

## Premiers résultats

Premier scan sur un vrai projet (Show me the REX, ~1 900 fichiers) : 15 constats,
dont **zéro alerte rouge** — et deux enseignements qui ont immédiatement changé
l'outil.

1. Le chiffrement des sauvegardes, l'opération la plus sensible du projet, **n'est
   pas dans le dépôt** : il vit dans un script sur le serveur. L'analyse statique
   seule ne verra jamais l'essentiel si on ne le lui déclare pas.
2. La première version signalait un `md5()` de test et une dépendance TOTP — dont
   SHA-1 est imposé par la spécification — comme des ruptures. Deux faux positifs
   sur quinze constats : de quoi perdre le lecteur. D'où la séparation entre
   *inventaire* et *usage*, et la mise hors sujet du code de test.
