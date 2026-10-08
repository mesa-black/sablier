# Juger l'inventaire de quelqu'un d'autre

*← retour au [README](../README.fr.md)*

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
