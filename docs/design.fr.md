# Comment c'est assemblé, et ce qu'il refuse

*← retour au [README](../README.fr.md)*

## Comment c'est assemblé

Deux points d'extension, parce que l'étude de cadrage nomme deux axes qui vont
réellement croître — et rien d'autre n'obtient une interface.

```
DetectorInterface   une façon de trouver de la cryptographie dans un type de fichier
  PhpDetector · ShellDetector · KeyMaterialDetector · AssetDetector
  EnvDetector · ServerConfigDetector · SshConfigDetector · TerraformDetector
  FrameworkConfigDetector · FrameworkYamlDetector · LaravelDetector
  SymfonyVaultDetector · DependencyDetector

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
