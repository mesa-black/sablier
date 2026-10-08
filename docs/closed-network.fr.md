# Sur un réseau fermé

*← retour au [README](../README.fr.md)*

## Sur un réseau qui n'en a pas

```bash
sablier scan /chemin/du/projet --airgap --out=rapport.html --pdf=rapport.pdf
```

`--airgap` refuse au lieu de désactiver. `--no-probe` est une commodité : il saute une
étape que vous auriez pu lancer ; sur un site fermé c'est la mauvaise forme, parce
qu'un drapeau qu'on peut oublier est un drapeau qu'on oubliera. Donc `sablier probe` et
`sablier advisories` s'arrêtent avec un message nommant quoi faire à la place, tout
conteneur est refusé puisqu'un conteneur se télécharge, et un hôte de sonde déclaré est
sauté et **écrit dans les angles morts** plutôt qu'abandonné en silence. Un site le
règle une fois pour tout le monde avec `SABLIER_AIRGAP=1`.

Le PDF n'a alors aucun navigateur à emprunter ni conteneur d'où en tirer un : il est
donc composé ici. A4, les trois polices que tout lecteur possède déjà, et un numéro de
page sur chaque page — la seule chose que l'export par navigateur ne sait pas faire,
puisque Chrome ignore le CSS qui en porterait un. Plus sobre que le HTML imprimé, et il
existe, ce qui est tout l'argument : un rapport qu'on ne peut pas imprimer ne peut être
ni signé ni classé.

Rien dans cet outil n'atteint le réseau à moins que vous ne nommiez un hôte. Les
sockets n'existent que dans quatre fichiers — `Probe.php`, `SshProbe.php` et les deux
transports — tous derrière `sablier probe` et l'étape de sonde d'une analyse, que
`--no-probe` supprime. `sablier advisories` est la seule commande qui sort, et elle sort
pour une base de vulnérabilités plutôt qu'avec votre inventaire.

Cette affirmation est épinglée par un test plutôt qu'affirmée : la liste des fichiers
autorisés à ouvrir une socket est vérifiée à chaque exécution, et la construction casse
le jour où un détecteur en acquiert une. Là où le noyau le permet, la suite lance aussi
une analyse complète avec la pile réseau retirée (`unshare -rn`) et compare le
résultat.

C'est important parce que c'est la sortie qui est sensible. Un inventaire de là où vit
la cryptographie d'un système est aussi sensible que le système lui-même : sur un
réseau fermé, la question n'est donc pas de savoir si un outil promet de ne rien
envoyer, mais s'il le *peut*. Il n'y a aucune télémétrie, aucune vérification de mise à
jour, aucune dépendance à aller chercher : quatre lignes d'autochargeur, PHP 8.4, et un
dépôt que quelqu'un peut lire en une après-midi avant de l'y porter.
