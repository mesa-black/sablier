# Sablier — étude de cadrage

> Nom de travail. Le sablier est la métaphore du produit : le sable ne s'écoule
> pas à la même vitesse pour chaque donnée, et la question n'est jamais « est-ce
> chiffré » mais « jusqu'à quand ».

État : cadrage, aucune ligne vendue. Document destiné à être contredit par le
premier scan sur un vrai projet.

---

## 1. Le problème, et pourquoi il est présent et non futur

La transition post-quantique est traitée partout comme une échéance lointaine.
C'est une erreur de raisonnement, et c'est le seul endroit où cet outil a
quelque chose à dire que les autres ne disent pas.

Le modèle de menace qui compte s'appelle **récolte maintenant, déchiffrement
plus tard** : un adversaire capable de capturer du trafic ou de copier une
sauvegarde le fait aujourd'hui, et conserve. Il déchiffrera le jour où un
calculateur quantique pertinent existera. Pour la donnée concernée, la date de
compromission n'est pas la date de l'attaque : **c'est le jour où elle a été
chiffrée.**

D'où la seule formule qui structure le produit :

```
si  (aujourd'hui + durée de confidentialité de la donnée)  >  année de péremption de l'algorithme
alors la protection a déjà échoué, et la migration ne la répare pas
```

Une session de chat qui expire en dix secondes n'a aucun problème. Un dossier
médical, un contrat, une clé de sauvegarde, un secret industriel, une donnée
RH — tout ce qui doit rester confidentiel au-delà de l'échéance — est **déjà**
en défaut s'il est protégé par RSA ou par une courbe elliptique.

Aucun outil du marché ne pose cette question, parce qu'aucun ne connaît la
durée de vie des données. C'est précisément ce que l'outil demandera à
l'équipe, et c'est le pivot de tout le reste.

### Les dates

À manier avec précaution, et à revérifier avant toute communication publique :
elles ont bougé plusieurs fois et bougeront encore.

| Repère | Contenu | À vérifier |
|---|---|---|
| FIPS 203 / 204 / 205 (2024) | ML-KEM, ML-DSA, SLH-DSA normalisés | non, c'est stable |
| NIST IR 8547 | trajectoire de dépréciation : RSA/ECC dépréciés ~2030, interdits ~2035 | **oui**, état du document |
| CNSA 2.0 (NSA) | calendriers par usage, plus agressifs sur la signature de code | oui |
| Recommandation UE 2024/1101 | feuilles de route nationales, premiers usages critiques avant 2030 | oui |
| ANSSI | hybridation obligatoire en phase de transition, position française | oui |

**Décision de conception qui découle de l'incertitude** : l'outil ne prédit pas
l'arrivée d'un calculateur quantique. Il utilise **l'échéance réglementaire**
comme date de péremption par défaut (2035, paramétrable), et le dit dans le
rapport. Prédire une date de rupture cryptographique serait exactement le genre
de chiffre inventé qu'on reproche aux autres.

---

## 2. Ce qui existe déjà, honnêtement

Le sujet n'est pas vierge. Prétendre le contraire ferait perdre six mois.

| Existant | Ce qu'il fait | Ce qu'il ne fait pas |
|---|---|---|
| CycloneDX 1.6+ (CBOM) | un **format** normalisé d'inventaire cryptographique | ce n'est pas un outil, et il ne juge rien |
| IBM `cbomkit` / plugin Sonar | scanne du code, produit un CBOM | pas de notion de durée de vie de la donnée, rapport austère, orienté Sonar |
| Éditeurs (crypto-agilité) | découverte réseau + inventaire, offres entreprise | cher, vendu à la DSI, pas au développeur ; agent à installer |
| `testssl.sh`, `sslyze`, `cryptolyzer` | ce qui est **négocié** par un serveur en vrai | ne voient que le réseau, rien du code ni des sauvegardes |
| Semgrep, règles crypto | mauvais usages ponctuels | pas d'inventaire, pas de priorisation |

**La place libre** n'est donc pas « inventorier la cryptographie ». C'est :

1. **relier l'inventaire à la durée de vie des données** — personne ne le fait ;
2. **un rapport qu'on peut montrer à quelqu'un qui décide**, pas un tableau
   d'analyse statique ;
3. **zéro dépendance, zéro compte, zéro envoi** — sur un outil qui lit là où
   sont les clés, c'est structurel et pas commercial.

C'est exactement la manœuvre de PhpMetrics : les métriques existaient, la
lisibilité et l'absence de friction n'existaient pas.

---

## 3. Ce que l'analyse statique peut voir, et ce qu'elle ne verra jamais

Section la plus importante du cadrage. Un outil de sécurité qui laisse croire
qu'il a tout vu est pire que pas d'outil : il produit une fausse assurance.

### Fiable (confiance haute)

- Appels à une API cryptographique avec l'algorithme **en littéral** :
  `openssl_sign(..., OPENSSL_ALGO_SHA256)`, `openssl_encrypt($d, 'aes-256-cbc', …)`,
  `hash('sha1', …)`, `password_hash(…, PASSWORD_BCRYPT)`, toute la famille `sodium_*`.
- Génération de clés avec paramètres littéraux : type et taille dans
  `openssl_pkey_new(['private_key_type' => …, 'private_key_bits' => …])`.
- **Matériel de clé présent dans le dépôt** : fichiers PEM, certificats, clés
  SSH — le type et la taille se lisent dans l'en-tête ou l'ASN.1.
- Algorithme de signature **littéral** d'un JWT (`RS256`, `ES256`, `HS256`, `EdDSA`).
- Configuration TLS déclarée dans le dépôt : Caddyfile, nginx, Apache.
- Dépendances cryptographiques déclarées dans `composer.lock` / `package-lock.json`.

### Incertain (confiance moyenne — à signaler comme tel, jamais à trancher)

- Algorithme ou taille venant d'une variable, d'une constante, d'un `.env`.
  L'outil doit écrire « indéterminé » et nommer le fichier, pas deviner.
- Cryptographie appelée à travers une couche d'abstraction maison.
- Versions de bibliothèques : la présence de `phpseclib` ne dit pas quel
  algorithme est réellement employé.

### Hors de portée (et le rapport doit le dire lui-même)

- **Ce qui est réellement négocié à l'exécution** — version de TLS, suite
  retenue face à un vrai pair. Il faut une sonde active, c'est un autre outil.
- **La cryptographie des services gérés** : chiffrement au repos d'une base
  managée, SSE d'un stockage objet, terminaison TLS d'un CDN. Rien de tout cela
  n'est dans le dépôt. Seule une déclaration humaine peut les faire entrer.
- **Les clés détenues en HSM ou par un fournisseur.**
- **La durée de vie des données.** Elle est indécidable depuis le code, et c'est
  très bien : elle est déclarée, revue, versionnée, et c'est le seul artefact du
  projet qui engage l'équipe plutôt que la machine.
- Le chiffrement à l'intérieur de binaires, de conteneurs tiers, de FFI.

> **Règle de produit** : le rapport imprime ses propres angles morts, en clair,
> dans le document, et pas dans une note de bas de page. Un inventaire qui ne
> dit pas ce qu'il n'a pas regardé n'est pas un inventaire.

---

## 4. Le modèle de risque

Le seul endroit où l'outil a une opinion. Trois distinctions que la plupart des
discours sur le post-quantique mélangent.

### 4.1 Confidentialité ≠ authenticité

- **Confidentialité** (chiffrement, échange de clés : RSA-OAEP, ECDH, TLS) —
  soumise à la récolte. L'urgence dépend de la durée de vie de la donnée.
  *Une donnée chiffrée aujourd'hui peut déjà être perdue.*
- **Authenticité** (signature : ECDSA, RSA-PSS, JWT) — **pas** soumise à la
  récolte. Une signature cassée en 2035 ne permet pas de forger rétroactivement
  une signature de 2026 dans la plupart des usages. L'urgence porte sur les
  **ancres de confiance à longue durée** : signature de code, autorité de
  certification, micrologiciel, horodatage.

Mélanger les deux, c'est soit paniquer pour rien, soit rater le vrai sujet.

### 4.2 Symétrique ≠ asymétrique

AES-256 et ChaCha20 ne sont pas le problème. Grover divise par deux la marge,
AES-128 devient inconfortable, AES-256 reste solide. L'outil doit le dire pour
éviter que l'équipe remplace ce qui va bien.

### 4.3 Classiquement cassé ≠ quantiquement menacé

MD5 et SHA-1 sont un problème **d'aujourd'hui**, sans aucun quantique. Ils
doivent sortir dans une catégorie distincte, avec une urgence supérieure — sinon
on repousse à 2030 un correctif qui était dû en 2017.

### 4.4 La note

```
exposition_fin   = année_courante + durée_de_confidentialité(domaine)
péremption       = année de péremption de l'algorithme (défaut : 2035, paramétrable)

confidentialité :  exposition_fin > péremption            → COMPROMIS
authenticité    :  ancre de confiance longue durée        → À MIGRER
                   sinon                                  → SURVEILLER
hash cassé      :  toujours                               → URGENT (classique)
symétrique fort :                                          → CONFORME
indéterminé     :                                          → À DÉCLARER
```

`COMPROMIS` ne veut pas dire « corrigez vite ». Il veut dire : **la donnée déjà
émise est perdue, la migration protège seulement ce qui viendra après.** C'est
une phrase désagréable, et c'est celle qui fait bouger une organisation.

---

## 5. Le rapport, qui est le produit

Maquette de la page. Un seul fichier HTML, aucune ressource externe, ouvrable
depuis une pièce jointe.

```
┌──────────────────────────────────────────────────────────────────────┐
│  SABLIER                            showmetherex.com — 30 sept. 2026 │
│                                                                      │
│  3 des 14 usages cryptographiques protègent des données dont la      │
│  confidentialité doit durer au-delà de la péremption de l'algorithme │
│  qui les protège.                                                    │
│                                                                      │
│  ──────────────────────────────────────────────────────────────────  │
│                                                                      │
│   2026        2030            2035                           2056    │
│    │───────────│───────────────│──────────────────────────────│      │
│    │           dépréciation    péremption                            │
│    │                                                                 │
│    ████████████████████████████████████████░░░░░░░░  facturation     │
│    │                           ↑ sauvegardes chiffrées — RSA-2048    │
│    │                             durée déclarée : 10 ans  COMPROMIS  │
│    ████████░░                                        sessions        │
│    │        ↑ TLS — ECDHE — durée : 1 jour            CONFORME       │
│                                                                      │
│  ──────────────────────────────────────────────────────────────────  │
│                                                                      │
│  COMPROMIS (3)                                                       │
│   ▸ Sauvegardes — RSA-2048                     deploy/backup.sh:41   │
│     Chiffrées aujourd'hui, à garder 10 ans. Récoltables.             │
│     Migration : chiffrement hybride, ou rotation + re-chiffrement.    │
│                                                                      │
│  À MIGRER (2)   ·   SURVEILLER (6)   ·   CONFORME (3)                │
│                                                                      │
│  ──────────────────────────────────────────────────────────────────  │
│  CE QUE CE RAPPORT N'A PAS REGARDÉ                                   │
│   · la cryptographie de vos services gérés (base, stockage, CDN)     │
│   · ce qui est réellement négocié à l'exécution                      │
│   · 4 usages où l'algorithme vient d'une variable : à déclarer        │
└──────────────────────────────────────────────────────────────────────┘
```

Trois partis pris :

1. **Une phrase de verdict en haut.** Pas un score sur 100 : un score se
   contemple, une phrase se transmet.
2. **La frise temporelle avant le tableau.** C'est le seul visuel qui fait
   comprendre le sujet à quelqu'un qui n'est pas cryptographe.
3. **Les angles morts dans le document**, à la même taille que le reste.

---

## 6. Périmètre du premier jet

**Dedans**

- Un langage : PHP. Terrain connu, et c'est là qu'est le public de PhpMetrics.
- Détection statique : appels OpenSSL/Sodium/hash, JWT littéraux, `composer.lock`.
- Matériel de clé et certificats présents dans l'arborescence.
- Configuration TLS déclarée (Caddy, nginx).
- Fichier de déclaration des domaines de données et de leur durée.
- Rapport HTML autonome + sortie JSON.
- **Zéro dépendance.** Pour un outil qui lit des clés, chaque dépendance est une
  chaîne d'approvisionnement à défendre. C'est aussi un argument de vente.

**Dehors, explicitement**

- Sonde réseau active (un autre outil, plus tard).
- Autres langages (JS, Go, Python) — après validation de la thèse.
- Correction automatique. Un outil qui réécrit de la cryptographie sans
  comprendre le contexte est un générateur d'incidents.
- SaaS, compte, télémétrie. Jamais.

---

## 7. Ce qui peut tuer le projet

À garder sous les yeux, et à réévaluer après le premier scan réel.

1. **« On verra en 2030. »** Le risque principal, et il est commercial, pas
   technique. Seul l'angle « votre donnée de 2026 est déjà perdue » y répond.
2. **Le bruit.** Un `md5()` employé comme clé de cache n'est pas une faille. Si
   le premier rapport sur un vrai projet noie trois vraies alertes dans quarante
   fausses, l'outil est mort. **C'est le critère d'arrêt du prototype.**
3. **La déclaration jamais remplie.** Sans durées de vie, l'outil retombe au
   niveau de ses concurrents. Il faut donc des valeurs par défaut raisonnables
   par type de domaine, et un rapport qui reste utile à moitié rempli.
4. **Un éditeur qui sort le même angle.** Réponse : la vitesse, l'absence de
   friction, et le fait qu'on peut publier chaque scan comme un retour
   d'expérience.

---

## 8. Ce qu'on fait maintenant

1. Scanner Show me the REX. Compter les vraies alertes et les fausses. Le
   rapport bruit/signal décide de la suite, pas l'enthousiasme.
2. Écrire le fichier de déclaration pour ce projet-là — et mesurer combien de
   temps ça prend réellement à quelqu'un qui connaît le code.
3. Si le résultat tient, publier le premier retour d'expérience.

Toute conclusion tirée avant l'étape 1 est une opinion.
