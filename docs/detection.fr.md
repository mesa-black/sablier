# Ce qu'il détecte, et à quel point il en est sûr

*← retour au [README](../README.fr.md)*

## Ce qu'il dit de lui-même

Ce dépôt porte sa propre déclaration et est analysé à chaque construction, le
résultat étant comparé à `.sablier/baseline.json`. Neuf constats : six signatures
Ed25519, deux empreintes SHA-256 qu'il a raison de laisser tranquilles, et un
qu'il classe comme identifiant plutôt que comme contrôle — notre propre fonction
d'empreinte, ce qu'elle est exactement.

La déclaration exclut quatre chemins, et un lecteur a droit à la raison de chacun :

| exclu | pourquoi |
|---|---|
| `src/Detector/*` | les détecteurs contiennent les motifs — la chaîne `rsa` y est ce qui trouve RSA, pas un usage de RSA |
| `src/Probe.php` | la même chose, pour le handshake qu'il lit |
| `tests/fixtures/*` | de la cryptographie plantée exprès, pour que les tests aient quelque chose à trouver |
| `tests/run.sh` | le `openssl genrsa` que la suite lance pour se fabriquer une clé |

Analysé en retirant cette liste, le dépôt produit 47 constats au lieu de neuf et
**pas un seul n'est rouge** : douze chaînes de motifs dans les détecteurs,
vingt-trois dans les jeux d'essai, et le reste déjà rapporté. La liste ne cache
rien ; elle est passée de huit entrées à quatre le jour où on a vérifié, parce que
quatre d'entre elles excluaient des fichiers qui ne contenaient rien.

La déclaration a dû elle aussi être mise au niveau que cet outil exige de tout le
monde. Elle porte maintenant `declared_by` et `declared_on`, et un
`service_until`, parce que le rapport imprimait notre propre horizon manquant dans
ses angles morts — c'est l'outil qui fonctionne, et ce n'était pas une façon
agréable de l'apprendre.

## À quelle fréquence il se trompe

Mesuré, pas affirmé : **31 dépôts PHP publics, 959 constats, 21 rouges, 3 d'entre
eux faux — 14 %.** Avant cette mesure, c'était 92 %, et les neuf rouges sur dix qui
étaient faux tenaient tous à la même poignée d'erreurs : `mcrypt_*` rapporté comme
DES, des codes de hachage d'objets et des noms de verrous lus comme des contrôles de
sécurité, HMAC-MD5 déclaré cassé, un appel trouvé dans un commentaire.

[`docs/false-positives.md`](docs/false-positives.md) donne la méthode, les
correctifs, le jugement sur chaque rouge restant, et les dépôts pour reproduire —
y compris les six qui n'ont jamais servi au réglage, où le taux remontait à 63 %
tant que les règles n'ont pas été rendues générales plutôt que particulières.

Trois faux positifs subsistent, documentés plutôt que masqués. Le rappel n'a pas
bougé : chaque constat réel du premier corpus est toujours rapporté.

## Les services managés, autant qu'un fichier puisse le dire

Chaque rapport porte le même aveu : la cryptographie de votre base de données, de
votre stockage objet et de votre terminaison TLS n'apparaît dans aucun fichier du
dépôt. C'est vrai d'une application. Ça cesse de l'être dès que l'infrastructure est
déclarée en code à côté.

Les fichiers `.tf` sont lus pour les décisions que quelqu'un a écrites —
`storage_encrypted = false`, un `minimum_protocol_version` sous ce qui se négocie
encore, le chiffrement serveur d'un seau et à qui appartient la clé, les clés que
l'infrastructure se fabrique, une clé KMS asymétrique. Une base managée qui garde dix
ans de comptabilité avec le chiffrement désactivé, c'est le même constat qu'un script
de sauvegarde sans chiffrement : le fournisseur ne change pas l'arithmétique.

Ce qui est lu là, c'est l'**intention**, pas le résultat : l'angle mort est donc
reformulé et non supprimé. Ce que le fournisseur fait réellement de cette déclaration
— ses propres clés, ses propres algorithmes, sa terminaison TLS — reste hors du
rapport.

## Deux sources, parce qu'un dépôt peut se tromper

La sonde couvre HTTPS, SMTP, IMAP, POP3, PostgreSQL, MySQL, LDAP, et les ports à TLS
implicite d'AMQP, Redis et MQTT — plus **SSH**, qui ne devient jamais du TLS et a
donc son propre lecteur : il prend la bannière et le KEXINIT du serveur, là où
apparaît `sntrup761x25519` quand quelqu'un a activé un échange de clés post-quantique
qu'aucun fichier du dépôt ne mentionne. Il envoie une bannière, lit un paquet et
raccroche : jamais de clé, jamais de mot de passe, jamais assez loin pour être une
tentative d'authentification.

**L'analyse statique** lit ce que le code déclare. **La sonde** effectue une poignée
de main TLS ordinaire et rapporte ce que le serveur négocie réellement — les deux se
contredisent assez souvent pour que ne rapporter que la première soit trompeur. Un
projet sans la moindre cryptographie post-quantique dans son code peut déjà être
protégé par son CDN ; un projet qui a tout configuré correctement peut être terminé
par un intermédiaire qui défait ce travail.

```
$ make probe HOST=example.org

  protocole négocié            TLSv1.3
  suite cryptographique        TLS_AES_256_GCM_SHA384 (256 bits)
  groupe négocié               X25519MLKEM768
  signature du certificat      ecdsa-with-SHA256
  versions acceptées           TLSv1.2, TLSv1.3
```

La sonde n'a sa place que contre des hôtes dont vous êtes responsable.

## Ce qu'un framework déclare

L'essentiel de cet outil lit du code. Les faits cryptographiques les plus utiles
d'une application web ne sont pas dans son code : personne n'écrit `RS256` dans un
contrôleur. On l'écrit une fois dans un firewall, et toutes les connexions des cinq
années suivantes s'en servent.

```
config/packages/security.yaml      hachage des mots de passe · OIDC · jetons
config/packages/lexik_jwt_*.yaml   la signature derrière chaque jeton d'API
config/packages/doctrine.yaml      si la connexion à la base est chiffrée
config/app.php · hashing.php       le chiffre et le hachage de Laravel
config/jwt.php · database.php      tymon/jwt-auth, et sslmode
config/filesystems.php             le chiffrement au repos demandé au stockage
config/passport.php                les clés RSA qui signent les jetons OAuth2
config/broadcasting.php            si le temps réel passe en TLS
app/Config/Encryption.php          le chiffre et le digest de CodeIgniter
config/web.php                     les cookies signés de Yii
```

Laravel a droit à une chose de plus, et elle parle d'effort plutôt que
d'algorithmes. `Crypt::encryptString()`, `Hash::make()` et l'aide nue `encrypt()`
ne nomment aucun algorithme — le chiffre est dans `config/app.php`, le pilote dans
`config/hashing.php` — donc la configuration seule donne un constat par
application et ne dit rien de ce qui en dépend. Ces appels sont relevés aussi, en
**confiance moyenne** et sans jamais prétendre nommer le chiffre, parce que le
jour où il doit changer, ce qui compte est le nombre d'endroits à rouvrir. C'est
le troisième facteur du modèle de risque, compté en endroits plutôt qu'estimé en
jours. Les aides nues ne sont lues que dans un fichier qui importe
`Illuminate` : `encrypt()` est le nom de fonction le plus générique du langage, et
hors de Laravel il appartient à quelqu'un d'autre.

Symfony a demandé un détecteur à lui, parce que c'est le seul framework ici à
mettre sa configuration de sécurité en YAML — et tant que celui-ci n'existait pas,
un outil qui n'ouvrait que des `.php` passait devant sans la voir.

**C'est la valeur qui décide, pas la clé.** `algorithm:` apparaît dans une douzaine
d'endroits sans rapport dans une configuration Symfony, donc un motif ne
correspond que si la valeur est un algorithme de hachage ou un algorithme JOSE que
cet outil connaît. Le coût d'une erreur là-dessus a été mesuré plutôt
qu'imaginé : une première version a lu `cookie_secure: auto` dans une vraie
application et a signalé un hachage de mot de passe qui n'existe pas, parce que
`auto` est aussi le nom de l'un d'eux. La fixture contient maintenant cette ligne
exacte, dans un fichier qui ne déclare aucun hachage, et un test échoue si elle
est un jour relue comme tel.

**`HS256` et `RS256` ne sont pas la même chose**, et un rapport qui imprime le nom
JOSE et s'arrête n'a rien dit à son lecteur. Le premier est un secret partagé et
survit à un calculateur quantique ; le second est une signature RSA et non.

**OIDC est le cas qui justifie à lui seul ce détecteur.** Un firewall qui délègue
la connexion à un fournisseur d'identité nomme le fournisseur et jamais la
signature : l'algorithme vient des clés que ce fournisseur publie, donc il n'est
pas dans le dépôt et ne peut pas y être. C'est toute la thèse de cet outil énoncée
par le format de configuration de quelqu'un d'autre — tout le chemin
d'authentification repose sur un algorithme que personne ici n'a choisi — donc
c'est signalé comme indéterminé et ça demande à être déclaré.

Et il reste dans son couloir. `verify_peer: false` sous `http_client` est un vrai
défaut et n'est délibérément pas signalé : c'est un problème de l'authentification
d'aujourd'hui, pas du moment où un chiffre cesse de tenir, et un outil qui se met
à signaler toutes les odeurs de sécurité perd le droit d'être cru sur 2035.

## Ce qui se cache dans les fichiers que personne ne lit

Les images, polices et archives d'un dépôt sont copiées, relues par personne et
livrées. C'est aussi un endroit commode pour laisser quelque chose. Trois contrôles,
classés par ce qu'ils prouvent réellement :

- **du matériel de clé dans un actif binaire.** Un en-tête PEM dans un `.png` n'est pas
  un accident — et il était déjà trouvé, parce que le détecteur de clés lit tous les
  fichiers et pas seulement ceux dont le nom ressemble à une clé. Ce qui est nouveau,
  c'est la phrase qui dit où : *« Bloc de clé trouvé à l'octet 73 d'un fichier .png. Un
  actif binaire n'est pas un endroit où du matériel de clé arrive par accident. »* ;
- **des octets après la fin de l'image.** Un PNG finit à `IEND`, un JPEG à `FFD9`, et un
  fichier qui continue au-delà porte autre chose. Rapporté comme **à confirmer**, avec
  le nombre d'octets, jamais comme un verdict : un profil colorimétrique et une archive
  exfiltrée se ressemblent vus d'ici, et un seul des deux est un problème ;
- **une extension qui ment sur le contenu.** Les octets magiques disent ce qu'est un
  fichier. Un `.png` qui commence par `PK\x03\x04` est un zip, ce qui mérite un coup
  d'œil et rien de plus.

Ce n'est délibérément **pas** de la détection de stéganographie, et le rapport le dit
dans ses angles morts. Un message caché dans les bits de poids faible d'une image est un
problème de recherche dont le taux de faux positifs enterrerait chaque constat réel que
cet outil imprime. Un outil qui crie au loup à propos de photos de vacances perd le
droit d'être cru à propos d'une clé de sauvegarde — c'est pourquoi le test de régression
qui compte le plus ici est celui qui vérifie le silence sur une image ordinaire.
