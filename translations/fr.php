<?php

declare(strict_types=1);

// Reference language: every other file is translated from this one.
return [
    // --- verdicts ---------------------------------------------------------
    'verdict.compromised' => 'COMPROMIS',
    'verdict.urgent' => "CASSÉ AUJOURD'HUI",
    'verdict.migrate' => 'À MIGRER',
    'verdict.declare' => 'À DÉCLARER',
    'verdict.watch' => 'SURVEILLER',
    'verdict.clear' => 'CONFORME',
    'verdict.noise' => 'PROBABLEMENT HORS SUJET',

    // --- reasoning --------------------------------------------------------
    'reason.undetermined' => "L'algorithme n'est pas lisible depuis le code. À confirmer à la main plutôt qu'à deviner.",
    'reason.unknown_algorithm' => 'Algorithme hors catalogue.',
    'reason.noise' => "Ressemble à un identifiant (clé de cache, empreinte) plutôt qu'à un contrôle de sécurité. À confirmer, pas à corriger.",
    'reason.inventory_broken' => 'Dépendance déclarée employant %s. Peut être imposé par la spécification du protocole, ou jamais appelé : à confirmer avant toute action.',
    'reason.broken' => "Cassé classiquement, indépendamment du quantique. L'échéance était hier.",
    'reason.quantum_safe' => 'Résiste aux algorithmes quantiques connus.',
    'reason.trust_anchor' => 'Ancre de confiance à longue durée : une signature qui doit rester vérifiable après %d se prépare maintenant.',
    'reason.signature' => 'Signature : pas de récolte possible. À migrer avant %d pour la conformité, sans urgence de confidentialité.',
    'reason.harvested' => "Chiffré aujourd'hui, à garder confidentiel jusqu'en %d — soit %d %s après la péremption de %s. Une capture faite maintenant sera lisible.",
    'reason.undeclared_domain' => "(durée par défaut : ce domaine n'est pas déclaré, le chiffre est à confirmer)",
    'reason.short_lived' => "La donnée cesse d'être sensible en %d, avant la péremption de %d. Migration à planifier pour le système, pas pour sauver cette donnée.",

    // --- units ------------------------------------------------------------
    'unit.year' => 'an', 'unit.years' => 'ans',
    'unit.use' => 'usage', 'unit.uses' => 'usages',
    'unit.bits' => 'bits',

    // --- algorithms -------------------------------------------------------
    'algo.rsa.note' => "Cassable par l'algorithme de Shor. La taille de clé n'y change rien.",
    'algo.rsa.replacement' => 'ML-KEM (chiffrement) ou ML-DSA (signature), en hybride pendant la transition',
    'algo.rsa-sign.note' => "Signature : pas de récolte possible, l'urgence dépend de la durée de vie de la clé.",
    'algo.rsa-sign.replacement' => 'ML-DSA, ou SLH-DSA pour une ancre de confiance longue durée',
    'algo.ecdsa.note' => 'Même exposition que RSA à Shor, sur des clés plus courtes.',
    'algo.ecdsa.replacement' => 'ML-DSA',
    'algo.ecdh.note' => 'Échange de clés : la cible principale de la récolte, puisqu\'il protège le trafic.',
    'algo.ecdh.replacement' => 'X25519 + ML-KEM en hybride',
    'algo.ed25519.note' => 'Excellent classiquement, vulnérable quantiquement comme toute courbe.',
    'algo.ed25519.replacement' => 'ML-DSA',
    'algo.dh.replacement' => 'ML-KEM en hybride',
    'algo.aes-128.note' => 'Grover ramène la marge à 64 bits : suffisant aujourd\'hui, inconfortable à long terme.',
    'algo.aes-128.replacement' => 'AES-256',
    'algo.aes-256.note' => 'Tient face à Grover. Rien à faire.',
    'algo.chacha20.note' => 'Rien à faire.',
    'algo.des.note' => "Cassé classiquement. Problème d'aujourd'hui, pas de 2035.",
    'algo.des.replacement' => 'AES-256',
    'algo.rc4.note' => 'Cassé classiquement.',
    'algo.rc4.replacement' => 'AES-256 ou ChaCha20',
    'algo.md5.note' => 'Collisions triviales depuis 2004. Sans aucun rapport avec le quantique.',
    'algo.md5.replacement' => "SHA-256, ou rien si l'usage n'est pas cryptographique",
    'algo.sha1.note' => 'Collisions démontrées depuis 2017.',
    'algo.sha1.replacement' => 'SHA-256',
    'algo.bcrypt.note' => 'Hachage de mot de passe : hors du périmètre post-quantique.',
    'algo.argon2.note' => 'Hachage de mot de passe : hors du périmètre post-quantique.',
    'algo.ml-kem.note' => 'Normalisé FIPS 203.',
    'algo.ml-dsa.note' => 'Normalisé FIPS 204.',

    // --- scanner details --------------------------------------------------
    'detail.cipher_from_variable' => "Le chiffre vient d'une variable ou d'une constante.",
    'detail.rsa_keygen' => 'Génération de clé RSA.',
    'detail.ec_keygen' => 'Génération de clé sur courbe elliptique.',
    'detail.openssl_sign' => 'Signature OpenSSL (clé à confirmer).',
    'detail.openssl_verify' => 'Vérification de signature OpenSSL.',
    'detail.sodium_box' => 'X25519 sous le capot.',
    'detail.sodium_kx' => 'Échange de clés X25519.',
    'detail.sodium_sign' => 'Signature Ed25519.',
    'detail.sodium_secretbox' => 'XSalsa20-Poly1305.',
    'detail.jwt' => 'Algorithme JWT.',
    'detail.mcrypt' => 'mcrypt est retiré de PHP depuis 7.2.',
    'detail.cli_symmetric' => 'Chiffrement symétrique en ligne de commande.',
    'detail.gpg' => 'Chiffrement GPG.',
    'detail.ssh_keygen' => 'Génération de clé SSH.',
    'detail.age' => 'Chiffrement age (X25519 + ChaCha20).',
    'detail.rsa_private_key' => "Clé privée RSA en clair dans l'arborescence.",
    'detail.ec_private_key' => 'Clé privée sur courbe elliptique.',
    'detail.openssh_private_key' => 'Clé privée OpenSSH (type à confirmer).',
    'detail.dsa_key' => 'Clé DSA.',
    'detail.x509' => 'Certificat X.509.',
    'detail.ssh_key' => 'Clé SSH.',
    'detail.tls_config' => 'Configuration TLS déclarée. Ce qui est réellement négocié demande une sonde active.',
    'detail.declared_dependency' => "Dépendance déclarée : l'usage réel reste à confirmer.",
    'detail.pkg.jwt' => 'Jetons JWT.',
    'detail.pkg.jose' => 'JOSE.',
    'detail.pkg.phpseclib' => 'Cryptographie généraliste en PHP pur.',
    'detail.pkg.halite' => 'Surcouche libsodium.',
    'detail.pkg.symmetric' => 'Chiffrement symétrique.',
    'detail.pkg.webauthn' => 'Passkeys : signatures ECDSA/EdDSA côté authentificateur.',
    'detail.pkg.totp' => 'TOTP : SHA-1 par spécification, sans enjeu quantique.',

    // --- probe ------------------------------------------------------------
    'probe.title' => 'Ce que le serveur négocie réellement',
    'probe.legend' => "Une poignée de main, pas une lecture de fichier : c'est le seul moyen de savoir ce qui protège vraiment le trafic, et cela peut contredire ce que le dépôt déclare.",
    'probe.no_connection' => 'aucune connexion TLS établie avec %s',
    'probe.unreachable' => "La sonde n'a pas pu joindre %s. Rien n'est conclu : une absence de réponse n'est pas une absence de problème.",
    'probe.fact.protocol' => 'protocole négocié',
    'probe.fact.cipher' => 'suite',
    'probe.fact.group' => 'groupe négocié',
    'probe.fact.cert_signature' => 'signature du certificat',
    'probe.fact.cert_key' => 'clé du certificat',
    'probe.fact.chain' => 'chaîne',
    'probe.fact.valid_until' => 'certificat valide jusqu\'au',
    'probe.fact.versions' => 'versions acceptées',
    'probe.note.no_group' => "Le groupe d'échange de clés n'a pas pu être lu : le binaire openssl est absent, ou sa sortie a changé. C'est la donnée la plus importante de cette sonde, et elle manque.",
    'probe.note.untestable' => "Versions non testables depuis cette machine (%s) : l'OpenSSL local refuse de les proposer. Leur absence de la liste ne prouve pas que le serveur les refuse.",
    'probe.detail.assumed_classical' => "Échange de clés présumé classique, faute d'avoir pu lire le groupe négocié.",
    'probe.detail.hybrid' => "Échange de clés hybride : une capture du trafic d'aujourd'hui reste illisible pour un adversaire quantique.",
    'probe.detail.classical' => "Échange de clés classique : le trafic capturé aujourd'hui sera déchiffrable une fois l'algorithme cassé.",
    'probe.detail.certificate' => 'Certificat serveur. Sa durée de vie est courte : le remplacer par une signature post-quantique se fera au renouvellement, sans migration de données.',
    'probe.detail.obsolete_version' => "Version de TLS obsolète encore acceptée. Problème d'aujourd'hui, sans rapport avec le quantique.",
    'probe.evidence.group' => 'groupe négocié : %s',
    'probe.evidence.cert' => 'certificat signé en %s, clé %s',
    'probe.evidence.version_accepted' => '%s accepté',
    'probe.elliptic_curve' => 'courbe elliptique',
    'probe.certificates' => 'certificats',
    'probe.unknown' => 'indéterminé',

    // --- report -----------------------------------------------------------
    'about.postquantum' => '<strong>Le post-quantique, en trois phrases.</strong> La cryptographie qui protège aujourd\'hui le web repose sur des problèmes faciles dans un sens et infaisables dans l\'autre — multiplier deux grands nombres premiers est immédiat, retrouver ces facteurs demanderait des milliers d\'années. Un calculateur quantique suffisamment grand rend ce retour possible : RSA et les courbes elliptiques, c\'est-à-dire l\'essentiel de ce qui chiffre et signe aujourd\'hui, tombent d\'un coup — la taille des clés n\'y change rien. La cryptographie <em>post-quantique</em> désigne les algorithmes conçus pour résister à cette machine, normalisés en 2024 (ML-KEM pour le chiffrement, ML-DSA pour la signature) ; le chiffrement symétrique, lui, AES et ChaCha20, n\'est pas menacé.',
    'about.tool' => '<strong>Sablier</strong> inventorie la cryptographie d\'un projet et la confronte à une information qu\'aucun outil ne possède : <em>combien de temps chaque donnée doit rester confidentielle</em>. Une donnée chiffrée aujourd\'hui avec RSA ou une courbe elliptique, et qui doit rester secrète au-delà de la péremption de ces algorithmes, est <em>déjà perdue</em> — un adversaire capture maintenant ce qu\'il déchiffrera plus tard, et la migration ne protégera que ce qui viendra après elle.<br><br>Ce rapport distingue donc ce qui se récolte (le chiffrement) de ce qui ne se récolte pas (les signatures), laisse tranquille la cryptographie symétrique, et sépare les problèmes d\'aujourd\'hui — MD5, SHA-1 — de l\'échéance quantique.',
    'headline.compromised' => "%d usage cryptographique protège des données dont la confidentialité doit durer au-delà de la péremption de l'algorithme qui les protège.",
    'headline.compromised.plural' => "%d usages cryptographiques protègent des données dont la confidentialité doit durer au-delà de la péremption des algorithmes qui les protègent.",
    'headline.urgent' => "Aucune donnée à longue durée n'est exposée à la récolte, mais %d usage repose sur un algorithme déjà cassé aujourd'hui.",
    'headline.urgent.plural' => "Aucune donnée à longue durée n'est exposée à la récolte, mais %d usages reposent sur des algorithmes déjà cassés aujourd'hui.",
    'headline.clear' => 'Aucune donnée dont la durée de confidentialité dépasse la péremption des algorithmes qui la protègent.',
    'report.subtitle' => "%d constats retenus sur l'ensemble analysé. Date de péremption retenue : <strong>%d</strong> — c'est l'échéance réglementaire, pas une prédiction de rupture cryptographique.",
    'report.files_read' => '%d fichiers lus',
    'report.elapsed' => 'analyse en %s',
    'report.footer' => "Sablier n'envoie rien, n'enregistre rien et ne dépend de rien. Ce fichier ne charge aucune ressource externe : il peut être lu hors ligne et transmis tel quel.",
    'timeline.title' => 'Durée de confidentialité des données, face à la péremption des algorithmes',
    'timeline.legend' => "Chaque barre est la durée pendant laquelle la donnée doit rester confidentielle. Elle passe en rouge quand un algorithme récoltable la protège au-delà du trait de péremption — dépasser le trait sans être rouge signifie que la donnée dure longtemps, mais qu'elle est protégée par de la cryptographie qui tiendra.",
    'timeline.deprecation' => 'dépréciation',
    'timeline.expiry' => 'péremption',
    'label.replacement' => 'Remplacement',
    'label.medium_confidence' => 'confiance moyenne',

    // --- blind spots ------------------------------------------------------
    'blind.title' => "Ce que ce rapport n'a pas regardé",
    'blind.motto' => "Un inventaire qui ne dit pas ce qu'il n'a pas vu n'est pas un inventaire.",
    'blind.managed_services' => "la cryptographie de vos services gérés — base de données, stockage objet, terminaison TLS chez un intermédiaire — n'apparaît dans aucun fichier de ce dépôt",
    'blind.runtime' => "ce qui est réellement négocié à l'exécution, pour tout hôte non déclaré dans la section « sonde »",
    'blind.hsm' => 'les clés détenues dans un HSM ou chez un fournisseur',
    'blind.lifetime' => "la durée de vie réelle des données : elle vient de votre déclaration, pas du code — un domaine non déclaré est calculé avec une durée par défaut de %d ans",
    'blind.undetermined' => "%d usage où l'algorithme vient d'une variable : listé ci-dessus, à confirmer à la main",
    'blind.undetermined.plural' => "%d usages où l'algorithme vient d'une variable : listés ci-dessus, à confirmer à la main",
    'blind.tls_config' => "Configuration TLS lue dans %s : c'est la déclaration, pas la négociation réelle.",

    // --- command line ---
    'cli.usage' => 'Sablier — ce qui est chiffré chez vous, et jusqu\'à quand ça tient.

  bin/sablier scan <chemin> [options]
  bin/sablier probe <hôte>          ce qu\'un serveur négocie réellement

    --declare=FICHIER   déclaration des domaines de données (défaut : sablier.json à la racine analysée)
    --out=FICHIER       rapport HTML (défaut : report.html)
    --json=FICHIER      inventaire brut en JSON
    --lang=fr|en|es     langue du rapport
    --no-probe          ne pas sonder les hôtes déclarés
    --quiet             pas de résumé au terminal',
    'cli.declaration' => 'déclaration',
    'cli.no_declaration' => 'aucune (durées par défaut)',
    'cli.findings' => '%d constats',
    'cli.missing_host' => 'hôte manquant : bin/sablier probe exemple.fr',
    'cli.missing_path' => 'chemin à analyser manquant ou introuvable',

    // --- PDF export ---
    'pdf.no_browser' => 'export PDF impossible : aucun navigateur Chrome ou Chromium trouvé sur cette machine. Le rapport HTML s\'imprime en PDF depuis n\'importe quel navigateur (feuille d\'impression fournie).',
    'pdf.missing_html' => 'export PDF impossible : %s est introuvable.',
    'pdf.failed' => 'export PDF échoué : %s n\'a produit aucun fichier.',
    'pdf.written' => '%s (%s Ko)',

    // --- projection ---
    'report.projection' => '⚠ Projection : ce rapport simule la situation en %d. Ce n\'est pas un état actuel — les verdicts sont ceux qu\'auraient les mêmes données si elles étaient chiffrées cette année-là.',

    // --- deadline freshness ---
    'report.deadline_checked' => 'Échéance vérifiée auprès de ses sources le %s.',
    'report.deadline_stale' => 'Cette vérification date de %d mois : à refaire avant de citer cette date.',
];
