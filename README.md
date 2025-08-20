# README

- common - Module contenant des structures communes comme :
    - Message - Pour la communication client/serveur
    - AuthType - Types d'authentification
    - CommandType - Types de commandes
    - BuiltinCommand - Commandes intégrées


- Biblothèques utilisés
    - `clap` (Command Line Argument Parser) avec /// pour les messages d'aides
    -  `env_logger` avec `log` Permet un affichage des logs 
    - `dialoguer` Pour les prompts interactifs

## Comment démarrer

1.  **Compiler le projet :**
    ```bash
    cargo build --release
    ```
    Cela créera les exécutables optimisés dans le répertoire `target/release/`.

2.  **Lancer le serveur :**
    Ouvrez un terminal et exécutez :
    ```bash
    ./target/release/server [OPTIONS]
    ```
    Par défaut, il écoutera sur `127.0.0.1:2222`. Vous pouvez voir les options avec `./target/release/server --help` (par exemple pour changer l'adresse ou le port).
    Le serveur ajoutera un utilisateur par défaut `testuser` avec le mot de passe `password123` au démarrage.

3.  **Lancer le client :**
    Ouvrez un *autre* terminal et exécutez :
    ```bash
    ./target/release/client --server 127.0.0.1 --port 2222 --username testuser
    ```
    Remplacez `127.0.0.1` et `2222` si vous avez démarré le serveur sur une adresse/port différent.
    Le client vous demandera le mot de passe (`password123` pour l'utilisateur par défaut).

4.  **Utiliser le REPL :**
    Une fois authentifié, vous serez dans un REPL (Read-Eval-Print Loop) où vous pourrez taper des commandes :
    *   **Navigation dans l'historique :** Utilisez les touches fléchées **Haut** et **Bas** pour naviguer dans les commandes précédemment tapées.
    *   **Autocomplétion :** Utilisez la touche **Tab** pour compléter les commandes intégrées (en début de ligne) ou les noms de fichiers/dossiers locaux.
    *   **Commandes externes :** (ex: `ls -l`, `echo hello`, `whoami`, etc.) - Celles-ci sont exécutées sur le serveur.
    *   **Commandes intégrées :**
        *   `cd <répertoire>` : Changer de répertoire courant sur le serveur.
        *   `pwd`: Afficher le répertoire courant sur le serveur.
        *   `ls [répertoire]` : Lister le contenu du répertoire courant ou spécifié sur le serveur.
        *   `env`: Afficher les variables d'environnement du serveur.
        *   `export VAR=valeur`: Définir une variable d'environnement pour la session sur le serveur.
        *   `history`: Afficher l'historique des commandes tapées dans la session courante et les précédentes.
        *   `exit`: Se déconnecter et quitter.

## Technologies Utilisées

*   `anyhow`: Gestion flexible des erreurs.
*   `clap`: Analyse des arguments de ligne de commande.
*   `dialoguer`: Création d'invites interactives (prompts) en terminal (utilisé dans l'exemple `client_ui`, mais pas intégré au REPL principal).
*   `env_logger` & `log`: Framework de journalisation (logging) configurable via variables d'environnement.
*   `serde` & `serde_json`: Sérialisation et désérialisation de structures de données (utilisé pour les messages Protocole en JSON).
*   `aes-gcm`: Chiffrement authentifié AES-GCM pour sécuriser la communication.
*   `rand`: Génération de nombres aléatoires (utilisé pour les sels et les nonces).
*   `argon2`: Hachage sécurisé de mots de passe (utilisé côté serveur pour stocker les mots de passe).
*   `rpassword`: Lecture sécurisée de mots de passe (utilisé côté client pour la saisie).
*   `rsa` & `sha2`: Cryptographie à clé publique RSA et fonctions de hachage SHA2 (prévu pour l'authentification par certificat, non implémentée).
*   `rustyline`: Bibliothèque pour créer une interface de ligne de commande (REPL) interactive avec historique.
*   `hex`: Encodage et décodage depuis/vers hexadécimal (utile pour le débogage des clés/sels).
*   `tokio`: Runtime asynchrone pour les opérations réseau et les processus.
*   `generic-array` & `typenum`: Utilitaires souvent requis par les crates de cryptographie pour gérer les tailles de tableaux génériques.


## Authentification

L'authentification initiale se fait avant l'établissement du canal sécurisé.

*   **Authentification par mot de passe (implémentée) :**
    1.  Le client se connecte au serveur via TCP.
    2.  Le client envoie un message `AuthenticatePassword` contenant le nom d'utilisateur et le mot de passe en clair au serveur.
    3.  Le serveur reçoit le message, recherche l'utilisateur dans son `UserStore` et récupère le hash Argon2 stocké pour cet utilisateur.
    4.  Le serveur vérifie si le mot de passe fourni correspond au hash stocké en utilisant Argon2.
    5.  Si la vérification réussit :
        *   Le serveur génère un sel unique (`kdf_salt`) spécifiquement pour la dérivation de la clé de session.
        *   Le serveur dérive la clé de session AES-GCM 256 bits en utilisant Argon2 avec le mot de passe original et le `kdf_salt`.
        *   Le serveur renvoie un message `AuthenticationResult` avec `success: true` et le `kdf_salt` au client.
    6.  Si la vérification échoue, le serveur renvoie `AuthenticationResult` avec `success: false` et ferme la connexion.
    7.  Le client reçoit le `AuthenticationResult`. Si `success` est `true` et qu'un `kdf_salt` est présent :
        *   Le client dérive la *même* clé de session AES-GCM 256 bits en utilisant Argon2 avec le mot de passe original qu'il a fourni et le `kdf_salt` reçu du serveur.
    8.  Le client et le serveur possèdent maintenant la même clé de session sans l'avoir échangée directement.

*   **Établissement du Canal Sécurisé :**
    *   Une fois la clé de session dérivée des deux côtés, le client et le serveur initialisent une `SecureConnection`.
    *   Toute communication ultérieure (commandes, réponses, etc.) est chiffrée et déchiffrée en utilisant AES-GCM avec la clé de session via cette `SecureConnection`.

*   **Vérification (Wireshark) :** Comme vous l'avez noté, après l'échange initial d'authentification (où le mot de passe est envoyé, mais seulement pour la dérivation de clé et non stocké en clair sur le long terme par le serveur après le hash), le reste du trafic est chiffré et apparaît comme des données inintelligibles dans Wireshark, confirmant que le canal sécurisé est actif.
    (image.png)

*   **Authentification par certificat (non implémentée) :** Le code contient des stubs et des dépendances (`rsa`, `sha2`) pour une future implémentation de l'authentification basée sur les certificats, mais cette fonctionnalité n'est pas active actuellement.

# Notes de Projet : Outil de type SSH avec Authentification par Certificat

## Résumé de l'Implémentation de l'Authentification par Certificat

Cette mise à jour a ajouté une authentification basée sur les certificats (clés Ed25519) au système d'authentification par mot de passe existant. L'objectif était de permettre à un client de s'authentifier auprès du serveur en utilisant une clé privée, le serveur connaissant la clé publique correspondante.

### Changements Clés :

1.  **Dépendances Ajoutées (`Cargo.toml`) :**
    *   `ed25519-dalek = "2.1"` (avec fonctionnalités `serde` et `pkcs8`) : Pour la génération et la vérification des signatures Ed25519.
    *   `pem = "3.0"` : Pour l'analyse des fichiers de clés encodés en PEM.
    *   `base64 = "0.21"` : Pour le décodage des données encodées en Base64, spécifiquement pour le format de clé publique OpenSSH.
    *   `pkcs8 = "0.10"` : Pour l'analyse des structures PKCS#8 et SubjectPublicKeyInfo à partir de clés encodées en DER.
    *   `byteorder = "1.4"` : Pour l'analyse des données ordonnancées par octets, utilisé dans le format de clé publique OpenSSH.

2.  **Mises à Jour du Protocole (`src/protocol.rs`) :**
    *   `ClientMessage` :
        *   Ajout de `AuthenticateCertificate { username: String }` pour initier l'authentification par certificat.
        *   Ajout de `AuthChallengeResponse { signature: Vec<u8> }` pour que le client envoie le défi signé.
    *   `ServerMessage` :
        *   Ajout de `AuthChallenge { challenge: Vec<u8> }` pour que le serveur envoie un défi au client.
        *   `AuthenticationResult` était déjà adapté aux deux méthodes d'authentification.

3.  **Logique d'Authentification (`src/auth.rs`) :**
    *   `UserStore` :
        *   Modifié pour stocker `AuthMethod`, un enum distinguant `PasswordHash(String)` et `PublicKey(VerifyingKey)`.
        *   Ajout de `load_test_users()` pour pré-remplir avec un utilisateur par mot de passe (`user_pass`) et un utilisateur par certificat (`user_cert`), chargeant la clé publique pour `user_cert` depuis `test_user_cert.pub`.
        *   Ajout de la méthode `user_count()`.
    *   Fonctions de Gestion des Clés :
        *   `load_private_key(path: &Path) -> Result<SigningKey>` : Charge une clé privée Ed25519 depuis un fichier PEM. Tente d'abord d'analyser le format PKCS#8 DER, puis se rabat sur les formats bruts de graine de 32 octets ou de paire de clés de 64 octets.
        *   `load_public_key_from_file(path: &str) -> Result<VerifyingKey>` : Charge une clé publique Ed25519. Supporte le format PEM standard `-----BEGIN PUBLIC KEY-----` (format SubjectPublicKeyInfo DER/ASN.1, vérifiant l'OID Ed25519) et le format OpenSSH `ssh-ed25519 ...`.
    *   Opérations Cryptographiques :
        *   `sign_challenge(signing_key: &SigningKey, challenge: &[u8]) -> Result<Signature>` : Signe un segment d'octets en utilisant la clé privée du client.
        *   `verify_signature(verifying_key: &VerifyingKey, challenge: &[u8], signature_bytes: &[u8]) -> Result<bool>` : Vérifie une signature par rapport au défi et à la clé publique de l'utilisateur.
    *   Dérivation de Clé de Session :
        *   `derive_session_key_from_signature(signature_bytes: &[u8]) -> Result<[u8; 32]>` : Dérive une clé de session de 32 octets en hachant la signature (SHA-256). C'est une méthode plus simple ; un protocole d'accord de clé serait plus robuste pour dériver des secrets partagés.

4.  **Intégration Côté Serveur (`src/server.rs`) :**
    *   `handle_client()` :
        *   Gère `ClientMessage::AuthenticateCertificate`.
        *   Récupère la clé publique de l'utilisateur depuis `UserStore`.
        *   Génère un défi aléatoire de 32 octets.
        *   Envoie `ServerMessage::AuthChallenge` au client.
        *   Attend `ClientMessage::AuthChallengeResponse`.
        *   Appelle `auth::verify_signature`.
        *   En cas de succès, appelle `auth::derive_session_key_from_signature`.
        *   Envoie `ServerMessage::AuthenticationResult` et passe à la session sécurisée.
    *   `main()` :
        *   Appelle `user_store.load_test_users()` au démarrage.

5.  **Intégration Côté Client (`src/client.rs`) :**
    *   `Args` (arguments CLI) :
        *   `auth_mode` accepte maintenant "certificate".
        *   `identity_file: Option<PathBuf>` (raccourci `-i`) ajouté, rendu obligatoire si `auth_mode` est "certificate".
    *   `run_client()` :
        *   Si `auth_mode` est "certificate" :
            *   Charge la clé privée spécifiée par `identity_file` en utilisant `auth::load_private_key`.
            *   Envoie `ClientMessage::AuthenticateCertificate`.
            *   Reçoit `ServerMessage::AuthChallenge`.
            *   Signe le défi en utilisant `auth::sign_challenge`.
            *   Envoie `ClientMessage::AuthChallengeResponse`.
            *   Reçoit `ServerMessage::AuthenticationResult`.
            *   En cas de succès, dérive la clé de session en utilisant `auth::derive_session_key_from_signature`.
            *   Initialise la connexion sécurisée.

## Commandes Exécutées

1.  **Génération de la Paire de Clés de Test Ed25519 :**
    *   Générer la clé privée :
        ```bash
        openssl genpkey -algorithm ed25519 -out test_user_private.key
        ```
    *   Extraire la clé publique de la clé privée :
        ```bash
        openssl pkey -in test_user_private.key -pubout -out test_user_cert.pub
        ```
    *(Ces fichiers sont attendus à la racine du projet pour la configuration de test actuelle.)*

2.  **Lancer le Serveur :**
    ```bash
    cargo run --bin server
    ```

3.  **Lancer le Client (Authentification par Certificat) :**
    ```bash
    cargo run --bin client -- --server 127.0.0.1 --port 2222 --username user_cert --auth-mode certificate -i test_user_private.key
    ```

4.  **Lancer le Client (Authentification par Mot de Passe - pour tester la fonctionnalité existante) :**
    ```bash
    cargo run --bin client -- --server 127.0.0.1 --port 2222 --username user_pass --auth-mode password
    ```
    (Mot de passe : `password123`)

## Prochaines Étapes / Améliorations Potentielles

*   Corriger les avertissements du compilateur (variables/imports inutilisés).
*   Implémenter une gestion robuste des erreurs pour le chargement des clés (par ex., clés privées protégées par mot de passe).
*   Envisager une méthode d'établissement de clé de session plus sécurisée que la dérivation à partir de la signature (par ex., échange Diffie-Hellman sécurisé par la signature Ed25519).
*   Gérer correctement les formats de clés privées OpenSSH s'ils diffèrent significativement des formats bruts ou PKCS#8.
*   Configuration pour les utilisateurs et leurs clés publiques au lieu de les coder en dur dans `load_test_users()`.

# Autocomplétion dans le REPL (Client)

## Résumé de l'Implémentation

L'objectif était d'ajouter une fonctionnalité d'autocomplétion activée par la touche `Tab` dans le REPL (Read-Eval-Print Loop) du client. L'autocomplétion doit suggérer :

1.  Les commandes intégrées (builtin commands) lorsque l'utilisateur commence à taper le premier mot de la ligne.
2.  Les noms de fichiers et de répertoires dans les autres cas (par exemple, après une commande comme `cd` ou `ls`).

L'implémentation utilise la crate `rustyline` (version 14.0), qui fournit le support pour les lignes de commande interactives.

### Changements Clés (`src/repl.rs`) :

1.  **Structure d'Aide (`ReplHelper`) :**
    *   Une structure `ReplHelper` a été créée pour encapsuler la logique d'aide personnalisée pour `rustyline`.
    *   Elle contient un `FilenameCompleter` (pour la complétion des chemins de fichiers) et un `HistoryHinter` (pour suggérer des commandes basées sur l'historique).

2.  **Implémentation des Traits `rustyline` :**
    *   Pour que `rustyline` utilise notre logique personnalisée, `ReplHelper` doit implémenter plusieurs traits définis par la crate :
        *   `Completer` : C'est le trait principal pour l'autocomplétion.
        *   `Hinter` : Pour les suggestions (hints).
        *   `Highlighter` : Pour la coloration syntaxique (non implémentée ici).
        *   `Validator` : Pour valider la ligne avant exécution (non implémentée ici).
        *   `Helper` : Le trait "parapluie" qui regroupe les autres.
    *   Après plusieurs tentatives pour satisfaire les exigences du compilateur concernant ces traits (notamment `Hinter` et `Highlighter` qui semblaient privés ou dont les bornes n'étaient pas satisfaites), une implémentation complète a été fournie pour chaque trait requis par `Helper`.

3.  **Logique de Complétion (`impl Completer for ReplHelper`) :**
    *   La méthode `complete` est appelée lorsque l'utilisateur appuie sur `Tab`.
    *   Elle détermine d'abord si le curseur se trouve à un endroit où une commande est attendue (début de ligne ou juste après un espace suivant le premier mot).
    *   **Si c'est une position de commande :** Elle compare le mot partiel tapé par l'utilisateur avec la liste `BUILTIN_COMMANDS` (`cd`, `pwd`, `ls`, `env`, `export`, `exit`) et renvoie les commandes correspondantes comme suggestions.
    *   **Sinon (ou si aucune commande intégrée ne correspond) :** Elle délègue la complétion au `FilenameCompleter` standard de `rustyline`. **Limitation actuelle :** Ce compléteur fonctionne sur le système de fichiers **local du client**, et non sur le système de fichiers distant du serveur.

4.  **Implémentations Minimales des Autres Traits :**
    *   `Hinter` : Délègue au `HistoryHinter` pour fournir des suggestions basées sur l'historique des commandes.
    *   `Highlighter` : Implémentation minimale qui ne fait aucune coloration syntaxique.
    *   `Validator` : Implémentation minimale qui ne fait aucune validation.

5.  **Configuration de `rustyline::Editor` (`Repl::new`) :**
    *   Une instance de `ReplHelper` est créée.
    *   Elle est passée à l'éditeur `rustyline` via la méthode `editor.set_helper(Some(helper))`.

### Utilisation :

*   Appuyer sur `Tab` en début de ligne complétera ou listera les commandes intégrées.
*   Appuyer sur `Tab` après une commande (comme `cd `) complétera ou listera les fichiers/répertoires du répertoire **courant du client**.

### Améliorations Futures Possibles :

*   Implémenter la complétion des chemins de fichiers basés sur le répertoire **distant du serveur**. Cela nécessiterait une communication asynchrone avec le serveur pendant la complétion (complexe avec l'API synchrone de `rustyline::Completer`) ou une mise en cache locale des listes de répertoires distants.
*   Ajouter une coloration syntaxique simple via `Highlighter`.
