# Securio

Une application légère pour chiffrer et déchiffrer vos fichiers sensibles, entièrement en local.
Cœur cryptographique en **Rust**, interface **Tauri** (React).

## Fonctionnalités

- 🔒 Chiffrement authentifié **AES-256-GCM**, découpé en segments : toute modification,
  troncature ou réorganisation du fichier chiffré est détectée
- 🔑 Dérivation de clé **Argon2id** (256 Mio, 3 passes, 4 voies), résistante aux attaques par
  carte graphique ; robustesse de la clé évaluée (dictionnaires français et anglais) et clés trop
  faibles refusées
- 📦 **Fichiers de toute taille** : traitement en flux, la mémoire utilisée ne dépend pas de la
  taille du fichier
- 🕶️ Nom et type du fichier d'origine **chiffrés** (et longueur du nom masquée) ; noms piégés
  (caractères invisibles, inversion du sens de lecture) neutralisés, alerte sur les programmes
- ♻️ **Rétro-compatible** : les fichiers de Securio 1.0 → 1.3 s'ouvrent toujours
- 🚀 Ouverture directe des `.encrypted` (double-clic) ; une seule fenêtre à la fois
- 🪶 Exécutable d'environ 10 Mo (contre ~110 Mo avec Electron)
- 💾 Aucune donnée ne quitte votre ordinateur, aucune clé n'est stockée

## Installation (Windows)

Téléchargez la dernière version depuis la [page des releases](https://github.com/SkY1331/Securio/releases)
(ou l'artefact « Securio-windows » de l'onglet *Actions*) :

- `Securio_x.y.z_x64-setup.exe` : installeur (sans droits administrateur), associe l'extension
  `.encrypted` à Securio → **double-clic** sur un fichier chiffré ;
- `Securio_x.y.z_x64_fr-FR.msi` : installeur MSI (déploiement en entreprise) ;
- `Securio-x.y.z-portable.exe` : exécutable seul, sans installation.

Securio utilise WebView2, déjà présent sur Windows 10 et 11 (l'installeur le télécharge si besoin).

**Vérifier l'authenticité d'un téléchargement** : chaque release contient `SHA256SUMS.txt`
(empreintes à comparer avec `Get-FileHash fichier.exe -Algorithm SHA256` dans PowerShell) et une
attestation de provenance GitHub prouvant que l'exécutable a été compilé par la CI depuis ce dépôt :

```bash
gh attestation verify Securio-2.1.0-portable.exe --repo SkY1331/Securio
```

## Utilisation

1. **Chiffrer** : glissez-déposez un fichier (ou cliquez sur la zone), saisissez la clé deux fois
   — **aucune récupération n'est possible en cas d'oubli** — puis « Chiffrer… » et choisissez où
   enregistrer le `.encrypted`.
2. **Déchiffrer** : ouvrez un `.encrypted` (glisser-déposer, clic ou double-clic), saisissez la
   clé, « Déchiffrer », puis « Sauvegarder ».

Le mode (chiffrer / déchiffrer) est choisi automatiquement selon le fichier. En cas d'erreur
(clé incorrecte, fichier altéré, disque plein…), aucun fichier partiel n'est laissé : le résultat
est écrit dans un fichier temporaire, renommé seulement en cas de succès — et si l'application est
interrompue en plein travail, le temporaire est supprimé à son démarrage suivant.

⚠️ Après chiffrement, **le fichier d'origine reste sur le disque** : supprimez-le vous-même si
nécessaire (sur SSD, un fichier supprimé peut rester récupérable : chiffrez de préférence vos
documents dès leur création, ou travaillez sur un disque chiffré type BitLocker).

### Anciens fichiers

| Créé avec | Format | Lecture |
|---|---|---|
| Securio 2.0 et + | v3 | natif |
| Securio 1.3 | v2 | identique |
| Securio 1.0 → 1.2.1 | v1 | mode compatibilité, algorithme AES-128/192/256 détecté automatiquement |

Les versions ≤ 1.2.1 lisaient certains fichiers de façon incorrecte avant de les chiffrer.
Securio les répare au déchiffrement, tout en laissant toujours la possibilité d'enregistrer le
contenu brut :

| Fichier chiffré avec ≤ 1.2.1 | Problème d'origine | Réparation |
|---|---|---|
| Images (`.png`, `.jpg`…) | stockées sous forme de texte `data:image/...;base64,…` | reconverties en image, à l'identique |
| `.txt` | accents stockés en Latin-1, caractères au-delà tronqués | accents reconvertis en UTF-8 ; ’ ‘ “ ” – — restaurés ; € (devenu ¬) et emojis non récupérables |
| `.csv`, `.md`, `.html`… | idem si le système les déclarait `text/*` | « version texte réparée » proposée en plus |
| Noms de plus de 32 octets | nom tronqué dans l'en-tête | nom complet retrouvé à partir du nom du `.encrypted` quand c'est possible |

> ℹ️ Les fichiers chiffrés en 2.0 (v3) ne peuvent pas être ouverts par les versions antérieures.

## Formats de fichier

### v3 (Securio ≥ 2.0)

| Offset | Taille | Champ |
|---|---|---|
| 0 | 7 | Magie `SECURIO` |
| 7 | 1 | Version (`3`) |
| 8 | 1 | KDF (`2` = Argon2id v1.3 ; 256 Mio / t=3 / p=4 par défaut depuis 2.1, 64 Mio en 2.0) |
| 9 | 4 | Argon2 mémoire en Kio (u32 LE) |
| 13 | 4 | Argon2 passes (u32 LE) |
| 17 | 1 | Argon2 parallélisme |
| 18 | 1 | Longueur du sel (16) |
| 19 | 1 | Chiffrement (`2` = AES-256-GCM STREAM) |
| 20 | 1 | Longueur du préfixe de nonce (7) |
| 21 | 4 | Taille d'un segment en clair (u32 LE, 1 Mio par défaut) |
| 25 | 4 | Taille du segment de métadonnées chiffré (u32 LE) |
| 29 | 16 | Sel |
| 45 | 7 | Préfixe de nonce |
| 52 | … | Segments |

Chaque segment est chiffré en AES-256-GCM (tag de 16 octets) avec l'en-tête complet comme
données associées et le nonce `préfixe ‖ compteur (u32 BE) ‖ drapeau « dernier »`
(construction STREAM). Segment 0 : métadonnées JSON `{name, type, size}` complétées par des
espaces à un multiple de 256 octets. Segments 1 et suivants : le fichier ; le dernier,
éventuellement vide, porte le drapeau « dernier ». Mot de passe : UTF-8 après normalisation NFC.

Les paramètres sont enregistrés dans chaque fichier : une version future pourra les durcir sans
casser la lecture des fichiers existants.

### v2 (Securio 1.3, lecture seule)

`SECURIO` · version `2` · PBKDF2-HMAC-SHA256 (itérations dans l'en-tête, 600 000) · AES-256-GCM
en un bloc, en-tête authentifié ; clair = `[u32 LE L][JSON L octets][fichier]`.
Détails : [`crates/securio-core/src/v2.rs`](crates/securio-core/src/v2.rs).

### v1 (Securio 1.0 → 1.2.1, lecture seule)

En-tête de 64 octets (version u32 LE = 1, nom UTF-8 sur 32 octets…), sel, IV, AES-CBC non
authentifié, PBKDF2-HMAC-SHA256 100 000 itérations.
Détails : [`crates/securio-core/src/v1.rs`](crates/securio-core/src/v1.rs).

## Sécurité

- Toute la cryptographie est en Rust ([RustCrypto](https://github.com/RustCrypto)) ; l'interface
  ne voit jamais le contenu des fichiers, seulement leurs chemins
- Clés, mots de passe et contenus déchiffrés effacés de la mémoire après usage (`zeroize`) ; la
  clé n'est plus conservée par l'interface une fois le fichier ouvert ; session effacée après
  5 minutes d'inactivité
- Interface Tauri : CSP stricte, prototypes JavaScript gelés, permissions limitées aux boîtes de
  dialogue Ouvrir/Enregistrer, aucun accès réseau
- Paramètres d'en-tête bornés (≤ 1 Gio, ≤ 10 passes) : un fichier forgé ne peut pas bloquer
  l'application
- Chaîne de compilation : permissions minimales, actions épinglées par empreinte, aucun script
  d'installation npm exécuté, audit RustSec/npm, empreintes SHA-256 et attestation de provenance
- Limite du format v1 : AES-CBC non authentifié, une altération n'y est pas détectable

## Développement

Prérequis : [Node.js](https://nodejs.org) ≥ 20, [Rust](https://rustup.rs) stable, et les
[prérequis Tauri](https://v2.tauri.app/start/prerequisites/) (Windows : *Build Tools for Visual
Studio* avec « Développement Desktop en C++ » ; Linux : `libwebkit2gtk-4.1-dev` etc.).

```bash
npm install
npm run app:dev     # application en mode développement (rechargement à chaud)
npm run app:build   # exécutable + installeurs (target/release/bundle/)
npm test            # tests Rust, dont la rétro-compatibilité
npm run lint        # ESLint + Clippy
```

Chaque `push` lance les tests et produit les exécutables Windows sur GitHub Actions
(`.github/workflows/build.yml`) ; un tag `v*` les publie sur la release.

```
crates/securio-core/   cœur cryptographique (formats v1, v2, v3) + tests
src-tauri/             application Tauri (commandes, fenêtres, installeurs)
src/                   interface React
test/fixtures/         fichiers témoins v1, v2, v3
test/legacy/           code JavaScript d'origine (1.2.1) qui a généré les témoins v1
```

### Rétro-compatibilité : règle d'or

`test/fixtures/` contient des fichiers chiffrés **par les versions d'origine** (v1 : code de la
1.2.1, conservé dans `test/legacy/` ; v2 : Securio 1.3 ; v3 : Securio 2.0). `cargo test` vérifie
qu'ils se déchiffrent toujours à l'octet près. Ces fichiers ne doivent jamais être régénérés ni
supprimés, et toute nouvelle version du format doit ajouter ses propres fichiers témoins.

## Licence

Ce projet est sous licence MIT. Voir le fichier [LICENSE](LICENSE) pour plus de détails.

## Contribution

Les contributions sont les bienvenues ! N'hésitez pas à :
1. Fork le projet
2. Créer une branche pour votre fonctionnalité
3. Commiter vos changements
4. Pousser vers la branche
5. Ouvrir une Pull Request

## Auteur

SkY1331 - [@SkY1331](https://github.com/SkY1331)
