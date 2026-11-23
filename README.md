# Securio

Une application sécurisée pour chiffrer et déchiffrer vos fichiers sensibles, entièrement en local.

## Fonctionnalités

- 🔒 Chiffrement authentifié **AES-256-GCM** (toute modification du fichier chiffré est détectée)
- 🔑 Dérivation de clé **PBKDF2-HMAC-SHA256, 600 000 itérations**, sel aléatoire par fichier
- 🕶️ Nom et type du fichier d'origine **chiffrés** dans le fichier `.encrypted`
- ♻️ **Rétro-compatible** : les fichiers créés par Securio 1.0 → 1.2.1 s'ouvrent toujours
- 🚀 Ouverture directe des fichiers `.encrypted` (double-clic / « Ouvrir avec »)
- 🖥️ Interface simple : le mode (chiffrer / déchiffrer) est détecté automatiquement
- 💾 Aucune donnée ne quitte votre ordinateur, aucune clé n'est stockée

## Installation

1. Téléchargez la dernière version depuis la [page des releases](https://github.com/SkY1331/Securio/releases)
   - `Securio-x.y.z-portable.exe` : version portable, sans installation
   - `Securio-x.y.z-setup.exe` : installeur, qui associe aussi l'extension `.encrypted` à Securio (double-clic)
2. Lancez l'application

## Utilisation

1. **Chiffrer un fichier**
   - Glissez-déposez le fichier (ou cliquez sur la zone pour le sélectionner)
   - Saisissez la clé secrète deux fois — **aucune récupération n'est possible en cas d'oubli**
   - Cliquez sur « Chiffrer » puis « Sauvegarder » : le fichier est enregistré avec l'extension `.encrypted`

2. **Déchiffrer un fichier**
   - Glissez-déposez le fichier `.encrypted`, ou double-cliquez dessus (version installée)
   - Saisissez la clé secrète, cliquez sur « Déchiffrer » puis « Sauvegarder »
   - Le fichier est restauré avec son nom d'origine

### Anciens fichiers (Securio ≤ 1.2.1)

Ils sont reconnus automatiquement (« ancien format v1 »). L'algorithme utilisé à l'époque
(AES-128/192/256-CBC) n'étant pas enregistré dans le fichier, Securio le **détecte
automatiquement** ; vous pouvez aussi l'imposer.

Les versions ≤ 1.2.1 lisaient certains fichiers de façon incorrecte avant de les chiffrer.
Securio 1.3 corrige ces fichiers au déchiffrement, tout en laissant toujours la possibilité
d'enregistrer le contenu brut :

| Fichier chiffré avec ≤ 1.2.1 | Problème d'origine | Réparation en 1.3 |
|---|---|---|
| Images (`.png`, `.jpg`…) | stockées sous forme de texte `data:image/...;base64,…` | reconverties automatiquement en image, à l'identique |
| `.txt` | accents stockés en Latin-1, caractères au-delà (€, ’, “ ”, –, —, emojis) tronqués | accents reconvertis en UTF-8 ; ’ ‘ “ ” – — restaurés ; € (devenu ¬) et emojis non récupérables |
| `.csv`, `.md`, `.html`… | idem si le système les déclarait `text/*` | une « version texte réparée » est proposée en plus |
| Noms de plus de 32 octets | nom tronqué dans l'en-tête | nom complet retrouvé à partir du nom du `.encrypted` quand c'est possible |

> ℹ️ Les fichiers chiffrés avec la 1.3 utilisent le nouveau format v2 : ils ne peuvent pas être
> ouverts par les versions antérieures. Mettez à jour Securio sur tous vos postes.

## Format de fichier

### v2 (Securio ≥ 1.3)

| Offset | Taille | Champ |
|---|---|---|
| 0 | 7 | Magie `SECURIO` |
| 7 | 1 | Version du format (`2`) |
| 8 | 1 | KDF (`1` = PBKDF2-HMAC-SHA256) |
| 9 | 4 | Itérations (uint32 LE) |
| 13 | 1 | Longueur du sel (16) |
| 14 | 1 | Chiffrement (`1` = AES-256-GCM) |
| 15 | 1 | Longueur de l'IV (12) |
| 16 | 16 | Sel |
| 32 | 12 | IV |
| 44 | … | Données chiffrées + tag GCM (16 octets) |

L'en-tête complet est authentifié (données associées GCM). Le contenu chiffré est
`[longueur des métadonnées : uint32 LE][métadonnées JSON {name, type, size}][octets du fichier]`.
Le mot de passe est encodé en UTF-8 après normalisation Unicode NFC.

Les paramètres étant enregistrés dans chaque fichier, une future version pourra augmenter
le nombre d'itérations ou changer d'algorithme sans casser la lecture des fichiers existants.

### v1 (Securio 1.0 → 1.2.1, lecture seule)

En-tête de 64 octets (version uint32 LE = 1, type, nom UTF-8 sur 32 octets, taille),
sel (16), IV (16), puis données AES-CBC. Clé PBKDF2-HMAC-SHA256 100 000 itérations.
Détails et implémentation : [`src/utils/legacyV1.js`](src/utils/legacyV1.js).

## Sécurité

- Toutes les opérations sont effectuées localement (Web Crypto API)
- Les clés ne sont jamais stockées ; l'application n'effectue aucune connexion réseau
- Fenêtre Electron isolée : `contextIsolation`, `sandbox`, pas d'accès Node depuis l'interface,
  politique CSP stricte, navigation et ouverture de fenêtres bloquées
- Intégrité garantie par AES-GCM pour le format v2 (le format v1, non authentifié, ne permet pas
  de détecter une altération)

## Développement

```bash
npm install            # dépendances
npm test               # tests (dont rétro-compatibilité v1)
npm run lint           # ESLint
npm run dev            # interface dans le navigateur (http://localhost:5173)
npm run electron:dev   # dans un 2e terminal : l'application Electron sur le serveur de dev
npm run build          # build de l'interface (dist/)
npm run electron:build            # exécutable portable Windows
npm run electron:build:installer  # installeur Windows (associe .encrypted)
```

### Rétro-compatibilité : règle d'or

`test/fixtures/v1/` contient des fichiers chiffrés par **le code d'origine de la 1.2.1**
(conservé tel quel dans `test/legacy/cryptoUtils.v1.original.js`). `npm test` vérifie qu'ils
se déchiffrent toujours. Ces fichiers ne doivent jamais être régénérés ni supprimés, et
toute nouvelle version du format doit ajouter ses propres fichiers témoins.

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
