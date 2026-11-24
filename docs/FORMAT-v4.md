# Format v4 : emplacements de clé — spécification (brouillon à valider)

> Statut : **proposition**. Rien n'est implémenté. Une fois des fichiers v4 créés, ce format ne
> pourra plus changer : chaque point ci-dessous doit être validé avant d'écrire le code.

## 1. Objectifs

| Besoin | Réponse du v4 |
|---|---|
| Mot de passe oublié = fichier perdu | **Clé de secours** : un second moyen d'ouvrir chaque fichier |
| Changer de mot de passe sans tout re-chiffrer | Seul l'en-tête est réécrit ; le contenu chiffré est recopié tel quel |
| Ouvrir sans taper de mot de passe (futur) | Emplacement **destinataire** déverrouillé par Windows Hello |
| Partager sans envoyer de mot de passe (futur) | Emplacement **destinataire** pour la clé publique d'une autre personne |
| AES-GCM n'engage pas la clé (risque théorique) | **Code d'authentification de l'en-tête** dérivé de la clé du fichier, qui engage cette clé |

Non-objectifs : gestionnaire de mots de passe intégré, serveur de récupération, synchronisation.

## 2. Principe : chiffrement « en enveloppe »

```
                ┌───────────────── en-tête (modifiable) ─────────────────┐
  mot de passe ─┤ emplacement 1 : Argon2id → enveloppe de la clé fichier │
  clé de secours┤ emplacement 2 : X25519   → enveloppe de la clé fichier │──► clé fichier (DEK,
  Windows Hello ┤ emplacement 3 : X25519   → enveloppe de la clé fichier │     256 bits aléatoires)
                └────────────────────────────────────────────────────────┘           │
                ┌──────────── cœur de l'en-tête (immuable) ─────────────┐            ▼
                │ version, paramètres, identifiant du fichier          │──► contenu AES-256-GCM
                └────────────────────────────────────────────────────────┘     par segments (v3)
```

- Chaque fichier a sa **clé fichier** (DEK), aléatoire. Le contenu est chiffré exactement comme en
  v3 (segments STREAM), mais avec une clé dérivée de la DEK et lié au **cœur** de l'en-tête
  seulement : on peut donc modifier les emplacements sans toucher au contenu.
- Chaque emplacement contient la DEK chiffrée (« enveloppée ») par une clé propre à ce moyen
  d'ouverture. Ouvrir = déverrouiller **un** emplacement.
- Règle de sécurité : **un fichier est aussi fragile que son emplacement le plus faible.**

## 3. Structure du fichier

Entiers en petit-boutiste (LE) sauf mention contraire.

### 3.1 Cœur de l'en-tête — immuable (41 octets)

| Offset | Taille | Champ |
|---|---|---|
| 0 | 7 | Magie `SECURIO` |
| 7 | 1 | Version = `4` |
| 8 | 1 | Chiffrement du contenu : `2` = AES-256-GCM STREAM (identique au v3) |
| 9 | 1 | Longueur du préfixe de nonce = `7` |
| 10 | 4 | Taille d'un segment en clair (u32) |
| 14 | 4 | Taille du segment de métadonnées chiffré (u32) |
| 18 | 16 | Identifiant du fichier (aléatoire) |
| 34 | 7 | Préfixe de nonce |

Le cœur est la donnée associée (AAD) de **chaque segment** du contenu. Il ne change jamais pour
un fichier donné.

### 3.2 Table des emplacements — modifiable

| Taille | Champ |
|---|---|
| 4 | Longueur L de la zone d'emplacements (u32, ≤ 64 Kio) |
| 1 | Nombre d'emplacements (1 à 16) |
| L − 1 | Emplacements : `type` (u8) · `longueur` (u16) · `contenu` |
| 32 | **Code d'authentification de l'en-tête** : HMAC-SHA256(K_entête, cœur ‖ L ‖ zone d'emplacements) |

Un type d'emplacement inconnu est **ignoré** : un fichier créé par une version future reste lisible
tant qu'il contient un emplacement connu.

### 3.3 Contenu

Identique au v3 : segment 0 = métadonnées JSON `{name, type, size}` complétées à 256 octets ;
segments suivants = le fichier ; nonce `préfixe ‖ compteur u32 BE ‖ drapeau dernier` ;
AAD = **cœur** (et non plus l'en-tête entier).

### 3.4 Dérivation des clés à partir de la DEK

```
K_contenu = HKDF-SHA256(DEK, sel = identifiant du fichier, info = "securio v4 contenu")
K_entête  = HKDF-SHA256(DEK, sel = identifiant du fichier, info = "securio v4 entete")
```

Le code d'authentification de l'en-tête (HMAC, qui engage la clé) garantit qu'une DEK obtenue par un
emplacement est bien **la** clé du fichier, et que la table n'a pas été modifiée par quelqu'un qui ne
peut pas ouvrir le fichier.

## 4. Types d'emplacements

Chaque enveloppe = AES-256-GCM(KEK, nonce aléatoire de 12 octets, DEK), avec pour AAD
`cœur ‖ type ‖ champs publics de l'emplacement`. Taille de l'enveloppe : 32 + 16 octets.

### Type 1 — mot de passe

| Taille | Champ |
|---|---|
| 4 / 4 / 1 | Argon2id : mémoire (Kio), passes, parallélisme — bornes du v3 (≤ 1 Gio, ≤ 10 passes) |
| 16 | Sel |
| 12 | Nonce de l'enveloppe |
| 48 | Enveloppe |

KEK = Argon2id(mot de passe UTF-8 NFC, sel). Par défaut : 256 Mio, t = 3, p = 4.

### Type 2 — destinataire X25519

| Taille | Champ |
|---|---|
| 32 | Clé publique éphémère |
| 12 | Nonce de l'enveloppe |
| 48 | Enveloppe |

KEK = HKDF-SHA256(X25519(éphémère, destinataire), sel = éphémère ‖ clé publique du destinataire,
info = `"securio v4 destinataire"`). **Aucun identifiant du destinataire** n'est stocké : on ne peut
pas savoir, sans les clés, que deux fichiers ont la même clé de secours. À l'ouverture, Securio
essaie ses clés connues sur chaque emplacement (quelques microsecondes chacune).

Ce type unique sert à trois usages :

| Usage | Clé privée | Disponible |
|---|---|---|
| **Clé de secours** | Imprimée par l'utilisateur ; **jamais stockée** sur le PC | v4 |
| Profil **Windows Hello** | Protégée par le TPM / Windows Hello | plus tard |
| **Partage** avec une autre personne | Détenue par cette personne | plus tard |

### Type 3 — réservé

Clé matérielle (FIDO2 `hmac-secret`, YubiKey), à spécifier séparément.

## 5. Clé de secours

- Créée **une fois** (Paramètres → « Créer ma clé de secours ») : paire X25519.
- La **clé privée** est affichée une seule fois sous forme de code à imprimer ou recopier, puis
  oubliée par l'application ; l'utilisateur doit en retaper deux groupes pour confirmer.
- La **clé publique** est conservée dans les paramètres (elle n'est pas secrète) et ajoutée
  automatiquement comme emplacement à **chaque nouveau fichier** : chiffrer ne demande donc jamais
  la clé de secours.
- Format proposé : 32 octets + 3 octets de contrôle en base32 Crockford, 14 groupes de 4 :
  `K7Q2-9XMA-…` (56 caractères, sans confusion 0/O ni 1/I, erreurs de frappe détectées).

Conseil affiché : la ranger comme un double de clé (coffre, gestionnaire de mots de passe d'un
proche de confiance), **jamais** à côté des fichiers ni sur le même PC.

## 6. Opérations

| Opération | Comment | Coût |
|---|---|---|
| Chiffrer | DEK aléatoire ; emplacement mot de passe ; + clé de secours si configurée | identique au v3 |
| Ouvrir | Essayer chaque emplacement connu → DEK → vérifier le code d'en-tête → métadonnées | 1 Argon2id ou 1 X25519 |
| **Changer le mot de passe** | Ouvrir, remplacer l'emplacement 1, recalculer le code d'en-tête, **recopier le contenu chiffré tel quel** dans un fichier temporaire, renommer | lecture/écriture seulement, pas de chiffrement |
| Ajouter / retirer un accès | Idem (le dernier emplacement ne peut pas être retiré) | idem |
| Convertir un v1/v2/v3 | Déchiffrement puis nouveau chiffrement complet | complet |

⚠️ **Changer le mot de passe ne protège pas les copies existantes** (sauvegardes, pièces jointes
déjà envoyées) : elles s'ouvrent toujours avec l'ancien, puisque la DEK ne change pas. Pour
révoquer réellement un mot de passe compromis : « Re-chiffrer avec une nouvelle clé » (nouvelle DEK,
coût complet), et détruire les anciennes copies.

## 7. Compatibilité

- Securio lit toujours v1, v2, v3 et v4 ; à sa sortie, le v4 devient le format d'écriture.
- Les versions ≤ 2.2 refusent un v4 avec le message « format plus récent, mettez à jour » (déjà en
  place).
- Fichiers témoins à ajouter : mot de passe seul ; mot de passe + clé de secours ; plusieurs
  destinataires ; emplacement de type inconnu (doit être ignoré) ; table modifiée sans la clé (doit
  être refusée) ; fichier dont le mot de passe a été changé (le contenu doit être identique à l'octet
  près).

## 8. Décisions à prendre

1. **Format de la clé de secours** : code base32 en groupes (proposé), ou liste de 22 mots
   français, plus facile à recopier mais plus longue.
2. **Clé de secours ajoutée par défaut** à tous les nouveaux fichiers une fois créée (proposé : oui,
   désactivable fichier par fichier).
3. **Changer le mot de passe** : réécriture complète du fichier par copie (proposé, sûr même en cas
   de coupure), ou modification sur place (plus rapide pour les très gros fichiers, mais un
   arrêt brutal au mauvais moment rendrait le fichier illisible).
4. **Nom du format** : conserver l'extension `.encrypted` (proposé).
