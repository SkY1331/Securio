# Securio

Une application sécurisée pour chiffrer et déchiffrer vos fichiers sensibles.

## Fonctionnalités

- 🔒 Chiffrement et déchiffrement de fichiers
- 📁 Support de multiples types de fichiers :
  - Documents (PDF, DOC, DOCX)
  - Images (JPG, PNG)
  - Feuilles de calcul (XLS, XLSX)
  - Fichiers texte (TXT, CSV)
  - Et plus encore...
- 🛡️ Algorithmes de chiffrement sécurisés :
  - AES-256-CBC
  - AES-192-CBC
  - AES-128-CBC
- 🔑 Gestion sécurisée des clés
- 💾 Format de fichier personnalisé avec métadonnées
- 🖥️ Interface utilisateur intuitive
- 🚀 Traitement local des données

## Installation

1. Téléchargez la dernière version depuis la [page des releases](https://github.com/SkY1331/Securio/releases)
2. Décompressez l'archive
3. Lancez l'application

## Utilisation

1. **Chiffrement d'un fichier** :
   - Glissez-déposez votre fichier dans la zone prévue
   - Entrez une clé secrète
   - Choisissez l'algorithme de chiffrement
   - Cliquez sur "Chiffrer"
   - Le fichier chiffré sera sauvegardé avec l'extension `.encrypted`

2. **Déchiffrement d'un fichier** :
   - Glissez-déposez votre fichier `.encrypted`
   - Entrez la clé secrète utilisée pour le chiffrement
   - Cliquez sur "Déchiffrer"
   - Le fichier sera restauré avec son type et nom d'origine

## Format de fichier

Les fichiers chiffrés utilisent un format personnalisé qui inclut :
- Un en-tête contenant les métadonnées du fichier
- Le type MIME original
- Le nom du fichier original
- Les données chiffrées

## Sécurité

- Toutes les opérations sont effectuées localement
- Les clés de chiffrement ne sont jamais stockées
- Utilisation d'algorithmes de chiffrement standards et sécurisés
- Vérification de l'intégrité des fichiers

## Développement

```bash
# Installation des dépendances
npm install

# Lancement en mode développement
npm run dev

# Construction de l'application
npm run build

# Construction de la version portable
npm run electron:build
```

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