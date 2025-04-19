# Securio - Application de Chiffrement/Déchiffrement

Une application desktop cross-platform pour chiffrer et déchiffrer du texte ou du code, développée avec Electron, Vite, React et Node.js.

## Fonctionnalités

- Chiffrement et déchiffrement de texte
- Support de plusieurs algorithmes de chiffrement (AES-256-CBC, AES-192-CBC, AES-128-CBC)
- Interface utilisateur intuitive et responsive
- Glisser-déposer de fichiers .txt
- Sauvegarde des résultats
- Application desktop cross-platform (Windows, macOS, Linux)
- Version portable disponible (sans installation)

## Prérequis

- Node.js (version 14 ou supérieure)
- npm ou yarn

## Installation

1. Clonez le dépôt :
```bash
git clone https://github.com/SkY1331/Securio.git
cd Securio
```

2. Installez les dépendances :
```bash
npm install
# ou
yarn install
```

## Développement

Pour lancer l'application en mode développement :
```bash
npm run dev
# ou
yarn dev
```

## Construction

Pour construire l'application :
```bash
npm run build
# ou
yarn build
```

Pour construire la version portable :
```bash
npm run electron:build
# ou
yarn electron:build
```

Les fichiers exécutables seront générés dans le dossier `release`.

## Structure du Projet

```
Securio/
├── src/
│   ├── components/     # Composants React
│   │   ├── EncryptForm.jsx
│   │   ├── FileDropZone.jsx
│   │   └── ResultDisplay.jsx
│   ├── utils/         # Utilitaires
│   │   └── crypto.js
│   ├── main.js        # Processus principal Electron
│   └── preload.js     # Script de préchargement
├── public/            # Fichiers statiques
│   └── icon.ico
├── electron.vite.config.js
├── vite.config.js
├── package.json
└── README.md
```

## Technologies Utilisées

- Electron : Framework pour applications desktop cross-platform
- Vite : Outil de build rapide
- React : Bibliothèque JavaScript pour l'interface utilisateur
- Node.js : Environnement d'exécution JavaScript
- Tailwind CSS : Framework CSS utilitaire
- Electron Builder : Outil de packaging pour Electron

## Sécurité

- Les clés de chiffrement ne sont jamais stockées
- Les fichiers sont traités localement, sans envoi vers des serveurs externes
- Utilisation d'algorithmes de chiffrement standards et sécurisés
- Version portable disponible pour une utilisation sans installation

## Licence

MIT

## Contribution

Les contributions sont les bienvenues ! N'hésitez pas à ouvrir une issue ou à soumettre une pull request.

## Auteur

SkY1331 - [@SkY1331](https://github.com/SkY1331) 