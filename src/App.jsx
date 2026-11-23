import { useState, useEffect } from 'react';
import EncryptForm from './components/EncryptForm';

function toFileData(file) {
  return { content: new Uint8Array(file.data), type: 'application/octet-stream', name: file.name };
}

function App() {
  const [initialFile, setInitialFile] = useState(null);

  useEffect(() => {
    const api = window.securio;
    if (!api) return undefined; // exécution dans un navigateur (npm run dev)

    // Fichier .encrypted passé au lancement (double-clic, « Ouvrir avec »)
    api
      .getLaunchFiles()
      .then((files) => {
        if (files?.length) setInitialFile(toFileData(files[0]));
      })
      .catch((e) => console.error('Erreur lors du chargement du fichier :', e));

    // Fichier ouvert alors que l'application est déjà lancée
    return api.onOpenFile((file) => setInitialFile(toFileData(file)));
  }, []);

  return (
    <div className="min-h-screen bg-gray-100 py-8 px-4 sm:px-6 lg:px-8">
      <div className="max-w-7xl mx-auto">
        <div className="text-center mb-8">
          <h1 className="text-xl font-bold text-gray-800">Securio</h1>
          <p className="mt-2 text-sm text-gray-600">
            Une petite application autonome pour chiffrer/déchiffrer vos fichiers (v{__APP_VERSION__})
          </p>
        </div>
        <EncryptForm initialFile={initialFile} />
      </div>
    </div>
  );
}

export default App;
